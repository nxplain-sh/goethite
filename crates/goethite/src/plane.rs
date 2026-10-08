//! The control plane: the store, the query log, filter rebuilds and list
//! downloads, the cluster and the API.
//!
//! It runs beside the data plane (the resolver, its policy and the DNS
//! server), which never needs it: queries are answered while it stops and
//! starts again. An upgrade stops it so the new goethite can open the
//! store, and starts it again if the upgrade fails.

use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwapOption;
use goethite_api::Api;
use goethite_resolver::{PolicyState, Resolver, TlsRoots, tls_client_config};
use goethite_server::ServerStats;
use goethite_store::{QueryLog, Store};
use jiff::Timestamp;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::certs::Served;
use crate::cluster::{self, Cluster};
use crate::config::{Config, OnFailure};
use crate::control::Control;
use crate::filterlists::FilterLists;
use crate::lists::ListStore;
use crate::metrics::Metrics;
use crate::secrets::Secrets;
use crate::sockets::Sockets;
use crate::{download, filters, node};

/// How long stopping may take before giving up on the store.
const STOP_TIMEOUT: Duration = Duration::from_secs(15);

/// What the control plane steers and reports on: the data plane.
pub struct DataPlane {
    /// The resolver, for its cache and upstreams, and for list downloads.
    pub resolver: Arc<Resolver>,
    /// The policy the resolver filters with.
    pub state: Arc<PolicyState>,
    /// Per-query counters.
    pub metrics: Arc<Metrics>,
    /// What the DNS listeners turned away.
    pub server: Arc<ServerStats>,
    /// The query log the DNS server writes to, while there is one.
    pub log: Arc<ArcSwapOption<QueryLog>>,
    /// The certificate for DNS over TLS and HTTPS, if they are served.
    pub dns_cert: Option<Arc<Served>>,
    /// When goethite started.
    pub started: Timestamp,
}

/// The running control plane.
pub struct ControlPlane {
    stop: watch::Sender<bool>,
    tasks: JoinSet<()>,
    store: Weak<Store>,
    log: Arc<QueryLog>,
    observer_log: Arc<ArcSwapOption<QueryLog>>,
    cluster: Option<Arc<Cluster>>,
    /// Kept so they go away on stop, with their references to the store.
    holders: (Arc<Control>, Arc<Api>),
}

impl ControlPlane {
    /// Opens the store and starts everything. `first` is the start with
    /// the process, as opposed to again after a failed upgrade.
    ///
    /// # Errors
    ///
    /// If the store cannot be used (and filtering fails closed), the filter
    /// cannot be built at the first start (and filtering fails closed), or
    /// a listener or certificate is unusable.
    pub async fn start(
        config: &Config,
        config_path: &Path,
        sockets: &Sockets,
        secrets: &Secrets,
        data: &DataPlane,
        first: bool,
    ) -> Result<Self> {
        let (stop, stopped) = watch::channel(false);
        let mut tasks = JoinSet::new();
        let (store, store_problem) = crate::open_store_or_fall_back(config)?;
        let store = Arc::new(store);
        crate::seed(&store, config, config_path)?;
        let upstream_names = config
            .upstream
            .iter()
            .map(|upstream| upstream.to_upstream().address.to_string())
            .collect();
        let log = store.start_query_log(config.querylog.to_config(), upstream_names)?;
        if first && !config.querylog.enabled {
            info!("the query log is turned off; statistics are still kept");
        }
        data.log.store(Some(Arc::clone(&log)));
        let control = Control::new(
            Arc::clone(&store),
            Arc::clone(&data.state),
            ListStore::new(config.lists_dir()),
        );
        // Filter from the first query on, with the lists already on disk.
        if !control.rebuild_filter().await {
            if first && config.filter.on_failure == OnFailure::Closed {
                bail!(
                    "the filter cannot be built ({}), and [filter] on_failure is \"closed\": not \
                     starting",
                    control.build_error().unwrap_or_default()
                );
            }
            warn!("running without filtering: [filter] on_failure is \"open\"");
        }
        if first && !control.store().config().settings.spec.protection {
            info!("filtering is turned off in the settings");
        }
        let api_cert = api_cert(config, secrets)?;
        let reloadable = api_cert.iter().chain(&data.dns_cert).cloned().collect();
        crate::reload_on_hangup(
            Arc::clone(&control),
            reloadable,
            &mut tasks,
            stopped.clone(),
        )?;
        let cluster = match (&config.cluster, &secrets.cluster) {
            (Some(section), Some(pem)) => {
                let listeners = sockets
                    .cluster_listener()?
                    .context("the cluster listener is missing")?;
                let parts = cluster::Parts {
                    control: &control,
                    log: &log,
                    started_at: data.started,
                };
                Some(cluster::start(
                    section, pem, listeners, &parts, &mut tasks, &stopped,
                )?)
            }
            (Some(_), None) => bail!("the cluster's certificates are missing"),
            (None, _) => None,
        };
        let tls = tls_client_config(&TlsRoots::Bundled, &[b"h2", b"http/1.1"])?;
        let filterlists = filterlists(config, data, &tls);
        let downloader =
            download::Downloader::new(Arc::clone(&data.resolver), tls, filters::MAX_LIST_LEN);
        control.spawn(downloader, &mut tasks, &stopped);
        let node = node::Node {
            control: Arc::clone(&control),
            resolver: Arc::clone(&data.resolver),
            server: Arc::clone(&data.server),
            metrics: Arc::clone(&data.metrics),
            log: Arc::clone(&log),
            querylog_enabled: config.querylog.enabled,
            started: data.started,
            store_problem,
            cluster: cluster.clone(),
            encrypted: encrypted_status(config),
            filterlists,
        };
        let api_tls = api_cert
            .as_ref()
            .map(|cert| cert.server_config(&[b"h2", b"http/1.1"]))
            .transpose()?;
        // The API exists even when it is not served: the primary runs the
        // replica's forwarded changes through it.
        let api = crate::api(config, &control, &log, node, api_tls);
        if let Some(cluster) = &cluster {
            cluster.set_api(Arc::clone(&api));
        }
        serve_api(sockets, &api, &mut tasks, &stopped)?;
        Ok(Self {
            stop,
            tasks,
            store: Arc::downgrade(&store),
            log,
            observer_log: Arc::clone(&data.log),
            cluster,
            holders: (control, api),
        })
    }

    /// Stops everything and closes the store. Queries go on being
    /// answered, by the last policy.
    ///
    /// # Errors
    ///
    /// If something still holds the store after [`STOP_TIMEOUT`].
    pub async fn stop(self) -> Result<()> {
        let Self {
            stop,
            mut tasks,
            store,
            log,
            observer_log,
            cluster,
            holders,
        } = self;
        stop.send_replace(true);
        if let Some(cluster) = &cluster {
            cluster.release_api();
        }
        let joined = tokio::time::timeout(STOP_TIMEOUT, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        if joined.is_err() {
            warn!("control plane tasks did not stop in time; aborting them");
            tasks.shutdown().await;
        }
        observer_log.store(None);
        drop((holders, cluster));
        tokio::task::spawn_blocking(move || log.close())
            .await
            .context("closing the query log failed")?;
        // Requests finishing and blocking work may still hold the store
        // for a moment.
        let started = Instant::now();
        while store.strong_count() > 0 {
            if started.elapsed() > STOP_TIMEOUT {
                bail!("the store is still in use after stopping the control plane");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    }
}

/// The API's certificate, if it serves HTTPS.
fn api_cert(config: &Config, secrets: &Secrets) -> Result<Option<Arc<Served>>> {
    secrets
        .api_tls
        .as_ref()
        .map(|pem| {
            let files = config.api.tls_cert.clone().zip(config.api.tls_key.clone());
            Served::new("API certificate", pem, files)
        })
        .transpose()
}

/// Serves the API on its sockets, if it has any, until `stopped`.
fn serve_api(
    sockets: &Sockets,
    api: &Arc<Api>,
    tasks: &mut JoinSet<()>,
    stopped: &watch::Receiver<bool>,
) -> Result<()> {
    if let Some(listeners) = sockets.api_listeners()? {
        let api = Arc::clone(api);
        let until = crate::until(stopped.clone());
        tasks.spawn(async move {
            if let Err(err) = goethite_api::serve(listeners, api, until).await {
                error!(%err, "the API failed");
            }
        });
    }
    Ok(())
}

/// How clients reach this node over DNS over TLS, HTTPS and QUIC, for the
/// API.
fn encrypted_status(config: &Config) -> Option<goethite_api::EncryptedStatus> {
    let server = config.server_config();
    config
        .server
        .tls
        .as_ref()
        .map(|_| goethite_api::EncryptedStatus {
            server_name: server.server_name,
            dot: server.dot.iter().map(ToString::to_string).collect(),
            doh: server.doh.iter().map(ToString::to_string).collect(),
            doq: server.doq.iter().map(ToString::to_string).collect(),
        })
}

/// The FilterLists directory, unless `[filter] directory` turns it off.
fn filterlists(
    config: &Config,
    data: &DataPlane,
    tls: &Arc<rustls::ClientConfig>,
) -> Option<Arc<FilterLists>> {
    config.filter.directory.then(|| {
        Arc::new(FilterLists::new(
            Arc::clone(&data.resolver),
            Arc::clone(tls),
        ))
    })
}
