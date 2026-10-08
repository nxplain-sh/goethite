//! Compiling the filter from the store's lists and rules, and downloading
//! lists.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use goethite_filter::{Filter, FilterBuilder, ListStats, Source};
use goethite_store::{ConfigSnapshot, List};
use jiff::Timestamp;
use tracing::{debug, error, info, warn};

use crate::config::FilterSection;
use crate::download::{Downloader, Fetched};
use crate::lists::{ListStore, validate};

/// List files and downloads larger than this many bytes are refused.
pub const MAX_LIST_LEN: usize = 128 * 1024 * 1024;

/// The ID of the source holding the custom rules.
pub const CUSTOM_RULES: &str = "custom";

/// How one list is doing, for logs and the API.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListStatus {
    /// What was read the last time the filter was compiled; `None` if the
    /// list was not read (disabled, not downloaded yet, or unreadable).
    pub stats: Option<ListStats>,
    /// Why the list could not be read, if it could not.
    pub error: Option<String>,
    /// When a download was last tried.
    pub last_attempt: Option<Timestamp>,
    /// When a download last succeeded or found the list unchanged.
    pub last_success: Option<Timestamp>,
    /// Why the last download failed or was rejected, if it was.
    pub download_error: Option<String>,
}

/// A compiled filter, with what each source is.
#[allow(
    dead_code,
    reason = "the API, in the next commit, reads the list statuses"
)]
pub struct Compiled {
    /// The filter.
    pub filter: Arc<Filter>,
    /// Source `i`'s ID: [`CUSTOM_RULES`], then list IDs.
    pub source_ids: Vec<Arc<str>>,
    /// What was read from each list, by list ID.
    pub lists: HashMap<String, ListStatus>,
}

impl Compiled {
    /// No rules at all.
    pub fn empty() -> Self {
        Self {
            filter: Arc::new(Filter::empty()),
            source_ids: Vec::new(),
            lists: HashMap::new(),
        }
    }

    /// The source index of `id`, if it was compiled in.
    pub fn source(&self, id: &str) -> Option<Source> {
        self.source_ids
            .iter()
            .position(|source| &**source == id)
            .and_then(Source::new)
    }
}

/// Compiles the enabled custom rules (source 0) and enabled lists (one
/// source each, in order). A list that cannot be read is logged, recorded in
/// its status and skipped: filtering must never take resolution down.
///
/// # Errors
///
/// Only if the FST cannot be built, which does not happen for parsed rules.
pub fn compile(config: &ConfigSnapshot, lists: &ListStore) -> Result<Compiled> {
    let mut builder = FilterBuilder::new();
    let mut source_ids: Vec<Arc<str>> = vec![CUSTOM_RULES.into()];
    let mut statuses = HashMap::new();
    let rules: Vec<&str> = config
        .rules
        .iter()
        .filter(|rule| rule.spec.enabled)
        .map(|rule| rule.spec.rule.as_str())
        .collect();
    if let Some(source) = Source::new(0)
        && !rules.is_empty()
    {
        log_stats("custom rules", builder.add_list(source, &rules.join("\n")));
    }
    for list in config.lists.iter().filter(|list| list.spec.enabled) {
        let Some(source) = Source::new(source_ids.len()) else {
            error!(list = %list.id, "too many filter lists; skipping this one");
            continue;
        };
        source_ids.push(list.id.as_str().into());
        let mut status = ListStatus::default();
        match list_file(list, lists) {
            None => info!(list = %list.spec.name, "not downloaded yet"),
            Some(path) => match read_list(&path) {
                Ok(text) => {
                    let read = builder.add_list(source, &text);
                    log_stats(&list.spec.name, read);
                    status.stats = Some(read);
                }
                Err(err) => {
                    error!(list = %list.spec.name, "{err:#}; skipping this list");
                    status.error = Some(format!("{err:#}"));
                }
            },
        }
        statuses.insert(list.id.clone(), status);
    }
    let filter = builder.build().context("cannot compile the filter")?;
    info!(
        rules = filter.rule_count(),
        memory_kib = filter.memory_bytes() / 1024,
        "filter ready"
    );
    Ok(Compiled {
        filter: Arc::new(filter),
        source_ids,
        lists: statuses,
    })
}

/// The file `list` is read from: its path, or the downloaded copy of its URL
/// (`None` if not downloaded yet).
fn list_file(list: &List, lists: &ListStore) -> Option<PathBuf> {
    match (&list.spec.path, &list.spec.url) {
        (Some(path), _) => Some(PathBuf::from(path)),
        (None, Some(url)) => Some(lists.path_for(url)).filter(|path| path.exists()),
        (None, None) => None,
    }
}

/// Reads and compiles the config file's rules and lists, for
/// `goethite check-config`: a list file that cannot be read is an error.
pub fn check(section: &FilterSection, lists: &ListStore) -> Result<()> {
    let mut builder = FilterBuilder::new();
    let source = Source::new(0).context("no filter source")?;
    if !section.rules.is_empty() {
        log_stats(
            "config rules",
            builder.add_list(source, &section.rules.join("\n")),
        );
    }
    for list in &section.list {
        let (name, path) = match (&list.path, &list.url) {
            (Some(path), _) => (path.display().to_string(), Some(path.clone())),
            (None, Some(url)) => (
                url.clone(),
                Some(lists.path_for(url)).filter(|p| p.exists()),
            ),
            (None, None) => continue,
        };
        let Some(path) = path else {
            info!(list = %name, "not downloaded yet");
            continue;
        };
        log_stats(&name, builder.add_list(source, &read_list(&path)?));
    }
    let filter = builder.build().context("cannot compile the filter")?;
    info!(rules = filter.rule_count(), "filter ready");
    Ok(())
}

fn log_stats(source: &str, stats: ListStats) {
    info!(
        list = %source,
        rules = stats.rules,
        unsupported = stats.unsupported,
        invalid = stats.invalid,
        "loaded filter rules"
    );
    if stats.over_limit > 0 {
        warn!(list = %source, dropped = stats.over_limit, "filter rule limit reached");
    }
}

/// Reads a list file, refusing files over [`MAX_LIST_LEN`]. Invalid UTF-8 is
/// replaced rather than rejected, so one bad byte does not lose the list.
fn read_list(path: &Path) -> Result<String> {
    let file =
        File::open(path).with_context(|| format!("cannot open filter list {}", path.display()))?;
    let limit = u64::try_from(MAX_LIST_LEN)?.saturating_add(1);
    let mut bytes = Vec::new();
    let len = file
        .take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read filter list {}", path.display()))?;
    if len > MAX_LIST_LEN {
        bail!(
            "filter list {} is larger than {MAX_LIST_LEN} bytes",
            path.display()
        );
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The outcome of one list download.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Downloaded {
    /// A new copy was saved.
    Changed,
    /// The server says the copy we have is current.
    Unchanged,
    /// The download failed or was rejected; the last good copy stays.
    Failed(String),
}

/// Downloads `url` into `lists` if it changed, validating it before it
/// replaces the last good copy.
pub async fn download(url: &str, lists: &ListStore, downloader: &Downloader) -> Downloaded {
    let validators = lists.validators(url);
    match downloader.fetch(url, &validators).await {
        Ok(Fetched::NotModified) => {
            debug!(list = %url, "list unchanged");
            Downloaded::Unchanged
        }
        Ok(Fetched::Body { bytes, validators }) => {
            let lists = lists.clone();
            let owned = url.to_owned();
            let saved = tokio::task::spawn_blocking(move || {
                let stats = validate(&bytes)?;
                lists.save(&owned, &bytes, &validators)?;
                Ok::<_, anyhow::Error>(stats)
            })
            .await;
            match saved {
                Ok(Ok(stats)) => {
                    info!(list = %url, rules = stats.rules, "list downloaded");
                    Downloaded::Changed
                }
                Ok(Err(err)) => {
                    warn!(list = %url, "download rejected: {err:#}; keeping the last good copy");
                    Downloaded::Failed(format!("rejected: {err:#}"))
                }
                Err(err) => {
                    error!(list = %url, %err, "saving the list failed");
                    Downloaded::Failed(format!("saving failed: {err}"))
                }
            }
        }
        Err(err) => {
            warn!(list = %url, "cannot download: {err:#}; keeping the last good copy");
            Downloaded::Failed(format!("{err:#}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use goethite_filter::Sources;
    use goethite_store::{ListSpec, ManagedBy, Rule, RuleSpec};

    use super::*;

    fn now() -> Timestamp {
        Timestamp::now()
    }

    fn list(id: &str, path: Option<&Path>, url: Option<&str>, enabled: bool) -> List {
        List {
            id: id.into(),
            revision: 1,
            created_at: now(),
            updated_at: now(),
            spec: ListSpec {
                name: id.into(),
                url: url.map(Into::into),
                path: path.map(|p| p.display().to_string()),
                enabled,
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        }
    }

    #[test]
    fn compiles_rules_and_lists_as_sources() {
        let dir = std::env::temp_dir().join(format!("goethite-compile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.txt");
        std::fs::write(&good, "0.0.0.0 ads.example\n").unwrap();
        let mut config = ConfigSnapshot::empty(now());
        config.rules.push(Rule {
            id: "ru_1".into(),
            revision: 1,
            created_at: now(),
            updated_at: now(),
            spec: RuleSpec {
                rule: "||tracker.example^".into(),
                enabled: true,
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        });
        config.lists = vec![
            list("li_good", Some(&good), None, true),
            list("li_missing", Some(&dir.join("missing.txt")), None, true),
            list("li_off", Some(&good), None, false),
            list("li_url", None, Some("https://lists.example/x"), true),
        ];
        let compiled = compile(&config, &ListStore::new(dir.join("lists"))).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(compiled.filter.rule_count(), 2);
        let ids: Vec<&str> = compiled.source_ids.iter().map(|id| &**id).collect();
        assert_eq!(ids, ["custom", "li_good", "li_missing", "li_url"]);
        let only = |id: &str| Sources::NONE.with(compiled.source(id).unwrap());
        let ads = "ads.example".parse().unwrap();
        assert!(compiled.filter.check(&ads, only("li_good")).is_blocked());
        assert!(!compiled.filter.check(&ads, only("custom")).is_blocked());
        let tracker = "x.tracker.example".parse().unwrap();
        assert!(compiled.filter.check(&tracker, only("custom")).is_blocked());
        assert_eq!(compiled.lists["li_good"].stats.unwrap().rules, 1);
        assert!(
            compiled.lists["li_missing"]
                .error
                .as_ref()
                .unwrap()
                .contains("cannot open filter list")
        );
        assert_eq!(
            compiled.lists["li_url"],
            ListStatus::default(),
            "not downloaded yet"
        );
        assert!(!compiled.lists.contains_key("li_off"));
    }

    #[test]
    fn checking_fails_on_unreadable_lists() {
        let section = FilterSection {
            list: vec![crate::config::ListSection {
                path: Some(PathBuf::from("/nonexistent/goethite/list.txt")),
                url: None,
            }],
            ..FilterSection::default()
        };
        let err = check(&section, &ListStore::new(PathBuf::from("/nonexistent"))).unwrap_err();
        assert!(
            err.to_string().contains("cannot open filter list"),
            "{err:#}"
        );
    }

    #[test]
    fn oversized_lists_are_refused() {
        let path = std::env::temp_dir().join(format!("goethite-huge-{}.txt", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(u64::try_from(MAX_LIST_LEN).unwrap() + 1)
            .unwrap();
        let err = read_list(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(err.to_string().contains("larger than"), "{err:#}");
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::doc_markdown,
    reason = "test server bookkeeping"
)]
mod update_tests {
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    use goethite_filter::{Sources, Verdict};
    use goethite_proto::Record;
    use goethite_resolver::{Resolver, TlsRoots, tls_client_config};
    use goethite_store::{ListSpec, ManagedBy};
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::header::{ETAG, IF_NONE_MATCH, LOCATION};
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::download::Downloader;

    const CA: &[u8] = include_bytes!("../../goethite-resolver/tests/fixtures/ca.pem");
    const CERT: &[u8] = include_bytes!("../../goethite-resolver/tests/fixtures/server.pem");
    const KEY: &[u8] = include_bytes!("../../goethite-resolver/tests/fixtures/server.key");

    struct Served {
        body: Vec<u8>,
        etag: String,
        requests: usize,
        not_modified: usize,
    }

    /// An HTTPS server for `dns.goethite.test` serving `/list` (with ETag
    /// revalidation), `/moved` (a redirect to it) and `/downgrade` (a
    /// redirect to http://). `alpn` picks HTTP/1.1 or HTTP/2.
    async fn server(list: Arc<Mutex<Served>>, alpn: &'static [u8]) -> SocketAddr {
        let certs = vec![CertificateDer::from_pem_slice(CERT).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        config.alpn_protocols = vec![alpn.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let list = Arc::clone(&list);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let list = Arc::clone(&list);
                        async move { Ok::<_, Infallible>(respond(&list, &request)) }
                    });
                    let io = TokioIo::new(tls);
                    if alpn == b"h2" {
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(io, service)
                            .await;
                    } else {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    }
                });
            }
        });
        addr
    }

    fn respond(list: &Mutex<Served>, request: &Request<Incoming>) -> Response<Full<Bytes>> {
        let mut list = list.lock().unwrap();
        list.requests += 1;
        let builder = Response::builder();
        let response = match request.uri().path() {
            "/moved" => builder
                .status(StatusCode::FOUND)
                .header(LOCATION, "/list")
                .body(Full::default()),
            "/downgrade" => builder
                .status(StatusCode::FOUND)
                .header(LOCATION, "http://dns.goethite.test/list")
                .body(Full::default()),
            "/list"
                if request
                    .headers()
                    .get(IF_NONE_MATCH)
                    .is_some_and(|tag| tag == list.etag.as_str()) =>
            {
                list.not_modified += 1;
                builder
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Full::default())
            }
            "/list" => builder
                .header(ETAG, list.etag.as_str())
                .body(Full::new(Bytes::from(list.body.clone()))),
            _ => builder.status(StatusCode::NOT_FOUND).body(Full::default()),
        };
        response.unwrap()
    }

    fn downloader(max_len: usize) -> Downloader {
        let name = "dns.goethite.test".parse().unwrap();
        let resolver = Resolver::new(vec![Record::a(name, 60, Ipv4Addr::LOCALHOST)]);
        let roots = TlsRoots::Custom(vec![CertificateDer::from_pem_slice(CA).unwrap().to_vec()]);
        let tls = tls_client_config(&roots, &[b"h2", b"http/1.1"]).unwrap();
        Downloader::new(Arc::new(resolver), tls, max_len)
    }

    /// The verdict for `name` with one URL list compiled from `lists`.
    fn verdict(lists: &ListStore, url: &str, name: &str) -> Verdict {
        let now = Timestamp::now();
        let mut config = ConfigSnapshot::empty(now);
        config.lists.push(List {
            id: "li_test".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: ListSpec {
                name: "test".into(),
                url: Some(url.into()),
                path: None,
                enabled: true,
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        });
        compile(&config, lists)
            .unwrap()
            .filter
            .check(&name.parse().unwrap(), Sources::ALL)
    }

    async fn download_cycle(alpn: &'static [u8]) {
        let list = Arc::new(Mutex::new(Served {
            body: b"0.0.0.0 ads.example\n".to_vec(),
            etag: "\"v1\"".into(),
            requests: 0,
            not_modified: 0,
        }));
        let addr = server(Arc::clone(&list), alpn).await;
        let cache_dir = std::env::temp_dir().join(format!(
            "goethite-downloads-{}-{}",
            std::process::id(),
            String::from_utf8_lossy(alpn)
        ));
        let lists = ListStore::new(cache_dir.clone());
        let base = format!("https://dns.goethite.test:{}", addr.port());
        let url = format!("{base}/list");
        let downloader = downloader(MAX_LIST_LEN);

        assert_eq!(
            verdict(&lists, &url, "ads.example"),
            Verdict::Pass,
            "nothing yet"
        );
        assert_eq!(
            download(&url, &lists, &downloader).await,
            Downloaded::Changed
        );
        assert!(verdict(&lists, &url, "ads.example").is_blocked());

        // Unchanged: revalidated with the ETag, nothing transferred.
        assert_eq!(
            download(&url, &lists, &downloader).await,
            Downloaded::Unchanged
        );
        assert_eq!(list.lock().unwrap().not_modified, 1);

        // An error page served with 200 is rejected; the old copy stays.
        {
            let mut list = list.lock().unwrap();
            list.body = b"<html><body>Service unavailable</body></html>\n".to_vec();
            list.etag = "\"v2\"".into();
        }
        let rejected = download(&url, &lists, &downloader).await;
        assert!(
            matches!(rejected, Downloaded::Failed(ref why) if why.starts_with("rejected")),
            "{rejected:?}"
        );
        assert!(verdict(&lists, &url, "ads.example").is_blocked());

        // A real update replaces it.
        {
            let mut list = list.lock().unwrap();
            list.body = b"||new.example^\n".to_vec();
            list.etag = "\"v3\"".into();
        }
        assert_eq!(
            download(&url, &lists, &downloader).await,
            Downloaded::Changed
        );
        assert!(verdict(&lists, &url, "x.new.example").is_blocked());
        assert_eq!(verdict(&lists, &url, "ads.example"), Verdict::Pass);

        // Redirects are followed, but never to http://.
        let moved = format!("{base}/moved");
        assert_eq!(
            download(&moved, &lists, &downloader).await,
            Downloaded::Changed
        );
        let downgrade = format!("{base}/downgrade");
        assert!(matches!(
            download(&downgrade, &lists, &downloader).await,
            Downloaded::Failed(_)
        ));

        // Too large: refused.
        let tiny = ListStore::new(cache_dir.join("tiny"));
        assert!(matches!(
            download(&url, &tiny, &self::downloader(4)).await,
            Downloaded::Failed(_)
        ));

        std::fs::remove_dir_all(&cache_dir).unwrap();
    }

    #[tokio::test]
    async fn downloads_over_http1() {
        download_cycle(b"http/1.1").await;
    }

    #[tokio::test]
    async fn downloads_over_http2() {
        download_cycle(b"h2").await;
    }
}
