//! The FilterLists directory (filterlists.com), for finding filter lists.
//!
//! This node fetches it from FilterLists' API, never the browser: the web
//! UI's Content Security Policy lets it talk to goethite only. It is
//! fetched only when someone browses it, over HTTPS through goethite's own
//! resolver, each answer at most [`MAX_RESPONSE`] bytes and
//! [`REQUEST_TIMEOUT`] long, and read by the bounded parsers in
//! [`goethite_api::catalog`]. The directory is kept for [`KEEP`], and so are
//! the details of up to [`MAX_DETAILS`] lists. One refresh runs at a time.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwapOption;
use goethite_api::catalog::{self, Directory, DirectoryList, Names};
use goethite_resolver::Resolver;
use jiff::Timestamp;
use rustls::ClientConfig;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::download::{Downloader, Fetched, Validators};

/// FilterLists' API.
pub(crate) const API: &str = "https://api.filterlists.com";

/// The largest answer read: the whole directory is about 600 KiB.
pub(crate) const MAX_RESPONSE: usize = 4 * 1024 * 1024;

/// How long one request may take.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the directory and list details are kept.
pub(crate) const KEEP: Duration = Duration::from_hours(24);

/// The most lists' details kept.
pub(crate) const MAX_DETAILS: usize = 256;

/// The directory and the names it refers to, as fetched at `at`.
struct Cached {
    at: Instant,
    directory: Directory,
    names: Names,
}

/// The FilterLists directory, fetched on demand.
pub(crate) struct FilterLists {
    downloader: Downloader,
    base: String,
    cached: ArcSwapOption<Cached>,
    details: Mutex<HashMap<u64, (Instant, DirectoryList)>>,
    refresh: Semaphore,
}

impl FilterLists {
    /// Fetches from [`API`], resolving with `resolver` and checking
    /// certificates with `tls`.
    pub(crate) fn new(resolver: Arc<Resolver>, tls: Arc<ClientConfig>) -> Self {
        Self::with_base(resolver, tls, API)
    }

    fn with_base(resolver: Arc<Resolver>, tls: Arc<ClientConfig>, base: &str) -> Self {
        Self {
            downloader: Downloader::new(resolver, tls, MAX_RESPONSE),
            base: base.trim_end_matches('/').to_owned(),
            cached: ArcSwapOption::empty(),
            details: Mutex::new(HashMap::new()),
            refresh: Semaphore::new(1),
        }
    }

    /// The lists goethite can use.
    ///
    /// # Errors
    ///
    /// If FilterLists cannot be reached or sends something unexpected.
    pub(crate) async fn directory(&self) -> Result<Directory> {
        Ok(self.current().await?.directory.clone())
    }

    /// The details of list `id`, with its addresses.
    ///
    /// # Errors
    ///
    /// If FilterLists cannot be reached or sends something unexpected.
    pub(crate) async fn list(&self, id: u64) -> Result<DirectoryList> {
        if let Some(list) = self.kept_detail(id) {
            return Ok(list);
        }
        let current = self.current().await?;
        let bytes = self.get(&format!("{}/lists/{id}", self.base)).await?;
        let list = catalog::parse_list(&bytes, &current.names)?;
        if let Ok(mut details) = self.details.lock() {
            if details.len() >= MAX_DETAILS {
                details.retain(|_, (at, _)| at.elapsed() < KEEP);
                if details.len() >= MAX_DETAILS {
                    details.clear();
                }
            }
            details.insert(id, (Instant::now(), list.clone()));
        }
        Ok(list)
    }

    fn kept_detail(&self, id: u64) -> Option<DirectoryList> {
        let details = self.details.lock().ok()?;
        let (at, list) = details.get(&id)?;
        (at.elapsed() < KEEP).then(|| list.clone())
    }

    fn fresh(&self) -> Option<Arc<Cached>> {
        self.cached
            .load_full()
            .filter(|cached| cached.at.elapsed() < KEEP)
    }

    /// The directory, fetched again once it is older than [`KEEP`].
    async fn current(&self) -> Result<Arc<Cached>> {
        if let Some(cached) = self.fresh() {
            return Ok(cached);
        }
        // One refresh at a time; who waited takes its result.
        let _refreshing = self.refresh.acquire().await?;
        if let Some(cached) = self.fresh() {
            return Ok(cached);
        }
        let [lists, syntaxes, tags, licenses] =
            ["lists", "syntaxes", "tags", "licenses"].map(|path| format!("{}/{path}", self.base));
        let (lists, syntaxes, tags, licenses) = tokio::try_join!(
            self.get(&lists),
            self.get(&syntaxes),
            self.get(&tags),
            self.get(&licenses),
        )?;
        let names = catalog::parse_names(&syntaxes, &tags, &licenses)?;
        let lists = catalog::parse_lists(&lists, &names)?;
        let cached = Arc::new(Cached {
            at: Instant::now(),
            directory: Directory {
                fetched_at: Timestamp::now(),
                lists,
            },
            names,
        });
        self.cached.store(Some(Arc::clone(&cached)));
        Ok(cached)
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        // Boxed: four of these run at once, and each is large.
        let fetched = timeout(
            REQUEST_TIMEOUT,
            Box::pin(self.downloader.fetch(url, &Validators::default())),
        )
        .await
        .map_err(|_| anyhow!("no answer within {} s", REQUEST_TIMEOUT.as_secs()))?
        .with_context(|| format!("cannot fetch {url}"))?;
        match fetched {
            Fetched::Body { bytes, .. } => Ok(bytes),
            Fetched::NotModified => bail!("{url} answered \"not modified\" to a plain request"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const LISTS: &str = r#"[
        {"id": 1, "name": "Hosts", "syntaxIds": [1], "tagIds": [2]},
        {"id": 2, "name": "Allow these", "syntaxIds": [2], "tagIds": [10]},
        {"id": 3, "name": "Browser only", "syntaxIds": [4]}
    ]"#;
    const DETAIL: &str = r#"{"id": 1, "name": "Hosts", "syntaxIds": [1],
        "viewUrls": [{"segmentNumber": 1, "primariness": 1, "url": "https://lists.example/hosts"}]}"#;

    /// A fake FilterLists on 127.0.0.1 over HTTPS, counting requests, and
    /// TLS settings that trust it.
    async fn fake(junk: bool) -> (String, Arc<ClientConfig>, Arc<AtomicUsize>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::clone(cert.der())).unwrap();
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: hyper::Request<_>| {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let body = match request.uri().path() {
                            _ if junk => Some("<html>not JSON</html>"),
                            "/lists" => Some(LISTS),
                            "/lists/1" => Some(DETAIL),
                            "/syntaxes" => Some(r#"[{"id": 1, "name": "Hosts (localhost IPv4)"}]"#),
                            "/tags" => Some(
                                r#"[{"id": 2, "name": "ads"}, {"id": 10, "name": "allowlist"}]"#,
                            ),
                            "/licenses" => Some("[]"),
                            _ => None,
                        };
                        async move {
                            let mut response =
                                Response::new(Full::new(Bytes::from(body.unwrap_or(""))));
                            if body.is_none() {
                                *response.status_mut() = StatusCode::NOT_FOUND;
                            }
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (format!("https://{addr}"), Arc::new(client), hits)
    }

    fn client(base: &str, tls: Arc<ClientConfig>) -> FilterLists {
        FilterLists::with_base(Arc::new(Resolver::new(Vec::new())), tls, base)
    }

    #[tokio::test]
    async fn fetches_once_a_day_and_keeps_what_goethite_can_use() {
        let (base, tls, hits) = fake(false).await;
        let filterlists = client(&base, tls);
        let directory = filterlists.directory().await.unwrap();
        let names: Vec<&str> = directory
            .lists
            .iter()
            .map(|list| list.name.as_str())
            .collect();
        assert_eq!(names, ["Hosts"], "no allowlist, no browser-only list");
        assert_eq!(directory.lists[0].tags, ["ads"]);
        assert_eq!(hits.load(Ordering::SeqCst), 4);
        filterlists.directory().await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 4, "kept, not fetched again");

        let list = filterlists.list(1).await.unwrap();
        assert_eq!(list.urls[0].url, "https://lists.example/hosts");
        assert!(list.usable);
        filterlists.list(1).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 5, "details kept too");
        assert!(filterlists.list(99).await.is_err(), "not found");
    }

    #[tokio::test]
    async fn unexpected_answers_are_errors() {
        let (base, tls, _) = fake(true).await;
        let err = client(&base, tls).directory().await.unwrap_err();
        assert!(
            format!("{err:#}").contains("unexpected data from FilterLists"),
            "{err:#}"
        );
        let nobody = client(
            "https://127.0.0.1:9",
            Arc::new(
                ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
            ),
        );
        assert!(nobody.directory().await.is_err());
    }
}
