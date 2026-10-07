//! Loading filter lists and keeping the compiled filter current.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use goethite_filter::{Filter, FilterBuilder, ListStats};
use goethite_resolver::Blocking;
use tracing::{debug, error, info, warn};

use crate::config::FilterSection;
use crate::download::{Downloader, Fetched};
use crate::lists::{ListStore, validate};

/// List files and downloads larger than this many bytes are refused.
pub const MAX_LIST_LEN: usize = 128 * 1024 * 1024;

/// Reads the configured rules and lists and compiles them, for startup: if
/// compiling fails, nothing is blocked rather than nothing resolving.
pub fn build(section: &FilterSection) -> Filter {
    compile(section).unwrap_or_else(Filter::empty)
}

/// Reads the configured rules and lists and compiles them.
///
/// A list that cannot be read is logged and skipped rather than failing:
/// filtering must never take resolution down. `None` if compiling failed.
fn compile(section: &FilterSection) -> Option<Filter> {
    let mut builder = FilterBuilder::new();
    if !section.rules.is_empty() {
        let stats = builder.add_list(&section.rules.join("\n"));
        log_stats("config rules", stats);
    }
    let store = section.cache_dir.clone().map(ListStore::new);
    for list in &section.list {
        let (source, path) = match (&list.path, &list.url, &store) {
            (Some(path), _, _) => (path.display().to_string(), path.clone()),
            (None, Some(url), Some(store)) => {
                let path = store.path_for(url);
                if !path.exists() {
                    info!(list = %url, "not downloaded yet");
                    continue;
                }
                (url.clone(), path)
            }
            _ => continue,
        };
        match read_list(&path) {
            Ok(text) => {
                let stats = builder.add_list(&text);
                log_stats(&source, stats);
            }
            Err(err) => error!(list = %source, "{err:#}; skipping this list"),
        }
    }
    match builder.build() {
        Ok(filter) => {
            info!(
                rules = filter.rule_count(),
                memory_kib = filter.memory_bytes() / 1024,
                "filter ready"
            );
            Some(filter)
        }
        Err(err) => {
            error!(%err, "cannot compile the filter");
            None
        }
    }
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

/// Downloads every `url` list that changed, validating each before it
/// replaces the last good copy. Returns whether anything changed.
pub async fn update(section: &FilterSection, downloader: &Downloader) -> bool {
    let Some(store) = section.cache_dir.clone().map(ListStore::new) else {
        return false;
    };
    let mut changed = false;
    for url in section.list.iter().filter_map(|list| list.url.clone()) {
        let validators = store.validators(&url);
        match downloader.fetch(&url, &validators).await {
            Ok(Fetched::NotModified) => debug!(list = %url, "list unchanged"),
            Ok(Fetched::Body { bytes, validators }) => {
                let store = store.clone();
                let saved = {
                    let url = url.clone();
                    tokio::task::spawn_blocking(move || {
                        let stats = validate(&bytes)?;
                        store.save(&url, &bytes, &validators)?;
                        Ok::<_, anyhow::Error>(stats)
                    })
                    .await
                };
                match saved {
                    Ok(Ok(stats)) => {
                        info!(list = %url, rules = stats.rules, "list downloaded");
                        changed = true;
                    }
                    Ok(Err(err)) => {
                        warn!(list = %url, "download rejected: {err:#}; keeping the last good copy");
                    }
                    Err(err) => error!(list = %url, %err, "saving the list failed"),
                }
            }
            Err(err) => {
                warn!(list = %url, "cannot download: {err:#}; keeping the last good copy");
            }
        }
    }
    changed
}

/// Downloads lists now and then every `update_hours` (with up to 10% random
/// delay, so many installations do not hit list servers at once), and
/// rebuilds the filter when one changed.
pub fn spawn_updates(blocking: Arc<Blocking>, section: FilterSection, downloader: Downloader) {
    if !section.list.iter().any(|list| list.url.is_some()) {
        return;
    }
    let interval = Duration::from_secs(u64::from(section.update_hours).saturating_mul(3600));
    tokio::spawn(async move {
        loop {
            if update(&section, &downloader).await {
                reload(&blocking, section.clone()).await;
            }
            let jitter = interval.mul_f64(rand::random::<f64>() * 0.1);
            tokio::time::sleep(interval.saturating_add(jitter)).await;
        }
    });
}

/// Rebuilds the filter from `section` off the async runtime and swaps it in.
/// If compiling fails, the current filter stays.
pub async fn reload(blocking: &Arc<Blocking>, section: FilterSection) {
    match tokio::task::spawn_blocking(move || compile(&section)).await {
        Ok(Some(filter)) => blocking.replace(filter),
        Ok(None) => error!("filter reload failed; keeping the current filter"),
        Err(err) => error!(%err, "filter reload failed; keeping the current filter"),
    }
}

#[cfg(test)]
mod tests {
    use goethite_filter::Verdict;

    use super::*;
    use crate::config::ListSection;

    #[test]
    fn unreadable_lists_are_skipped() {
        let dir = std::env::temp_dir().join(format!("goethite-lists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.txt");
        std::fs::write(&good, "0.0.0.0 ads.example\n").unwrap();
        let section = FilterSection {
            rules: vec!["||tracker.example^".into()],
            list: vec![
                ListSection {
                    path: Some(good),
                    url: None,
                },
                ListSection {
                    path: Some(dir.join("missing.txt")),
                    url: None,
                },
            ],
            ..FilterSection::default()
        };
        let filter = build(&section);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(filter.rule_count(), 2);
        assert_eq!(
            filter.check(&"ads.example".parse().unwrap()),
            Verdict::Blocked
        );
        assert_eq!(
            filter.check(&"x.tracker.example".parse().unwrap()),
            Verdict::Blocked
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

    use goethite_filter::Verdict;
    use goethite_proto::Record;
    use goethite_resolver::{Resolver, TlsRoots, tls_client_config};
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
    use crate::config::ListSection;
    use crate::download::Downloader;

    const CA: &[u8] = include_bytes!("../../goethite-resolver/tests/fixtures/ca.pem");
    const CERT: &[u8] = include_bytes!("../../goethite-resolver/tests/fixtures/server.pem");
    const KEY: &[u8] = include_bytes!("../../goethite-resolver/tests/fixtures/server.key");

    struct List {
        body: Vec<u8>,
        etag: String,
        requests: usize,
        not_modified: usize,
    }

    /// An HTTPS server for `dns.goethite.test` serving `/list` (with ETag
    /// revalidation), `/moved` (a redirect to it) and `/downgrade` (a
    /// redirect to http://). `alpn` picks HTTP/1.1 or HTTP/2.
    async fn server(list: Arc<Mutex<List>>, alpn: &'static [u8]) -> SocketAddr {
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

    fn respond(list: &Mutex<List>, request: &Request<Incoming>) -> Response<Full<Bytes>> {
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

    fn section(cache_dir: &Path, url: String) -> FilterSection {
        FilterSection {
            cache_dir: Some(cache_dir.to_path_buf()),
            list: vec![ListSection {
                path: None,
                url: Some(url),
            }],
            ..FilterSection::default()
        }
    }

    fn verdict(section: &FilterSection, name: &str) -> Verdict {
        compile(section).unwrap().check(&name.parse().unwrap())
    }

    async fn download_cycle(alpn: &'static [u8]) {
        let list = Arc::new(Mutex::new(List {
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
        let base = format!("https://dns.goethite.test:{}", addr.port());
        let section = section(&cache_dir, format!("{base}/list"));
        let downloader = downloader(MAX_LIST_LEN);

        assert_eq!(
            verdict(&section, "ads.example"),
            Verdict::Pass,
            "nothing yet"
        );
        assert!(update(&section, &downloader).await);
        assert_eq!(verdict(&section, "ads.example"), Verdict::Blocked);

        // Unchanged: revalidated with the ETag, nothing transferred.
        assert!(!update(&section, &downloader).await);
        assert_eq!(list.lock().unwrap().not_modified, 1);

        // An error page served with 200 is rejected; the old copy stays.
        {
            let mut list = list.lock().unwrap();
            list.body = b"<html><body>Service unavailable</body></html>\n".to_vec();
            list.etag = "\"v2\"".into();
        }
        assert!(!update(&section, &downloader).await);
        assert_eq!(verdict(&section, "ads.example"), Verdict::Blocked);

        // A real update replaces it.
        {
            let mut list = list.lock().unwrap();
            list.body = b"||new.example^\n".to_vec();
            list.etag = "\"v3\"".into();
        }
        assert!(update(&section, &downloader).await);
        assert_eq!(verdict(&section, "x.new.example"), Verdict::Blocked);
        assert_eq!(verdict(&section, "ads.example"), Verdict::Pass);

        // Redirects are followed, but never to http://.
        let moved = section_for(&cache_dir.join("moved"), format!("{base}/moved"));
        assert!(update(&moved, &downloader).await);
        let downgrade = section_for(&cache_dir.join("downgrade"), format!("{base}/downgrade"));
        assert!(!update(&downgrade, &downloader).await);

        // Too large: refused.
        let tiny = section_for(&cache_dir.join("tiny"), format!("{base}/list"));
        assert!(!update(&tiny, &self::downloader(4)).await);

        std::fs::remove_dir_all(&cache_dir).unwrap();
    }

    fn section_for(cache_dir: &Path, url: String) -> FilterSection {
        section(cache_dir, url)
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
