//! Serving DNS over HTTPS (RFC 8484) on one TLS connection, over HTTP/1.1
//! or HTTP/2.
//!
//! Only `/dns-query` (and `/dns-query/<client ID>`) answers, to `GET` with
//! the `dns` parameter and to `POST` with an `application/dns-message`
//! body. As an Oblivious DoH target it also answers `POST`s with an
//! `application/oblivious-dns-message` body there, and serves its keys at
//! `/.well-known/odohconfigs`. Everything is bounded: header size and the
//! time to send them, the body's size and the time to send it, concurrent
//! HTTP/2 streams, and how long a connection may go without a request.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpStream;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tracing::{debug, trace};

use crate::doh::{self, DohError};
use crate::odoh::{self, OdohError, OdohKeys};
use crate::stream::TLS_HANDSHAKE_TIMEOUT;
use crate::{Engine, ServerStats, Shared, Transport, stopped};

/// The media type of DNS messages over HTTPS.
const DNS_MESSAGE: &str = "application/dns-message";

/// Concurrent requests on one HTTP/2 connection.
const MAX_STREAMS: u32 = 64;

/// The largest request head: request line and headers. A `GET` of the
/// largest DNS message does not fit; such messages are sent with `POST`.
const MAX_HEAD: usize = 64 * 1024;

/// How long the connection's last requests may take once it is closing.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Serves DNS over HTTPS on `stream` until the client hangs up, the
/// connection goes [`crate::ServerConfig::tls_idle_timeout`] without a
/// request, or shutdown.
pub(crate) async fn serve_connection(
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    sni_id: Option<String>,
    shared: &Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let idle = shared.config.tls_idle_timeout;
    let activity = Arc::new(Activity::new());
    let context = Arc::new(Context {
        engine: Arc::clone(&shared.engine),
        odoh: shared.odoh.clone(),
        stats: Arc::clone(&shared.stats),
        peer,
        sni_id,
        body_timeout: idle,
        activity: Arc::clone(&activity),
    });
    let service = service_fn(move |request| {
        let context = Arc::clone(&context);
        async move { Ok::<_, Infallible>(context.handle(request).await) }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(TLS_HANDSHAKE_TIMEOUT)
        .max_buf_size(MAX_HEAD);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(MAX_STREAMS)
        .max_header_list_size(u32::try_from(MAX_HEAD).unwrap_or(u32::MAX));
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    loop {
        tokio::select! {
            served = connection.as_mut() => {
                if let Err(err) = served {
                    debug!(%peer, %err, "DNS over HTTPS connection ended");
                }
                return;
            }
            () = stopped(&mut stop) => break,
            () = activity.wait(idle) => {
                if activity.is_idle(idle) {
                    trace!(%peer, "closing idle DNS over HTTPS connection");
                    break;
                }
            }
        }
    }
    // HTTP/2 says GOAWAY, HTTP/1.1 closes after the request in progress.
    connection.as_mut().graceful_shutdown();
    let _ = timeout(CLOSE_GRACE, connection).await;
}

/// When a connection last had a request, and how many it has now.
struct Activity {
    started: Instant,
    open: AtomicUsize,
    /// Milliseconds from `started` to the end of the last request.
    last: AtomicU64,
    /// Woken when a request ends, to re-check the deadline.
    notify: Notify,
}

impl Activity {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            open: AtomicUsize::new(0),
            last: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    /// Marks a request as in progress until the guard is dropped.
    fn begin(self: &Arc<Self>) -> Busy {
        self.open.fetch_add(1, Ordering::Relaxed);
        Busy(Arc::clone(self))
    }

    /// Waits for the connection to be quiet for `idle`, or for a request to
    /// end. A deadline already past means a request is open past it: wait
    /// for the wake-up from its end instead of returning at once, which
    /// would spin the caller until the request finishes.
    async fn wait(&self, idle: Duration) {
        let quiet_until = self.quiet_until(idle);
        if Instant::now() >= quiet_until {
            self.notify.notified().await;
            return;
        }
        tokio::select! {
            () = tokio::time::sleep_until(quiet_until.into()) => {}
            () = self.notify.notified() => {}
        }
    }

    /// When the connection has gone `idle` without a request, if none
    /// starts meanwhile.
    fn quiet_until(&self, idle: Duration) -> Instant {
        let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
        self.started
            .checked_add(last)
            .and_then(|last| last.checked_add(idle))
            .unwrap_or_else(Instant::now)
    }

    fn is_idle(&self, idle: Duration) -> bool {
        self.open.load(Ordering::Relaxed) == 0 && Instant::now() >= self.quiet_until(idle)
    }
}

/// A request in progress.
struct Busy(Arc<Activity>);

impl Drop for Busy {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.0.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.0.last.store(elapsed, Ordering::Relaxed);
        self.0.open.fetch_sub(1, Ordering::Relaxed);
        self.0.notify.notify_one();
    }
}

/// What every request on a connection shares.
struct Context {
    engine: Arc<Engine>,
    /// The Oblivious DoH keys, if this is a target.
    odoh: Option<Arc<OdohKeys>>,
    stats: Arc<ServerStats>,
    peer: SocketAddr,
    /// The client ID in the TLS server name, if any.
    sni_id: Option<String>,
    body_timeout: Duration,
    activity: Arc<Activity>,
}

impl Context {
    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let _busy = self.activity.begin();
        let response = self.answer(request).await;
        if !response.status().is_success() {
            ServerStats::count(&self.stats.https_rejected);
        }
        response
    }

    async fn answer(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        if request.uri().path() == odoh::CONFIGS_PATH
            && let Some(keys) = &self.odoh
        {
            return configs(request.method(), keys);
        }
        let path_id = match doh::client_id_from_path(request.uri().path()) {
            Ok(id) => id.map(str::to_owned),
            Err(err) => {
                let status = if err == DohError::NotFound {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::BAD_REQUEST
                };
                return plain(status, &err.to_string());
            }
        };
        let mut message = Vec::new();
        match *request.method() {
            Method::GET => {
                if let Err(err) = doh::decode_get(request.uri().query(), &mut message) {
                    return plain(StatusCode::BAD_REQUEST, &err.to_string());
                }
            }
            Method::POST => match self.read_body(request).await {
                Ok((Body::Dns, body)) => message = body,
                Ok((Body::Oblivious(keys), body)) => {
                    let client_id = path_id.as_deref().or(self.sni_id.as_deref());
                    return self.oblivious(&keys, &body, client_id).await;
                }
                Err((status, text)) => return plain(status, text),
            },
            _ => {
                let mut response = plain(StatusCode::METHOD_NOT_ALLOWED, "use GET or POST");
                response
                    .headers_mut()
                    .insert(ALLOW, HeaderValue::from_static("GET, POST"));
                return response;
            }
        }
        // The path's client ID wins over the server name's.
        let client_id = path_id.as_deref().or(self.sni_id.as_deref());
        let mut out = Vec::new();
        match self
            .engine
            .answer(&message, Transport::Https, self.peer, client_id, &mut out)
            .await
        {
            Some(answered) => dns_message(out, answered.min_ttl),
            None => plain(StatusCode::BAD_REQUEST, "not a DNS query"),
        }
    }

    /// Answers an Oblivious DoH query: decrypts it, answers the DNS query
    /// in it and encrypts the answer.
    async fn oblivious(
        &self,
        keys: &OdohKeys,
        body: &[u8],
        client_id: Option<&str>,
    ) -> Response<Full<Bytes>> {
        let query = match keys.open(body) {
            Ok(query) => query,
            Err(OdohError::UnknownKey) => {
                return plain(
                    StatusCode::UNAUTHORIZED,
                    "unknown key: fetch /.well-known/odohconfigs again",
                );
            }
            Err(err) => return plain(StatusCode::BAD_REQUEST, &err.to_string()),
        };
        let mut out = Vec::new();
        if self
            .engine
            .answer(
                query.dns(),
                Transport::Oblivious,
                self.peer,
                client_id,
                &mut out,
            )
            .await
            .is_none()
        {
            return plain(StatusCode::BAD_REQUEST, "not a DNS query");
        }
        match keys.seal(&query, &out) {
            Ok(sealed) => oblivious_message(sealed),
            Err(err) => {
                debug!(peer = %self.peer, %err, "cannot encrypt an Oblivious DoH answer");
                plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cannot encrypt the answer",
                )
            }
        }
    }

    /// The body of a `POST`, sent in time: a DNS message of at most
    /// [`doh::MAX_MESSAGE_LEN`] bytes, or for an Oblivious DoH target an
    /// ODoH message of at most [`odoh::MAX_MESSAGE_LEN`].
    async fn read_body(
        &self,
        request: Request<Incoming>,
    ) -> Result<(Body, Vec<u8>), (StatusCode, &'static str)> {
        let headers = request.headers();
        let media = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        let (kind, limit) = match (media, &self.odoh) {
            (Some(media), _) if media.eq_ignore_ascii_case(DNS_MESSAGE) => {
                (Body::Dns, doh::MAX_MESSAGE_LEN)
            }
            (Some(media), Some(keys)) if media.eq_ignore_ascii_case(odoh::MEDIA_TYPE) => {
                (Body::Oblivious(Arc::clone(keys)), odoh::MAX_MESSAGE_LEN)
            }
            _ => {
                return Err((
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "send an application/dns-message body",
                ));
            }
        };
        let too_large = (StatusCode::PAYLOAD_TOO_LARGE, "the body is too large");
        let declared = headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|len| usize::try_from(len).map_or(true, |len| len > limit)) {
            return Err(too_large);
        }
        let body = Limited::new(request.into_body(), limit);
        match timeout(self.body_timeout, body.collect()).await {
            Ok(Ok(collected)) => Ok((kind, collected.to_bytes().to_vec())),
            Ok(Err(err)) if err.is::<LengthLimitError>() => Err(too_large),
            Ok(Err(err)) => {
                debug!(peer = %self.peer, %err, "cannot read a DNS over HTTPS body");
                Err((StatusCode::BAD_REQUEST, "cannot read the body"))
            }
            Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "the body took too long")),
        }
    }
}

/// What a `POST` carries.
enum Body {
    /// A DNS message.
    Dns,
    /// An Oblivious DoH message, for these keys.
    Oblivious(Arc<OdohKeys>),
}

/// The target's keys, as an `ObliviousDoHConfigs`. Clients fetch them again
/// when a query gets a 401, so an hour's caching is plenty.
fn configs(method: &Method, keys: &OdohKeys) -> Response<Full<Bytes>> {
    if method != Method::GET && method != Method::HEAD {
        let mut response = plain(StatusCode::METHOD_NOT_ALLOWED, "use GET");
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let mut response = Response::new(Full::new(Bytes::copy_from_slice(&keys.configs())));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=3600"));
    response
}

/// An encrypted Oblivious DoH answer, which no one may cache (RFC 9230,
/// section 4.1).
fn oblivious_message(wire: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(wire)));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(odoh::MEDIA_TYPE));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    response
}

/// A DNS answer, cacheable for as long as its shortest time to live (RFC
/// 8484, section 5.1).
fn dns_message(wire: Vec<u8>, min_ttl: Option<u32>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(wire)));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE));
    let max_age = format!("max-age={}", min_ttl.unwrap_or(0));
    if let Ok(value) = HeaderValue::from_str(&max_age) {
        headers.insert(CACHE_CONTROL, value);
    }
    response
}

/// An HTTP error with a short explanation.
fn plain(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(format!("{text}\n"))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_open_request_does_not_spin_the_idle_wait() {
        let activity = Arc::new(Activity::new());
        let busy = activity.begin();
        // The deadline has passed (a request outlived its idle period, as
        // with a trickling POST body), but the request is still open.
        assert!(!activity.is_idle(Duration::ZERO));
        assert!(
            timeout(Duration::from_millis(50), activity.wait(Duration::ZERO))
                .await
                .is_err(),
            "the wait returned while a request was open"
        );
        // The request ends: the wake-up lets the caller re-check and close.
        drop(busy);
        timeout(Duration::from_secs(1), async {
            activity.wait(Duration::ZERO).await;
            assert!(activity.is_idle(Duration::ZERO));
        })
        .await
        .expect("the wait woke when the request ended");
    }
}
