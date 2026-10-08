//! The API reference at `/api/docs`: Scalar, rendered from this build's
//! OpenAPI document, for people working on the node itself.
//!
//! It is off unless `[api] docs` turns it on, and even then answers loopback
//! clients only, without a token: the document describes the API, not this
//! node's data, and the same reference is on the project's website. Every
//! file is built into the binary (`web/dist-docs`, from `npm run build`), so
//! nothing comes from a CDN.
//!
//! Scalar injects its styles at run time, so this page's Content Security
//! Policy differs from the rest of the API's in styles only:
//!
//! - scripts stay `'self'` only;
//! - `<style>` elements need the page's nonce (fresh for every request, and
//!   in a `csp-nonce` meta tag Scalar puts on its styles) or one of the hashes
//!   of the few stylesheets Scalar adds without it ([`SCALAR_STYLES`]);
//! - `style` attributes are allowed. Scalar sets sizes and positions in them,
//!   which no hash can cover. They run no code, and with images and fonts
//!   limited to `'self'` they reach nowhere else; the page shows goethite's
//!   own OpenAPI document, never data from a request.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_SECURITY_POLICY, CONTENT_TYPE, VARY,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::auth::PeerAddr;
use crate::{Api, ApiError, WebAssets};

#[derive(rust_embed::Embed)]
#[folder = "../../web/dist-docs"]
#[allow_missing = true]
struct Dist;

/// The API reference's files built into this binary, from `web/dist-docs`.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedDocs;

impl EmbeddedDocs {
    /// The built-in reference, if this binary has one: building goethite
    /// before `web/` leaves it out.
    pub fn get() -> Option<Self> {
        Dist::get(SCALAR).map(|_| Self)
    }
}

impl WebAssets for EmbeddedDocs {
    fn file(&self, path: &str) -> Option<std::borrow::Cow<'static, [u8]>> {
        Dist::get(path).map(|file| file.data)
    }
}

/// Scalar's standalone bundle, gzipped at build time.
pub const SCALAR: &str = "scalar.js.gz";

/// The stylesheets Scalar 1.73.1 adds without the nonce, by SHA-256. The
/// end-to-end test of `/api/docs` fails on any style the policy refuses, so
/// a new Scalar that adds others shows up there.
const SCALAR_STYLES: [&str; 4] = [
    "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    "sha256-DLlkYCuDYGe6ME23YkUFB7Tc36rGDeo4mVBFbZX3uaU=",
    "sha256-ZW1GSuo0pKyEx5Ar7ZC5Dflb/mjatjeTW9aVx0iZAzE=",
    "sha256-nT0S1Qe6I3DXxjh7v5KM5jmdlxs04kQiH5PEGYxqKcU=",
];

/// Starts Scalar on the page. Its own file: scripts are `'self'` only.
const START: &str = r"Scalar.createApiReference('#reference', {
  url: '/api/docs/openapi.json',
  theme: 'none',
  layout: 'modern',
  forceDarkModeState: 'light',
  hideDarkModeToggle: true,
  withDefaultFonts: false,
  telemetry: false,
  hideClientButton: true,
  hideTestRequestButton: true,
  showDeveloperTools: 'never',
  mcp: { disabled: true },
  agent: { disabled: true },
  documentDownloadType: 'json',
})
";

/// Whether the docs answer this request: turned on, and from loopback.
fn allowed(api: &Api, request: &Request) -> bool {
    api.config.docs.is_some() && from_loopback(request)
}

/// Whether the request came from this machine.
fn from_loopback(request: &Request) -> bool {
    request
        .extensions()
        .get::<PeerAddr>()
        .is_some_and(|peer| peer.0.ip().is_loopback())
}

fn not_found() -> Response {
    ApiError::not_found("there is no such endpoint").into_response()
}

/// `/api/docs`: the page, with a fresh nonce.
pub(crate) async fn page(State(api): State<Arc<Api>>, request: Request) -> Response {
    if !allowed(&api, &request) {
        return not_found();
    }
    let nonce = nonce();
    let html = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta property=\"csp-nonce\" content=\"{nonce}\">\n\
         <title>goethite API reference</title>\n</head>\n<body>\n\
         <div id=\"reference\"></div>\n\
         <script src=\"/api/docs/scalar.js\"></script>\n\
         <script src=\"/api/docs/start.js\"></script>\n</body>\n</html>\n"
    );
    let hashes = SCALAR_STYLES.map(|hash| format!("'{hash}'")).join(" ");
    let policy = format!(
        "default-src 'self'; script-src 'self'; style-src 'self' 'nonce-{nonce}'; \
         style-src-elem 'self' 'nonce-{nonce}' {hashes}; style-src-attr 'unsafe-inline'; \
         img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; \
         base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    let mut response = Response::new(Body::from(html));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(policy) = HeaderValue::from_str(&policy) {
        headers.insert(CONTENT_SECURITY_POLICY, policy);
    }
    response
}

/// `/api/docs/scalar.js`: Scalar, gzipped as built.
pub(crate) async fn scalar(State(api): State<Arc<Api>>, request: Request) -> Response {
    if !allowed(&api, &request) {
        return not_found();
    }
    let Some(data) = api
        .config
        .docs
        .as_deref()
        .and_then(|docs| docs.file(SCALAR))
    else {
        return not_found();
    };
    if !accepts_gzip(request.headers()) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            "the API reference is served gzipped only",
        )
            .into_response();
    }
    let mut response = Response::new(Body::from(data));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    headers.insert(VARY, HeaderValue::from_static("accept-encoding"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// `/api/docs/start.js`.
pub(crate) async fn start(State(api): State<Arc<Api>>, request: Request) -> Response {
    if !allowed(&api, &request) {
        return not_found();
    }
    ([(CONTENT_TYPE, "text/javascript; charset=utf-8")], START).into_response()
}

/// `/api/docs/openapi.json`: the document, without a token.
pub(crate) async fn document(State(api): State<Arc<Api>>, request: Request) -> Response {
    if !allowed(&api, &request) {
        return not_found();
    }
    ([(CONTENT_TYPE, "application/json")], crate::openapi_json()).into_response()
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|coding| {
            let mut parts = coding.split(';');
            let name = parts.next().unwrap_or_default().trim();
            let refused = parts.any(|parameter| {
                parameter
                    .trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.parse::<f32>().ok())
                    .is_some_and(|q| q == 0.0)
            });
            (name.eq_ignore_ascii_case("gzip") || name == "*") && !refused
        })
}

/// 128 random bits as hex: a valid CSP nonce.
fn nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes
        .iter()
        .fold(String::with_capacity(32), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_accept_encoding() {
        let mut headers = HeaderMap::new();
        assert!(!accepts_gzip(&headers));
        for (value, gzip) in [
            ("gzip, deflate, br", true),
            ("br;q=1.0, GZIP;q=0.5", true),
            ("*", true),
            ("gzip;q=0", false),
            ("br", false),
            ("identity", false),
        ] {
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(value));
            assert_eq!(accepts_gzip(&headers), gzip, "{value}");
        }
    }

    #[test]
    fn only_loopback_is_answered() {
        let from = |address: &str| {
            let mut request = Request::new(Body::empty());
            if !address.is_empty() {
                request
                    .extensions_mut()
                    .insert(PeerAddr(address.parse().unwrap()));
            }
            from_loopback(&request)
        };
        assert!(from("127.0.0.1:40000"));
        assert!(from("[::1]:40000"));
        assert!(!from("192.0.2.10:40000"));
        assert!(!from("[2001:db8::1]:40000"));
        assert!(!from(""), "no peer address: refused");
    }

    #[test]
    fn nonces_differ() {
        let (a, b) = (nonce(), nonce());
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
