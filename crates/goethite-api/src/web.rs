//! The web UI: static files served next to the API.
//!
//! The UI is a single-page app (`web/`), built to `web/dist` and embedded
//! into the binary. Its files need no authentication: they hold no data, and
//! everything they show comes from the API, which does. Paths that are not
//! files get `index.html`, so deep links work; `/api/` paths and missing
//! `/assets/` files never do, so a typo in the API or a stale asset fails
//! loudly instead of returning HTML.

use std::borrow::Cow;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::{Api, ApiError};

/// Where the web UI's files come from.
pub trait WebAssets: Send + Sync + std::fmt::Debug {
    /// The file at `path` (relative, such as `assets/index-1234.js`), if
    /// there is one.
    fn file(&self, path: &str) -> Option<Cow<'static, [u8]>>;
}

#[derive(rust_embed::Embed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Dist;

/// The web UI built into this binary, from `web/dist` at build time.
///
/// Debug builds read the files from `web/dist` at run time instead, so a
/// rebuilt UI shows up without rebuilding goethite.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedWeb;

impl EmbeddedWeb {
    /// The built-in web UI, if this binary has one: building goethite
    /// before the UI (`npm run build` in `web/`) leaves it out.
    pub fn get() -> Option<Self> {
        Dist::get(INDEX).map(|_| Self)
    }
}

impl WebAssets for EmbeddedWeb {
    fn file(&self, path: &str) -> Option<Cow<'static, [u8]>> {
        Dist::get(path).map(|file| file.data)
    }
}

const INDEX: &str = "index.html";

/// Files under this prefix have content hashes in their names, so they can
/// be cached for good; a missing one is a 404, never `index.html`.
const ASSETS: &str = "assets/";

/// Serves the web UI for every path no API route matched.
pub(crate) async fn serve(State(api): State<Arc<Api>>, method: Method, uri: Uri) -> Response {
    let path = uri.path();
    let Some(web) = api.config.web.as_deref() else {
        return not_found();
    };
    if path == "/api" || path.starts_with("/api/") || !matches!(method, Method::GET | Method::HEAD)
    {
        return not_found();
    }
    let relative = match path.strip_prefix('/') {
        Some("") => Some(INDEX),
        Some(relative) if is_plain(relative) => Some(relative),
        _ => None,
    };
    if let Some(relative) = relative {
        if let Some(data) = web.file(relative) {
            return file(relative, data);
        }
        if relative.starts_with(ASSETS) {
            return not_found();
        }
    }
    match web.file(INDEX) {
        Some(data) => file(INDEX, data),
        None => not_found(),
    }
}

fn not_found() -> Response {
    ApiError::not_found("there is no such endpoint").into_response()
}

/// Whether `path` is a plain relative file path: ASCII letters, digits and
/// `._-` in segments separated by single slashes, none of them `.` or `..`.
pub fn is_plain(path: &str) -> bool {
    path.len() <= 256
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn file(path: &str, data: Cow<'static, [u8]>) -> Response {
    let cache = if path.starts_with(ASSETS) {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let mut response = Response::new(Body::from(data));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type(path)));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(cache));
    *response.status_mut() = StatusCode::OK;
    response
}

/// The media type for a file name. The UI is built by our own tooling, so a
/// short list covers it.
fn content_type(path: &str) -> &'static str {
    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    match extension {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths() {
        for good in [
            "index.html",
            "assets/index-Bc_9.js",
            "favicon.svg",
            "a/b/c.woff2",
        ] {
            assert!(is_plain(good), "{good}");
        }
        for bad in [
            "",
            "../etc/passwd",
            "assets/../index.html",
            "./index.html",
            "a//b",
            "a/",
            "a\\b",
            "a%2Fb",
            "a b",
            "é.js",
        ] {
            assert!(!is_plain(bad), "{bad}");
        }
        assert!(!is_plain(&"a".repeat(257)));
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(
            content_type("assets/x.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type("assets/x.woff2"), "font/woff2");
        assert_eq!(content_type("README"), "application/octet-stream");
    }
}
