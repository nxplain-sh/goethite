//! The API in a cluster: which node this is, where configuration changes
//! go, and handing them to the primary.
//!
//! On a replica, a configuration change (a `POST`, `PUT` or `DELETE` of a
//! list, rule, group, client, schedule or the settings) is forwarded to the
//! primary with the caller's identity, and answered with the primary's
//! answer once this node has copied the change, so the caller reads its own
//! write. While the primary is unreachable such changes are refused; reads,
//! pausing and list downloads stay local. The binary does the forwarding
//! ([`Control::forward`]); the primary runs forwarded changes through the
//! same routes ([`execute`]).

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, ETAG, HOST, IF_MATCH, LOCATION};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use goethite_store::{Actor, ConfigVersion};
use http_body_util::BodyExt;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tower::ServiceExt as _;
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorBody};
use crate::{Api, MAX_BODY, router};

/// How long a replica waits to copy a change it forwarded, so the caller
/// reads its own write.
const READ_YOUR_WRITE: Duration = Duration::from_secs(3);

/// A node's role in its cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterRole {
    /// Owns the configuration.
    Primary,
    /// Copies the primary's configuration and forwards changes to it.
    Replica,
}

/// This node's cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClusterStatus {
    /// This node's name.
    pub node: String,
    /// Its role.
    pub role: ClusterRole,
    /// Its configuration's version.
    pub config: ConfigVersion,
    /// Whether configuration changes can be made through this node now:
    /// on the primary, or on a replica that reaches the primary.
    pub writable: bool,
    /// The other node, as last seen.
    pub peer: PeerStatus,
    /// On a replica, how following the primary goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncStatus>,
    /// Things someone should look at, in words, such as both nodes being
    /// primary.
    pub problems: Vec<String>,
}

/// The other node, as last seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PeerStatus {
    /// Its name.
    pub node: String,
    /// Its cluster address.
    pub address: String,
    /// Whether it answered the last check.
    pub reachable: bool,
    /// When it was last checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<Timestamp>,
    /// Its role, when last reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<ClusterRole>,
    /// Its goethite version, when last reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Its configuration's version, when last reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigVersion>,
    /// Why the last check failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// How a replica follows the primary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SyncStatus {
    /// When the primary last answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_contact: Option<Timestamp>,
    /// When its configuration was last copied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_copy: Option<Timestamp>,
    /// Why the last attempt failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Where configuration changes made through this node go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Writes {
    /// Into this node's store: a node on its own, or the primary.
    Local,
    /// To the primary, through [`Control::forward`](crate::Control::forward).
    Forward,
    /// Nowhere, for this reason: a replica that cannot reach the primary.
    ReadOnly(String),
}

/// A configuration change, forwarded from a replica to the primary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forwarded {
    /// The HTTP method.
    pub method: String,
    /// The path and query, under `/api/v1/`.
    pub path: String,
    /// The `If-Match` header, if the caller sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_match: Option<String>,
    /// The body as sent, if there was one; the primary checks it as it
    /// checks any request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Who made the change, as the replica authenticated them.
    pub actor: Actor,
}

/// The primary's answer to a forwarded change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardedAnswer {
    /// The HTTP status.
    pub status: u16,
    /// The `ETag` header, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// The `Location` header, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The body as the primary sent it, if any: JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// The primary's configuration version after the change.
    pub version: ConfigVersion,
}

/// The identity of a forwarded change, set by [`execute`]. Extensions never
/// come from the wire, so no HTTP client can set it.
#[derive(Clone, Debug)]
pub(crate) struct TrustedActor(pub(crate) Actor);

/// Whether `method` on `path` changes the configuration store.
fn is_config_write(method: &Method, path: &str) -> bool {
    if !matches!(*method, Method::POST | Method::PUT | Method::DELETE) {
        return false;
    }
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return false;
    };
    let resource = rest.split('/').next().unwrap_or_default();
    matches!(
        resource,
        "lists" | "rules" | "groups" | "clients" | "schedules" | "settings"
    ) && rest != "lists/refresh"
}

/// Sends configuration changes made through a replica to the primary.
/// Runs after authentication, which put the caller's [`Actor`] in place.
pub(crate) async fn forward_writes(
    State(api): State<Arc<Api>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let forwarded_here = request.extensions().get::<TrustedActor>().is_some();
    if forwarded_here || !is_config_write(request.method(), request.uri().path()) {
        return Ok(next.run(request).await);
    }
    match api.control.writes() {
        Writes::Local => Ok(next.run(request).await),
        Writes::ReadOnly(reason) => Err(ApiError::unavailable(reason)),
        Writes::Forward => forward(&api, request).await,
    }
}

async fn forward(api: &Arc<Api>, request: Request) -> Result<Response, ApiError> {
    let actor = request
        .extensions()
        .get::<Actor>()
        .cloned()
        .ok_or_else(|| ApiError::internal("no caller to forward the change for"))?;
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let body = if bytes.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| ApiError::bad_request("the body is not UTF-8 JSON"))?,
        )
    };
    let forwarded = Forwarded {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map_or_else(|| parts.uri.path().to_owned(), |pq| pq.as_str().to_owned()),
        if_match: parts
            .headers
            .get(IF_MATCH)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body,
        actor,
    };
    let answer = api.control.forward(forwarded).await?;
    // Read your own write: wait until this node has copied the change.
    let mut changes = api.store.subscribe();
    let target = answer.version;
    let _ = tokio::time::timeout(READ_YOUR_WRITE, async {
        let _ = changes
            .wait_for(|have| !target.replaces(*have))
            .await
            .is_ok();
    })
    .await;
    Ok(answer_response(answer))
}

/// The primary's answer as this node's response.
fn answer_response(answer: ForwardedAnswer) -> Response {
    let status = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = match answer.body {
        Some(body) => (
            status,
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            body,
        )
            .into_response(),
        None => status.into_response(),
    };
    let headers = response.headers_mut();
    for (name, value) in [(ETAG, answer.etag), (LOCATION, answer.location)] {
        if let Some(value) = value.and_then(|v| HeaderValue::from_str(&v).ok()) {
            headers.insert(name, value);
        }
    }
    response
}

/// Runs a change forwarded by the replica `node` through this node's
/// routes, as its original caller.
///
/// # Errors
///
/// [`ApiError`] if the request is not a configuration change.
pub async fn execute(
    api: &Arc<Api>,
    node: &str,
    forwarded: Forwarded,
) -> Result<ForwardedAnswer, ApiError> {
    let method = Method::from_bytes(forwarded.method.as_bytes())
        .map_err(|_| ApiError::bad_request("unknown method"))?;
    let path_only = forwarded
        .path
        .split_once('?')
        .map_or(forwarded.path.as_str(), |(path, _)| path);
    if !is_config_write(&method, path_only) {
        return Err(ApiError::forbidden(
            "only configuration changes are forwarded",
        ));
    }
    let mut actor = forwarded.actor;
    actor.node = Some(node.to_owned());
    let mut builder = Request::builder()
        .method(method)
        .uri(&forwarded.path)
        .header(HOST, "localhost");
    if let Some(if_match) = &forwarded.if_match {
        builder = builder.header(IF_MATCH, if_match);
    }
    let body = match forwarded.body {
        Some(body) => {
            builder = builder.header(CONTENT_TYPE, "application/json");
            Body::from(body)
        }
        None => Body::empty(),
    };
    let mut request = builder
        .body(body)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    request.extensions_mut().insert(TrustedActor(actor));
    let response = router(api)
        .oneshot(request)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    let status = response.status().as_u16();
    let etag = header(&response, &ETAG);
    let location = header(&response, &LOCATION);
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?
        .to_bytes();
    let body = if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    };
    Ok(ForwardedAnswer {
        status,
        etag,
        location,
        body,
        version: api.store.version(),
    })
}

/// A response header as text, if it is set.
fn header(response: &Response, name: &axum::http::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// This node's cluster: its role, the other node, and how following the
/// primary goes.
#[utoipa::path(get, path = "/api/v1/cluster", tag = "cluster",
    responses(
        (status = 200, description = "The cluster", body = ClusterStatus),
        (status = 404, description = "This node is not in a cluster", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn get_cluster(
    State(api): State<Arc<Api>>,
) -> Result<Json<ClusterStatus>, ApiError> {
    api.control
        .cluster()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("this node is not in a cluster"))
}

/// How to change a node's role.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleChange {
    /// Change it even though the other node is reachable and would
    /// disagree, leaving two primaries (or two replicas) until one changes.
    #[serde(default)]
    pub force: bool,
}

/// Makes this node the primary. Its configuration becomes the cluster's,
/// in a new epoch. Refused while the current primary is reachable, unless
/// forced: demote that one first.
#[utoipa::path(post, path = "/api/v1/cluster/promote", tag = "cluster",
    request_body = RoleChange,
    responses(
        (status = 200, description = "This node is the primary", body = ClusterStatus),
        (status = 404, description = "This node is not in a cluster", body = ErrorBody),
        (status = 409, description = "The other node is reachable and primary", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn promote(
    State(api): State<Arc<Api>>,
    axum::Extension(actor): axum::Extension<Actor>,
    body: axum::body::Bytes,
) -> Result<Json<ClusterStatus>, ApiError> {
    let change = role_change(&body)?;
    api.control
        .set_role(ClusterRole::Primary, change.force, actor)
        .await
        .map(Json)
}

/// Makes this node a replica: it copies the other node's configuration
/// from then on, replacing its own. Refused unless the other node is
/// reachable and primary, unless forced.
#[utoipa::path(post, path = "/api/v1/cluster/demote", tag = "cluster",
    request_body = RoleChange,
    responses(
        (status = 200, description = "This node is a replica", body = ClusterStatus),
        (status = 404, description = "This node is not in a cluster", body = ErrorBody),
        (status = 409, description = "The other node is not a reachable primary", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn demote(
    State(api): State<Arc<Api>>,
    axum::Extension(actor): axum::Extension<Actor>,
    body: axum::body::Bytes,
) -> Result<Json<ClusterStatus>, ApiError> {
    let change = role_change(&body)?;
    api.control
        .set_role(ClusterRole::Replica, change.force, actor)
        .await
        .map(Json)
}

/// A role change from a body that may be empty.
fn role_change(body: &[u8]) -> Result<RoleChange, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(RoleChange::default());
    }
    serde_json::from_slice(body).map_err(|err| ApiError::bad_request(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_writes() {
        for (method, path) in [
            (Method::POST, "/api/v1/lists"),
            (Method::PUT, "/api/v1/lists/li_1"),
            (Method::DELETE, "/api/v1/rules/ru_1"),
            (Method::PUT, "/api/v1/settings"),
            (Method::POST, "/api/v1/clients"),
        ] {
            assert!(is_config_write(&method, path), "{method} {path}");
        }
        for (method, path) in [
            (Method::GET, "/api/v1/lists"),
            (Method::POST, "/api/v1/lists/refresh"),
            (Method::PUT, "/api/v1/pause"),
            (Method::POST, "/api/v1/cluster/promote"),
            (Method::POST, "/api/v2/lists"),
            (Method::PATCH, "/api/v1/lists/li_1"),
        ] {
            assert!(!is_config_write(&method, path), "{method} {path}");
        }
    }
}
