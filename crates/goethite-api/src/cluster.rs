//! The API in a cluster: which node this is, where configuration changes
//! go, and handing them to the leader.
//!
//! The members of a cluster agree on configuration changes with Raft, and
//! one of them leads. On any other member, a configuration change (a
//! `POST`, `PUT` or `DELETE` of a list, rule, local record, group, client,
//! schedule or the settings, or removing a member) is forwarded to the
//! leader with the caller's identity, and answered with the leader's answer
//! once this node has applied the change, so the caller reads its own
//! write. While there is no leader such changes are refused; reads, pausing
//! and list downloads stay local. The binary does the forwarding
//! ([`Control::forward`]); the leader runs forwarded changes through the
//! same routes ([`execute`]).
//!
//! For clients of goethite 0.4, the leader is the `primary` and every other
//! member a `replica`.

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

/// How long a member waits to apply a change it forwarded, so the caller
/// reads its own write.
const READ_YOUR_WRITE: Duration = Duration::from_secs(3);

/// A node's role in its cluster, as goethite 0.4 named it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterRole {
    /// Leads the cluster: configuration changes are made through it.
    Primary,
    /// Any other member: it applies the leader's changes and forwards its
    /// own to it.
    Replica,
}

/// What a member does in the cluster right now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemberState {
    /// It leads: configuration changes are made through it.
    Leader,
    /// It follows the leader and votes.
    Follower,
    /// It is standing for election.
    Candidate,
    /// It follows the leader without voting, or waits to be added to a
    /// cluster.
    Learner,
    /// Raft stopped on it.
    Stopped,
    /// It answered with a state this node does not know, or is a node of
    /// goethite 0.4.
    #[default]
    Unknown,
}

/// How a member belongs to the cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Membership {
    /// It votes: a majority of voters must agree on every change.
    Voter,
    /// It receives every change, but does not vote.
    Learner,
    /// It is in this node's config file, but not in the cluster (yet).
    Configured,
}

/// This node's cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClusterStatus {
    /// This node's name.
    pub node: String,
    /// Its role: `primary` while it leads.
    pub role: ClusterRole,
    /// What it does in the cluster; `unknown` from goethite 0.4.
    #[serde(default)]
    pub state: MemberState,
    /// The cluster's ID, if this node is in one: chosen when the cluster
    /// started, or was taken over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// The leader, if there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leader: Option<String>,
    /// The Raft term: it counts elections.
    #[serde(default)]
    pub term: u64,
    /// Its configuration's version.
    pub config: ConfigVersion,
    /// Whether configuration changes can be made through this node now:
    /// on the leader, or on a member that reaches the leader.
    pub writable: bool,
    /// Every member: this node, the cluster's other members, and those in
    /// this node's config file; empty from goethite 0.4.
    #[serde(default)]
    pub members: Vec<MemberStatus>,
    /// One other member, for clients of goethite 0.4: the leader, or on
    /// the leader another member. Use `members`.
    pub peer: PeerStatus,
    /// Off the leader, how following it goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncStatus>,
    /// Things someone should look at, in words, such as a member in
    /// another cluster.
    pub problems: Vec<String>,
}

/// A member of the cluster, as last seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MemberStatus {
    /// Its name.
    pub node: String,
    /// Its cluster address.
    pub address: String,
    /// Whether it is this node.
    pub this_node: bool,
    /// How it belongs to the cluster.
    pub membership: Membership,
    /// Whether it is a witness: it votes, never leads and answers no DNS.
    pub witness: bool,
    /// Whether it answered the last check.
    pub reachable: bool,
    /// When it was last checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<Timestamp>,
    /// What it does, when last reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<MemberState>,
    /// Its goethite version, when last reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Its configuration's version, when last reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigVersion>,
    /// On the leader: the last log entry it is known to hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<u64>,
    /// Why the last check failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Another member, as last seen, in goethite 0.4's terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PeerStatus {
    /// Its name; empty when the cluster has no other member.
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

/// How a member follows the leader.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SyncStatus {
    /// When the leader last sent changes or a heartbeat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_contact: Option<Timestamp>,
    /// When this node's configuration last changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_copy: Option<Timestamp>,
    /// Why it cannot follow, if it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Where configuration changes made through this node go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Writes {
    /// Into this node's store: a node on its own, or the leader.
    Local,
    /// To the leader, through [`Control::forward`](crate::Control::forward).
    Forward,
    /// Nowhere, for this reason, such as a cluster without a leader.
    ReadOnly(String),
}

/// A configuration change, forwarded from a member to the leader.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forwarded {
    /// The HTTP method.
    pub method: String,
    /// The path and query, under `/api/v1/`.
    pub path: String,
    /// The `If-Match` header, if the caller sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_match: Option<String>,
    /// The body as sent, if there was one; the leader checks it as it
    /// checks any request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Who made the change, as the forwarding member authenticated them.
    pub actor: Actor,
}

/// The leader's answer to a forwarded change.
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
    /// The body as the leader sent it, if any: JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// The leader's configuration version after the change.
    pub version: ConfigVersion,
}

/// The identity of a forwarded change, set by [`execute`]. Extensions never
/// come from the wire, so no HTTP client can set it.
#[derive(Clone, Debug)]
pub(crate) struct TrustedActor(pub(crate) Actor);

/// Whether `method` on `path` changes the cluster's configuration, so the
/// leader must make it.
fn is_config_write(method: &Method, path: &str) -> bool {
    if !matches!(*method, Method::POST | Method::PUT | Method::DELETE) {
        return false;
    }
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return false;
    };
    if *method == Method::DELETE && rest.starts_with("cluster/members/") {
        return true;
    }
    let resource = rest.split('/').next().unwrap_or_default();
    matches!(
        resource,
        "lists" | "rules" | "records" | "groups" | "clients" | "schedules" | "settings" | "users"
    ) && rest != "lists/refresh"
}

/// Sends configuration changes made through a member to the leader.
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

/// The leader's answer as this node's response.
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

/// Runs a change forwarded by the member `node` through this node's
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

/// This node's cluster: what this node does in it, its leader and members,
/// and how following the leader goes.
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
    /// Change it even though the cluster seems to disagree: take a cluster
    /// over while its leader is reachable, or leave one without another to
    /// join. Two clusters can result, until one node is demoted.
    #[serde(default)]
    pub force: bool,
}

/// Takes the cluster over: this node starts a new cluster, as its only
/// voter, with its configuration. For a cluster that has lost most of its
/// voters for good, such as two nodes without a witness that lost the
/// leader. Refused while a leader is reachable, unless forced. The other
/// members join the new cluster once demoted.
#[utoipa::path(post, path = "/api/v1/cluster/promote", tag = "cluster",
    request_body = RoleChange,
    responses(
        (status = 200, description = "This node leads a cluster of its own", body = ClusterStatus),
        (status = 404, description = "This node is not in a cluster", body = ErrorBody),
        (status = 409, description = "The cluster has a reachable leader", body = ErrorBody),
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

/// Leaves this node's cluster to join another: after a takeover, on a
/// node of the old cluster. It keeps its configuration until the other
/// cluster's leader adds it, which then replaces it. Refused unless the
/// leader of another cluster is reachable, unless forced.
#[utoipa::path(post, path = "/api/v1/cluster/demote", tag = "cluster",
    request_body = RoleChange,
    responses(
        (status = 200, description = "This node left its cluster", body = ClusterStatus),
        (status = 404, description = "This node is not in a cluster", body = ErrorBody),
        (status = 409, description = "No other cluster's leader is reachable", body = ErrorBody),
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

/// Removes a member from the cluster for good, such as a node taken out of
/// service. Remove it from the leader's config file first, or it is added
/// again. Made by the leader, like configuration changes.
#[utoipa::path(delete, path = "/api/v1/cluster/members/{node}", tag = "cluster",
    params(("node" = String, Path, description = "The member's name")),
    responses(
        (status = 200, description = "The member is gone", body = ClusterStatus),
        (status = 404, description = "No such member", body = ErrorBody),
        (status = 409, description = "It is the leader, or still in the leader's config file", body = ErrorBody),
        (status = 503, description = "The cluster has no leader", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn remove_member(
    State(api): State<Arc<Api>>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::extract::Path(node): axum::extract::Path<String>,
) -> Result<Json<ClusterStatus>, ApiError> {
    api.control.remove_member(node, actor).await.map(Json)
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
            (Method::DELETE, "/api/v1/records/rc_1"),
            (Method::DELETE, "/api/v1/cluster/members/dns3"),
        ] {
            assert!(is_config_write(&method, path), "{method} {path}");
        }
        for (method, path) in [
            (Method::GET, "/api/v1/lists"),
            (Method::POST, "/api/v1/lists/refresh"),
            (Method::POST, "/api/v1/leak-tests"),
            (Method::PUT, "/api/v1/pause"),
            (Method::POST, "/api/v1/cluster/promote"),
            (Method::POST, "/api/v1/cluster/demote"),
            (Method::POST, "/api/v1/cluster/members/dns3"),
            (Method::POST, "/api/v2/lists"),
            (Method::PATCH, "/api/v1/lists/li_1"),
        ] {
            assert!(!is_config_write(&method, path), "{method} {path}");
        }
    }
}
