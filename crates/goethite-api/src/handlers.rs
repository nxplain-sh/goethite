//! The `/api/v1` handlers.
//!
//! Resources follow one pattern: `GET` the collection, `POST` a spec to
//! create, and `GET`, `PUT` (the whole spec) or `DELETE` one by ID. Single
//! resources carry their revision as an `ETag`; sending it back in
//! `If-Match` makes an update or delete fail with 412 if someone else
//! changed the resource in the meantime. Store calls block on disk I/O, so
//! they run on a blocking thread, and a change is applied to the data plane
//! before the response is sent.

#![allow(
    unused_qualifications,
    reason = "utoipa's generated code for `params(...)` qualifies the parameter types"
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, FromRequestParts, Path, Query, State};
use axum::http::header::{CONTENT_TYPE, ETAG, IF_MATCH, LOCATION};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use goethite_store::stats::{TOP_FOR_MERGE, TOP_IN_REPORT};
use goethite_store::{
    Actor, AuditAction, AuditEntry, Client, ClientSpec, Group, GroupSpec, Kind, List, ListSpec,
    QueryOutcome, QueryPage, Rule, RuleSpec, Schedule, ScheduleSpec, Search, Settings,
    SettingsSpec, StatsReport, StoreError,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::PeerAddr;
use crate::catalog::{Directory, DirectoryList};
use crate::error::{ApiError, ApiJson, ErrorBody};
use crate::leak::{LeakTest, LeakTestList};
use crate::recommended::{self, Recommended, RecommendedSizes};
use crate::services::Services;
use crate::{Api, Change, Status};

type Shared = State<Arc<Api>>;

/// The longest pause, in seconds: a week.
pub const MAX_PAUSE_SECONDS: u32 = 7 * 86_400;

/// The most audit entries one request returns.
const MAX_AUDIT_PAGE: usize = 1000;

/// Runs a blocking store call off the async runtime.
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?
        .map_err(ApiError::from)
}

/// The revision in `If-Match`, if there is one: `"3"`, `W/"3"` or `3`.
fn expected_revision(headers: &HeaderMap) -> Result<Option<u64>, ApiError> {
    let Some(value) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .map(|text| text.trim().trim_start_matches("W/").trim_matches('"'))
        .and_then(|text| text.parse().ok())
        .map(Some)
        .ok_or_else(|| ApiError::bad_request("If-Match must be a revision such as \"3\""))
}

fn with_etag(revision: u64, body: impl IntoResponse) -> Response {
    let mut response = body.into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("\"{revision}\"")) {
        response.headers_mut().insert(ETAG, value);
    }
    response
}

/// A query string. Unlike [`Query`], one that does not parse is answered
/// with an [`ApiError`] in JSON.
pub(crate) struct ApiQuery<T>(T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    Query<T>: FromRequestParts<S, Rejection = QueryRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|rejection| ApiError::bad_request(rejection.body_text()))
    }
}

macro_rules! resource_handlers {
    (
        $kind:ident, $spec:ident, $change:expr, $tag:literal, $collection:literal, $item:literal,
        $one:literal, $many:literal,
        $list:ident, $get:ident, $create:ident, $update:ident, $delete:ident
    ) => {
        #[utoipa::path(
            get, path = $collection, tag = $tag,
            summary = concat!("Lists all ", $many, ", oldest first."),
            responses(
                (status = 200, description = "All of them, oldest first", body = Vec<$kind>),
                (status = 401, description = "No valid admin token", body = ErrorBody),
            ),
            security(("token" = [])),
        )]
        pub(crate) async fn $list(State(api): Shared) -> Json<Vec<$kind>> {
            Json(<$kind as Kind>::all(&api.store.config()).clone())
        }

        #[utoipa::path(
            get, path = $item, tag = $tag,
            summary = concat!("Gets one ", $one, "."),
            params(("id" = String, Path, description = "The ID")),
            responses(
                (status = 200, description = "It, with its revision as the ETag", body = $kind),
                (status = 404, description = "No such ID", body = ErrorBody),
            ),
            security(("token" = [])),
        )]
        pub(crate) async fn $get(
            State(api): Shared,
            Path(id): Path<String>,
        ) -> Result<Response, ApiError> {
            let resource = api.store.get::<$kind>(&id).ok_or_else(|| {
                ApiError::not_found(format!("there is no {} {id:?}", <$kind as Kind>::NAME))
            })?;
            Ok(with_etag(resource.revision, Json(resource)))
        }

        #[utoipa::path(
            post, path = $collection, tag = $tag,
            summary = concat!("Creates a ", $one, "."),
            request_body = $spec,
            responses(
                (status = 201, description = "Created", body = $kind),
                (status = 409, description = "It refers to something that does not exist", body = ErrorBody),
                (status = 422, description = "It is not valid", body = ErrorBody),
            ),
            security(("token" = [])),
        )]
        pub(crate) async fn $create(
            State(api): Shared,
            Extension(actor): Extension<Actor>,
            ApiJson(spec): ApiJson<$spec>,
        ) -> Result<Response, ApiError> {
            let store = Arc::clone(&api.store);
            let created = blocking(move || store.create::<$kind>(spec, &actor)).await?;
            api.control.apply($change).await;
            let location = format!(concat!($collection, "/{}"), created.id);
            let mut response = with_etag(created.revision, (StatusCode::CREATED, Json(created)));
            if let Ok(location) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(LOCATION, location);
            }
            Ok(response)
        }

        #[utoipa::path(
            put, path = $item, tag = $tag,
            summary = concat!("Replaces a ", $one, "'s spec."),
            params(
                ("id" = String, Path, description = "The ID"),
                ("If-Match" = Option<String>, Header, description = "The revision the change is based on"),
            ),
            request_body = $spec,
            responses(
                (status = 200, description = "Updated", body = $kind),
                (status = 404, description = "No such ID", body = ErrorBody),
                (status = 409, description = "It refers to something that does not exist", body = ErrorBody),
                (status = 412, description = "It changed since that revision", body = ErrorBody),
                (status = 422, description = "It is not valid", body = ErrorBody),
            ),
            security(("token" = [])),
        )]
        pub(crate) async fn $update(
            State(api): Shared,
            Extension(actor): Extension<Actor>,
            Path(id): Path<String>,
            headers: HeaderMap,
            ApiJson(spec): ApiJson<$spec>,
        ) -> Result<Response, ApiError> {
            let expected = expected_revision(&headers)?;
            let store = Arc::clone(&api.store);
            let updated =
                blocking(move || store.update::<$kind>(&id, spec, expected, &actor)).await?;
            api.control.apply($change).await;
            Ok(with_etag(updated.revision, Json(updated)))
        }

        #[utoipa::path(
            delete, path = $item, tag = $tag,
            summary = concat!("Deletes a ", $one, "."),
            params(
                ("id" = String, Path, description = "The ID"),
                ("If-Match" = Option<String>, Header, description = "The revision the deletion is based on"),
            ),
            responses(
                (status = 204, description = "Deleted"),
                (status = 404, description = "No such ID", body = ErrorBody),
                (status = 409, description = "Something still refers to it", body = ErrorBody),
                (status = 412, description = "It changed since that revision", body = ErrorBody),
            ),
            security(("token" = [])),
        )]
        pub(crate) async fn $delete(
            State(api): Shared,
            Extension(actor): Extension<Actor>,
            Path(id): Path<String>,
            headers: HeaderMap,
        ) -> Result<StatusCode, ApiError> {
            let expected = expected_revision(&headers)?;
            let store = Arc::clone(&api.store);
            blocking(move || store.delete::<$kind>(&id, expected, &actor)).await?;
            api.control.apply($change).await;
            Ok(StatusCode::NO_CONTENT)
        }
    };
}

resource_handlers!(
    List,
    ListSpec,
    Change::Filter,
    "lists",
    "/api/v1/lists",
    "/api/v1/lists/{id}",
    "filter list",
    "filter lists",
    list_lists,
    get_list,
    create_list,
    update_list,
    delete_list
);
resource_handlers!(
    Rule,
    RuleSpec,
    Change::Filter,
    "rules",
    "/api/v1/rules",
    "/api/v1/rules/{id}",
    "custom rule",
    "custom rules",
    list_rules,
    get_rule,
    create_rule,
    update_rule,
    delete_rule
);
resource_handlers!(
    Group,
    GroupSpec,
    Change::Policy,
    "groups",
    "/api/v1/groups",
    "/api/v1/groups/{id}",
    "group",
    "groups",
    list_groups,
    get_group,
    create_group,
    update_group,
    delete_group
);
resource_handlers!(
    Client,
    ClientSpec,
    Change::Policy,
    "clients",
    "/api/v1/clients",
    "/api/v1/clients/{id}",
    "client",
    "clients",
    list_clients,
    get_client,
    create_client,
    update_client,
    delete_client
);
resource_handlers!(
    Schedule,
    ScheduleSpec,
    Change::Policy,
    "schedules",
    "/api/v1/schedules",
    "/api/v1/schedules/{id}",
    "schedule",
    "schedules",
    list_schedules,
    get_schedule,
    create_schedule,
    update_schedule,
    delete_schedule
);

/// The answer to a health check.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Health {
    /// Always `ok`.
    pub status: String,
}

/// Whether the API is up. Needs no token.
#[utoipa::path(get, path = "/api/v1/health", tag = "node",
    responses((status = 200, description = "Up", body = Health)))]
pub(crate) async fn health() -> Json<Health> {
    Json(Health {
        status: "ok".into(),
    })
}

/// How the node is doing: filter, lists, upstreams, cache, query log.
#[utoipa::path(get, path = "/api/v1/status", tag = "node",
    responses((status = 200, description = "The status", body = Status)),
    security(("token" = [])))]
pub(crate) async fn get_status(State(api): Shared) -> Json<Status> {
    let mut status = api.control.status();
    status.api_docs = api.config.docs.is_some();
    Json(status)
}

/// The filtering settings.
#[utoipa::path(get, path = "/api/v1/settings", tag = "settings",
    responses((status = 200, description = "The settings, with their revision as the ETag", body = Settings)),
    security(("token" = [])))]
pub(crate) async fn get_settings(State(api): Shared) -> Response {
    let settings = api.store.config().settings.clone();
    with_etag(settings.revision, Json(settings))
}

/// Replaces the filtering settings.
#[utoipa::path(put, path = "/api/v1/settings", tag = "settings",
    params(("If-Match" = Option<String>, Header, description = "The revision the change is based on")),
    request_body = SettingsSpec,
    responses(
        (status = 200, description = "Updated", body = Settings),
        (status = 412, description = "They changed since that revision", body = ErrorBody),
        (status = 422, description = "They are not valid", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn put_settings(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<SettingsSpec>,
) -> Result<Response, ApiError> {
    let expected = expected_revision(&headers)?;
    let store = Arc::clone(&api.store);
    let settings = blocking(move || store.update_settings(spec, expected, &actor)).await?;
    api.control.apply(Change::Policy).await;
    Ok(with_etag(settings.revision, Json(settings)))
}

/// Whether filtering is paused.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Pause {
    /// Until when filtering is paused; absent when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<Timestamp>,
}

/// How long to pause filtering.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PauseRequest {
    /// Seconds, from 1 to 604,800 (a week).
    pub seconds: u32,
}

fn pause_state(api: &Api) -> Pause {
    Pause {
        paused_until: api
            .control
            .paused_until()
            .and_then(|until| Timestamp::try_from(until).ok()),
    }
}

/// Whether filtering is paused.
#[utoipa::path(get, path = "/api/v1/pause", tag = "settings",
    responses((status = 200, description = "Whether filtering is paused", body = Pause)),
    security(("token" = [])))]
pub(crate) async fn get_pause(State(api): Shared) -> Json<Pause> {
    Json(pause_state(&api))
}

/// Pauses filtering for everyone for a while. It resumes by itself, and on a
/// restart.
#[utoipa::path(put, path = "/api/v1/pause", tag = "settings",
    request_body = PauseRequest,
    responses(
        (status = 200, description = "Paused", body = Pause),
        (status = 422, description = "Not between 1 second and a week", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn put_pause(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    ApiJson(request): ApiJson<PauseRequest>,
) -> Result<Json<Pause>, ApiError> {
    if !(1..=MAX_PAUSE_SECONDS).contains(&request.seconds) {
        return Err(ApiError::from(StoreError::Invalid(
            goethite_store::ValidationError {
                field: "seconds".into(),
                message: format!("must be between 1 and {MAX_PAUSE_SECONDS}"),
                conflict: false,
            },
        )));
    }
    let until = SystemTime::now()
        .checked_add(Duration::from_secs(u64::from(request.seconds)))
        .ok_or_else(|| ApiError::bad_request("the pause ends too far in the future"))?;
    let store = Arc::clone(&api.store);
    let detail = format!("for {} seconds", request.seconds);
    blocking(move || store.record(&actor, AuditAction::Pause, Some(detail))).await?;
    api.control.pause(Some(until));
    Ok(Json(pause_state(&api)))
}

/// Resumes filtering.
#[utoipa::path(delete, path = "/api/v1/pause", tag = "settings",
    responses((status = 200, description = "Resumed", body = Pause)),
    security(("token" = [])))]
pub(crate) async fn delete_pause(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Pause>, ApiError> {
    let store = Arc::clone(&api.store);
    blocking(move || store.record(&actor, AuditAction::Resume, None)).await?;
    api.control.pause(None);
    Ok(Json(pause_state(&api)))
}

/// Downloads every URL list now, in the background. `GET /api/v1/status`
/// shows the result.
#[utoipa::path(post, path = "/api/v1/lists/refresh", tag = "lists",
    responses((status = 202, description = "The download started")),
    security(("token" = [])))]
pub(crate) async fn refresh_lists(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
) -> Result<StatusCode, ApiError> {
    let store = Arc::clone(&api.store);
    blocking(move || store.record(&actor, AuditAction::Refresh, None)).await?;
    api.control.refresh_lists();
    Ok(StatusCode::ACCEPTED)
}

/// What to look for in the query log.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct QueryLogParams {
    /// Only entries older than this ID: the `next` of the previous page.
    before: Option<u64>,
    /// How many entries, 1 to 1000 (default 100).
    limit: Option<usize>,
    /// Only this client address, client ID or group ID.
    client: Option<String>,
    /// Only names containing this text, ignoring case.
    name: Option<String>,
    /// Only this outcome.
    outcome: Option<QueryOutcome>,
    /// Only entries at or after this time (RFC 3339).
    #[param(value_type = Option<String>, format = DateTime)]
    since: Option<Timestamp>,
    /// Only entries before this time (RFC 3339).
    #[param(value_type = Option<String>, format = DateTime)]
    until: Option<Timestamp>,
}

/// Searches the query log, newest first. A search looks at no more than
/// 100,000 entries; follow `next` to continue.
#[utoipa::path(get, path = "/api/v1/querylog", tag = "querylog",
    params(QueryLogParams),
    responses((status = 200, description = "A page of entries", body = QueryPage)),
    security(("token" = [])))]
pub(crate) async fn get_querylog(
    State(api): Shared,
    ApiQuery(params): ApiQuery<QueryLogParams>,
) -> Result<Json<QueryPage>, ApiError> {
    let search = Search {
        before: params.before,
        limit: params.limit.unwrap_or(100),
        client: params.client,
        name: params.name,
        outcome: params.outcome,
        since: params.since,
        until: params.until,
    };
    let store = Arc::clone(&api.store);
    Ok(Json(blocking(move || store.search_queries(&search)).await?))
}

/// Which statistics.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct StatsParams {
    /// The last this many hours, 1 to 720 (default 24).
    hours: Option<u32>,
    /// `node` (the default) for this node's counts, or `cluster` for every
    /// node's added up. A cluster's top lists are approximate.
    #[param(inline)]
    scope: Option<StatsScope>,
}

/// Whose statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StatsScope {
    /// This node's.
    #[default]
    Node,
    /// Every node's in the cluster, added up.
    Cluster,
}

/// Counts per hour, and the names and clients asked most.
#[utoipa::path(get, path = "/api/v1/stats", tag = "querylog",
    params(StatsParams),
    responses((status = 200, description = "The statistics", body = StatsReport)),
    security(("token" = [])))]
pub(crate) async fn get_stats(
    State(api): Shared,
    ApiQuery(params): ApiQuery<StatsParams>,
) -> Json<StatsReport> {
    let hours = params.hours.unwrap_or(24);
    let cluster = match params.scope.unwrap_or_default() {
        StatsScope::Cluster => api.control.cluster(),
        StatsScope::Node => None,
    };
    let Some(cluster) = cluster else {
        return Json(api.log.stats(hours));
    };
    // Long top lists from every node, merged, then cut.
    let mut report = api.log.stats_top(hours, TOP_FOR_MERGE);
    report.nodes.push(cluster.node);
    if let Ok(peer) = api.control.peer_stats(hours).await {
        report.merge(&peer, TOP_IN_REPORT);
        report.nodes.push(cluster.peer.node);
    } else {
        report.cut_top(TOP_IN_REPORT);
        report.unreachable.push(cluster.peer.node);
    }
    Json(report)
}

/// Which audit entries.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AuditParams {
    /// Only entries before this ID.
    before: Option<u64>,
    /// How many, 1 to 1000 (default 100).
    limit: Option<usize>,
}

/// The audit log: every change, newest first.
#[utoipa::path(get, path = "/api/v1/audit", tag = "audit",
    params(AuditParams),
    responses((status = 200, description = "Entries, newest first", body = Vec<AuditEntry>)),
    security(("token" = [])))]
pub(crate) async fn get_audit(
    State(api): Shared,
    ApiQuery(params): ApiQuery<AuditParams>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let limit = params.limit.unwrap_or(100).clamp(1, MAX_AUDIT_PAGE);
    let store = Arc::clone(&api.store);
    Ok(Json(
        blocking(move || store.audit(params.before, limit)).await?,
    ))
}

/// This API's OpenAPI document.
#[utoipa::path(get, path = "/api/v1/openapi.json", tag = "node",
    responses((status = 200, description = "The OpenAPI 3.1 document", content_type = "application/json")),
    security(("token" = [])))]
pub(crate) async fn get_openapi() -> Response {
    ([(CONTENT_TYPE, "application/json")], crate::openapi_json()).into_response()
}

/// Metrics in the Prometheus text format.
#[utoipa::path(get, path = "/metrics", tag = "node",
    responses((status = 200, description = "Prometheus text format", content_type = "text/plain")),
    security(("token" = [])))]
pub(crate) async fn get_metrics(State(api): Shared) -> Response {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        api.control.metrics(),
    )
        .into_response()
}

/// The filter lists goethite recommends, each checked to download and read
/// cleanly, by category: one base list against ads and trackers, security
/// lists to stack on it, optional lists by topic, and legacy lists the base
/// lists include. Lists that do the same job name each other in `excludes`.
/// Presets are sets of them for a group; the `default` one is what a new
/// node starts with.
#[utoipa::path(get, path = "/api/v1/lists/recommended", tag = "lists",
    responses((status = 200, description = "Recommended lists and presets", body = Recommended)),
    security(("token" = [])))]
pub(crate) async fn recommended_lists() -> Json<Recommended> {
    Json(recommended::RECOMMENDED)
}

/// How big the recommended lists say they are, read from the start of each
/// list by the node when asked, and kept for a day. Lists whose header
/// states no size are left out.
#[utoipa::path(get, path = "/api/v1/lists/recommended/sizes", tag = "lists",
    responses(
        (status = 200, description = "The sizes", body = RecommendedSizes),
        (status = 503, description = "Turned off on this node", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn recommended_sizes(
    State(api): Shared,
) -> Result<Json<RecommendedSizes>, ApiError> {
    Ok(Json(api.control.recommended_sizes().await?))
}

/// The FilterLists directory (filterlists.com): the lists goethite can
/// read, allowlists left out. The node fetches it when asked, and keeps it
/// for a day.
#[utoipa::path(get, path = "/api/v1/lists/directory", tag = "lists",
    responses(
        (status = 200, description = "The directory", body = Directory),
        (status = 503, description = "Turned off on this node, or FilterLists cannot be reached", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn get_directory(State(api): Shared) -> Result<Json<Directory>, ApiError> {
    Ok(Json(api.control.directory().await?))
}

/// A list's details from the FilterLists directory, with its `https://`
/// addresses. Licenses and descriptions are FilterLists' and may be out of
/// date.
#[utoipa::path(get, path = "/api/v1/lists/directory/{id}", tag = "lists",
    params(("id" = u64, Path, description = "The list's FilterLists ID")),
    responses(
        (status = 200, description = "The list", body = DirectoryList),
        (status = 503, description = "Turned off on this node, or FilterLists cannot be reached", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn get_directory_list(
    State(api): Shared,
    Path(id): Path<String>,
) -> Result<Json<DirectoryList>, ApiError> {
    let id = id
        .parse::<u64>()
        .map_err(|_| ApiError::bad_request("a FilterLists ID is a number"))?;
    Ok(Json(api.control.directory_list(id).await?))
}

/// The services groups can block (`blocked_services`), such as TikTok or
/// YouTube, with the rules that block them. The catalog is AdGuard's
/// HostlistsRegistry (GPL-3.0), which the node downloads and refreshes with
/// the filter lists.
#[utoipa::path(get, path = "/api/v1/services", tag = "groups",
    responses(
        (status = 200, description = "The services", body = Services),
        (status = 503, description = "Turned off on this node", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn get_services(State(api): Shared) -> Result<Json<Services>, ApiError> {
    Ok(Json(api.control.services()?))
}

/// Starts a DNS leak test: names under `leak.goethite.test` that only
/// goethite answers, for the device being tested to look up. The lookups
/// that reach this node are recorded for an hour; names that never arrive
/// were asked of another resolver. Tests live in memory, on this node.
#[utoipa::path(post, path = "/api/v1/leak-tests", tag = "node",
    responses(
        (status = 201, description = "The test, with the names to look up", body = LeakTest),
        (status = 503, description = "Not run on this node", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn create_leak_test(
    State(api): Shared,
    peer: Option<Extension<PeerAddr>>,
) -> Result<(StatusCode, Json<LeakTest>), ApiError> {
    let requested_by = peer.map(|Extension(peer)| peer.0.ip());
    let test = api.control.leak_tests()?.create(requested_by);
    Ok((StatusCode::CREATED, Json(test)))
}

/// The DNS leak tests this node keeps, newest first, with the lookups
/// that reached it.
#[utoipa::path(get, path = "/api/v1/leak-tests", tag = "node",
    responses(
        (status = 200, description = "The tests", body = LeakTestList),
        (status = 503, description = "Not run on this node", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn list_leak_tests(State(api): Shared) -> Result<Json<LeakTestList>, ApiError> {
    Ok(Json(api.control.leak_tests()?.list()))
}

/// A DNS leak test: which of its names reached this node, from where, how
/// and as which client.
#[utoipa::path(get, path = "/api/v1/leak-tests/{id}", tag = "node",
    params(("id" = String, Path, description = "The test's ID")),
    responses(
        (status = 200, description = "The test", body = LeakTest),
        (status = 404, description = "No such test, or it expired", body = ErrorBody),
        (status = 503, description = "Not run on this node", body = ErrorBody),
    ),
    security(("token" = [])))]
pub(crate) async fn get_leak_test(
    State(api): Shared,
    Path(id): Path<String>,
) -> Result<Json<LeakTest>, ApiError> {
    api.control
        .leak_tests()?
        .get(&id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no such leak test; tests are kept for an hour"))
}

/// Every route that needs authentication.
pub(crate) fn routes() -> Router<Arc<Api>> {
    Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/settings", get(get_settings).put(put_settings))
        .route(
            "/api/v1/pause",
            get(get_pause).put(put_pause).delete(delete_pause),
        )
        .route("/api/v1/lists", get(list_lists).post(create_list))
        .route("/api/v1/lists/refresh", post(refresh_lists))
        .route("/api/v1/lists/recommended", get(recommended_lists))
        .route("/api/v1/lists/recommended/sizes", get(recommended_sizes))
        .route("/api/v1/lists/directory", get(get_directory))
        .route("/api/v1/lists/directory/{id}", get(get_directory_list))
        .route(
            "/api/v1/lists/{id}",
            get(get_list).put(update_list).delete(delete_list),
        )
        .route("/api/v1/rules", get(list_rules).post(create_rule))
        .route(
            "/api/v1/rules/{id}",
            get(get_rule).put(update_rule).delete(delete_rule),
        )
        .route("/api/v1/groups", get(list_groups).post(create_group))
        .route(
            "/api/v1/groups/{id}",
            get(get_group).put(update_group).delete(delete_group),
        )
        .route("/api/v1/services", get(get_services))
        .route(
            "/api/v1/leak-tests",
            get(list_leak_tests).post(create_leak_test),
        )
        .route("/api/v1/leak-tests/{id}", get(get_leak_test))
        .route("/api/v1/clients", get(list_clients).post(create_client))
        .route(
            "/api/v1/clients/{id}",
            get(get_client).put(update_client).delete(delete_client),
        )
        .route(
            "/api/v1/schedules",
            get(list_schedules).post(create_schedule),
        )
        .route(
            "/api/v1/schedules/{id}",
            get(get_schedule)
                .put(update_schedule)
                .delete(delete_schedule),
        )
        .route("/api/v1/querylog", get(get_querylog))
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/audit", get(get_audit))
        .route("/api/v1/openapi.json", get(get_openapi))
        .route("/metrics", get(get_metrics))
}
