//! The OpenAPI document, generated from the handlers by utoipa.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::{cluster, handlers, users};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "goethite API",
        description = "Configure and observe a goethite DNS filtering resolver. \
            Every request except `/api/v1/health`, `/api/v1/auth/login` and \
            `/api/v1/auth/reset` needs the admin token as \
            `Authorization: Bearer <token>`, or a session cookie from a sign-in; while \
            the node has neither a token nor users, the API only answers on loopback. \
            Changes are validated, audit-logged and applied at \
            once. Resources have a revision: send it back in `If-Match` to make an update \
            fail if someone else changed the resource in the meantime.",
        license(name = "AGPL-3.0-only", identifier = "AGPL-3.0-only"),
    ),
    paths(
        handlers::health,
        handlers::get_status,
        handlers::check_update,
        handlers::create_leak_test,
        handlers::list_leak_tests,
        handlers::get_leak_test,
        handlers::get_metrics,
        handlers::get_openapi,
        handlers::get_settings,
        handlers::put_settings,
        handlers::get_pause,
        handlers::put_pause,
        handlers::delete_pause,
        handlers::list_lists,
        handlers::create_list,
        handlers::get_list,
        handlers::update_list,
        handlers::delete_list,
        handlers::refresh_lists,
        handlers::flush_cache,
        handlers::recommended_lists,
        handlers::recommended_sizes,
        handlers::get_directory,
        handlers::get_directory_list,
        handlers::list_rules,
        handlers::create_rule,
        handlers::get_rule,
        handlers::update_rule,
        handlers::delete_rule,
        handlers::list_records,
        handlers::create_record,
        handlers::get_record,
        handlers::update_record,
        handlers::delete_record,
        handlers::list_groups,
        handlers::create_group,
        handlers::get_group,
        handlers::update_group,
        handlers::delete_group,
        handlers::get_services,
        handlers::list_clients,
        handlers::create_client,
        handlers::get_client,
        handlers::update_client,
        handlers::delete_client,
        handlers::list_schedules,
        handlers::create_schedule,
        handlers::get_schedule,
        handlers::update_schedule,
        handlers::delete_schedule,
        handlers::get_querylog,
        handlers::get_stats,
        handlers::get_audit,
        users::login,
        users::reset_with_token,
        users::logout,
        users::session_info,
        users::change_password,
        users::otp_setup,
        users::otp_enable,
        users::otp_disable,
        users::list_users,
        users::get_user,
        users::create_user,
        users::update_user,
        users::delete_user,
        users::set_user_password,
        users::issue_reset,
        users::clear_user_otp,
        cluster::get_cluster,
        cluster::promote,
        cluster::demote,
        cluster::remove_member,
    ),
    modifiers(&BearerToken),
    tags(
        (name = "node", description = "Health, status, metrics"),
        (name = "settings", description = "Filtering settings and pausing"),
        (name = "lists", description = "Filter lists"),
        (name = "rules", description = "Custom filtering rules"),
        (name = "records", description = "Local DNS records, answered before the filter"),
        (name = "groups", description = "Groups of clients with the same filtering"),
        (name = "clients", description = "Devices and networks, by address"),
        (name = "schedules", description = "Weekly time windows for scheduled lists"),
        (name = "querylog", description = "The query log and statistics"),
        (name = "audit", description = "Every configuration change"),
        (name = "auth", description = "Signing in, sessions and second factors"),
        (name = "users", description = "The users with access to the API"),
        (name = "cluster", description = "This node's cluster: its leader and members, taking over and joining"),
    ),
)]
struct ApiDoc;

/// Adds the bearer token scheme the paths refer to.
struct BearerToken;

impl Modify for BearerToken {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("The admin token printed by `goethite token`."))
                    .build(),
            ),
        );
    }
}

/// The OpenAPI document for `/api/v1`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// The OpenAPI document as pretty-printed JSON, with a final newline.
pub fn openapi_json() -> String {
    let mut json = openapi().to_pretty_json().unwrap_or_default();
    json.push('\n');
    json
}
