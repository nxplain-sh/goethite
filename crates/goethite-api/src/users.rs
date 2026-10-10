//! Users, sign-in, sessions and second factors.
//!
//! Admin endpoints manage users (`/api/v1/users…`); the `/api/v1/auth…`
//! endpoints are what a signed-in browser uses on itself. Sign-in checks
//! the password first, then the second factor when one is enabled: a TOTP
//! code or one of the recovery codes. Sessions travel in an `HttpOnly`
//! cookie ([`crate::sessions`]).
//!
//! Every path that changes a user record bumps its revision, which makes
//! every session the user held stale: a password change signs other tabs
//! out on every node, because a session names the revision it was made at.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use goethite_store::{Actor, ActorKind, ResetSpec, Role, TotpSpec, User, UserSpec};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::PeerAddr;
use crate::error::{ApiError, ApiJson, ErrorBody};
use crate::handlers::{expected_revision, with_etag};
use crate::sessions;
use crate::{Api, passwords, totp};

type Shared = State<Arc<Api>>;

/// Failed sign-ins from one address that are tolerated in the window.
const MAX_IP_FAILURES: u32 = 20;
/// Failed sign-ins for one name that are tolerated in the window.
const MAX_NAME_FAILURES: u32 = 5;
/// How long an issued password reset works, in seconds: one hour.
const RESET_TTL_SECONDS: i64 = 60 * 60;
/// What a reset token starts with.
const RESET_TOKEN_PREFIX: &str = "gtr_";

/// Now, in seconds since the Unix epoch.
fn now() -> i64 {
    Timestamp::now().as_second()
}

/// What a session says about its user.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SessionView {
    /// The user's ID.
    pub id: String,
    /// The sign-in name.
    pub name: String,
    /// What the user may do.
    pub role: Role,
    /// Whether a second factor is enabled.
    pub totp: bool,
    /// Recovery codes left.
    pub recovery_codes_left: usize,
}

/// A user as the API shows one: never a hash, secret or code.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct UserView {
    /// The ID.
    pub id: String,
    /// The sign-in name.
    pub name: String,
    /// What the user may do.
    pub role: Role,
    /// Whether the user is disabled.
    pub disabled: bool,
    /// Whether a second factor is enabled.
    pub totp: bool,
    /// Recovery codes left.
    pub recovery_codes_left: usize,
    /// Whether a password reset was issued and has not expired.
    pub reset_pending: bool,
    /// Counts updates, as an `ETag` on the single-user responses.
    pub revision: u64,
    /// When the user was created.
    pub created_at: Timestamp,
    /// When the user last changed.
    pub updated_at: Timestamp,
}

impl From<&User> for UserView {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.clone(),
            name: user.spec.name.clone(),
            role: user.spec.role,
            disabled: user.spec.disabled,
            totp: user.spec.totp.as_ref().is_some_and(|totp| totp.enabled),
            recovery_codes_left: user.spec.recovery.len(),
            reset_pending: user
                .spec
                .reset
                .as_ref()
                .is_some_and(|reset| reset.expires_at > Timestamp::now()),
            revision: user.revision,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

/// A new user.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CreateUser {
    /// The sign-in name.
    pub name: String,
    /// The first password.
    pub password: String,
    /// What the user may do; `admin` by default.
    #[serde(default)]
    pub role: Role,
}

/// What an admin may change about a user.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct UpdateUser {
    /// The sign-in name.
    pub name: String,
    /// What the user may do.
    #[serde(default)]
    pub role: Role,
    /// Whether the user is disabled.
    #[serde(default)]
    pub disabled: bool,
}

/// A password, set by an admin.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct NewPassword {
    /// The new password.
    pub password: String,
}

/// A sign-in attempt.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct Login {
    /// The sign-in name.
    pub name: String,
    /// The password.
    pub password: String,
    /// A TOTP or recovery code, when a second factor is enabled.
    #[serde(default)]
    pub code: Option<String>,
}

/// A password reset, with the one-time token an admin issued.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ResetWithToken {
    /// The one-time token from the reset link.
    pub token: String,
    /// The new password.
    pub password: String,
}

/// A password change by the user itself.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ChangePassword {
    /// The current password.
    pub current_password: String,
    /// The new password.
    pub new_password: String,
}

/// A password, to confirm something.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct WithPassword {
    /// The user's current password.
    pub password: String,
}

/// A code from an authenticator app.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct WithCode {
    /// Six digits, or a recovery code.
    pub code: String,
}

/// A password reset an admin issued; shown once.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct IssuedReset {
    /// The one-time token; goes into the reset link.
    pub token: String,
    /// When it stops working.
    pub expires_at: Timestamp,
}

/// A TOTP secret being set up; shown once.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct OtpSetup {
    /// The secret, base32.
    pub secret: String,
    /// The `otpauth://` URI, for the QR code.
    pub uri: String,
}

/// Recovery codes; shown once.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RecoveryCodes {
    /// The codes.
    pub recovery_codes: Vec<String>,
}

/// The routes a signed-in caller may use, with authentication in front.
pub(crate) fn routes() -> Router<Arc<Api>> {
    Router::new()
        .route("/api/v1/users", get(list_users).post(create_user))
        .route(
            "/api/v1/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/api/v1/users/{id}/password", post(set_user_password))
        .route("/api/v1/users/{id}/reset", post(issue_reset))
        .route("/api/v1/users/{id}/otp/disable", post(clear_user_otp))
        .route("/api/v1/auth/session", get(session_info))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/password", post(change_password))
        .route("/api/v1/auth/otp/setup", post(otp_setup))
        .route("/api/v1/auth/otp/enable", post(otp_enable))
        .route("/api/v1/auth/otp/disable", post(otp_disable))
}

/// The routes that need no session: signing in, and finishing a reset.
pub(crate) fn public_routes() -> Router<Arc<Api>> {
    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/reset", post(reset_with_token))
}

/// Runs a blocking store call off the async runtime.
async fn offload<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?
}

/// The user `id`, or 404.
fn user(api: &Api, id: &str) -> Result<User, ApiError> {
    api.store
        .get::<User>(id)
        .ok_or_else(|| ApiError::not_found(format!("there is no user {id:?}")))
}

/// Reads the user `id`, lets `edit` change the spec, and writes it back,
/// all on a blocking thread. The write fails if the user changed in
/// between.
async fn edit_user<F>(api: &Arc<Api>, id: String, actor: Actor, edit: F) -> Result<User, ApiError>
where
    F: FnOnce(&mut UserSpec) -> Result<(), ApiError> + Send + 'static,
{
    let store = Arc::clone(&api.store);
    offload(move || {
        let before = store
            .get::<User>(&id)
            .ok_or_else(|| ApiError::not_found(format!("there is no user {id:?}")))?;
        let mut spec = before.spec.clone();
        edit(&mut spec)?;
        store
            .update::<User>(&id, spec, Some(before.revision), &actor)
            .map_err(ApiError::from)
    })
    .await
}

/// The password hash of `password`, on a blocking thread.
async fn hash_password(password: String) -> Result<String, ApiError> {
    check_password(&password)?;
    offload(move || {
        passwords::hash_password(&password)
            .ok_or_else(|| ApiError::internal("cannot hash the password"))
    })
    .await
}

/// Checks a new password against the policy.
fn check_password(password: &str) -> Result<(), ApiError> {
    passwords::check_new(password).map_err(|err| ApiError::invalid(err.to_string()))
}

/// Whether `password` is `user`'s, on a blocking thread.
async fn password_matches(user: User, password: String) -> Result<bool, ApiError> {
    offload(move || {
        Ok(passwords::verify_password(
            &user.spec.password_hash,
            &password,
        ))
    })
    .await
}

/// Hands the browser a fresh session cookie for `user`.
fn set_session(api: &Api, user: &User) -> Result<HeaderValue, ApiError> {
    let token = api.sessions.create(&user.id, user.revision, now());
    HeaderValue::from_str(&sessions::cookie_set(&token, api.config.tls.is_some()))
        .map_err(|_| ApiError::internal("cannot build the session cookie"))
}

/// Builds the response to a session check or a sign-in.
fn session_response(api: &Api, user: &User) -> Result<Response, ApiError> {
    let cookie = set_session(api, user)?;
    let view = SessionView {
        id: user.id.clone(),
        name: user.spec.name.clone(),
        role: user.spec.role,
        totp: user.spec.totp.as_ref().is_some_and(|totp| totp.enabled),
        recovery_codes_left: user.spec.recovery.len(),
    };
    let mut response = Json(view).into_response();
    response.headers_mut().insert(SET_COOKIE, cookie);
    Ok(response)
}

/// Records one failed sign-in against both the address and the name.
fn failed(api: &Api, ip: &str, name: &str) {
    let now = now();
    api.attempts.fail(ip, now);
    api.attempts
        .fail(&format!("user:{}", name.to_ascii_lowercase()), now);
}

/// Signs in with a name and a password, and a code when a second factor is
/// enabled. Answers with the session cookie.
#[utoipa::path(
    post, path = "/api/v1/auth/login", tag = "auth",
    request_body = Login,
    responses(
        (status = 200, description = "Signed in; the session is the Set-Cookie", body = SessionView),
        (status = 401, description = "Wrong name or password, a wrong or missing code, or an expired reset", body = ErrorBody),
        (status = 403, description = "The account is disabled", body = ErrorBody),
        (status = 429, description = "Too many failed sign-ins", body = ErrorBody),
    ),
)]
pub(crate) async fn login(
    State(api): Shared,
    Extension(PeerAddr(peer)): Extension<PeerAddr>,
    ApiJson(body): ApiJson<Login>,
) -> Result<Response, ApiError> {
    let now = now();
    let ip_key = format!("ip:{}", peer.ip());
    if !api.attempts.allowed(&ip_key, MAX_IP_FAILURES, now)
        || !api.attempts.allowed(
            &format!("user:{}", body.name.to_ascii_lowercase()),
            MAX_NAME_FAILURES,
            now,
        )
    {
        return Err(ApiError::too_many_requests(
            "too many failed sign-ins; wait five minutes",
        ));
    }
    let store = Arc::clone(&api.store);
    let (name, password) = (body.name.clone(), body.password.clone());
    let found = offload(move || -> Result<Option<User>, ApiError> {
        if let Some(user) = store.user_by_name(&name) {
            return Ok(
                passwords::verify_password(&user.spec.password_hash, &password).then_some(user),
            );
        }
        // Pay the same hashing cost as a sign-in for a known name.
        let _ = passwords::verify_password(passwords::dummy_hash(), &password);
        Ok(None)
    })
    .await?;
    let Some(mut user) = found else {
        failed(&api, &ip_key, &body.name);
        return Err(ApiError::unauthorized_with("wrong user name or password"));
    };
    if user.spec.disabled {
        return Err(ApiError::forbidden("this account is disabled"));
    }
    if user.spec.totp.as_ref().is_some_and(|totp| totp.enabled) {
        let Some(code) = body.code.as_deref() else {
            return Err(ApiError::otp_required());
        };
        match second_factor(&api, &user, code, &peer.ip().to_string()).await? {
            SecondFactor::Wrong => {
                failed(&api, &ip_key, &body.name);
                return Err(ApiError::unauthorized_with("that code is not valid"));
            }
            SecondFactor::Accepted(None) => {}
            SecondFactor::Accepted(Some(fresh)) => user = *fresh,
        }
    }
    api.attempts.clear(&ip_key);
    api.attempts
        .clear(&format!("user:{}", body.name.to_ascii_lowercase()));
    tracing::info!(user = %user.spec.name, "signed in");
    session_response(&api, &user)
}

/// What checking a second factor found.
enum SecondFactor {
    /// The code was right, with the user's fresh record when a recovery
    /// code was used up.
    Accepted(Option<Box<User>>),
    /// The code was wrong.
    Wrong,
}

/// Checks a TOTP code or a recovery code. A recovery code is removed from
/// the user's record when it is used.
async fn second_factor(
    api: &Arc<Api>,
    user: &User,
    code: &str,
    address: &str,
) -> Result<SecondFactor, ApiError> {
    let Some(secret) = user
        .spec
        .totp
        .as_ref()
        .and_then(|totp| totp::decode_secret(&totp.secret))
    else {
        return Err(ApiError::internal("the stored TOTP secret is not base32"));
    };
    let seconds = u64::try_from(now()).unwrap_or(0);
    if totp::verify(&secret, code, seconds) {
        return Ok(SecondFactor::Accepted(None));
    }
    let hash = totp::hash_recovery_code(code);
    if user
        .spec
        .recovery
        .iter()
        .any(|held| totp::same(held.as_bytes(), hash.as_bytes()))
    {
        let actor = Actor::user(user.spec.name.clone(), Some(address.to_owned()));
        let fresh = edit_user(api, user.id.clone(), actor, move |spec| {
            spec.recovery.retain(|held| held != &hash);
            Ok(())
        })
        .await?;
        return Ok(SecondFactor::Accepted(Some(Box::new(fresh))));
    }
    Ok(SecondFactor::Wrong)
}

/// Finishes a password reset with the one-time token an admin issued.
#[utoipa::path(
    post, path = "/api/v1/auth/reset", tag = "auth",
    request_body = ResetWithToken,
    responses(
        (status = 204, description = "The password was set; all sessions of the user are gone"),
        (status = 401, description = "The token is not valid or has expired", body = ErrorBody),
        (status = 422, description = "The new password is not acceptable", body = ErrorBody),
        (status = 429, description = "Too many attempts", body = ErrorBody),
    ),
)]
pub(crate) async fn reset_with_token(
    State(api): Shared,
    Extension(PeerAddr(peer)): Extension<PeerAddr>,
    ApiJson(body): ApiJson<ResetWithToken>,
) -> Result<StatusCode, ApiError> {
    let now = now();
    let ip_key = format!("reset:{}", peer.ip());
    if !api.attempts.allowed(&ip_key, MAX_IP_FAILURES, now) {
        return Err(ApiError::too_many_requests(
            "too many attempts; wait five minutes",
        ));
    }
    check_password(&body.password)?;
    let hash = totp::hash_recovery_code(&body.token);
    let store = Arc::clone(&api.store);
    let token_hash = hash.clone();
    let found = offload(move || {
        Ok(store
            .config()
            .users
            .iter()
            .find(|user| {
                user.spec
                    .reset
                    .as_ref()
                    .is_some_and(|reset| totp::same(reset.hash.as_bytes(), token_hash.as_bytes()))
            })
            .cloned())
    })
    .await?;
    let Some(user) = found else {
        api.attempts.fail(&ip_key, now);
        return Err(ApiError::unauthorized_with(
            "that reset link is not valid or has expired",
        ));
    };
    if user
        .spec
        .reset
        .as_ref()
        .is_none_or(|reset| reset.expires_at <= Timestamp::now())
    {
        api.attempts.fail(&ip_key, now);
        return Err(ApiError::unauthorized_with(
            "that reset link is not valid or has expired",
        ));
    }
    let password_hash = hash_password(body.password).await?;
    let actor = Actor::user(user.spec.name.clone(), Some(peer.ip().to_string()));
    let id = user.id.clone();
    let changed = edit_user(&api, id, actor, move |spec| {
        spec.password_hash = password_hash;
        spec.reset = None;
        Ok(())
    })
    .await?;
    tracing::info!(user = %changed.spec.name, "password reset");
    Ok(StatusCode::NO_CONTENT)
}

/// What the signed-in caller is.
#[utoipa::path(
    get, path = "/api/v1/auth/session", tag = "auth",
    responses(
        (status = 200, description = "The signed-in user", body = SessionView),
        (status = 401, description = "Not signed in", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn session_info(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
) -> Result<Json<SessionView>, ApiError> {
    let user = signed_in_user(&api, &actor)?;
    Ok(Json(SessionView {
        id: user.id.clone(),
        name: user.spec.name.clone(),
        role: user.spec.role,
        totp: user.spec.totp.as_ref().is_some_and(|totp| totp.enabled),
        recovery_codes_left: user.spec.recovery.len(),
    }))
}

/// Signs out: the session is gone and the cookie is cleared.
#[utoipa::path(
    post, path = "/api/v1/auth/logout", tag = "auth",
    responses((status = 204, description = "Signed out")),
    security(("token" = [])),
)]
pub(crate) async fn logout(
    State(api): Shared,
    headers: HeaderMap,
    Extension(actor): Extension<Actor>,
) -> Result<Response, ApiError> {
    if let Some(token) = sessions::cookie_value(&headers) {
        api.sessions.remove(&token);
    }
    if actor.kind == ActorKind::User {
        tracing::info!(user = %actor.name.as_deref().unwrap_or("?"), "signed out");
    }
    let secure = api.config.tls.is_some();
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = HeaderValue::from_str(&sessions::cookie_clear(secure)) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    Ok(response)
}

/// The signed-in user behind `actor`, or an error for a token caller.
fn signed_in_user(api: &Api, actor: &Actor) -> Result<User, ApiError> {
    if actor.kind != ActorKind::User {
        return Err(ApiError::bad_request(
            "this endpoint is for a signed-in user; a token has no account",
        ));
    }
    actor
        .name
        .as_deref()
        .and_then(|name| api.store.user_by_name(name))
        .ok_or_else(ApiError::unauthorized)
}

/// Changes the signed-in user's password. Every other session of the user
/// stops working; this one gets a fresh cookie.
#[utoipa::path(
    post, path = "/api/v1/auth/password", tag = "auth",
    request_body = ChangePassword,
    responses(
        (status = 204, description = "Changed; this session continues with a new cookie"),
        (status = 401, description = "The current password is wrong", body = ErrorBody),
        (status = 422, description = "The new password is not acceptable", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn change_password(
    State(api): Shared,
    headers: HeaderMap,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<ChangePassword>,
) -> Result<Response, ApiError> {
    let user = signed_in_user(&api, &actor)?;
    if !password_matches(user.clone(), body.current_password).await? {
        return Err(ApiError::unauthorized_with("the current password is wrong"));
    }
    let password_hash = hash_password(body.new_password).await?;
    let id = user.id.clone();
    let changed = edit_user(&api, id, actor.clone(), move |spec| {
        spec.password_hash = password_hash;
        Ok(())
    })
    .await?;
    if let Some(token) = sessions::cookie_value(&headers) {
        api.sessions.remove_others(&changed.id, &token);
    }
    let cookie = set_session(&api, &changed)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(SET_COOKIE, cookie);
    Ok(response)
}

/// Starts setting up a TOTP second factor: answers the secret and the
/// `otpauth://` URI. Nothing is enforced until a code confirms it. Storing
/// the pending secret changes the user's record, so the answer carries a
/// fresh session cookie.
#[utoipa::path(
    post, path = "/api/v1/auth/otp/setup", tag = "auth",
    request_body = WithPassword,
    responses(
        (status = 200, description = "The secret and its URI; this session continues with a new cookie", body = OtpSetup),
        (status = 401, description = "The password is wrong", body = ErrorBody),
        (status = 409, description = "A second factor is already enabled", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn otp_setup(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<WithPassword>,
) -> Result<Response, ApiError> {
    let user = signed_in_user(&api, &actor)?;
    if user.spec.totp.as_ref().is_some_and(|totp| totp.enabled) {
        return Err(ApiError::conflict(
            "a second factor is already enabled; disable it first",
        ));
    }
    if !password_matches(user.clone(), body.password).await? {
        return Err(ApiError::unauthorized_with("the password is wrong"));
    }
    let secret =
        totp::new_secret().ok_or_else(|| ApiError::internal("cannot gather randomness"))?;
    let encoded = totp::encode_secret(&secret);
    let stored = encoded.clone();
    let id = user.id.clone();
    let changed = edit_user(&api, id, actor, move |spec| {
        spec.totp = Some(TotpSpec {
            secret: stored,
            enabled: false,
        });
        Ok(())
    })
    .await?;
    let cookie = set_session(&api, &changed)?;
    let mut response = Json(OtpSetup {
        secret: encoded.clone(),
        uri: totp::uri(&encoded, &user.spec.name),
    })
    .into_response();
    response.headers_mut().insert(SET_COOKIE, cookie);
    Ok(response)
}

/// Confirms the TOTP code and enables the factor; answers the recovery
/// codes, once.
#[utoipa::path(
    post, path = "/api/v1/auth/otp/enable", tag = "auth",
    request_body = WithCode,
    responses(
        (status = 200, description = "Enabled; the recovery codes are shown once", body = RecoveryCodes),
        (status = 401, description = "The code is wrong", body = ErrorBody),
        (status = 409, description = "No setup is waiting", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn otp_enable(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<WithCode>,
) -> Result<Response, ApiError> {
    let user = signed_in_user(&api, &actor)?;
    let Some(secret) = user
        .spec
        .totp
        .as_ref()
        .filter(|totp| !totp.enabled)
        .and_then(|totp| totp::decode_secret(&totp.secret))
    else {
        return Err(ApiError::conflict("run the setup first"));
    };
    let seconds = u64::try_from(now()).unwrap_or(0);
    if !totp::verify(&secret, body.code.trim(), seconds) {
        return Err(ApiError::unauthorized_with("that code is not valid"));
    }
    let codes =
        totp::new_recovery_codes().ok_or_else(|| ApiError::internal("cannot gather randomness"))?;
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| totp::hash_recovery_code(code))
        .collect();
    let id = user.id.clone();
    let changed = edit_user(&api, id, actor, move |spec| {
        if let Some(totp) = &mut spec.totp {
            totp.enabled = true;
        }
        spec.recovery = hashes;
        Ok(())
    })
    .await?;
    let cookie = set_session(&api, &changed)?;
    let mut response = Json(RecoveryCodes {
        recovery_codes: codes,
    })
    .into_response();
    response.headers_mut().insert(SET_COOKIE, cookie);
    Ok(response)
}

/// Turns the second factor off; the password confirms it.
#[utoipa::path(
    post, path = "/api/v1/auth/otp/disable", tag = "auth",
    request_body = WithPassword,
    responses(
        (status = 204, description = "Disabled; recovery codes are gone too"),
        (status = 401, description = "The password is wrong", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn otp_disable(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<WithPassword>,
) -> Result<StatusCode, ApiError> {
    let user = signed_in_user(&api, &actor)?;
    if !password_matches(user.clone(), body.password).await? {
        return Err(ApiError::unauthorized_with("the password is wrong"));
    }
    let id = user.id.clone();
    edit_user(&api, id, actor, move |spec| {
        spec.totp = None;
        spec.recovery.clear();
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// All users.
#[utoipa::path(
    get, path = "/api/v1/users", tag = "users",
    responses((status = 200, description = "The users", body = [UserView])),
    security(("token" = [])),
)]
pub(crate) async fn list_users(State(api): Shared) -> Json<Vec<UserView>> {
    let config = api.store.config();
    Json(config.users.iter().map(UserView::from).collect())
}

/// One user, with its revision as the `ETag`.
#[utoipa::path(
    get, path = "/api/v1/users/{id}", tag = "users",
    params(("id" = String, Path, description = "The ID")),
    responses(
        (status = 200, description = "The user", body = UserView),
        (status = 404, description = "No such ID", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn get_user(
    State(api): Shared,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let user = user(&api, &id)?;
    Ok(with_etag(user.revision, Json(UserView::from(&user))))
}

/// Creates a user. The password is hashed here; nothing else ever sees it.
#[utoipa::path(
    post, path = "/api/v1/users", tag = "users",
    request_body = CreateUser,
    responses(
        (status = 201, description = "Created", body = UserView),
        (status = 409, description = "The name is taken", body = ErrorBody),
        (status = 422, description = "The user is not valid", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn create_user(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<CreateUser>,
) -> Result<Response, ApiError> {
    let password_hash = hash_password(body.password).await?;
    let store = Arc::clone(&api.store);
    let spec = UserSpec {
        name: body.name,
        role: body.role,
        disabled: false,
        password_hash,
        totp: None,
        recovery: Vec::new(),
        reset: None,
    };
    let created =
        offload(move || store.create::<User>(spec, &actor).map_err(ApiError::from)).await?;
    let mut response = with_etag(
        created.revision,
        (StatusCode::CREATED, Json(UserView::from(&created))),
    );
    if let Ok(location) = HeaderValue::from_str(&format!("/api/v1/users/{}", created.id)) {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    Ok(response)
}

/// Replaces a user's name, role and disabled flag. The password and the
/// second factor are not touched here.
#[utoipa::path(
    put, path = "/api/v1/users/{id}", tag = "users",
    params(
        ("id" = String, Path, description = "The ID"),
        ("If-Match" = Option<String>, Header, description = "The revision the change is based on"),
    ),
    request_body = UpdateUser,
    responses(
        (status = 200, description = "Updated", body = UserView),
        (status = 404, description = "No such ID", body = ErrorBody),
        (status = 409, description = "The name is taken, or the last admin would be disabled", body = ErrorBody),
        (status = 412, description = "It changed since that revision", body = ErrorBody),
        (status = 422, description = "The user is not valid", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn update_user(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<UpdateUser>,
) -> Result<Response, ApiError> {
    let expected = expected_revision(&headers)?;
    let store = Arc::clone(&api.store);
    let updated = offload(move || {
        let before = store
            .get::<User>(&id)
            .ok_or_else(|| ApiError::not_found(format!("there is no user {id:?}")))?;
        if let Some(expected) = expected
            && expected != before.revision
        {
            return Err(ApiError::from(goethite_store::StoreError::Revision {
                kind: "user",
                id: id.clone(),
                expected,
                actual: before.revision,
            }));
        }
        let spec = UserSpec {
            name: body.name,
            role: body.role,
            disabled: body.disabled,
            ..before.spec.clone()
        };
        store
            .update::<User>(&id, spec, Some(before.revision), &actor)
            .map_err(ApiError::from)
    })
    .await?;
    Ok(with_etag(updated.revision, Json(UserView::from(&updated))))
}

/// Deletes a user. The last enabled admin cannot be deleted.
#[utoipa::path(
    delete, path = "/api/v1/users/{id}", tag = "users",
    params(
        ("id" = String, Path, description = "The ID"),
        ("If-Match" = Option<String>, Header, description = "The revision the deletion is based on"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "No such ID", body = ErrorBody),
        (status = 409, description = "It is the last enabled admin", body = ErrorBody),
        (status = 412, description = "It changed since that revision", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn delete_user(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let expected = expected_revision(&headers)?;
    let store = Arc::clone(&api.store);
    offload(move || {
        store
            .delete::<User>(&id, expected, &actor)
            .map_err(ApiError::from)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets a user's password, as an admin. Every session of that user stops
/// working.
#[utoipa::path(
    post, path = "/api/v1/users/{id}/password", tag = "users",
    params(("id" = String, Path, description = "The ID")),
    request_body = NewPassword,
    responses(
        (status = 204, description = "Set"),
        (status = 404, description = "No such ID", body = ErrorBody),
        (status = 422, description = "The password is not acceptable", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn set_user_password(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<NewPassword>,
) -> Result<StatusCode, ApiError> {
    let password_hash = hash_password(body.password).await?;
    edit_user(&api, id, actor, move |spec| {
        spec.password_hash = password_hash;
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Issues a one-time password reset for a user: the answer carries the
/// token for the `/reset` link, shown once.
#[utoipa::path(
    post, path = "/api/v1/users/{id}/reset", tag = "users",
    params(("id" = String, Path, description = "The ID")),
    responses(
        (status = 200, description = "Issued; the token goes into the reset link", body = IssuedReset),
        (status = 404, description = "No such ID", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn issue_reset(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<Json<IssuedReset>, ApiError> {
    let mut token = String::from(RESET_TOKEN_PREFIX);
    let random: [u8; 32] = rand::random();
    for byte in random {
        let _ = write!(token, "{byte:02x}");
    }
    let hash = totp::hash_recovery_code(&token);
    let expires_at = Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(RESET_TTL_SECONDS))
        .unwrap_or_else(|_| Timestamp::now());
    edit_user(&api, id, actor, move |spec| {
        spec.reset = Some(ResetSpec { hash, expires_at });
        Ok(())
    })
    .await?;
    Ok(Json(IssuedReset { token, expires_at }))
}

/// Clears a user's second factor and recovery codes, as an admin: the way
/// back in for someone who lost their authenticator.
#[utoipa::path(
    post, path = "/api/v1/users/{id}/otp/disable", tag = "users",
    params(("id" = String, Path, description = "The ID")),
    responses(
        (status = 204, description = "Cleared"),
        (status = 404, description = "No such ID", body = ErrorBody),
    ),
    security(("token" = [])),
)]
pub(crate) async fn clear_user_otp(
    State(api): Shared,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    edit_user(&api, id, actor, move |spec| {
        spec.totp = None;
        spec.recovery.clear();
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
