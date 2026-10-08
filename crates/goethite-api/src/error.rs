//! Errors as JSON responses, and a JSON body extractor whose rejections are
//! JSON too.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::http::header::WWW_AUTHENTICATE;
use axum::response::{IntoResponse, Response};
use goethite_store::StoreError;
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;

/// The body of every error response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// What went wrong.
    pub error: ErrorDetail,
}

/// What went wrong.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorDetail {
    /// A stable code: `not_found`, `invalid`, `conflict`,
    /// `revision_mismatch`, `unauthorized`, `forbidden`, `bad_request`,
    /// `unavailable` or `internal`.
    pub code: String,
    /// For people.
    pub message: String,
}

/// An error, as an HTTP status and a JSON body.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    /// 400: the request is malformed.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// 401: no valid admin token.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "send the admin token as `Authorization: Bearer <token>`",
        )
    }

    /// 403: not allowed from here.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// 404.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// 409: the change conflicts with the node's state.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// 413: the body is too large.
    pub fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "bad_request",
            "the request body is too large",
        )
    }

    /// 503: not possible right now, such as a configuration change on a
    /// replica that cannot reach the primary.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }

    /// 500, logged.
    pub fn internal(message: impl Into<String>) -> Self {
        let message = message.into();
        error!(%message, "API request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }

    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        let message = err.to_string();
        match err {
            StoreError::NotFound { .. } => Self::not_found(message),
            StoreError::Invalid(_) => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid", message)
            }
            StoreError::Conflict(_) => Self::new(StatusCode::CONFLICT, "conflict", message),
            StoreError::Revision { .. } => Self::new(
                StatusCode::PRECONDITION_FAILED,
                "revision_mismatch",
                message,
            ),
            StoreError::Locked(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
            }
            _ => Self::internal(message),
        }
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        let status = rejection.status();
        let code = if status == StatusCode::UNPROCESSABLE_ENTITY {
            "invalid"
        } else {
            "bad_request"
        };
        Self::new(status, code, rejection.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code.to_owned(),
                message: self.message,
            },
        };
        let mut response = (self.status, Json(body)).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"goethite\""),
            );
        }
        response
    }
}

/// A JSON request body. Unlike [`Json`], a body that does not parse (or has
/// unknown fields) is answered with an [`ApiError`] in JSON.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(request, state).await?;
        Ok(Self(value))
    }
}
