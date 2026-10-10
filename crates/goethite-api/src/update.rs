//! Checking the project's releases for a newer goethite.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The newest published release, next to the version this node runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateCheck {
    /// The version this node runs.
    pub current: String,
    /// The newest release's version, without the tag's `v`.
    pub latest: String,
    /// The release's page.
    pub url: String,
    /// When it was published, if the release says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<Timestamp>,
    /// Whether `latest` is newer than `current`.
    pub newer: bool,
}
