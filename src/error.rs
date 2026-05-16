use std::time::Duration;

pub type BoxedOsError = Box<dyn std::error::Error + Send + Sync>;

/// Error variants surfaced by all `uniwifi` operations.
///
/// `AdapterNotFound` and `NoStoredCredentials` carry the printable form
/// of the `AdapterId` / `Ssid` (via `Display`) rather than the typed
/// values, so this module has no dependency on `crate::types`. Backends
/// format the IDs at the construction site
/// (e.g., `Error::AdapterNotFound(adapter.id().to_string())`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no wifi adapter found")]
    NoAdapter,

    #[error("adapter {0} not found")]
    AdapterNotFound(String),

    #[error("ssid not in range or not visible")]
    SsidNotInRange,

    #[error("authentication failed (wrong password or unsupported security)")]
    AuthenticationFailed,

    #[error("no stored credentials for ssid {0}")]
    NoStoredCredentials(String),

    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    #[error("permission denied: {0}")]
    PermissionDenied(&'static str),

    #[error("operation cancelled by user")]
    UserCancelled,

    #[error("operation not supported on this platform: {0}")]
    Unsupported(&'static str),

    #[error("internal os error: {0}")]
    Os(#[source] BoxedOsError),
}
