//! Cross-platform Wi-Fi hardware abstraction layer.

mod api;
mod backend;
mod error;
mod platform;
mod preflight;
mod scan_rollup;
mod types;

pub use api::{UniWifi, WifiAdapter};
pub use error::{BoxedOsError, Error};
pub use types::{
    AdapterId, Band, ConnectOptions, Credentials, ScanOptions, SecurityFlags, Ssid, SsidError,
    VisibleNetwork,
};

#[cfg(feature = "mock")]
pub use platform::mock::{MockBackend, MockState, VisibleNetworkProps};
