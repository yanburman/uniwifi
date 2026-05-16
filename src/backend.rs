use async_trait::async_trait;

use crate::error::Error;
use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

/// Per-adapter description returned by `Backend::list_adapters`.
#[derive(Clone, Debug)]
pub struct AdapterInfo {
    pub id: AdapterId,
    pub name: String,
}

/// Internal backend contract. There is exactly one impl active per build
/// configuration; `UniWifi` holds a `Box<dyn Backend>`.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Enumerate Wi-Fi adapters visible to the host process.
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error>;

    /// Connect on the given adapter using explicit credentials.
    async fn connect(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        credentials: &Credentials,
        options: &ConnectOptions,
    ) -> Result<(), Error>;

    /// Connect using credentials already on the system (per-platform semantics).
    async fn connect_with_stored_credentials(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        options: &ConnectOptions,
    ) -> Result<(), Error>;

    /// Disconnect from the given SSID.
    async fn disconnect(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<(), Error>;

    /// Remove the SSID profile. Returns `true` if a profile was removed.
    async fn remove_profile(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<bool, Error>;

    async fn list_visible_networks(
        &self,
        adapter: &AdapterId,
        options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error>;
}
