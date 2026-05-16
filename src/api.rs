use std::sync::Arc;

use crate::backend::{AdapterInfo, Backend};
use crate::error::Error;
use crate::platform;
use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

/// Top-level entry point. Holds the active platform backend.
///
/// `Backend` is intentionally private to this crate, so the only ways to
/// construct a `UniWifi` are [`UniWifi::new`] (platform default) and,
/// under the `mock` feature, `UniWifi::with_mock`.
pub struct UniWifi {
    backend: Arc<dyn Backend + Send + Sync>,
}

impl UniWifi {
    /// Construct using the platform-default backend.
    ///
    /// The fallible signature lets backends surface OS-handle startup
    /// failures (e.g. opening the WLAN client on Windows) as
    /// [`Error::Os`] / [`Error::PermissionDenied`]. On unsupported
    /// `target_os` values, returns [`Error::Unsupported`].
    ///
    /// # Errors
    ///
    /// Returns an error if the platform-default backend fails to
    /// initialize.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            backend: Arc::from(platform::default_backend()?),
        })
    }

    /// Construct from an in-memory mock for tests.
    #[cfg(feature = "mock")]
    #[must_use]
    pub fn with_mock(mock: crate::platform::mock::MockBackend) -> Self {
        Self {
            backend: Arc::new(mock),
        }
    }

    /// Enumerate Wi-Fi adapters. Each entry is a [`WifiAdapter`] handle
    /// you can call `connect`, `disconnect`, etc. on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Os`] if the underlying OS enumeration call fails.
    /// On platforms with no Wi-Fi hardware the call typically returns
    /// `Ok(vec![])` rather than an error; consult the per-backend docs.
    pub async fn list_adapters(&self) -> Result<Vec<WifiAdapter>, Error> {
        let infos = self.backend.list_adapters().await?;
        Ok(infos
            .into_iter()
            .map(|info| WifiAdapter {
                info,
                backend: Arc::clone(&self.backend),
            })
            .collect())
    }
}

/// Handle for a single Wi-Fi adapter.
pub struct WifiAdapter {
    info: AdapterInfo,
    backend: Arc<dyn Backend + Send + Sync>,
}

impl WifiAdapter {
    /// The opaque, platform-stable identifier for this adapter.
    #[must_use]
    pub const fn id(&self) -> &AdapterId {
        &self.info.id
    }

    /// The human-readable name reported by the OS for this adapter
    /// (e.g. `"Intel(R) Wi-Fi 6 AX201"` on Windows, `"en0"` on macOS).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// Connect to `ssid` using the given `credentials`.
    ///
    /// # Errors
    ///
    /// - [`Error::SsidNotInRange`] if the SSID is not visible in the
    ///   current scan results (when the backend supports a pre-flight scan).
    /// - [`Error::AuthenticationFailed`] if the supplied password is
    ///   rejected by the access point or the security mode is unsupported.
    /// - [`Error::Timeout`] if the operation does not complete within
    ///   [`ConnectOptions::effective_timeout`].
    /// - [`Error::PermissionDenied`] if the host process lacks the
    ///   capability to manage the radio (e.g., missing `Location` permission
    ///   on Windows / Android, or the macOS sandbox entitlement).
    /// - [`Error::AdapterNotFound`] if `self` refers to an adapter that has
    ///   since been removed (USB unplug, hibernation, etc.).
    /// - [`Error::Os`] for any other OS-surfaced failure.
    pub async fn connect(
        &self,
        ssid: &Ssid,
        credentials: Credentials,
        options: ConnectOptions,
    ) -> Result<(), Error> {
        self.backend
            .connect(&self.info.id, ssid, &credentials, &options)
            .await
    }

    /// Connect to `ssid` using credentials already stored on the system
    /// from a previous successful `connect` call (or installed out-of-band
    /// via the OS UI).
    ///
    /// # Errors
    ///
    /// - [`Error::NoStoredCredentials`] if the system has no stored profile
    ///   for `ssid` on this adapter.
    /// - [`Error::SsidNotInRange`], [`Error::AuthenticationFailed`],
    ///   [`Error::Timeout`], [`Error::PermissionDenied`],
    ///   [`Error::AdapterNotFound`], or [`Error::Os`] under the same
    ///   conditions documented on [`WifiAdapter::connect`].
    pub async fn connect_with_stored_credentials(
        &self,
        ssid: &Ssid,
        options: ConnectOptions,
    ) -> Result<(), Error> {
        self.backend
            .connect_with_stored_credentials(&self.info.id, ssid, &options)
            .await
    }

    /// Disconnect from `ssid` on this adapter.
    ///
    /// Disconnect is idempotent on backends with desktop semantics: calling
    /// it when not connected to `ssid` is treated as a no-op success.
    ///
    /// # Errors
    ///
    /// - [`Error::AdapterNotFound`] if the adapter has been removed.
    /// - [`Error::PermissionDenied`] if the host process lacks the
    ///   capability to manage the radio.
    /// - [`Error::Os`] for any other OS-surfaced failure.
    pub async fn disconnect(&self, ssid: &Ssid) -> Result<(), Error> {
        self.backend.disconnect(&self.info.id, ssid).await
    }

    /// Remove the stored profile for `ssid` on this adapter.
    ///
    /// Returns `Ok(true)` if a profile was removed, `Ok(false)` if no
    /// matching profile existed.
    ///
    /// # Errors
    ///
    /// - [`Error::AdapterNotFound`] if the adapter has been removed.
    /// - [`Error::PermissionDenied`] if the host process lacks the
    ///   capability to manage stored network profiles.
    /// - [`Error::Os`] for any other OS-surfaced failure.
    pub async fn remove_profile(&self, ssid: &Ssid) -> Result<bool, Error> {
        self.backend.remove_profile(&self.info.id, ssid).await
    }

    /// List Wi-Fi networks currently visible to this adapter, rolled up
    /// per SSID.
    ///
    /// The returned vector is sorted by [`VisibleNetwork::signal_quality`]
    /// descending; ties are broken by SSID byte order, so the ordering is
    /// deterministic across runs. Networks with empty SSIDs (hidden APs that
    /// beacon without one) are filtered out entirely — every entry has a
    /// non-empty `ssid`.
    ///
    /// # Errors
    ///
    /// - [`Error::AdapterNotFound`] if the adapter has been removed.
    /// - [`Error::PermissionDenied`] on Android when neither
    ///   `ACCESS_FINE_LOCATION` nor `NEARBY_WIFI_DEVICES` is granted.
    /// - [`Error::Unsupported`] on iOS (no public scan API).
    /// - [`Error::Os`] for any other OS-surfaced failure.
    pub async fn list_visible_networks(
        &self,
        options: ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        self.backend
            .list_visible_networks(&self.info.id, &options)
            .await
    }
}

#[cfg(test)]
#[cfg(feature = "mock")]
mod tests {
    use super::*;
    use crate::platform::mock::MockBackend;
    use crate::types::{ConnectOptions, Credentials, Ssid};

    #[tokio::test]
    async fn list_adapters_yields_one_mock_adapter() {
        let mock = MockBackend::new();
        let hal = UniWifi::with_mock(mock);
        let adapters = hal.list_adapters().await.unwrap();
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].name(), "Mock Wi-Fi");
    }

    #[tokio::test]
    async fn full_connect_disconnect_cycle() {
        let mock = MockBackend::new();
        mock.state()
            .add_visible_ssid(Ssid::from_utf8("home"), "letmein");
        let hal = UniWifi::with_mock(mock);

        let adapters = hal.list_adapters().await.unwrap();
        let adapter = &adapters[0];

        adapter
            .connect(
                &Ssid::from_utf8("home"),
                Credentials::password("letmein"),
                ConnectOptions::default(),
            )
            .await
            .unwrap();

        adapter.disconnect(&Ssid::from_utf8("home")).await.unwrap();

        // Profile remains until removed explicitly (desktop semantics).
        // Public-API verification: first `remove_profile` returns `true`,
        // second returns `false`.
        let removed = adapter
            .remove_profile(&Ssid::from_utf8("home"))
            .await
            .unwrap();
        assert!(removed);

        let removed_again = adapter
            .remove_profile(&Ssid::from_utf8("home"))
            .await
            .unwrap();
        assert!(!removed_again);
    }
}
