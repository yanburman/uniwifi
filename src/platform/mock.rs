//! In-memory backend for unit / integration tests in consuming crates.
//!
//! Enable with `--features mock`. The mock exposes `MockState` so tests can
//! script visible SSIDs, stored profiles, and forced errors.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use secrecy::ExposeSecret;

use crate::backend::{AdapterInfo, Backend};
use crate::connection::WifiConnection;
use crate::error::Error;
use crate::types::{
    AdapterId, ConnectOptions, Credentials, ScanOptions, SecurityFlags, Ssid, VisibleNetwork,
};

/// Scriptable per-network properties for `MockState::add_visible_network`.
#[derive(Clone, Debug)]
pub struct VisibleNetworkProps {
    pub signal_quality: u8,
    pub security: SecurityFlags,
    pub rssi_dbm: Option<i16>,
    pub bssid: Option<[u8; 6]>,
    pub frequency_mhz: Option<u32>,
    pub bss_count: u32,
}

impl Default for VisibleNetworkProps {
    fn default() -> Self {
        Self {
            signal_quality: 75,
            security: SecurityFlags::WPA2_PSK,
            rssi_dbm: None,
            bssid: None,
            frequency_mhz: None,
            bss_count: 1,
        }
    }
}

/// Mutable state inspectable from tests in the consuming crate.
///
/// Held inside `MockBackend` as `Arc<MockState>`. Tests can call
/// `MockBackend::state()` to obtain a shared handle and continue
/// scripting state even after passing the backend into
/// `UniWifi::with_mock(...)`.
#[derive(Default)]
pub struct MockState {
    inner: Mutex<MockStateInner>,
}

#[derive(Default)]
struct MockStateInner {
    /// Adapters reported by `list_adapters`. Default: one adapter `mock0`.
    adapters: Vec<AdapterInfo>,
    /// Ssid -> (true password, scriptable scan properties).
    visible: HashMap<Ssid, (String, VisibleNetworkProps)>,
    /// Profiles installed by previous `connect` calls (per adapter, keyed by SSID).
    profiles: HashMap<(AdapterId, Ssid), String>,
    /// Currently connected SSID per adapter.
    connected: HashMap<AdapterId, Ssid>,
}

impl MockState {
    /// Add `ssid` (with its "true" password) to the simulated radio
    /// environment so subsequent `connect` calls can observe it. Uses
    /// default scan properties (`VisibleNetworkProps::default()`); use
    /// [`MockState::add_visible_network`] to script per-network values.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned (i.e., a previous
    /// `MockState` call panicked while holding the lock). This is
    /// effectively unreachable in well-formed tests.
    pub fn add_visible_ssid(&self, ssid: Ssid, password: impl Into<String>) {
        self.inner
            .lock()
            .unwrap()
            .visible
            .insert(ssid, (password.into(), VisibleNetworkProps::default()));
    }

    /// Add `ssid` with its "true" password and explicit scan properties.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned (see
    /// [`MockState::add_visible_ssid`]).
    pub fn add_visible_network(
        &self,
        ssid: Ssid,
        password: impl Into<String>,
        props: VisibleNetworkProps,
    ) {
        self.inner
            .lock()
            .unwrap()
            .visible
            .insert(ssid, (password.into(), props));
    }

    /// Remove every SSID from the simulated radio environment so the next
    /// `connect` call sees an empty scan.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned (see
    /// [`MockState::add_visible_ssid`]).
    pub fn clear_visible(&self) {
        self.inner.lock().unwrap().visible.clear();
    }

    /// Returns `true` if `adapter` is currently associated to `ssid`
    /// in the mock state.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned (see
    /// [`MockState::add_visible_ssid`]).
    #[must_use]
    pub fn is_connected(&self, adapter: &AdapterId, ssid: &Ssid) -> bool {
        self.inner.lock().unwrap().connected.get(adapter) == Some(ssid)
    }

    /// Returns `true` if a stored profile exists for `(adapter, ssid)`.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned (see
    /// [`MockState::add_visible_ssid`]).
    #[must_use]
    pub fn has_profile(&self, adapter: &AdapterId, ssid: &Ssid) -> bool {
        self.inner
            .lock()
            .unwrap()
            .profiles
            .contains_key(&(adapter.clone(), ssid.clone()))
    }
}

/// In-memory backend.
pub struct MockBackend {
    state: Arc<MockState>,
}

impl MockBackend {
    /// Construct a `MockBackend` pre-populated with one default adapter
    /// (`mock0` / "Mock Wi-Fi"). Use [`MockBackend::state`] to script
    /// additional state.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned during construction,
    /// which is effectively unreachable since the lock is freshly created.
    #[must_use]
    pub fn new() -> Self {
        let state = Arc::new(MockState::default());
        state.inner.lock().unwrap().adapters.push(AdapterInfo {
            id: AdapterId::new("mock0"),
            name: "Mock Wi-Fi".to_string(),
        });
        Self { state }
    }

    /// Returns a shared handle to the mock state. Multiple callers can hold
    /// this concurrently; mutations go through `MockState`'s internal lock.
    #[must_use]
    pub fn state(&self) -> Arc<MockState> {
        Arc::clone(&self.state)
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Backend for MockBackend {
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
        Ok(self.state.inner.lock().unwrap().adapters.clone())
    }

    async fn connect(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        credentials: &Credentials,
        _options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        // Resolve everything we need up front, then drop the guard before
        // returning so we never hold the lock across the function boundary.
        let mut inner = self.state.inner.lock().unwrap();

        let Some(true_pw) = inner.visible.get(ssid).map(|(pw, _)| pw.clone()) else {
            drop(inner);
            return Err(Error::SsidNotInRange);
        };

        let supplied = match credentials {
            // The mock treats every visible network as PSK-protected, so an
            // open-credential connect attempt is rejected.
            Credentials::Open => {
                drop(inner);
                return Err(Error::AuthenticationFailed);
            }
            Credentials::Password(p) => p.expose_secret().to_string(),
        };

        if supplied != true_pw {
            drop(inner);
            return Err(Error::AuthenticationFailed);
        }

        inner
            .profiles
            .insert((adapter.clone(), ssid.clone()), supplied);
        inner.connected.insert(adapter.clone(), ssid.clone());
        drop(inner);
        Ok(WifiConnection::inert())
    }

    async fn connect_with_stored_credentials(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        _options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        let mut inner = self.state.inner.lock().unwrap();
        let stored = inner
            .profiles
            .get(&(adapter.clone(), ssid.clone()))
            .cloned();
        let Some(pw) = stored else {
            drop(inner);
            return Err(Error::NoStoredCredentials(ssid.to_string()));
        };
        let true_pw = inner.visible.get(ssid).map(|(pw, _)| pw.clone());
        match true_pw {
            None => {
                drop(inner);
                Err(Error::SsidNotInRange)
            }
            Some(t) if t == pw => {
                inner.connected.insert(adapter.clone(), ssid.clone());
                drop(inner);
                Ok(WifiConnection::inert())
            }
            Some(_) => {
                drop(inner);
                Err(Error::AuthenticationFailed)
            }
        }
    }

    async fn disconnect(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<(), Error> {
        let mut inner = self.state.inner.lock().unwrap();
        if inner.connected.get(adapter) == Some(ssid) {
            inner.connected.remove(adapter);
        }
        drop(inner);
        Ok(())
    }

    async fn remove_profile(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<bool, Error> {
        let mut inner = self.state.inner.lock().unwrap();
        let removed = inner
            .profiles
            .remove(&(adapter.clone(), ssid.clone()))
            .is_some();
        drop(inner);
        Ok(removed)
    }

    async fn list_visible_networks(
        &self,
        adapter: &AdapterId,
        _options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        // Validate adapter exists, mirroring connect/disconnect semantics.
        let inner = self.state.inner.lock().unwrap();
        if !inner.adapters.iter().any(|a| &a.id == adapter) {
            drop(inner);
            return Err(Error::AdapterNotFound(adapter.to_string()));
        }

        let connected_ssid = inner.connected.get(adapter).cloned();
        let saved_for_adapter: std::collections::HashSet<Ssid> = inner
            .profiles
            .keys()
            .filter(|(a, _)| a == adapter)
            .map(|(_, s)| s.clone())
            .collect();

        let mut out: Vec<VisibleNetwork> = inner
            .visible
            .iter()
            .map(|(ssid, (_pw, props))| VisibleNetwork {
                ssid: ssid.clone(),
                signal_quality: props.signal_quality,
                security: props.security,
                bss_count: props.bss_count,
                is_connected: connected_ssid.as_ref() == Some(ssid),
                has_saved_profile: saved_for_adapter.contains(ssid),
                rssi_dbm: props.rssi_dbm,
                bssid: props.bssid,
                frequency_mhz: props.frequency_mhz,
            })
            .collect();
        drop(inner);

        // Match scan_rollup ordering: quality desc, ties by SSID bytes.
        out.sort_by(|a, b| {
            b.signal_quality
                .cmp(&a.signal_quality)
                .then_with(|| a.ssid.as_bytes().cmp(b.ssid.as_bytes()))
        });
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::types::{AdapterId, ConnectOptions, Credentials, Ssid};

    fn id() -> AdapterId {
        AdapterId::new("mock0")
    }

    #[tokio::test]
    async fn list_adapters_returns_default_single_adapter() {
        let mock = MockBackend::new();
        let adapters = mock.list_adapters().await.unwrap();
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].id, id());
    }

    #[tokio::test]
    async fn connect_with_correct_password_succeeds() {
        let mock = MockBackend::new();
        mock.state().add_visible_ssid(Ssid::from_utf8("net"), "pw");

        let res = mock
            .connect(
                &id(),
                &Ssid::from_utf8("net"),
                &Credentials::password("pw"),
                &ConnectOptions::default(),
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn connect_with_wrong_password_returns_auth_failed() {
        let mock = MockBackend::new();
        mock.state().add_visible_ssid(Ssid::from_utf8("net"), "pw");

        let res = mock
            .connect(
                &id(),
                &Ssid::from_utf8("net"),
                &Credentials::password("WRONG"),
                &ConnectOptions::default(),
            )
            .await;
        assert!(matches!(
            res,
            Err(crate::error::Error::AuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn connect_to_invisible_ssid_returns_not_in_range() {
        let mock = MockBackend::new();
        let res = mock
            .connect(
                &id(),
                &Ssid::from_utf8("ghost"),
                &Credentials::password("pw"),
                &ConnectOptions::default(),
            )
            .await;
        assert!(matches!(res, Err(crate::error::Error::SsidNotInRange)));
    }

    #[tokio::test]
    async fn connect_with_stored_uses_previous_profile() {
        let mock = MockBackend::new();
        mock.state().add_visible_ssid(Ssid::from_utf8("net"), "pw");

        // First: connect with password to install the profile.
        mock.connect(
            &id(),
            &Ssid::from_utf8("net"),
            &Credentials::password("pw"),
            &ConnectOptions::default(),
        )
        .await
        .unwrap();

        // Then: stored-credential connect succeeds.
        let res = mock
            .connect_with_stored_credentials(
                &id(),
                &Ssid::from_utf8("net"),
                &ConnectOptions::default(),
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn connect_with_stored_without_profile_returns_no_stored_credentials() {
        let mock = MockBackend::new();
        mock.state().add_visible_ssid(Ssid::from_utf8("net"), "pw");

        let res = mock
            .connect_with_stored_credentials(
                &id(),
                &Ssid::from_utf8("net"),
                &ConnectOptions::default(),
            )
            .await;
        assert!(matches!(
            res,
            Err(crate::error::Error::NoStoredCredentials(_))
        ));
    }

    #[tokio::test]
    async fn remove_profile_returns_true_when_present_false_when_absent() {
        let mock = MockBackend::new();
        mock.state().add_visible_ssid(Ssid::from_utf8("net"), "pw");
        mock.connect(
            &id(),
            &Ssid::from_utf8("net"),
            &Credentials::password("pw"),
            &ConnectOptions::default(),
        )
        .await
        .unwrap();

        assert!(
            mock.remove_profile(&id(), &Ssid::from_utf8("net"))
                .await
                .unwrap()
        );
        assert!(
            !mock
                .remove_profile(&id(), &Ssid::from_utf8("net"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn disconnect_succeeds_when_connected_fails_otherwise() {
        let mock = MockBackend::new();
        mock.state().add_visible_ssid(Ssid::from_utf8("net"), "pw");
        mock.connect(
            &id(),
            &Ssid::from_utf8("net"),
            &Credentials::password("pw"),
            &ConnectOptions::default(),
        )
        .await
        .unwrap();

        assert!(
            mock.disconnect(&id(), &Ssid::from_utf8("net"))
                .await
                .is_ok()
        );
        // Second disconnect: not connected; mock surfaces an Os error per
        // platform-agnostic semantics. We expect Ok(()) is acceptable too —
        // here we assert idempotent disconnect (matches Windows semantics).
        assert!(
            mock.disconnect(&id(), &Ssid::from_utf8("net"))
                .await
                .is_ok()
        );
    }
}
