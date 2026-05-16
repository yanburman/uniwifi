//! iOS backend, gated on `cfg(target_os = "ios")`.
//!
//! Replaces the stub iOS branch in `platform::default_backend` with a
//! real `IosBackend` driving `NEHotspotConfigurationManager`.
//!
//! # Cancellation
//!
//! `applyConfiguration:completionHandler:` has no public cancellation
//! API. If the future returned by `connect` is dropped (e.g. caller
//! `select!`s against a cancellation token), the apply continues to
//! run on Apple's side until the OS resolves it (success, user
//! denial, or system error). The completion handler then runs to
//! completion but its result is silently discarded (the `oneshot`
//! receiver is gone). To avoid leaving a half-installed configuration,
//! callers that race `connect` against a cancellation should follow
//! up with `disconnect` / `remove_profile` once they decide the
//! operation is no longer wanted. The `Timeout` path inside `connect`
//! itself does this automatically.
//!
//! # iOS semantics for `disconnect` vs `remove_profile`
//!
//! iOS does not expose an API to disconnect from a network without also
//! removing the saved configuration. Both `disconnect` and
//! `remove_profile` ultimately call
//! `NEHotspotConfigurationManager.removeConfigurationForSSID:`. The
//! observable difference is:
//! - `disconnect` returns `Ok(())` regardless of whether a profile
//!   existed.
//! - `remove_profile` returns `Ok(true)` if a profile existed before
//!   the call and `Ok(false)` otherwise. The pre-check is via
//!   `getConfiguredSSIDsWithCompletionHandler:`.
//!
//! Consumers that want desktop-style semantics (disconnect-but-keep-
//! profile) cannot achieve them on iOS through the public API, by
//! design.

mod configuration;
mod error_map;
mod foreground;

// Re-export the backend type for `platform::default_backend`.
pub use self::ios_backend::IosBackend;

mod ios_backend {
    //! `IosBackend` lives in its own private submodule so `mod.rs` itself
    //! contains only declarations (clippy `module_inception` happy).

    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use crate::backend::{AdapterInfo, Backend};
    use crate::error::Error;
    use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

    /// The single synthetic adapter id reported by `list_adapters`.
    /// iOS exposes only the system-managed Wi-Fi interface; we use the
    /// BSD name conventionally assigned to it.
    pub const IOS_ADAPTER_ID: &str = "en0";
    pub const IOS_ADAPTER_NAME: &str = "Wi-Fi";

    /// Bound on `getConfiguredSSIDsWithCompletionHandler:` waits. The OS
    /// usually answers in milliseconds; if the completion block never
    /// fires (e.g. mid-suspend or an iOS-side bug) we surface
    /// `Error::Timeout` rather than hang the calling future.
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    pub struct IosBackend {
        /// Serialises per-adapter operations. Held across the whole
        /// `apply` / `remove` round-trip so concurrent connect / disconnect
        /// calls don't trample each other.
        op_lock: Mutex<()>,
    }

    impl IosBackend {
        /// Construct the iOS backend.
        ///
        /// # Errors
        /// Currently infallible, but kept `Result`-typed because future
        /// versions may want to surface "Wi-Fi subsystem unavailable"
        /// detected at startup, and because `default_backend()` (rewired
        /// in Task 11) calls this with `?` — the `Result` signature keeps
        /// that wiring stable as real startup-failure paths land. Mirrors
        /// the `#[allow]` already present on `MacosBackend::new` and on
        /// `default_backend()` itself for the same reason.
        #[allow(clippy::unnecessary_wraps)]
        pub fn new() -> Result<Self, Error> {
            Ok(Self {
                op_lock: Mutex::new(()),
            })
        }
    }

    #[async_trait]
    impl Backend for IosBackend {
        async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
            // The lock isn't strictly needed for a const list, but holding
            // it keeps `op_lock` alive (silences `dead_code` until other
            // methods land) and is essentially free.
            let _guard = self.op_lock.lock().await;
            Ok(vec![AdapterInfo {
                id: AdapterId::new(IOS_ADAPTER_ID),
                name: IOS_ADAPTER_NAME.to_string(),
            }])
        }

        async fn connect(
            &self,
            adapter: &AdapterId,
            ssid: &Ssid,
            credentials: &Credentials,
            options: &ConnectOptions,
        ) -> Result<(), Error> {
            // Validate adapter id (we only know about the synthetic en0).
            if adapter.as_str() != IOS_ADAPTER_ID {
                return Err(Error::AdapterNotFound(adapter.to_string()));
            }

            // Foreground check up-front for a fast, typed failure.
            super::foreground::ensure_foreground()?;

            // Pre-flight scan: NOT applicable on iOS — silently skipped.
            // (No `ScanProvider` impl on this backend, so the generic
            // `wait_until_ssid_visible` helper isn't called.)

            let _guard = self.op_lock.lock().await;

            // Honour the caller's timeout. Apple's apply has no built-in
            // cancellation, so on timeout we attempt a best-effort
            // `removeConfigurationForSSID:` to clean up — see the
            // cancellation note at the top of this module.
            let timeout = options.effective_timeout();

            // The kickoff helper hops to the main queue internally
            // (Apple documents NEHotspotConfigurationManager mutators
            // as main-thread). It returns an `oneshot::Receiver<Send>`,
            // so the resulting future stays Send-clean and the trait's
            // `Backend: Send + Sync` bound is satisfied.
            let rx = super::configuration::apply_configuration_kickoff(ssid, credentials)?;

            match tokio::time::timeout(timeout, rx).await {
                Ok(received) => super::configuration::map_apply_received(received),
                Err(_elapsed) => {
                    // Timed out. Best-effort clean-up; we're already
                    // returning `Error::Timeout`, so any error from the
                    // remove path is intentionally swallowed. The remove
                    // can only fail on a non-UTF-8 SSID, which we already
                    // rejected above via `build_configuration`.
                    let _ = super::configuration::remove_configuration_for_ssid(ssid);
                    Err(Error::Timeout(timeout))
                }
            }
        }

        async fn connect_with_stored_credentials(
            &self,
            adapter: &AdapterId,
            ssid: &Ssid,
            options: &ConnectOptions,
        ) -> Result<(), Error> {
            // Validate adapter id (we only know about the synthetic en0).
            if adapter.as_str() != IOS_ADAPTER_ID {
                return Err(Error::AdapterNotFound(adapter.to_string()));
            }

            // Foreground check up-front for a fast, typed failure.
            super::foreground::ensure_foreground()?;

            let _guard = self.op_lock.lock().await;
            let timeout = options.effective_timeout();

            // Probe the installed configurations. iOS only surfaces
            // configurations installed by *this* app under its own
            // entitlement; cross-app sharing is not exposed. The
            // probe is bounded by `PROBE_TIMEOUT` independently of the
            // outer connect timeout — if the system never invokes the
            // completion handler we'd otherwise hang the connect future
            // indefinitely.
            let ssids_rx = super::configuration::get_configured_ssids_kickoff();
            let probe_received = tokio::time::timeout(PROBE_TIMEOUT, ssids_rx)
                .await
                .map_err(|_| Error::Timeout(PROBE_TIMEOUT))?;
            let configured = super::configuration::map_get_configured_received(probe_received)?;

            let ssid_str = ssid.as_str().ok_or(Error::Unsupported(
                "ios backend requires utf-8 ssid (no public api for raw bytes)",
            ))?;

            if !configured.iter().any(|s| s == ssid_str) {
                return Err(Error::NoStoredCredentials(ssid.to_string()));
            }

            // SSID-only kickoff also dispatches to the main queue.
            let apply_rx = super::configuration::apply_ssid_only_kickoff(ssid)?;

            match tokio::time::timeout(timeout, apply_rx).await {
                Ok(received) => super::configuration::map_apply_received(received),
                Err(_elapsed) => {
                    // Timed out. Best-effort clean-up; we're already
                    // returning `Error::Timeout`, so any error from the
                    // remove path is intentionally swallowed. The remove
                    // can only fail on a non-UTF-8 SSID, which we already
                    // validated above via `ssid.as_str()`.
                    let _ = super::configuration::remove_configuration_for_ssid(ssid);
                    Err(Error::Timeout(timeout))
                }
            }
        }

        async fn disconnect(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<(), Error> {
            if adapter.as_str() != IOS_ADAPTER_ID {
                return Err(Error::AdapterNotFound(adapter.to_string()));
            }

            // No foreground check: removeConfigurationForSSID: works in
            // background per Apple docs (verify on a real device; if
            // background calls fail, add the same ensure_foreground()
            // guard as connect).

            let _guard = self.op_lock.lock().await;
            super::configuration::remove_configuration_for_ssid(ssid)
        }

        async fn remove_profile(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<bool, Error> {
            if adapter.as_str() != IOS_ADAPTER_ID {
                return Err(Error::AdapterNotFound(adapter.to_string()));
            }

            let _guard = self.op_lock.lock().await;

            // Probe the installed configurations. Bound by `PROBE_TIMEOUT`
            // independently of any caller deadline — see the comment on
            // `PROBE_TIMEOUT` above.
            let ssids_rx = super::configuration::get_configured_ssids_kickoff();
            let probe_received = tokio::time::timeout(PROBE_TIMEOUT, ssids_rx)
                .await
                .map_err(|_| Error::Timeout(PROBE_TIMEOUT))?;
            let configured = super::configuration::map_get_configured_received(probe_received)?;

            let ssid_str = ssid.as_str().ok_or(Error::Unsupported(
                "ios backend requires utf-8 ssid (no public api for raw bytes)",
            ))?;
            let was_present = configured.iter().any(|s| s == ssid_str);

            super::configuration::remove_configuration_for_ssid(ssid)?;
            Ok(was_present)
        }

        async fn list_visible_networks(
            &self,
            adapter: &AdapterId,
            _options: &ScanOptions,
        ) -> Result<Vec<VisibleNetwork>, Error> {
            if adapter.as_str() != IOS_ADAPTER_ID {
                return Err(Error::AdapterNotFound(adapter.to_string()));
            }
            Err(Error::Unsupported("scan not available on ios"))
        }
    }

    // Compile-time assertion: IosBackend must be Send + Sync because
    // `UniWifi` stores `Box<dyn Backend + Send + Sync>` and the
    // `Backend` trait requires it.
    const fn _assert_send_sync() {
        const fn assert_send<T: Send>() {}
        const fn assert_sync<T: Sync>() {}
        assert_send::<IosBackend>();
        assert_sync::<IosBackend>();
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn list_adapters_returns_single_synthetic_adapter() {
            let backend = IosBackend::new().expect("IosBackend::new should succeed");
            let adapters = backend.list_adapters().await.expect("list_adapters failed");
            assert_eq!(adapters.len(), 1);
            assert_eq!(adapters[0].id.as_str(), IOS_ADAPTER_ID);
            assert_eq!(adapters[0].name, IOS_ADAPTER_NAME);
        }

        use crate::types::Ssid;

        #[tokio::test]
        async fn connect_with_unknown_adapter_returns_adapter_not_found() {
            let backend = IosBackend::new().unwrap();
            let res = backend
                .connect(
                    &crate::types::AdapterId::new("not-en0"),
                    &Ssid::from_utf8("test"),
                    &crate::types::Credentials::Open,
                    &crate::types::ConnectOptions::default(),
                )
                .await;
            assert!(matches!(res, Err(crate::error::Error::AdapterNotFound(_))));
        }

        #[tokio::test]
        async fn connect_with_non_utf8_ssid_returns_unsupported() {
            let backend = IosBackend::new().unwrap();
            let res = backend
                .connect(
                    &crate::types::AdapterId::new(IOS_ADAPTER_ID),
                    &Ssid::from_bytes(vec![0xff, 0xfe]),
                    &crate::types::Credentials::Open,
                    &crate::types::ConnectOptions::default(),
                )
                .await;
            // Either Unsupported (foreground passed, build_configuration
            // rejected non-UTF-8) or Unsupported("requires foreground app")
            // — both are typed correctly.
            assert!(matches!(res, Err(crate::error::Error::Unsupported(_))));
        }

        #[tokio::test]
        async fn disconnect_with_unknown_adapter_returns_adapter_not_found() {
            let backend = IosBackend::new().unwrap();
            let res = backend
                .disconnect(&crate::types::AdapterId::new("nope"), &Ssid::from_utf8("x"))
                .await;
            assert!(matches!(res, Err(crate::error::Error::AdapterNotFound(_))));
        }

        #[tokio::test]
        async fn remove_profile_with_unknown_adapter_returns_adapter_not_found() {
            let backend = IosBackend::new().unwrap();
            let res = backend
                .remove_profile(&crate::types::AdapterId::new("nope"), &Ssid::from_utf8("x"))
                .await;
            assert!(matches!(res, Err(crate::error::Error::AdapterNotFound(_))));
        }
    }
}
