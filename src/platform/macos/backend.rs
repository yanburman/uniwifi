//! `MacosBackend`: implements the crate-internal `Backend` trait against
//! `CoreWLAN`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::backend::{AdapterInfo, Backend};
use crate::error::Error;
use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

use super::client::SharedClient;

/// macOS Wi-Fi backend.
pub struct MacosBackend {
    pub(super) client: SharedClient,
    /// One mutex per adapter id, lazily created. Held for the duration of
    /// any operation that mutates the radio (connect / disconnect).
    pub(super) op_locks: Mutex<HashMap<AdapterId, Arc<tokio::sync::Mutex<()>>>>,
}

impl MacosBackend {
    /// Construct the backend by acquiring the process-global `CWWiFiClient`.
    ///
    /// # Errors
    /// Currently infallible, but kept `Result`-typed because future versions
    /// may want to surface "Wi-Fi subsystem unavailable" detected at startup,
    /// and because `default_backend()` (rewired in Task 11) calls this with
    /// `?` — the `Result` signature keeps that wiring stable as real
    /// startup-failure paths land. Mirrors the `#[allow]` already present
    /// on `default_backend()` itself for the same reason.
    #[allow(clippy::unnecessary_wraps)]
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            client: SharedClient::new(),
            op_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Return (lazily creating if needed) the per-adapter operation mutex.
    ///
    /// # Panics
    /// Panics if the internal `op_locks` mutex is poisoned. We treat
    /// poisoning as a programmer bug because every call site holds the
    /// lock only long enough to do a hashmap lookup/insert and never
    /// panics inside that critical section. Mirrors the rationale on
    /// `SharedClient::with`.
    pub(super) fn op_lock_for(&self, adapter: &AdapterId) -> Arc<tokio::sync::Mutex<()>> {
        let mut guard = self.op_locks.lock().expect("op_locks mutex poisoned");
        if let Some(existing) = guard.get(adapter) {
            return Arc::clone(existing);
        }
        let new_lock = Arc::new(tokio::sync::Mutex::new(()));
        guard.insert(adapter.clone(), Arc::clone(&new_lock));
        new_lock
    }
}

#[async_trait]
impl Backend for MacosBackend {
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
        // CoreWLAN calls are synchronous and very fast (a few ms at worst).
        // We *could* offload to a worker thread, but the cost of an
        // unconditional spawn_blocking is higher than the call itself, so we
        // run inline. If a future profile shows a hot-path bottleneck we can
        // revisit.
        let infos = self.client.with(|client| {
            // SAFETY: `interfaces` is documented as returning either nil or
            // an NSArray of CWInterface; both branches are handled below.
            // The returned `Retained<NSArray<CWInterface>>` is owned by us.
            let array = unsafe { client.interfaces() };
            let Some(array) = array else {
                return Vec::new();
            };

            // We use `to_vec()` rather than `for iface in &array` because the
            // borrowed-NSArray iterator lives behind the `NSEnumerator` cargo
            // feature on `objc2-foundation`, which this crate does not
            // enable. `to_vec()` retains each element and returns
            // `Vec<Retained<CWInterface>>` which we then iterate by ref.
            let ifaces = array.to_vec();
            let mut out = Vec::with_capacity(ifaces.len());
            for iface in &ifaces {
                // SAFETY: `interfaceName` returns Option<Retained<NSString>>.
                let name = unsafe { iface.interfaceName() };
                let Some(name) = name else { continue };
                let bsd = name.to_string();
                let id = AdapterId::new(bsd.clone());
                out.push(AdapterInfo { id, name: bsd });
            }
            out
        });

        // Empty interfaces list -> Ok(vec![]) per the trait contract:
        // "On platforms with no Wi-Fi hardware the call typically returns
        // Ok(vec![]) rather than an error." Returning NoAdapter here was
        // inconsistent with Linux/Windows and forced callers to special-
        // case macOS for the no-Wi-Fi case.
        Ok(infos)
    }

    async fn connect(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        credentials: &Credentials,
        options: &ConnectOptions,
    ) -> Result<(), Error> {
        let lock = self.op_lock_for(adapter);
        let _guard = lock.lock().await;
        super::connect::connect(
            self.client.clone(),
            adapter.clone(),
            ssid.clone(),
            credentials,
            options,
        )
        .await
    }

    async fn connect_with_stored_credentials(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        options: &ConnectOptions,
    ) -> Result<(), Error> {
        let lock = self.op_lock_for(adapter);
        let _guard = lock.lock().await;
        super::connect::connect_with_stored(
            self.client.clone(),
            adapter.clone(),
            ssid.clone(),
            options,
        )
        .await
    }

    async fn disconnect(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<(), Error> {
        let lock = self.op_lock_for(adapter);
        let _guard = lock.lock().await;
        super::connect::disconnect(self.client.clone(), adapter.clone(), ssid.clone()).await
    }

    async fn remove_profile(&self, _adapter: &AdapterId, ssid: &Ssid) -> Result<bool, Error> {
        let ssid = ssid.clone();
        super::threading::run_blocking(move || super::keychain::delete_wifi_password(&ssid)).await
    }

    async fn list_visible_networks(
        &self,
        adapter: &AdapterId,
        options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        // Eager adapter check: avoids spawning a blocking worker just
        // to surface AdapterNotFound when the adapter id is bad. Both
        // fetch_bsses and fetch_scan_context would also resolve, so
        // this is purely a fast-fail optimization for the common
        // not-found path.
        let _ = self
            .client
            .with(|c| super::adapter::resolve_interface_by_id(c, adapter))?;
        let bsses = self.fetch_bsses(adapter, options).await?;
        let ctx = self.fetch_scan_context(adapter).await?;
        Ok(crate::scan_rollup::rollup(bsses, &ctx))
    }
}
