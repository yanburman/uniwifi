//! Windows backend for `uniwifi` — Native Wifi (WLAN) API via the
//! `windows` crate.

#![allow(clippy::module_name_repetitions)] // WindowsBackend is intentional.

mod adapters;
mod connect;
mod disconnect;
mod handle;
mod notifications;
mod profile;
mod profile_xml;
mod reason;
mod scan;
mod security;
mod util;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use windows::core::GUID;

use handle::WlanClient;
use notifications::Dispatcher;

use crate::backend::{AdapterInfo, Backend};
use crate::connection::WifiConnection;
use crate::error::Error;
use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

/// Real Windows backend. Constructed once per `UniWifi` and shared via `Arc`.
///
/// **Field ordering matters.** Rust drops struct fields in declaration
/// order. We declare `client` BEFORE `dispatcher` so that on `Drop`:
///
/// 1. The Drop impl unregisters notifications and reclaims the leaked
///    Arc strong count for `dispatcher`.
/// 2. Field-drop runs `client`'s drop FIRST — `WlanCloseHandle` acts
///    as the implicit drain point for any in-flight WLAN-service
///    callback that was on the wire when `WlanRegisterNotification`
///    returned.
/// 3. Field-drop then runs `dispatcher`'s drop — the Arc count goes
///    to 0 and the Dispatcher is freed only after the WLAN service has
///    stopped invoking the callback thunk.
///
/// Reordering these fields would create a window where a still-running
/// callback could deref freed dispatcher memory.
pub struct WindowsBackend {
    client: Arc<WlanClient>,
    dispatcher: Arc<Dispatcher>,
    /// Per-adapter serializing locks. `connect`/`disconnect` acquire the
    /// lock for their adapter for the duration of the operation.
    adapter_locks: Mutex<HashMap<GUID, Arc<tokio::sync::Mutex<()>>>>,
}

impl WindowsBackend {
    /// Open a WLAN client handle and register the notification callback.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os(_)` if either `WlanOpenHandle` or
    /// `WlanRegisterNotification` fails.
    pub fn new() -> Result<Self, Error> {
        let client = Arc::new(WlanClient::new()?);
        let dispatcher = Arc::new(Dispatcher::new());
        dispatcher.register(&client)?;
        Ok(Self {
            client,
            dispatcher,
            adapter_locks: Mutex::new(HashMap::new()),
        })
    }

    fn adapter_lock(&self, guid: GUID) -> Arc<tokio::sync::Mutex<()>> {
        let mut g = self.adapter_locks.lock().expect("adapter_locks poisoned");
        Arc::clone(
            g.entry(guid)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }
}

#[async_trait]
impl Backend for WindowsBackend {
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
        let client = Arc::clone(&self.client);
        // WLAN APIs are synchronous; offload to spawn_blocking so we don't
        // park the async runtime.
        tokio::task::spawn_blocking(move || adapters::list_adapters(&client))
            .await
            .map_err(|e| {
                Error::Os(Box::new(std::io::Error::other(format!(
                    "spawn_blocking join: {e}"
                ))))
            })?
    }

    async fn connect(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        credentials: &Credentials,
        options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        let interface = util::adapter_id_to_guid(adapter)?;
        let lock = self.adapter_lock(interface);
        let _g = lock.lock().await;

        let deadline = options.effective_timeout();

        let scanner = scan::WindowsScanner::new(
            Arc::clone(&self.client),
            Arc::clone(&self.dispatcher),
            interface,
        );
        let preflight_outcome = crate::preflight::wait_until_ssid_visible(
            &scanner,
            ssid,
            deadline.min(Duration::from_secs(5)),
        )
        .await;
        if matches!(preflight_outcome, crate::preflight::ScanOutcome::NotVisible) {
            return Err(Error::SsidNotInRange);
        }

        connect::run_connect(
            Arc::clone(&self.client),
            Arc::clone(&self.dispatcher),
            interface,
            ssid,
            credentials,
            deadline,
        )
        .await
        .map(|()| WifiConnection::inert())
    }

    async fn connect_with_stored_credentials(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        let interface = util::adapter_id_to_guid(adapter)?;
        let lock = self.adapter_lock(interface);
        let _g = lock.lock().await;
        connect::run_connect_stored(
            Arc::clone(&self.client),
            Arc::clone(&self.dispatcher),
            interface,
            ssid,
            options.effective_timeout(),
        )
        .await
        .map(|()| WifiConnection::inert())
    }

    async fn disconnect(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<(), Error> {
        let interface = util::adapter_id_to_guid(adapter)?;
        let lock = self.adapter_lock(interface);
        let _g = lock.lock().await;
        disconnect::run_disconnect(Arc::clone(&self.client), interface, ssid.clone()).await
    }

    async fn remove_profile(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<bool, Error> {
        let interface = util::adapter_id_to_guid(adapter)?;
        let lock = self.adapter_lock(interface);
        let _g = lock.lock().await;
        let name = String::from_utf8_lossy(ssid.as_bytes()).into_owned();
        profile::run_remove_profile(Arc::clone(&self.client), interface, &name).await
    }

    // Per-adapter lock is held across the WlanScan wait (~5s with
    // force_rescan: true) and the subsequent context query. This
    // intentionally serializes against connect / disconnect / remove_profile
    // on the same adapter to avoid WlanScan racing against WlanConnect, at
    // the cost of a brief stall when a connect/disconnect is issued during
    // a force-rescan window. Pre-existing crate-wide pattern; documented
    // here for the public API surface.
    async fn list_visible_networks(
        &self,
        adapter: &AdapterId,
        options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        // Validate adapter exists and serialize per-adapter.
        let interface = util::adapter_id_to_guid(adapter)?;
        let lock = self.adapter_lock(interface);
        let _g = lock.lock().await;

        let bsses = self.fetch_bsses(adapter, options).await?;
        let ctx = self.fetch_scan_context(adapter).await?;
        Ok(crate::scan_rollup::rollup(bsses, &ctx))
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        // Unregister notifications first so no late callbacks reference
        // freed memory.
        let _ = Dispatcher::unregister(&self.client);

        // Reclaim the strong count we leaked into the callback context.
        // The pointer was created by `Arc::into_raw(Arc::clone(&self.dispatcher))`
        // in `Dispatcher::register`. Reconstructing it here drops the leak.
        //
        // SAFETY: only this Drop impl reclaims the leaked count, and it
        // runs at most once per `WindowsBackend`. The dispatcher's strong
        // count therefore goes from N+1 (with leak) to N at this point.
        unsafe {
            let raw: *const Dispatcher = Arc::as_ptr(&self.dispatcher);
            let _ = Arc::<Dispatcher>::from_raw(raw);
        }
    }
}
