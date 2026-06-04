//! `LinuxBackend`: `NetworkManager` via the system D-Bus.
//!
//! `new()` is sync — it does a one-shot blocking probe to confirm
//! `NetworkManager` is on the bus, then drops the blocking handle. The
//! async `Connection` and typed proxies are constructed lazily on the
//! first async call via `OnceCell`, so `UniWifi::new()` does not need
//! the caller to be in a tokio context.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, OnceCell};

use crate::backend::{AdapterInfo, Backend};
use crate::connection::WifiConnection;
use crate::error::{BoxedOsError, Error};
use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

use super::error_map::from_zbus;
use super::proxies::{NetworkManagerProxy, SettingsProxy};

const NM_BUS_NAME: &str = "org.freedesktop.NetworkManager";

/// Cached async `zbus` handles, lazy-initialized on first async call.
pub struct NmHandles {
    pub conn: zbus::Connection,
    pub network_manager: NetworkManagerProxy<'static>,
    pub settings: SettingsProxy<'static>,
}

/// Linux backend driving `NetworkManager` over D-Bus.
pub struct LinuxBackend {
    handles: OnceCell<NmHandles>,
    /// Per-adapter mutex so concurrent calls on the same Wi-Fi device
    /// serialize. Different devices proceed in parallel.
    pub adapter_locks: Mutex<HashMap<AdapterId, Arc<Mutex<()>>>>,
}

impl LinuxBackend {
    /// Construct a `LinuxBackend`. Eagerly probes `NetworkManager` on the
    /// system bus; returns `Error::Unsupported("NetworkManager not
    /// running")` if the probe fails.
    ///
    /// # Errors
    ///
    /// - `Error::Unsupported("NetworkManager not running")` — the system
    ///   bus is unreachable, or `org.freedesktop.NetworkManager` has no
    ///   owner on it.
    /// - `Error::Os(_)` — the D-Bus daemon is reachable but a probe call
    ///   failed for an unexpected reason.
    pub fn new() -> Result<Self, Error> {
        // Sync probe: open a `zbus::blocking` system-bus connection and
        // ask the daemon whether NM has an owner. The blocking handle
        // (and its internal driver thread) is dropped at the end of
        // this function; the async handles are built lazily later.
        let blocking_conn = zbus::blocking::Connection::system()
            .map_err(|_| Error::Unsupported("NetworkManager not running"))?;

        let dbus = zbus::blocking::fdo::DBusProxy::new(&blocking_conn)
            .map_err(|e| Error::Os(Box::new(e) as BoxedOsError))?;

        let nm_name = zbus::names::BusName::try_from(NM_BUS_NAME)
            .expect("invariant: NM_BUS_NAME is a valid bus name literal");
        let has_owner = dbus
            .name_has_owner(nm_name)
            .map_err(|e| Error::Os(Box::new(e) as BoxedOsError))?;

        if !has_owner {
            return Err(Error::Unsupported("NetworkManager not running"));
        }

        Ok(Self {
            handles: OnceCell::new(),
            adapter_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Lazy-initialize and borrow the async D-Bus proxies. Each `Backend`
    /// method calls this on entry.
    pub async fn proxies(&self) -> Result<&NmHandles, Error> {
        self.handles
            .get_or_try_init(|| async {
                let conn = zbus::Connection::system().await.map_err(from_zbus)?;
                let network_manager = NetworkManagerProxy::new(&conn).await.map_err(from_zbus)?;
                let settings = SettingsProxy::new(&conn).await.map_err(from_zbus)?;
                Ok::<_, Error>(NmHandles {
                    conn,
                    network_manager,
                    settings,
                })
            })
            .await
    }

    /// Look up (or insert) the per-adapter serialization mutex.
    pub async fn adapter_lock(&self, id: &AdapterId) -> Arc<Mutex<()>> {
        let mut map = self.adapter_locks.lock().await;
        Arc::clone(
            map.entry(id.clone())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }
}

#[async_trait]
impl Backend for LinuxBackend {
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
        let handles = self.proxies().await?;
        super::adapters::list_wifi_adapters(handles).await
    }

    async fn connect(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        credentials: &Credentials,
        options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        let handles = self.proxies().await?;
        let lock = self.adapter_lock(adapter).await;
        let _guard = lock.lock().await;
        super::connect::connect_with_credentials(handles, adapter, ssid, credentials, options)
            .await
            .map(|()| WifiConnection::inert())
    }

    async fn connect_with_stored_credentials(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        let handles = self.proxies().await?;
        let lock = self.adapter_lock(adapter).await;
        let _guard = lock.lock().await;
        super::connect::connect_with_stored(handles, adapter, ssid, options)
            .await
            .map(|()| WifiConnection::inert())
    }

    async fn disconnect(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<(), Error> {
        let handles = self.proxies().await?;
        let lock = self.adapter_lock(adapter).await;
        let _guard = lock.lock().await;
        super::disconnect::disconnect_ssid(handles, adapter, ssid).await
    }

    async fn remove_profile(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<bool, Error> {
        let handles = self.proxies().await?;
        let lock = self.adapter_lock(adapter).await;
        let _guard = lock.lock().await;
        super::disconnect::remove_profile_for_ssid(handles, adapter, ssid).await
    }

    // Per-adapter lock is held across the WirelessDevice.RequestScan call
    // (which NM rate-limits to ~10s) and the subsequent property reads.
    // This intentionally serializes against connect / disconnect /
    // remove_profile on the same adapter to avoid the rescan racing
    // against an in-flight ActivateConnection. Pre-existing crate-wide
    // pattern (see also macos/windows backends); documented here for the
    // public API surface.
    async fn list_visible_networks(
        &self,
        adapter: &AdapterId,
        options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        let handles = self.proxies().await?;
        let lock = self.adapter_lock(adapter).await;
        let _g = lock.lock().await;
        let bsses = super::scan::fetch_bsses(handles, adapter, options).await?;
        let ctx = super::scan::fetch_scan_context(handles, adapter).await?;
        Ok(crate::scan_rollup::rollup(bsses, &ctx))
    }
}
