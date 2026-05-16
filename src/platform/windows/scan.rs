//! `WindowsScanner` — drives `WlanScan` and `WlanGetAvailableNetworkList`,
//! and bridges the scan-complete notification into our `ScanProvider`
//! contract.

use std::collections::HashSet;
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::timeout;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::WiFi::{
    DOT11_SSID, WLAN_AVAILABLE_NETWORK, WLAN_AVAILABLE_NETWORK_LIST, WLAN_BSS_ENTRY, WLAN_BSS_LIST,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_OPCODE_VALUE_TYPE, WLAN_RAW_DATA, WlanFreeMemory,
    WlanGetAvailableNetworkList, WlanGetNetworkBssList, WlanQueryInterface, WlanScan,
    dot11_BSS_type_infrastructure, wlan_intf_opcode_current_connection,
};
use windows::core::GUID;

use crate::error::Error;
use crate::platform::windows::handle::WlanClient;
use crate::platform::windows::notifications::Dispatcher;
use crate::platform::windows::security::security_from_auth_cipher;
use crate::platform::windows::util::{adapter_id_to_guid, check_win32};
use crate::preflight::{ScanError, ScanProvider};
use crate::scan_rollup::{RawBss, ScanContext, quality_from_dbm};
use crate::types::{AdapterId, ScanOptions, SecurityFlags, Ssid};

pub struct WindowsScanner {
    client: Arc<WlanClient>,
    dispatcher: Arc<Dispatcher>,
    interface: GUID,
}

impl WindowsScanner {
    #[must_use]
    pub const fn new(
        client: Arc<WlanClient>,
        dispatcher: Arc<Dispatcher>,
        interface: GUID,
    ) -> Self {
        Self {
            client,
            dispatcher,
            interface,
        }
    }
}

/// Issue a `WlanScan` for `interface`.
///
/// # Errors
///
/// Returns `Error::Os(_)` if `WlanScan` returns a non-zero status code.
fn issue_scan_raw(client: &WlanClient, interface: GUID) -> Result<(), Error> {
    // SAFETY: handle/interface valid; reserved fields null.
    let code = unsafe {
        WlanScan(
            client.handle(),
            &raw const interface,
            Some(ptr::null::<DOT11_SSID>()),
            Some(ptr::null::<WLAN_RAW_DATA>()),
            Some(ptr::null::<core::ffi::c_void>()),
        )
    };
    check_win32("WlanScan", WIN32_ERROR(code))
}

impl super::WindowsBackend {
    /// Enumerate per-BSS observations for `adapter`. Performs an active
    /// `WlanScan` first when `options.force_rescan` is set, otherwise
    /// returns the OS's cached results.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os(_)` for any underlying Win32 failure, or
    /// `Error::AdapterNotFound(_)` when `adapter` is not a parseable GUID.
    pub(super) async fn fetch_bsses(
        &self,
        adapter: &AdapterId,
        options: &ScanOptions,
    ) -> Result<Vec<RawBss>, Error> {
        let interface = adapter_id_to_guid(adapter)?;
        let force = options.force_rescan;
        let client = Arc::clone(&self.client);
        let dispatcher = Arc::clone(&self.dispatcher);

        if force {
            // Register oneshot first so we don't miss the notification.
            let rx = dispatcher.pending_scan(interface);
            let c = Arc::clone(&client);
            // On `spawn_blocking` join failure or `WlanScan` error, drop
            // the pending entry so a late SCAN_COMPLETE can't fire the
            // next call's tx and report stale completion.
            let scan_outcome = tokio::task::spawn_blocking(move || issue_scan_raw(&c, interface))
                .await
                .map_err(|e| {
                    Error::Os(Box::new(std::io::Error::other(format!(
                        "spawn_blocking join: {e}"
                    ))))
                })
                .and_then(|inner| inner);
            if let Err(e) = scan_outcome {
                dispatcher.drop_pending_scan(interface);
                return Err(e);
            }

            // Best-effort: if the scan-complete notification doesn't arrive
            // within 5s, we proceed to read whatever cached results exist
            // rather than erroring. Matches `force_rescan`'s "best-effort"
            // contract documented on `ScanOptions`. We must also drop the
            // pending entry on timeout so a late notification doesn't
            // fire the next call's tx.
            if timeout(Duration::from_secs(5), rx).await.is_err() {
                dispatcher.drop_pending_scan(interface);
            }
        }

        let c = Arc::clone(&client);
        tokio::task::spawn_blocking(move || collect_bsses_blocking(&c, interface))
            .await
            .map_err(|e| {
                Error::Os(Box::new(std::io::Error::other(format!(
                    "spawn_blocking join: {e}"
                ))))
            })?
    }

    /// Snapshot the per-adapter scan context: currently-connected SSID
    /// and the set of SSIDs for which the OS has a saved profile.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os(_)` for any underlying Win32 failure, or
    /// `Error::AdapterNotFound(_)` when `adapter` is not a parseable GUID.
    pub(super) async fn fetch_scan_context(
        &self,
        adapter: &AdapterId,
    ) -> Result<ScanContext, Error> {
        let interface = adapter_id_to_guid(adapter)?;
        let client = Arc::clone(&self.client);
        tokio::task::spawn_blocking(move || collect_context_blocking(&client, interface))
            .await
            .map_err(|e| {
                Error::Os(Box::new(std::io::Error::other(format!(
                    "spawn_blocking join: {e}"
                ))))
            })?
    }
}

fn collect_bsses_blocking(client: &WlanClient, interface: GUID) -> Result<Vec<RawBss>, Error> {
    // 1) Enumerate available networks (per-SSID rollup the OS produces).
    let mut net_list: *mut WLAN_AVAILABLE_NETWORK_LIST = ptr::null_mut();
    // SAFETY: handle/interface valid; reserved is null; out-pointer initialized.
    let code = unsafe {
        WlanGetAvailableNetworkList(
            client.handle(),
            &raw const interface,
            0,
            Some(ptr::null::<core::ffi::c_void>()),
            &raw mut net_list,
        )
    };
    check_win32("WlanGetAvailableNetworkList", WIN32_ERROR(code))?;
    if net_list.is_null() {
        return Ok(Vec::new());
    }

    // SAFETY: net_list non-null and produced by the WLAN runtime.
    let net_header = unsafe { &*net_list };
    let n_nets = net_header.dwNumberOfItems as usize;
    let nets: &[WLAN_AVAILABLE_NETWORK] = if n_nets == 0 {
        &[]
    } else {
        // SAFETY: trailing flexible array length matches dwNumberOfItems.
        unsafe { slice::from_raw_parts(net_header.Network.as_ptr(), n_nets) }
    };

    let mut out: Vec<RawBss> = Vec::new();
    for net in nets {
        let len = net.dot11Ssid.uSSIDLength as usize;
        if len == 0 || len > net.dot11Ssid.ucSSID.len() {
            continue;
        }
        let ssid_bytes = net.dot11Ssid.ucSSID[..len].to_vec();
        let security = security_from_auth_cipher(
            net.dot11DefaultAuthAlgorithm,
            net.dot11DefaultCipherAlgorithm,
        );

        // 2) Fan out: enumerate BSSes for this SSID. The Windows binding
        // takes `bsecurityenabled: bool`, and `windows_core::BOOL: Into<bool>`
        // does the conversion.
        let mut bss_list: *mut WLAN_BSS_LIST = ptr::null_mut();
        let name = net.dot11Ssid;
        // SAFETY: handle/interface valid; SSID lives until after the call.
        let bss_code = unsafe {
            WlanGetNetworkBssList(
                client.handle(),
                &raw const interface,
                Some(&raw const name),
                dot11_BSS_type_infrastructure,
                net.bSecurityEnabled.into(),
                Some(ptr::null::<core::ffi::c_void>()),
                &raw mut bss_list,
            )
        };
        if bss_code != 0 || bss_list.is_null() {
            // Could not get per-BSS; emit one "unknown-BSS" entry so the
            // SSID still appears in the rollup with no BSSID/freq/RSSI.
            // wlanSignalQuality is documented as 0..=100; the saturating
            // cast preserves that range (and treats any out-of-spec value
            // as 0 rather than panicking).
            let quality = u8::try_from(net.wlanSignalQuality.min(100)).unwrap_or(0);
            out.push(RawBss {
                ssid: Ssid::from_bytes(ssid_bytes.clone()),
                security,
                rssi_dbm: None,
                quality,
                bssid: None,
                frequency_mhz: None,
            });
            continue;
        }

        // SAFETY: bss_list non-null, OS-allocated.
        let bss_header = unsafe { &*bss_list };
        let n_bss = bss_header.dwNumberOfItems as usize;
        let bsses: &[WLAN_BSS_ENTRY] = if n_bss == 0 {
            &[]
        } else {
            // SAFETY: trailing flexible array length matches dwNumberOfItems.
            unsafe { slice::from_raw_parts(bss_header.wlanBssEntries.as_ptr(), n_bss) }
        };
        for entry in bsses {
            out.push(raw_bss_from_entry(&ssid_bytes, security, entry));
        }
        // SAFETY: matches the WLAN_BSS_LIST allocator.
        unsafe { WlanFreeMemory(bss_list.cast()) };
    }

    // SAFETY: matches the WLAN_AVAILABLE_NETWORK_LIST allocator.
    unsafe { WlanFreeMemory(net_list.cast()) };
    Ok(out)
}

fn raw_bss_from_entry(
    ssid_bytes: &[u8],
    security: SecurityFlags,
    entry: &WLAN_BSS_ENTRY,
) -> RawBss {
    // RSSI dBm is in [-127, 0] in practice; saturate the i32→i16
    // conversion for any out-of-spec value rather than panicking.
    let rssi = i16::try_from(entry.lRssi).unwrap_or(i16::MIN);
    let bssid = Some(entry.dot11Bssid);
    // ulChCenterFrequency is in kHz per Microsoft docs — convert to MHz.
    let mhz = entry.ulChCenterFrequency / 1000;
    RawBss {
        ssid: Ssid::from_bytes(ssid_bytes.to_vec()),
        security,
        rssi_dbm: Some(rssi),
        quality: quality_from_dbm(rssi),
        bssid,
        frequency_mhz: Some(mhz),
    }
}

fn collect_context_blocking(client: &WlanClient, interface: GUID) -> Result<ScanContext, Error> {
    // 1) Current connection.
    let mut data_size: u32 = 0;
    let mut data: *mut core::ffi::c_void = ptr::null_mut();
    let mut opcode_kind = WLAN_OPCODE_VALUE_TYPE::default();
    let connected_ssid = {
        // SAFETY: handle/interface valid; out-pointers initialized; reserved null.
        let code = unsafe {
            WlanQueryInterface(
                client.handle(),
                &raw const interface,
                wlan_intf_opcode_current_connection,
                Some(ptr::null::<core::ffi::c_void>()),
                &raw mut data_size,
                &raw mut data,
                Some(&raw mut opcode_kind),
            )
        };
        if code == 0 && !data.is_null() {
            // SAFETY: per MSDN, WlanQueryInterface with
            // wlan_intf_opcode_current_connection allocates a single
            // WLAN_CONNECTION_ATTRIBUTES into *ppData on success. We checked
            // `code == 0 && !data.is_null()` above, so the buffer is valid and
            // has the documented layout.
            let attrs: &WLAN_CONNECTION_ATTRIBUTES = unsafe { &*data.cast() };
            let ssid = attrs.wlanAssociationAttributes.dot11Ssid;
            let len = ssid.uSSIDLength as usize;
            let s = if len > 0 && len <= ssid.ucSSID.len() {
                Some(Ssid::from_bytes(ssid.ucSSID[..len].to_vec()))
            } else {
                None
            };
            // SAFETY: matches the WLAN allocator.
            unsafe { WlanFreeMemory(data) };
            s
        } else {
            None
        }
    };

    // 2) Saved profiles: read strProfileName from each WLAN_AVAILABLE_NETWORK.
    // Same source list collect_bsses_blocking enumerates, but recollected
    // here for layering simplicity (the two paths are deliberately
    // independent of each other).
    let mut net_list: *mut WLAN_AVAILABLE_NETWORK_LIST = ptr::null_mut();
    // SAFETY: handle/interface valid; reserved is null; out-pointer initialized.
    let code = unsafe {
        WlanGetAvailableNetworkList(
            client.handle(),
            &raw const interface,
            0,
            Some(ptr::null::<core::ffi::c_void>()),
            &raw mut net_list,
        )
    };
    check_win32("WlanGetAvailableNetworkList", WIN32_ERROR(code))?;

    let mut saved_ssids: HashSet<Ssid> = HashSet::new();
    if !net_list.is_null() {
        // SAFETY: net_list non-null and produced by the WLAN runtime.
        let header = unsafe { &*net_list };
        let n = header.dwNumberOfItems as usize;
        let nets: &[WLAN_AVAILABLE_NETWORK] = if n == 0 {
            &[]
        } else {
            // SAFETY: trailing flexible array length matches dwNumberOfItems.
            unsafe { slice::from_raw_parts(header.Network.as_ptr(), n) }
        };
        for net in nets {
            // strProfileName is a fixed-size [u16; 256] terminated by NUL.
            let name_len = net
                .strProfileName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(net.strProfileName.len());
            if name_len == 0 {
                continue;
            }
            let len = net.dot11Ssid.uSSIDLength as usize;
            if len == 0 || len > net.dot11Ssid.ucSSID.len() {
                continue;
            }
            saved_ssids.insert(Ssid::from_bytes(net.dot11Ssid.ucSSID[..len].to_vec()));
        }
        // SAFETY: matches the WLAN_AVAILABLE_NETWORK_LIST allocator.
        unsafe { WlanFreeMemory(net_list.cast()) };
    }

    Ok(ScanContext {
        connected_ssid,
        saved_ssids,
    })
}

#[async_trait]
impl ScanProvider for WindowsScanner {
    async fn scan(&self) -> Result<Vec<Ssid>, ScanError> {
        // Build the same blocking-call envelope WindowsBackend::fetch_bsses
        // uses, but without holding a backend handle — the scanner already
        // owns its `WlanClient` and `Dispatcher`.
        let rx = self.dispatcher.pending_scan(self.interface);
        let client = Arc::clone(&self.client);
        let interface = self.interface;
        // Per spec §4: WlanScan failures flow through scan_error_from to
        // ScanError::Os, matching the macOS path's single-mapping invariant.
        // The previous "Err -> Unsupported" short-circuit conflated transient
        // OS errors with platform-unsupported, reducing telemetry fidelity.
        let dispatcher = Arc::clone(&self.dispatcher);
        let intf = self.interface;
        let kickoff = tokio::task::spawn_blocking(move || issue_scan_raw(&client, interface))
            .await
            .map_err(|e| ScanError::Os(Box::new(std::io::Error::other(format!("join: {e}")))))
            .and_then(|inner| inner.map_err(crate::preflight::scan_error_from));
        if let Err(e) = kickoff {
            dispatcher.drop_pending_scan(intf);
            return Err(e);
        }
        // Best-effort: if the scan-complete notification doesn't arrive
        // within 5s, we proceed to read whatever cached results exist
        // rather than erroring. Matches `force_rescan`'s "best-effort"
        // contract documented on `ScanOptions`. Drop the pending entry
        // on timeout so a late SCAN_COMPLETE doesn't fire the next call's
        // tx.
        if timeout(Duration::from_secs(5), rx).await.is_err() {
            dispatcher.drop_pending_scan(intf);
        }

        let client = Arc::clone(&self.client);
        let interface = self.interface;
        let bsses = tokio::task::spawn_blocking(move || collect_bsses_blocking(&client, interface))
            .await
            .map_err(|e| ScanError::Os(Box::new(std::io::Error::other(format!("join: {e}")))))?
            .map_err(crate::preflight::scan_error_from)?;
        Ok(bsses.into_iter().map(|b| b.ssid).collect())
    }
}
