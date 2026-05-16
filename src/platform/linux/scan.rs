//! `ScanProvider` implementation — pokes `WirelessDevice.RequestScan`
//! and reads the SSIDs of all visible access points.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::preflight::{ScanError, ScanProvider};
use crate::scan_rollup::{RawBss, ScanContext};
use crate::types::{AdapterId, ScanOptions, Ssid};

use super::adapters::resolve_device_path;
use super::backend::NmHandles;
use super::error_map::from_zbus;
use super::proxies::{
    AccessPointProxy, ActiveConnectionProxy, DeviceProxy, SettingsConnectionProxy,
    WirelessDeviceProxy,
};

/// Per-adapter `ScanProvider` view. Constructed transiently by
/// `connect()` so the foundation `wait_until_ssid_visible` helper has a
/// type to call. The scan caller holds it for the duration of the
/// pre-flight and drops it.
pub struct LinuxScanProvider<'a> {
    pub handles: &'a NmHandles,
    pub adapter: &'a AdapterId,
}

#[async_trait]
impl ScanProvider for LinuxScanProvider<'_> {
    async fn scan(&self) -> Result<Vec<Ssid>, ScanError> {
        let bsses = fetch_bsses(
            self.handles,
            self.adapter,
            &ScanOptions { force_rescan: true },
        )
        .await
        .map_err(crate::preflight::scan_error_from)?;
        Ok(bsses.into_iter().map(|b| b.ssid).collect())
    }
}

/// Translate `NetworkManager` `(Flags, WpaFlags, RsnFlags)` to `SecurityFlags`.
///
/// NM exposes both legacy WPA1 capabilities (`WpaFlags`) and RSN/WPA2/WPA3
/// capabilities (`RsnFlags`) as bitfields. The `Flags` field on the AP has
/// the privacy bit (`0x1`).
///
/// Mutual exclusion: an OWE BSS does not set the privacy bit, so we never
/// pair `OWE` with `OPEN`. If no IE-based key-management bit is set and OWE
/// is absent, we fall back to the privacy bit: set → `WEP`, clear → `OPEN`.
pub(super) fn security_from_nm_flags(
    flags: u32,
    wpa_flags: u32,
    rsn_flags: u32,
) -> crate::types::SecurityFlags {
    use crate::types::SecurityFlags;

    const PRIVACY: u32 = 0x1;
    const KEY_MGMT_PSK: u32 = 0x100;
    const KEY_MGMT_8021X: u32 = 0x200;
    const KEY_MGMT_SAE: u32 = 0x400;
    const KEY_MGMT_OWE: u32 = 0x800;
    const KEY_MGMT_OWE_TM: u32 = 0x1000;
    // WPA3-Enterprise key-management bits exposed by NM ≥ 1.26 in
    // `NM80211ApSecurityFlags`. SUITE_B_192 is Suite-B 192-bit (CNSA);
    // EAP_SHA384 is the lower-strength WPA3-Enterprise variant. Without
    // these arms a WPA3-Enterprise BSS would fall through to the
    // privacy-bit fallback and report `WEP` or `OPEN`.
    const KEY_MGMT_EAP_SUITE_B_192: u32 = 0x2000;
    const KEY_MGMT_EAP_SHA384: u32 = 0x4000;

    let mut out = SecurityFlags::empty();
    let saw_owe = (rsn_flags & (KEY_MGMT_OWE | KEY_MGMT_OWE_TM)) != 0;

    if saw_owe {
        out |= SecurityFlags::OWE;
    }

    if wpa_flags & KEY_MGMT_PSK != 0 {
        out |= SecurityFlags::WPA_PSK;
    }
    if wpa_flags & KEY_MGMT_8021X != 0 {
        // Legacy WPA1-Enterprise rolled into the WPA2_ENTERPRISE bucket;
        // SecurityFlags has no separate WPA1_ENTERPRISE.
        out |= SecurityFlags::WPA2_ENTERPRISE;
    }
    if rsn_flags & KEY_MGMT_PSK != 0 {
        out |= SecurityFlags::WPA2_PSK;
    }
    if rsn_flags & KEY_MGMT_8021X != 0 {
        out |= SecurityFlags::WPA2_ENTERPRISE;
    }
    if rsn_flags & KEY_MGMT_SAE != 0 {
        out |= SecurityFlags::WPA3_SAE;
    }
    if rsn_flags & (KEY_MGMT_EAP_SUITE_B_192 | KEY_MGMT_EAP_SHA384) != 0 {
        out |= SecurityFlags::WPA3_ENTERPRISE;
    }

    if out.is_empty() && !saw_owe {
        // No RSN/WPA/OWE IEs. Fall back to privacy bit:
        // privacy=true → WEP; privacy=false → OPEN.
        if flags & PRIVACY != 0 {
            out |= SecurityFlags::WEP;
        } else {
            out |= SecurityFlags::OPEN;
        }
    }

    out
}

/// Enumerate the per-BSS observations visible to NM on `adapter`.
///
/// `force_rescan` triggers a `RequestScan` D-Bus call. NM rate-limits this;
/// any error is intentionally swallowed (per the `force_rescan` best-effort
/// contract — the caller still gets cached results).
pub(super) async fn fetch_bsses(
    handles: &NmHandles,
    adapter: &AdapterId,
    options: &ScanOptions,
) -> Result<Vec<RawBss>, crate::error::Error> {
    let device_path = resolve_device_path(handles, adapter).await?;

    let wifi = WirelessDeviceProxy::builder(&handles.conn)
        .path(device_path)
        .map_err(from_zbus)?
        .build()
        .await
        .map_err(from_zbus)?;

    if options.force_rescan {
        let scan_opts: HashMap<&str, Value<'_>> = HashMap::new();
        let _ignore = wifi.request_scan(scan_opts).await;
    }

    let aps = wifi.access_points().await.map_err(from_zbus)?;

    let mut bsses = Vec::with_capacity(aps.len());
    for ap_path in aps {
        let ap = AccessPointProxy::builder(&handles.conn)
            .path(ap_path)
            .map_err(from_zbus)?
            .build()
            .await
            .map_err(from_zbus)?;

        // APs that disappear between snapshot and per-property reads are
        // benign — skip them.
        let Ok(ssid_bytes) = ap.ssid().await else {
            continue;
        };
        let Ok(strength) = ap.strength().await else {
            continue;
        };
        let frequency_mhz = ap.frequency().await.ok();
        let bssid = ap.hw_address().await.ok().and_then(|s| parse_bssid(&s));
        let flags = ap.flags().await.unwrap_or(0);
        let wpa_flags = ap.wpa_flags().await.unwrap_or(0);
        let rsn_flags = ap.rsn_flags().await.unwrap_or(0);

        bsses.push(RawBss {
            ssid: Ssid::from_bytes(ssid_bytes),
            security: security_from_nm_flags(flags, wpa_flags, rsn_flags),
            rssi_dbm: None,
            quality: strength,
            bssid,
            frequency_mhz,
        });
    }
    Ok(bsses)
}

/// Build the per-adapter `ScanContext` (currently-connected SSID + saved
/// SSIDs known to NM) used to stamp `is_connected` / `is_known` onto each
/// rolled-up `VisibleNetwork`.
pub(super) async fn fetch_scan_context(
    handles: &NmHandles,
    adapter: &AdapterId,
) -> Result<ScanContext, crate::error::Error> {
    let device_path = resolve_device_path(handles, adapter).await?;

    let device = DeviceProxy::builder(&handles.conn)
        .path(device_path)
        .map_err(from_zbus)?
        .build()
        .await
        .map_err(from_zbus)?;

    let connected_ssid = match device.active_connection().await {
        Ok(path) if path.as_str() != "/" => connected_ssid_from_active(handles, &path).await,
        _ => None,
    };

    let saved_ssids = saved_wifi_ssids(handles).await.unwrap_or_default();

    Ok(ScanContext {
        connected_ssid,
        saved_ssids,
    })
}

/// Resolve the SSID of an `ActiveConnection`'s specific (Wi-Fi) AP.
/// Returns `None` if any leg of the resolution fails — callers treat that
/// as "not currently connected on this adapter".
async fn connected_ssid_from_active(
    handles: &NmHandles,
    active_path: &OwnedObjectPath,
) -> Option<Ssid> {
    let active = ActiveConnectionProxy::builder(&handles.conn)
        .path(active_path.clone())
        .ok()?
        .build()
        .await
        .ok()?;
    let specific = active.specific_object().await.ok()?;
    if specific.as_str() == "/" {
        return None;
    }
    let ap = AccessPointProxy::builder(&handles.conn)
        .path(specific)
        .ok()?
        .build()
        .await
        .ok()?;
    let bytes = ap.ssid().await.ok()?;
    if bytes.is_empty() {
        None
    } else {
        Some(Ssid::from_bytes(bytes))
    }
}

/// Walk every saved NM `Settings.Connection` and collect SSIDs of those
/// whose `connection.type == "802-11-wireless"`. A profile that disappears
/// or fails to deserialize mid-walk is skipped.
async fn saved_wifi_ssids(handles: &NmHandles) -> zbus::Result<HashSet<Ssid>> {
    let conns = handles.settings.list_connections().await?;
    let mut out: HashSet<Ssid> = HashSet::new();
    for path in conns {
        let conn = SettingsConnectionProxy::builder(&handles.conn)
            .path(path)?
            .build()
            .await?;
        let Ok(settings) = conn.get_settings().await else {
            continue;
        };
        let Some(connection_block) = settings.get("connection") else {
            continue;
        };
        let ty = connection_block
            .get("type")
            .and_then(|v| v.try_clone().ok())
            .and_then(|v| String::try_from(v).ok());
        if ty.as_deref() != Some("802-11-wireless") {
            continue;
        }
        let Some(wifi_block) = settings.get("802-11-wireless") else {
            continue;
        };
        let Some(ssid_v) = wifi_block.get("ssid") else {
            continue;
        };
        let Ok(cloned) = ssid_v.try_clone() else {
            continue;
        };
        if let Ok(bytes) = Vec::<u8>::try_from(cloned)
            && !bytes.is_empty()
        {
            out.insert(Ssid::from_bytes(bytes));
        }
    }
    Ok(out)
}

/// Parse a `xx:xx:xx:xx:xx:xx` BSSID string into a 6-byte array. Returns
/// `None` for malformed input (wrong number of octets, non-hex digits).
fn parse_bssid(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod security_tests {
    use super::security_from_nm_flags;
    use crate::types::SecurityFlags;

    // Constants from `NetworkManager.h`:
    // NM_802_11_AP_FLAGS_PRIVACY              = 0x1
    // NM_802_11_AP_SEC_KEY_MGMT_PSK           = 0x100
    // NM_802_11_AP_SEC_KEY_MGMT_802_1X        = 0x200
    // NM_802_11_AP_SEC_KEY_MGMT_SAE           = 0x400
    // NM_802_11_AP_SEC_KEY_MGMT_OWE           = 0x800
    // NM_802_11_AP_SEC_KEY_MGMT_OWE_TM        = 0x1000
    // NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192 = 0x2000  (NM ≥ 1.26)
    // NM_802_11_AP_SEC_KEY_MGMT_EAP_SHA384    = 0x4000  (NM ≥ 1.26)

    const PRIVACY: u32 = 0x1;
    const PSK: u32 = 0x100;
    const EAP: u32 = 0x200;
    const SAE: u32 = 0x400;
    const OWE: u32 = 0x800;
    const OWE_TM: u32 = 0x1000;
    const EAP_SUITE_B_192: u32 = 0x2000;
    const EAP_SHA384: u32 = 0x4000;

    #[test]
    fn open_no_privacy_no_ies() {
        assert_eq!(security_from_nm_flags(0, 0, 0), SecurityFlags::OPEN);
    }

    #[test]
    fn wep_privacy_no_rsn_or_wpa() {
        assert_eq!(security_from_nm_flags(PRIVACY, 0, 0), SecurityFlags::WEP);
    }

    #[test]
    fn wpa_psk_only() {
        assert_eq!(
            security_from_nm_flags(PRIVACY, PSK, 0),
            SecurityFlags::WPA_PSK
        );
    }

    #[test]
    fn wpa2_psk() {
        assert_eq!(
            security_from_nm_flags(PRIVACY, 0, PSK),
            SecurityFlags::WPA2_PSK
        );
    }

    #[test]
    fn wpa3_sae() {
        assert_eq!(
            security_from_nm_flags(PRIVACY, 0, SAE),
            SecurityFlags::WPA3_SAE
        );
    }

    #[test]
    fn transition_psk_plus_sae() {
        assert_eq!(
            security_from_nm_flags(PRIVACY, 0, PSK | SAE),
            SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE
        );
    }

    #[test]
    fn enterprise_eap() {
        assert_eq!(
            security_from_nm_flags(PRIVACY, 0, EAP),
            SecurityFlags::WPA2_ENTERPRISE
        );
    }

    #[test]
    fn owe_alone_not_open() {
        // OWE BSSes do not set the privacy bit.
        let s = security_from_nm_flags(0, 0, OWE);
        assert_eq!(s, SecurityFlags::OWE);
        assert!(!s.contains(SecurityFlags::OPEN));
    }

    #[test]
    fn owe_transition_alone_not_open() {
        let s = security_from_nm_flags(0, 0, OWE_TM);
        assert_eq!(s, SecurityFlags::OWE);
        assert!(!s.contains(SecurityFlags::OPEN));
    }

    #[test]
    fn wpa3_enterprise_suite_b_192() {
        let s = security_from_nm_flags(PRIVACY, 0, EAP_SUITE_B_192);
        assert_eq!(s, SecurityFlags::WPA3_ENTERPRISE);
    }

    #[test]
    fn wpa3_enterprise_sha384() {
        let s = security_from_nm_flags(PRIVACY, 0, EAP_SHA384);
        assert_eq!(s, SecurityFlags::WPA3_ENTERPRISE);
    }

    #[test]
    fn wpa3_enterprise_with_legacy_eap_yields_both() {
        let s = security_from_nm_flags(PRIVACY, 0, EAP | EAP_SHA384);
        assert!(s.contains(SecurityFlags::WPA2_ENTERPRISE));
        assert!(s.contains(SecurityFlags::WPA3_ENTERPRISE));
    }
}
