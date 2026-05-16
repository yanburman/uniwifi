//! Scan helpers and the [`ScanProvider`] impl that powers
//! `wait_until_ssid_visible` inside `connect`.

use std::sync::Arc;

use async_trait::async_trait;
use objc2_core_wlan::CWSecurity;

use crate::preflight::{ScanError, ScanProvider};
use crate::scan_rollup::{RawBss, ScanContext, quality_from_dbm};
use crate::types::{AdapterId, ScanOptions, Ssid};

use super::client::SharedClient;
use super::threading::run_blocking;

/// `ScanProvider` is a per-adapter notion: a single backend object can
/// implement it by carrying both a client *and* the target adapter id.
pub(super) struct AdapterScan {
    pub(super) client: SharedClient,
    pub(super) adapter: AdapterId,
}

#[async_trait]
impl ScanProvider for AdapterScan {
    async fn scan(&self) -> Result<Vec<Ssid>, ScanError> {
        let client = self.client.clone();
        let adapter = self.adapter.clone();
        // Pre-flight always issues an active scan, matching pre-existing
        // behavior (scanForNetworksWithName_error, blocking).
        let bsses = run_blocking(move || {
            fetch_bsses_blocking(&client, &adapter, /*force_rescan=*/ true)
        })
        .await
        .map_err(crate::preflight::scan_error_from)?;
        Ok(bsses.into_iter().map(|b| b.ssid).collect())
    }
}

/// Convenience wrapper used by `connect()` to build an `AdapterScan` on
/// demand without exposing `SharedClient` outside the module.
pub(super) fn make_scan_provider(client: SharedClient, adapter: AdapterId) -> Arc<AdapterScan> {
    Arc::new(AdapterScan { client, adapter })
}

/// Translate a list of supported `CWSecurity` values from a single
/// `CWNetwork` to our portable `SecurityFlags`. The caller passes the
/// observed set produced by probing each `CWSecurity` discriminant via
/// `supportsSecurity:`.
///
/// Per the design's mutual-exclusion rule for `OPEN` and `OWE` on a
/// single BSS: if `OWE` is observed, `OPEN` is NOT set even when
/// `CWSecurity::None` is also observed (the AP uses OWE encryption
/// without setting the privacy bit; we report it as OWE alone).
pub(super) fn security_from_cw_set(observed: &[CWSecurity]) -> crate::types::SecurityFlags {
    use crate::types::SecurityFlags;

    let mut out = SecurityFlags::empty();
    let mut saw_owe = false;
    for sec in observed {
        match *sec {
            CWSecurity::None => out |= SecurityFlags::OPEN,
            CWSecurity::WEP | CWSecurity::DynamicWEP => out |= SecurityFlags::WEP,
            CWSecurity::WPAPersonal | CWSecurity::WPAPersonalMixed => {
                out |= SecurityFlags::WPA_PSK;
            }
            CWSecurity::WPA2Personal => {
                out |= SecurityFlags::WPA2_PSK;
            }
            // CWSecurity::Personal is "any-personal": maps to the union
            // of WPA / WPA2 / WPA3-personal so a network reporting only
            // this generic flag doesn't lose its full capability set.
            CWSecurity::Personal => {
                out |= SecurityFlags::WPA_PSK | SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE;
            }
            CWSecurity::WPA3Personal => {
                out |= SecurityFlags::WPA3_SAE;
            }
            // WPA2/WPA3 transition mode: AP advertises BOTH WPA2-PSK and
            // WPA3-SAE simultaneously. Report the union so callers can
            // tell the AP supports either auth method.
            CWSecurity::WPA3Transition => {
                out |= SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE;
            }
            CWSecurity::WPAEnterprise
            | CWSecurity::WPAEnterpriseMixed
            | CWSecurity::WPA2Enterprise
            | CWSecurity::Enterprise => {
                out |= SecurityFlags::WPA2_ENTERPRISE;
            }
            CWSecurity::WPA3Enterprise => out |= SecurityFlags::WPA3_ENTERPRISE,
            CWSecurity::OWE | CWSecurity::OWETransition => {
                out |= SecurityFlags::OWE;
                saw_owe = true;
            }
            // `CWSecurity::Unknown` (NSIntegerMax) and any future
            // discriminants fall through here. Treat them as no-op
            // rather than panicking — the underlying Apple type is a
            // `NS_ENUM` mapped to a `repr(transparent)` newtype, so
            // exhaustiveness is not enforced.
            _ => {}
        }
    }
    if saw_owe {
        out.remove(SecurityFlags::OPEN);
    }
    out
}

/// Probe the `CWSecurity` enum range against a `CWNetwork` and return the
/// set of supported modes. Used by `fetch_bsses` (Task 8) to feed
/// `security_from_cw_set`.
pub(super) fn observed_security(net: &objc2_core_wlan::CWNetwork) -> Vec<CWSecurity> {
    const PROBES: &[CWSecurity] = &[
        CWSecurity::None,
        CWSecurity::WEP,
        CWSecurity::WPAPersonal,
        CWSecurity::WPAPersonalMixed,
        CWSecurity::WPA2Personal,
        CWSecurity::Personal,
        CWSecurity::DynamicWEP,
        CWSecurity::WPAEnterprise,
        CWSecurity::WPAEnterpriseMixed,
        CWSecurity::WPA2Enterprise,
        CWSecurity::Enterprise,
        CWSecurity::WPA3Personal,
        CWSecurity::WPA3Enterprise,
        CWSecurity::WPA3Transition,
        CWSecurity::OWE,
        CWSecurity::OWETransition,
    ];
    PROBES
        .iter()
        .copied()
        // SAFETY: `supportsSecurity:` is a const-time predicate on
        // `CWNetwork` that does not retain or mutate the receiver and
        // accepts any `CWSecurity` discriminant; passing an unknown
        // value returns NO rather than throwing.
        .filter(|s| unsafe { net.supportsSecurity(*s) })
        .collect()
}

impl super::backend::MacosBackend {
    pub(super) async fn fetch_bsses(
        &self,
        adapter: &AdapterId,
        options: &ScanOptions,
    ) -> Result<Vec<RawBss>, crate::error::Error> {
        let client = self.client.clone();
        let adapter = adapter.clone();
        let force = options.force_rescan;
        run_blocking(move || fetch_bsses_blocking(&client, &adapter, force)).await
    }

    pub(super) async fn fetch_scan_context(
        &self,
        adapter: &AdapterId,
    ) -> Result<ScanContext, crate::error::Error> {
        let client = self.client.clone();
        let adapter = adapter.clone();
        run_blocking(move || fetch_scan_context_blocking(&client, &adapter)).await
    }
}

fn fetch_bsses_blocking(
    client: &SharedClient,
    adapter: &AdapterId,
    force_rescan: bool,
) -> Result<Vec<RawBss>, crate::error::Error> {
    client.with(|c| {
        let iface = super::adapter::resolve_interface_by_id(c, adapter)?;
        let networks_set = if force_rescan {
            // SAFETY: nil name means "scan all SSIDs"; returns
            // Result<Retained<NSSet<CWNetwork>>, Retained<NSError>>.
            unsafe { iface.scanForNetworksWithName_error(None) }
                .map_err(|e| super::error::map_scan_nserror_to_error(&e))?
        } else {
            // SAFETY: cachedScanResults() returns
            // Option<Retained<NSSet<CWNetwork>>>; missing -> empty list.
            match unsafe { iface.cachedScanResults() } {
                Some(set) => set,
                None => return Ok(Vec::new()),
            }
        };
        let nets_vec = networks_set.allObjects().to_vec();
        let mut out = Vec::with_capacity(nets_vec.len());
        for net in &nets_vec {
            // SAFETY: ssidData returns Option<Retained<NSData>>; the
            // bytes are copied via to_vec() before the loop iteration ends.
            let Some(ssid_data) = (unsafe { net.ssidData() }) else {
                continue;
            };
            let ssid_bytes = ssid_data.to_vec();
            // Empty-SSID filtering happens in scan_rollup::rollup.

            // SAFETY: rssiValue returns NSInteger (isize on macOS).
            // Truncating cast — RSSI dBm is in [-127, 0] which is in
            // i16's range, so no information is lost in practice.
            #[allow(clippy::cast_possible_truncation)]
            let rssi_raw = unsafe { net.rssiValue() } as i16;
            // CoreWLAN reports rssi=0 for cached entries that have no
            // valid measurement (e.g. driver-stale entries); treat that
            // as unknown rather than a real -0 dBm reading, otherwise the
            // rollup would inflate the BSS to quality=100 and shadow
            // freshly-measured BSSes.
            let rssi = if rssi_raw == 0 { None } else { Some(rssi_raw) };
            let quality = rssi.map_or(0, quality_from_dbm);

            // SAFETY: bssid returns Option<Retained<NSString>>.
            let bssid = unsafe { net.bssid() }
                .as_ref()
                .and_then(|s| parse_bssid(&s.to_string()));

            // SAFETY: wlanChannel returns Option<Retained<CWChannel>>.
            let frequency_mhz = unsafe { net.wlanChannel() }.as_ref().and_then(|ch| {
                // SAFETY: channelNumber and channelBand are no-arg readers
                // on a CWChannel pointer that we hold across this call.
                channel_to_mhz(unsafe { ch.channelNumber() }, unsafe { ch.channelBand() })
            });

            let observed = observed_security(net);
            let security = security_from_cw_set(&observed);

            out.push(RawBss {
                ssid: Ssid::from_bytes(ssid_bytes),
                security,
                rssi_dbm: rssi,
                quality,
                bssid,
                frequency_mhz,
            });
        }
        Ok(out)
    })
}

fn fetch_scan_context_blocking(
    client: &SharedClient,
    adapter: &AdapterId,
) -> Result<ScanContext, crate::error::Error> {
    use std::collections::HashSet;

    // Phase 1: gather under the SharedClient lock. We deliberately do NOT
    // probe the keychain here — `keychain_entry_exists` can synchronously
    // trigger Security-framework UI prompts (e.g. on a revoked ACL), and
    // holding the SharedClient mutex across a UI-blocking call would
    // serialize every other macOS Wi-Fi op behind that prompt. Mirrors the
    // design's contract that `has_saved_profile` matches what
    // `connect_with_stored_credentials` will actually use.
    let (connected_ssid, candidate_saved): (Option<Ssid>, Vec<Ssid>) =
        client.with(|c| -> Result<_, crate::error::Error> {
            let iface = super::adapter::resolve_interface_by_id(c, adapter)?;

            // SAFETY: ssidData on a CWInterface returns Option<Retained<NSData>>.
            let connected = unsafe { iface.ssidData() }.map(|d| Ssid::from_bytes(d.to_vec()));

            let mut candidates: Vec<Ssid> = Vec::new();
            // SAFETY: configuration() returns Option<Retained<CWConfiguration>>.
            if let Some(cfg) = unsafe { iface.configuration() } {
                // SAFETY: networkProfiles() returns
                // Retained<NSOrderedSet<CWNetworkProfile>>.
                let profiles = unsafe { cfg.networkProfiles() };
                // NSOrderedSet exposes `array()` (no NSEnumerator feature
                // required) — same workaround used elsewhere in this module.
                let arr = profiles.array();
                let profs = arr.to_vec();
                for prof in &profs {
                    // SAFETY: ssidData on a CWNetworkProfile returns
                    // Option<Retained<NSData>>.
                    if let Some(data) = unsafe { prof.ssidData() } {
                        candidates.push(Ssid::from_bytes(data.to_vec()));
                    }
                }
            }
            Ok((connected, candidates))
        })?;

    // Phase 2: keychain probes outside the lock.
    let mut saved: HashSet<Ssid> = HashSet::new();
    for ssid in candidate_saved {
        if super::keychain::keychain_entry_exists(&ssid) {
            saved.insert(ssid);
        }
    }

    Ok(ScanContext {
        connected_ssid,
        saved_ssids: saved,
    })
}

/// Parse `CoreWLAN`'s `xx:xx:xx:xx:xx:xx` BSSID string into 6 bytes.
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

/// Convert a `CoreWLAN` (`channelNumber`, `channelBand`) pair to MHz.
///
/// `channelNumber` is `NSInteger` (isize) per the binding; we narrow to
/// `u32` because every legal channel fits. Returns `None` when the
/// channel number is negative (unrepresentable as `u32`) or when the
/// `CWChannelBand` is unknown to us — surfacing `None` to consumers
/// rather than a misleading `Some(0)`.
fn channel_to_mhz(channel: isize, band: objc2_core_wlan::CWChannelBand) -> Option<u32> {
    use objc2_core_wlan::CWChannelBand;
    let channel = u32::try_from(channel).ok()?;
    match band {
        CWChannelBand::Band2GHz => {
            // 2.4 GHz: ch 14 = 2484, otherwise 2407 + 5*ch (so ch 1 = 2412).
            if channel == 14 {
                Some(2484)
            } else {
                Some(2407 + 5 * channel)
            }
        }
        CWChannelBand::Band5GHz => Some(5000 + 5 * channel),
        CWChannelBand::Band6GHz => Some(5950 + 5 * channel),
        _ => None,
    }
}

#[cfg(test)]
mod parser_tests {
    use super::security_from_cw_set;
    use crate::types::SecurityFlags;
    use objc2_core_wlan::CWSecurity;

    #[test]
    fn open_network() {
        let s = security_from_cw_set(&[CWSecurity::None]);
        assert_eq!(s, SecurityFlags::OPEN);
    }

    #[test]
    fn wpa2_psk() {
        let s = security_from_cw_set(&[CWSecurity::WPA2Personal]);
        assert_eq!(s, SecurityFlags::WPA2_PSK);
    }

    #[test]
    fn wpa3_personal_maps_to_sae() {
        let s = security_from_cw_set(&[CWSecurity::WPA3Personal]);
        assert_eq!(s, SecurityFlags::WPA3_SAE);
    }

    #[test]
    fn transition_mode_yields_both_bits() {
        let s = security_from_cw_set(&[CWSecurity::WPA2Personal, CWSecurity::WPA3Personal]);
        assert_eq!(s, SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE);
    }

    #[test]
    fn wpa3_transition_alone_yields_wpa2_psk_and_wpa3_sae() {
        // CWSecurity::WPA3Transition denotes a BSS that simultaneously
        // advertises WPA2-PSK + WPA3-SAE. Reporting only WPA3_SAE would
        // hide the legacy capability and confuse callers selecting auth
        // methods.
        let s = security_from_cw_set(&[CWSecurity::WPA3Transition]);
        assert!(s.contains(SecurityFlags::WPA2_PSK));
        assert!(s.contains(SecurityFlags::WPA3_SAE));
    }

    #[test]
    fn personal_alone_yields_all_personal_bits() {
        // CWSecurity::Personal is a generic any-personal flag; mapping
        // it to a single specific variant would lose information. The
        // expected behavior is the union of WPA / WPA2 / WPA3 personal.
        let s = security_from_cw_set(&[CWSecurity::Personal]);
        assert!(s.contains(SecurityFlags::WPA_PSK));
        assert!(s.contains(SecurityFlags::WPA2_PSK));
        assert!(s.contains(SecurityFlags::WPA3_SAE));
    }

    #[test]
    fn enterprise_modes() {
        let s = security_from_cw_set(&[CWSecurity::WPA2Enterprise]);
        assert_eq!(s, SecurityFlags::WPA2_ENTERPRISE);
        let s = security_from_cw_set(&[CWSecurity::WPA3Enterprise]);
        assert_eq!(s, SecurityFlags::WPA3_ENTERPRISE);
    }

    #[test]
    fn owe_open_is_owe_only_not_open() {
        // OWE BSSes do not set the privacy bit but advertise an OWE IE.
        // Per spec, the parser must pick OWE alone, not OPEN | OWE.
        let s = security_from_cw_set(&[CWSecurity::OWE]);
        assert_eq!(s, SecurityFlags::OWE);
        assert!(!s.contains(SecurityFlags::OPEN));
    }

    #[test]
    fn none_plus_owe_yields_owe_only() {
        let s = security_from_cw_set(&[CWSecurity::None, CWSecurity::OWE]);
        assert_eq!(s, SecurityFlags::OWE);
        assert!(!s.contains(SecurityFlags::OPEN));
    }

    #[test]
    fn parse_bssid_round_trip() {
        use super::parse_bssid;
        assert_eq!(
            parse_bssid("11:22:33:44:55:66"),
            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        );
        assert_eq!(
            parse_bssid("AA:BB:CC:DD:EE:FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
    }

    #[test]
    fn parse_bssid_rejects_malformed() {
        use super::parse_bssid;
        assert!(parse_bssid("").is_none());
        assert!(parse_bssid("11:22:33:44:55").is_none()); // too few octets
        assert!(parse_bssid("11:22:33:44:55:66:77").is_none()); // too many
        assert!(parse_bssid("zz:22:33:44:55:66").is_none()); // bad hex
    }

    #[test]
    fn channel_to_mhz_2_4_ghz() {
        use super::channel_to_mhz;
        use objc2_core_wlan::CWChannelBand;
        assert_eq!(channel_to_mhz(1, CWChannelBand::Band2GHz), Some(2412));
        assert_eq!(channel_to_mhz(6, CWChannelBand::Band2GHz), Some(2437));
        assert_eq!(channel_to_mhz(11, CWChannelBand::Band2GHz), Some(2462));
        // Channel 14 is the special case (Japan-only).
        assert_eq!(channel_to_mhz(14, CWChannelBand::Band2GHz), Some(2484));
    }

    #[test]
    fn channel_to_mhz_5_ghz() {
        use super::channel_to_mhz;
        use objc2_core_wlan::CWChannelBand;
        assert_eq!(channel_to_mhz(36, CWChannelBand::Band5GHz), Some(5180));
        assert_eq!(channel_to_mhz(165, CWChannelBand::Band5GHz), Some(5825));
    }

    #[test]
    fn channel_to_mhz_6_ghz() {
        use super::channel_to_mhz;
        use objc2_core_wlan::CWChannelBand;
        assert_eq!(channel_to_mhz(1, CWChannelBand::Band6GHz), Some(5955));
        assert_eq!(channel_to_mhz(233, CWChannelBand::Band6GHz), Some(7115));
    }

    #[test]
    fn channel_to_mhz_unknown_band_yields_none() {
        use super::channel_to_mhz;
        use objc2_core_wlan::CWChannelBand;
        // CWChannelBand::BandUnknown maps to None per design — frequency_mhz
        // is None rather than a misleading Some(0).
        assert_eq!(channel_to_mhz(1, CWChannelBand::BandUnknown), None);
    }

    #[test]
    fn channel_to_mhz_negative_channel_yields_none() {
        use super::channel_to_mhz;
        use objc2_core_wlan::CWChannelBand;
        assert_eq!(channel_to_mhz(-1, CWChannelBand::Band2GHz), None);
    }
}
