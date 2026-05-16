//! Shared rollup, normalization, and ordering for `list_visible_networks`.
//!
//! Each backend produces `Vec<RawBss>` plus a `ScanContext`; this module
//! collapses them to `Vec<VisibleNetwork>` with the cross-cutting
//! invariants documented in the design (empty-SSID filtering, sort
//! ordering, security union).

use std::collections::{HashMap, HashSet};

use crate::types::{Band, SecurityFlags, Ssid, VisibleNetwork};

/// Per-BSS observation produced by a backend's `fetch_bsses` helper.
///
/// Declared `pub` (rather than `pub(crate)`) because this module is
/// already private (`mod scan_rollup;` in `lib.rs`), so `pub(crate)` here
/// would trip `clippy::redundant_pub_crate` from the `nursery` group.
pub struct RawBss {
    pub ssid: Ssid,
    pub security: SecurityFlags,
    pub rssi_dbm: Option<i16>,
    /// 0..=100. Backends compute via `quality_from_dbm` when they have
    /// dBm, or pass through the OS-reported quality directly.
    pub quality: u8,
    pub bssid: Option<[u8; 6]>,
    pub frequency_mhz: Option<u32>,
}

/// Per-adapter context that stamps each rolled-up entry.
pub struct ScanContext {
    pub connected_ssid: Option<Ssid>,
    pub saved_ssids: HashSet<Ssid>,
}

/// Microsoft's `wlanSignalQuality` formula: linearly map -100 dBm → 0
/// and -50 dBm → 100, clamped to `[0, 100]`.
///
/// Linux's `NetworkManager` already exposes a 0..=100 quality, so the
/// Linux backend doesn't reach for this helper. Gated to backends that
/// actually need it so `cargo clippy --target x86_64-unknown-linux-gnu`
/// doesn't trip the `dead_code` lint.
#[cfg(any(
    test,
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
))]
#[must_use]
pub fn quality_from_dbm(rssi_dbm: i16) -> u8 {
    let v = 2 * (i32::from(rssi_dbm) + 100);
    v.clamp(0, 100).try_into().expect("clamped to u8 range")
}

/// Map an operating frequency in MHz to a coarse band. `None` outside
/// the 2.4 / 5 / 6 GHz windows.
#[must_use]
pub const fn band_from_mhz(mhz: u32) -> Option<Band> {
    match mhz {
        2400..=2500 => Some(Band::Ghz2_4),
        4915..=5825 => Some(Band::Ghz5),
        5925..=7125 => Some(Band::Ghz6),
        _ => None,
    }
}

/// Roll up per-BSS observations into per-SSID `VisibleNetwork`s.
///
/// Invariants enforced here so backends cannot drift apart:
/// - Empty SSIDs (zero-byte) are filtered before aggregation.
/// - Within each SSID group, the strongest BSS determines the reported
///   `signal_quality`, `rssi_dbm`, `bssid`, and `frequency_mhz`. Ranking:
///   max `quality`, then known-`rssi_dbm` beats `None`, then greater
///   `rssi_dbm`, then observation order.
/// - `security` is the union across all BSSes broadcasting the SSID.
/// - `bss_count` is the number of (post-filter) BSSes in the group.
/// - Output is sorted by `signal_quality` descending; ties are broken by
///   SSID byte order so the order is deterministic.
pub fn rollup(bsses: Vec<RawBss>, ctx: &ScanContext) -> Vec<VisibleNetwork> {
    struct Acc {
        best_index: usize,
        best_quality: u8,
        best_rssi: Option<i16>,
        security_union: SecurityFlags,
        bss_count: u32,
    }

    let bsses: Vec<RawBss> = bsses
        .into_iter()
        .filter(|b| !b.ssid.as_bytes().is_empty())
        .collect();

    let mut by_ssid: HashMap<Ssid, Acc> = HashMap::new();
    for (i, bss) in bsses.iter().enumerate() {
        let entry = by_ssid.entry(bss.ssid.clone()).or_insert(Acc {
            best_index: i,
            best_quality: 0,
            best_rssi: None,
            security_union: SecurityFlags::empty(),
            bss_count: 0,
        });
        entry.bss_count += 1;
        entry.security_union |= bss.security;

        // At equal quality, prefer the BSS with a known rssi_dbm so the
        // resulting VisibleNetwork carries the more informative metadata
        // (bssid / frequency_mhz / rssi_dbm). Without this, a bare-cache
        // entry with rssi=None can shadow a freshly-scanned entry with a
        // real RSSI reading.
        let rssi_tiebreak = match (bss.rssi_dbm, entry.best_rssi) {
            (Some(_), None) => true,
            (Some(new), Some(old)) => new > old,
            (None, _) => false,
        };
        let is_better = bss.quality > entry.best_quality
            || (bss.quality == entry.best_quality && rssi_tiebreak);
        if entry.bss_count == 1 || is_better {
            entry.best_index = i;
            entry.best_quality = bss.quality;
            entry.best_rssi = bss.rssi_dbm;
        }
    }

    let mut out: Vec<VisibleNetwork> = by_ssid
        .into_values()
        .map(|acc| {
            let bss = &bsses[acc.best_index];
            VisibleNetwork {
                ssid: bss.ssid.clone(),
                signal_quality: acc.best_quality,
                security: acc.security_union,
                bss_count: acc.bss_count,
                is_connected: ctx.connected_ssid.as_ref() == Some(&bss.ssid),
                has_saved_profile: ctx.saved_ssids.contains(&bss.ssid),
                rssi_dbm: bss.rssi_dbm,
                bssid: bss.bssid,
                frequency_mhz: bss.frequency_mhz,
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.signal_quality
            .cmp(&a.signal_quality)
            .then_with(|| a.ssid.as_bytes().cmp(b.ssid.as_bytes()))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_clamps_low() {
        assert_eq!(quality_from_dbm(-101), 0);
        assert_eq!(quality_from_dbm(-200), 0);
    }

    #[test]
    fn quality_at_minus_100_is_zero() {
        assert_eq!(quality_from_dbm(-100), 0);
    }

    #[test]
    fn quality_at_minus_50_is_one_hundred() {
        assert_eq!(quality_from_dbm(-50), 100);
    }

    #[test]
    fn quality_clamps_high() {
        assert_eq!(quality_from_dbm(-30), 100);
        assert_eq!(quality_from_dbm(0), 100);
    }

    #[test]
    fn quality_midpoint() {
        assert_eq!(quality_from_dbm(-75), 50);
    }

    #[test]
    fn band_2_4() {
        assert_eq!(band_from_mhz(2412), Some(Band::Ghz2_4));
        assert_eq!(band_from_mhz(2484), Some(Band::Ghz2_4));
    }

    #[test]
    fn band_5() {
        assert_eq!(band_from_mhz(5180), Some(Band::Ghz5));
    }

    #[test]
    fn band_6() {
        assert_eq!(band_from_mhz(5955), Some(Band::Ghz6));
        assert_eq!(band_from_mhz(7115), Some(Band::Ghz6));
    }

    #[test]
    fn band_out_of_range() {
        assert_eq!(band_from_mhz(1000), None);
        assert_eq!(band_from_mhz(8000), None);
    }

    fn raw(ssid: &str, quality: u8, security: SecurityFlags, rssi: Option<i16>) -> RawBss {
        RawBss {
            ssid: Ssid::from_utf8(ssid),
            security,
            rssi_dbm: rssi,
            quality,
            bssid: None,
            frequency_mhz: None,
        }
    }

    fn empty_ctx() -> ScanContext {
        ScanContext {
            connected_ssid: None,
            saved_ssids: HashSet::new(),
        }
    }

    #[test]
    fn rollup_groups_by_ssid_and_keeps_strongest() {
        let bsses = vec![
            raw("home", 60, SecurityFlags::WPA2_PSK, Some(-70)),
            raw("home", 80, SecurityFlags::WPA2_PSK, Some(-60)),
            raw("home", 50, SecurityFlags::WPA2_PSK, Some(-75)),
        ];
        let out = rollup(bsses, &empty_ctx());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ssid.as_str(), Some("home"));
        assert_eq!(out[0].signal_quality, 80);
        assert_eq!(out[0].rssi_dbm, Some(-60));
        assert_eq!(out[0].bss_count, 3);
    }

    #[test]
    fn rollup_unions_security_flags() {
        let bsses = vec![
            raw("transition", 70, SecurityFlags::WPA2_PSK, None),
            raw("transition", 70, SecurityFlags::WPA3_SAE, None),
        ];
        let out = rollup(bsses, &empty_ctx());
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].security,
            SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE
        );
    }

    #[test]
    fn rollup_filters_empty_ssids() {
        let bsses = vec![
            RawBss {
                ssid: Ssid::from_bytes(vec![]),
                security: SecurityFlags::OPEN,
                rssi_dbm: None,
                quality: 100,
                bssid: None,
                frequency_mhz: None,
            },
            raw("real", 50, SecurityFlags::WPA2_PSK, None),
        ];
        let out = rollup(bsses, &empty_ctx());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ssid.as_str(), Some("real"));
    }

    #[test]
    fn rollup_returns_empty_for_all_empty_input() {
        let out = rollup(vec![], &empty_ctx());
        assert!(out.is_empty());
    }

    #[test]
    fn rollup_sort_is_quality_desc_then_ssid_asc() {
        let bsses = vec![
            raw("b_low", 30, SecurityFlags::OPEN, None),
            raw("a_high", 80, SecurityFlags::OPEN, None),
            raw("a_low", 30, SecurityFlags::OPEN, None),
            raw("c_high", 80, SecurityFlags::OPEN, None),
        ];
        let out = rollup(bsses, &empty_ctx());
        let names: Vec<_> = out.iter().map(|n| n.ssid.as_str().unwrap()).collect();
        assert_eq!(names, vec!["a_high", "c_high", "a_low", "b_low"]);
    }

    #[test]
    fn rollup_stamps_is_connected() {
        let bsses = vec![
            raw("home", 50, SecurityFlags::WPA2_PSK, None),
            raw("away", 50, SecurityFlags::WPA2_PSK, None),
        ];
        let ctx = ScanContext {
            connected_ssid: Some(Ssid::from_utf8("home")),
            saved_ssids: HashSet::new(),
        };
        let out = rollup(bsses, &ctx);
        let home = out
            .iter()
            .find(|n| n.ssid.as_str() == Some("home"))
            .unwrap();
        let away = out
            .iter()
            .find(|n| n.ssid.as_str() == Some("away"))
            .unwrap();
        assert!(home.is_connected);
        assert!(!away.is_connected);
    }

    #[test]
    fn rollup_stamps_has_saved_profile() {
        let bsses = vec![
            raw("saved", 50, SecurityFlags::WPA2_PSK, None),
            raw("new", 50, SecurityFlags::WPA2_PSK, None),
        ];
        let mut saved = HashSet::new();
        saved.insert(Ssid::from_utf8("saved"));
        let ctx = ScanContext {
            connected_ssid: None,
            saved_ssids: saved,
        };
        let out = rollup(bsses, &ctx);
        let s = out
            .iter()
            .find(|n| n.ssid.as_str() == Some("saved"))
            .unwrap();
        let n = out.iter().find(|n| n.ssid.as_str() == Some("new")).unwrap();
        assert!(s.has_saved_profile);
        assert!(!n.has_saved_profile);
    }

    #[test]
    fn rollup_equal_quality_prefers_known_rssi() {
        // At identical quality, a BSS reporting Some(rssi) should win over
        // a BSS reporting None so the resulting VisibleNetwork carries the
        // more informative metadata.
        let known_bssid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let bsses = vec![
            RawBss {
                ssid: Ssid::from_utf8("net"),
                security: SecurityFlags::WPA2_PSK,
                rssi_dbm: None,
                quality: 50,
                bssid: None,
                frequency_mhz: None,
            },
            RawBss {
                ssid: Ssid::from_utf8("net"),
                security: SecurityFlags::WPA2_PSK,
                rssi_dbm: Some(-65),
                quality: 50,
                bssid: Some(known_bssid),
                frequency_mhz: Some(2412),
            },
        ];
        let out = rollup(bsses, &empty_ctx());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rssi_dbm, Some(-65));
        assert_eq!(out[0].bssid, Some(known_bssid));
        assert_eq!(out[0].frequency_mhz, Some(2412));
    }

    #[test]
    fn rollup_strongest_preserves_bssid_freq() {
        let strong_bssid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let weak_bssid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let bsses = vec![
            RawBss {
                ssid: Ssid::from_utf8("net"),
                security: SecurityFlags::WPA2_PSK,
                rssi_dbm: Some(-80),
                quality: 40,
                bssid: Some(weak_bssid),
                frequency_mhz: Some(2412),
            },
            RawBss {
                ssid: Ssid::from_utf8("net"),
                security: SecurityFlags::WPA2_PSK,
                rssi_dbm: Some(-50),
                quality: 100,
                bssid: Some(strong_bssid),
                frequency_mhz: Some(5180),
            },
        ];
        let out = rollup(bsses, &empty_ctx());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].bssid, Some(strong_bssid));
        assert_eq!(out[0].frequency_mhz, Some(5180));
    }
}
