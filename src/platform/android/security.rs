//! Android `ScanResult.capabilities` string → [`SecurityFlags`].
//!
//! `capabilities` is a concatenation of `[KEY-MGMT-CIPHER]` tokens plus
//! topology hints like `[ESS]`, `[WPS]`. We test each token for the
//! presence of `PSK`, `EAP`, `SAE`, `OWE` substrings independently, so:
//!  - 802.11r fast-transition variants (e.g. `[RSN-FT/SAE-CCMP]`) are
//!    classified by their key-management infix.
//!  - Plus-joined transition tokens (e.g. `[WPA2-PSK+SAE-CCMP]`) yield
//!    multiple [`SecurityFlags`] bits.

use crate::types::SecurityFlags;

#[must_use]
pub(super) fn security_from_capabilities(caps: &str) -> SecurityFlags {
    let mut out = SecurityFlags::empty();
    let mut saw_owe = false;
    let mut saw_any_ie = false;

    for token in caps.split('[').filter(|s| !s.is_empty()) {
        let token = token.trim_end_matches(']');

        // Skip topology / capability tokens that aren't security key-mgmt.
        if matches!(token, "ESS" | "IBSS" | "WPS" | "MFPC" | "MFPR" | "P2P") {
            continue;
        }
        saw_any_ie = true;

        // WEP is handled standalone (not a WPA/RSN family).
        if token.starts_with("WEP") {
            out |= SecurityFlags::WEP;
            continue;
        }

        // Determine which RSN/WPA family this token belongs to.
        // wpa_supplicant emits one of: WPA-, WPA2-, WPA3-, RSN-.
        // FT-roaming variants embed an `FT/` infix (e.g. RSN-FT/SAE-CCMP) —
        // we use `contains` for key-management names so those still match.
        // Plus-joined transition tokens (e.g. WPA2-PSK+SAE-CCMP) are also
        // handled because we test each key-mgmt substring independently.
        let is_legacy_wpa1 =
            token.starts_with("WPA-") && !token.starts_with("WPA2") && !token.starts_with("WPA3");
        let has_psk = token.contains("PSK");
        let has_eap = token.contains("EAP");
        let has_sae = token.contains("SAE");
        let has_owe = token.contains("OWE");

        if has_owe {
            out |= SecurityFlags::OWE;
            saw_owe = true;
        }
        if has_sae {
            out |= SecurityFlags::WPA3_SAE;
        }
        if has_psk {
            if is_legacy_wpa1 {
                out |= SecurityFlags::WPA_PSK;
            } else {
                out |= SecurityFlags::WPA2_PSK;
            }
        }
        if has_eap {
            // Both legacy WPA1-EAP and modern WPA2/WPA3-EAP roll into
            // WPA2_ENTERPRISE — SecurityFlags doesn't carry a WPA1-EAP
            // bit, and the design says enterprise modes are
            // informational only (the public Credentials type doesn't
            // support EAP).
            out |= SecurityFlags::WPA2_ENTERPRISE;
        }
        // SUITE-B and other rarities not modelled.
    }

    if !saw_any_ie {
        // No security IE → either truly open or non-security tokens only.
        out |= SecurityFlags::OPEN;
    }
    if saw_owe {
        out.remove(SecurityFlags::OPEN);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ess_only_means_open() {
        assert_eq!(security_from_capabilities("[ESS]"), SecurityFlags::OPEN);
    }

    #[test]
    fn empty_string_means_open() {
        assert_eq!(security_from_capabilities(""), SecurityFlags::OPEN);
    }

    #[test]
    fn wpa2_psk() {
        assert_eq!(
            security_from_capabilities("[WPA2-PSK-CCMP][ESS]"),
            SecurityFlags::WPA2_PSK
        );
    }

    #[test]
    fn legacy_wpa1_psk() {
        assert_eq!(
            security_from_capabilities("[WPA-PSK-TKIP][ESS]"),
            SecurityFlags::WPA_PSK
        );
    }

    #[test]
    fn transition_psk_plus_sae() {
        assert_eq!(
            security_from_capabilities("[WPA2-PSK-CCMP][RSN-SAE-CCMP][ESS]"),
            SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE
        );
    }

    #[test]
    fn enterprise() {
        assert_eq!(
            security_from_capabilities("[WPA2-EAP-CCMP][ESS]"),
            SecurityFlags::WPA2_ENTERPRISE
        );
    }

    #[test]
    fn wep() {
        assert_eq!(security_from_capabilities("[WEP][ESS]"), SecurityFlags::WEP);
    }

    #[test]
    fn owe_alone_not_open() {
        let s = security_from_capabilities("[RSN-OWE-CCMP][ESS]");
        assert_eq!(s, SecurityFlags::OWE);
        assert!(!s.contains(SecurityFlags::OPEN));
    }

    #[test]
    fn fast_transition_sae_classifies_as_wpa3() {
        let s = security_from_capabilities("[ESS][RSN-FT/SAE-CCMP]");
        assert_eq!(s, SecurityFlags::WPA3_SAE);
    }

    #[test]
    fn fast_transition_psk_classifies_as_wpa2() {
        let s = security_from_capabilities("[ESS][RSN-FT/PSK-CCMP]");
        assert_eq!(s, SecurityFlags::WPA2_PSK);
    }

    #[test]
    fn fast_transition_eap_classifies_as_enterprise() {
        let s = security_from_capabilities("[ESS][RSN-FT/EAP-SHA256-CCMP]");
        assert_eq!(s, SecurityFlags::WPA2_ENTERPRISE);
    }

    #[test]
    fn plus_joined_psk_sae_yields_both_bits() {
        let s = security_from_capabilities("[WPA2-PSK+SAE-CCMP][ESS]");
        assert_eq!(s, SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE);
    }
}
