//! Windows `(DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGORITHM)` →
//! `SecurityFlags` translation. Pure function; isolated from the OS-call
//! layer for unit-test coverage.

use windows::Win32::NetworkManagement::WiFi::{
    DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_AUTH_ALGO_OWE,
    DOT11_AUTH_ALGO_RSNA, DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA_NONE,
    DOT11_AUTH_ALGO_WPA_PSK, DOT11_AUTH_ALGO_WPA3, DOT11_AUTH_ALGO_WPA3_ENT,
    DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGO_NONE, DOT11_CIPHER_ALGORITHM,
};

use crate::types::SecurityFlags;

/// Map Windows auth/cipher pair to portable `SecurityFlags`.
///
/// `windows = "0.62"` exposes WPA3 / OWE constants symbolically
/// (`DOT11_AUTH_ALGO_WPA3`, `_WPA3_SAE`, `_WPA3_ENT`, `_OWE`) so we match
/// them directly. Note that `DOT11_AUTH_ALGO_WPA3` and the legacy alias
/// `DOT11_AUTH_ALGO_WPA3_ENT_192` share the same integer (`8`); only one
/// of them can appear as a match arm. We keep `_WPA3` as the canonical
/// WPA3-Enterprise (192-bit suite) arm and add `_WPA3_ENT` (`11`) for
/// the newer plain WPA3-Enterprise constant. Both map to
/// `WPA3_ENTERPRISE`.
#[must_use]
pub(super) fn security_from_auth_cipher(
    auth: DOT11_AUTH_ALGORITHM,
    cipher: DOT11_CIPHER_ALGORITHM,
) -> SecurityFlags {
    match auth {
        DOT11_AUTH_ALGO_80211_OPEN if cipher == DOT11_CIPHER_ALGO_NONE => SecurityFlags::OPEN,
        // Some adapters report 80211_OPEN with a WEP cipher to denote
        // "WEP open system" — treat that as WEP rather than OPEN.
        DOT11_AUTH_ALGO_80211_OPEN | DOT11_AUTH_ALGO_80211_SHARED_KEY => SecurityFlags::WEP,
        DOT11_AUTH_ALGO_WPA | DOT11_AUTH_ALGO_WPA_NONE | DOT11_AUTH_ALGO_WPA_PSK => {
            SecurityFlags::WPA_PSK
        }
        DOT11_AUTH_ALGO_RSNA => SecurityFlags::WPA2_ENTERPRISE,
        DOT11_AUTH_ALGO_RSNA_PSK => SecurityFlags::WPA2_PSK,
        DOT11_AUTH_ALGO_WPA3 | DOT11_AUTH_ALGO_WPA3_ENT => SecurityFlags::WPA3_ENTERPRISE,
        DOT11_AUTH_ALGO_WPA3_SAE => SecurityFlags::WPA3_SAE,
        DOT11_AUTH_ALGO_OWE => SecurityFlags::OWE,
        _ => SecurityFlags::empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::{SecurityFlags, security_from_auth_cipher};
    use windows::Win32::NetworkManagement::WiFi::{
        DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_OWE, DOT11_AUTH_ALGO_RSNA_PSK,
        DOT11_AUTH_ALGO_WPA3_ENT_192, DOT11_AUTH_ALGO_WPA3_SAE, DOT11_CIPHER_ALGO_CCMP,
        DOT11_CIPHER_ALGO_NONE, DOT11_CIPHER_ALGO_WEP,
    };

    #[test]
    fn open_no_cipher() {
        assert_eq!(
            security_from_auth_cipher(DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_NONE),
            SecurityFlags::OPEN
        );
    }

    #[test]
    fn open_with_wep_cipher_is_wep() {
        // Some adapters report 80211_OPEN + WEP cipher as a "WEP open
        // system" arrangement.
        assert_eq!(
            security_from_auth_cipher(DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_WEP),
            SecurityFlags::WEP
        );
    }

    #[test]
    fn wpa2_psk() {
        assert_eq!(
            security_from_auth_cipher(DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_CCMP),
            SecurityFlags::WPA2_PSK
        );
    }

    #[test]
    fn wpa3_sae() {
        assert_eq!(
            security_from_auth_cipher(DOT11_AUTH_ALGO_WPA3_SAE, DOT11_CIPHER_ALGO_CCMP),
            SecurityFlags::WPA3_SAE
        );
    }

    #[test]
    fn owe() {
        assert_eq!(
            security_from_auth_cipher(DOT11_AUTH_ALGO_OWE, DOT11_CIPHER_ALGO_CCMP),
            SecurityFlags::OWE
        );
    }

    /// Lock down the documented SDK collision: `DOT11_AUTH_ALGO_WPA3` and
    /// `DOT11_AUTH_ALGO_WPA3_ENT_192` share integer value 8, so the same
    /// match arm covers both. This test pins down that the `_ENT_192`
    /// alias still maps to `WPA3_ENTERPRISE` via the shared discriminant.
    #[test]
    fn wpa3_ent_192_alias_maps_to_enterprise() {
        assert_eq!(
            security_from_auth_cipher(DOT11_AUTH_ALGO_WPA3_ENT_192, DOT11_CIPHER_ALGO_CCMP),
            SecurityFlags::WPA3_ENTERPRISE
        );
    }
}
