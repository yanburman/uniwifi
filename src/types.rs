use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// Wi-Fi SSID. Stored as raw octets per IEEE 802.11; SSIDs are not guaranteed
/// to be valid UTF-8 (though in practice almost all are).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ssid(Vec<u8>);

impl Ssid {
    /// Build an `Ssid` from a UTF-8 string.
    ///
    /// This is the infallible inherent constructor. Length is **not**
    /// validated here; out-of-range values are clamped/rejected at the
    /// platform layer rather than panicking. Use [`Ssid::try_from_bytes`]
    /// if you need explicit IEEE 802.11 length validation.
    ///
    /// `Ssid` also implements [`std::str::FromStr`] (with `Err = Infallible`)
    /// for callers that want the trait-based API.
    ///
    /// The method is named `from_utf8` (rather than `from_str`) to avoid
    /// shadowing the `FromStr` trait method, since the trait requires a
    /// `Result` return type while this method is infallible.
    #[must_use]
    pub fn from_utf8(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Build an `Ssid` from raw octets without length validation.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Build an `Ssid`, rejecting empty or >32-byte inputs per IEEE 802.11.
    ///
    /// # Errors
    ///
    /// Returns [`SsidError::InvalidLength`] if `bytes.len()` is `0` or
    /// greater than `32`. Per IEEE 802.11, an SSID must be 1..=32 bytes.
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, SsidError> {
        if bytes.is_empty() || bytes.len() > 32 {
            return Err(SsidError::InvalidLength(bytes.len()));
        }
        Ok(Self(bytes))
    }

    /// Borrow the raw SSID octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the SSID as a `&str` if it is valid UTF-8.
    ///
    /// Returns `None` for SSIDs containing non-UTF-8 byte sequences
    /// (legal under IEEE 802.11 but rare in practice).
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl FromStr for Ssid {
    type Err = Infallible;

    /// Parse an `Ssid` from a UTF-8 string. Always succeeds (the parsing
    /// itself cannot fail; length validation is handled separately by
    /// [`Ssid::try_from_bytes`]).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.as_bytes().to_vec()))
    }
}

impl fmt::Debug for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "Ssid({s:?})"),
            None => write!(f, "Ssid({:02x?})", self.0),
        }
    }
}

impl fmt::Display for Ssid {
    /// SSIDs that are valid UTF-8 print verbatim. Non-UTF-8 SSIDs print as
    /// `<hex:0102ff>` so the output is parseable, round-trippable, and
    /// distinguishable from a UTF-8 SSID that happens to look like a Rust
    /// debug-format byte slice (e.g. `[ff, 01]`). The wrapper also makes
    /// the rendered SSID safe to embed in error messages without
    /// ambiguity.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(s) = self.as_str() {
            f.write_str(s)
        } else {
            f.write_str("<hex:")?;
            for b in &self.0 {
                write!(f, "{b:02x}")?;
            }
            f.write_str(">")
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SsidError {
    #[error("ssid length {0} is outside the valid range 1..=32")]
    InvalidLength(usize),
}

/// Opaque, platform-stable identifier for a Wi-Fi adapter.
///
/// The internal representation is a string that is stable for the lifetime
/// of the OS install:
/// - **Windows:** the WLAN interface GUID (e.g. `"{00000000-...}"`).
/// - **macOS:** the BSD name (e.g. `"en0"`).
/// - **Android / iOS:** the synthetic single-adapter id `"wlan0"` / `"en0"`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AdapterId(String);

impl AdapterId {
    /// Wrap a backend-supplied identifier string in an `AdapterId`.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the underlying identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AdapterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Knobs for `connect` / `connect_with_stored_credentials`.
#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    /// `None` means "platform default", which the crate interprets as
    /// 30 seconds for the overall operation including the optional
    /// pre-flight scan.
    pub timeout: Option<Duration>,
}

impl ConnectOptions {
    /// Resolve the timeout, falling back to the platform default of 30s
    /// when [`ConnectOptions::timeout`] is `None`.
    #[must_use]
    pub fn effective_timeout(&self) -> Duration {
        self.timeout.unwrap_or(Duration::from_secs(30))
    }
}

use secrecy::SecretString;

/// Authentication material for a connection attempt.
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Open network (no authentication).
    Open,
    /// WPA2/WPA3 Personal passphrase. Held in a `SecretString` so that
    /// `Debug` does not leak the password and the buffer is zeroized on drop.
    Password(SecretString),
}

impl Credentials {
    /// Convenience constructor for password-protected networks.
    pub fn password(pw: impl Into<String>) -> Self {
        Self::Password(SecretString::new(pw.into().into_boxed_str()))
    }
}

#[cfg(test)]
mod ssid_tests {
    use super::*;

    #[test]
    fn from_utf8_round_trips_ascii() {
        let s = Ssid::from_utf8("MyAccessPoint");
        assert_eq!(s.as_bytes(), b"MyAccessPoint");
        assert_eq!(s.as_str().unwrap(), "MyAccessPoint");
    }

    #[test]
    fn from_str_trait_round_trips_ascii() {
        let s: Ssid = "MyAccessPoint".parse().unwrap();
        assert_eq!(s.as_bytes(), b"MyAccessPoint");
    }

    #[test]
    fn from_bytes_accepts_non_utf8() {
        let s = Ssid::from_bytes(vec![0xff, 0xfe]);
        assert_eq!(s.as_bytes(), &[0xff, 0xfe]);
        assert!(s.as_str().is_none());
    }

    #[test]
    fn rejects_empty_or_oversized() {
        assert!(Ssid::try_from_bytes(vec![]).is_err());
        assert!(Ssid::try_from_bytes(vec![0; 33]).is_err());
        assert!(Ssid::try_from_bytes(vec![0; 32]).is_ok());
    }

    #[test]
    fn debug_does_not_panic_on_non_utf8() {
        let s = Ssid::from_bytes(vec![0xff]);
        let _ = format!("{s:?}");
    }
}

#[cfg(test)]
mod adapter_id_tests {
    use super::*;

    #[test]
    fn round_trips_string() {
        let id = AdapterId::new("wlan0");
        assert_eq!(id.as_str(), "wlan0");
        assert_eq!(format!("{id}"), "wlan0");
    }
}

#[cfg(test)]
mod connect_options_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn default_timeout_is_none_meaning_platform_default() {
        let opts = ConnectOptions::default();
        assert_eq!(opts.timeout, None);
    }

    #[test]
    fn effective_timeout_falls_back_when_unset() {
        let opts = ConnectOptions::default();
        assert_eq!(opts.effective_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn effective_timeout_uses_explicit_value() {
        let opts = ConnectOptions {
            timeout: Some(Duration::from_secs(5)),
        };
        assert_eq!(opts.effective_timeout(), Duration::from_secs(5));
    }
}

#[cfg(test)]
mod credentials_tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn open_variant_has_no_secret() {
        let c = Credentials::Open;
        assert!(matches!(c, Credentials::Open));
    }

    #[test]
    fn password_holds_secret() {
        let c = Credentials::password("hunter2");
        match &c {
            Credentials::Password(s) => assert_eq!(s.expose_secret(), "hunter2"),
            Credentials::Open => panic!("wrong variant"),
        }
    }

    #[test]
    fn debug_does_not_leak_password() {
        let c = Credentials::password("supersecret");
        let formatted = format!("{c:?}");
        assert!(!formatted.contains("supersecret"));
    }
}

bitflags::bitflags! {
    /// Security modes the AP advertises in beacons / probe responses.
    /// Multiple bits can be set when an SSID is broadcast under a
    /// transition mode (e.g. `WPA2_PSK | WPA3_SAE`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct SecurityFlags: u16 {
        const OPEN              = 1 << 0;
        const WEP               = 1 << 1;
        const WPA_PSK           = 1 << 2;
        const WPA2_PSK          = 1 << 3;
        const WPA3_SAE          = 1 << 4;
        const WPA2_ENTERPRISE   = 1 << 5;
        const WPA3_ENTERPRISE   = 1 << 6;
        const OWE               = 1 << 7;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Band {
    Ghz2_4,
    Ghz5,
    Ghz6,
}

/// Options controlling a `list_visible_networks` call.
///
/// `force_rescan` is best-effort: macOS honors it (cached vs active
/// scan), Windows honors it via `WlanScan` + scan-complete notification,
/// Linux and Android may rate-limit / throttle and silently fall through
/// to cached results.
#[derive(Clone, Debug, Default)]
pub struct ScanOptions {
    pub force_rescan: bool,
}

/// One Wi-Fi network visible to a `WifiAdapter`, rolled up across all
/// observed BSSes broadcasting the same SSID.
///
/// Returned by `WifiAdapter::list_visible_networks`.
#[derive(Clone, Debug)]
pub struct VisibleNetwork {
    pub ssid: Ssid,
    pub signal_quality: u8,
    pub security: SecurityFlags,
    pub bss_count: u32,
    pub is_connected: bool,
    pub has_saved_profile: bool,
    pub rssi_dbm: Option<i16>,
    pub bssid: Option<[u8; 6]>,
    pub frequency_mhz: Option<u32>,
}

impl VisibleNetwork {
    /// Band derived from `frequency_mhz`. `None` iff `frequency_mhz` is
    /// `None` or falls outside the recognised 2.4 / 5 / 6 GHz windows.
    #[must_use]
    pub fn band(&self) -> Option<Band> {
        self.frequency_mhz
            .and_then(crate::scan_rollup::band_from_mhz)
    }
}

#[cfg(test)]
mod scan_types_tests {
    use super::*;

    #[test]
    fn security_flags_set_and_union() {
        let s = SecurityFlags::WPA2_PSK | SecurityFlags::WPA3_SAE;
        assert!(s.contains(SecurityFlags::WPA2_PSK));
        assert!(s.contains(SecurityFlags::WPA3_SAE));
        assert!(!s.contains(SecurityFlags::OPEN));
    }

    #[test]
    fn security_flags_default_is_empty() {
        let s = SecurityFlags::empty();
        assert!(s.is_empty());
    }

    #[test]
    fn band_variants_are_distinct() {
        assert_ne!(Band::Ghz2_4, Band::Ghz5);
        assert_ne!(Band::Ghz5, Band::Ghz6);
    }

    #[test]
    fn scan_options_default_is_no_force_rescan() {
        let opts = ScanOptions::default();
        assert!(!opts.force_rescan);
    }

    fn make_network(frequency_mhz: Option<u32>) -> VisibleNetwork {
        VisibleNetwork {
            ssid: Ssid::from_utf8("x"),
            signal_quality: 0,
            security: SecurityFlags::empty(),
            bss_count: 1,
            is_connected: false,
            has_saved_profile: false,
            rssi_dbm: None,
            bssid: None,
            frequency_mhz,
        }
    }

    #[test]
    fn band_is_none_when_frequency_is_none() {
        assert_eq!(make_network(None).band(), None);
    }

    #[test]
    fn band_2_4_ghz() {
        assert_eq!(make_network(Some(2412)).band(), Some(Band::Ghz2_4));
        assert_eq!(make_network(Some(2484)).band(), Some(Band::Ghz2_4));
    }

    #[test]
    fn band_5_ghz() {
        assert_eq!(make_network(Some(5180)).band(), Some(Band::Ghz5));
        assert_eq!(make_network(Some(5825)).band(), Some(Band::Ghz5));
    }

    #[test]
    fn band_6_ghz() {
        assert_eq!(make_network(Some(5955)).band(), Some(Band::Ghz6));
        assert_eq!(make_network(Some(7115)).band(), Some(Band::Ghz6));
    }

    #[test]
    fn band_out_of_range_yields_none() {
        assert_eq!(make_network(Some(1000)).band(), None);
        assert_eq!(make_network(Some(8000)).band(), None);
    }

    #[test]
    fn ssid_display_utf8_prints_verbatim() {
        let s = Ssid::from_utf8("home");
        assert_eq!(format!("{s}"), "home");
    }

    #[test]
    fn ssid_display_non_utf8_uses_hex_wrapper() {
        let s = Ssid::from_bytes(vec![0xff, 0x01, 0xfe]);
        assert_eq!(format!("{s}"), "<hex:ff01fe>");
    }

    #[test]
    fn ssid_display_empty_uses_hex_wrapper() {
        let s = Ssid::from_bytes(vec![]);
        assert_eq!(format!("{s}"), "");
    }
}
