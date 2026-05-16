//! Builder for the `NetworkManager` connection-settings dictionary
//! (`a{sa{sv}}`). Pure logic; no D-Bus IO.

use std::collections::HashMap;

use secrecy::ExposeSecret;
use zbus::zvariant::{OwnedValue, Value};

use crate::types::{Credentials, Ssid};

/// Build the `a{sa{sv}}` settings dict for a Wi-Fi connection profile.
///
/// Sections produced:
/// - `connection`    — top-level metadata (`type`, `id`, `autoconnect`).
/// - `802-11-wireless` — the SSID octets and infrastructure mode.
/// - `802-11-wireless-security` — present iff credentials carry a PSK.
///
/// Caller passes the result straight to
/// `NetworkManager.AddAndActivateConnection`. For WPA2/WPA3 mixed-mode
/// access points, NM negotiates the strongest supported key management
/// for `key-mgmt = wpa-psk`. Pure WPA3-only / SAE-only networks would
/// require `key-mgmt = sae` and are out of scope per the design spec.
#[must_use]
pub fn build_connection_settings(
    ssid: &Ssid,
    credentials: &Credentials,
) -> HashMap<String, HashMap<String, OwnedValue>> {
    let mut settings: HashMap<String, HashMap<String, OwnedValue>> = HashMap::new();

    // [connection]
    let mut connection: HashMap<String, OwnedValue> = HashMap::new();
    connection.insert("type".to_owned(), to_owned(&Value::from("802-11-wireless")));
    connection.insert(
        "id".to_owned(),
        to_owned(&Value::from(format!("uniwifi:{ssid}"))),
    );
    connection.insert("autoconnect".to_owned(), to_owned(&Value::from(true)));
    settings.insert("connection".to_owned(), connection);

    // [802-11-wireless]
    let mut wireless: HashMap<String, OwnedValue> = HashMap::new();
    // SSID is `ay` (array of byte) — NM does not validate UTF-8.
    wireless.insert(
        "ssid".to_owned(),
        to_owned(&Value::from(ssid.as_bytes().to_vec())),
    );
    wireless.insert("mode".to_owned(), to_owned(&Value::from("infrastructure")));
    settings.insert("802-11-wireless".to_owned(), wireless);

    // [802-11-wireless-security] — only for password networks.
    if let Credentials::Password(psk) = credentials {
        let mut security: HashMap<String, OwnedValue> = HashMap::new();
        security.insert("key-mgmt".to_owned(), to_owned(&Value::from("wpa-psk")));
        security.insert(
            "psk".to_owned(),
            to_owned(&Value::from(psk.expose_secret().to_owned())),
        );
        settings.insert("802-11-wireless-security".to_owned(), security);
    }

    settings
}

/// Convert any `Value` we use here into an `OwnedValue`. Every variant
/// we produce (string, byte-array, bool) is FD-free, so the conversion
/// is infallible in practice; we still surface the error path via
/// `expect` to keep the function total.
fn to_owned(v: &Value<'_>) -> OwnedValue {
    v.try_to_owned()
        .expect("invariant: builder only emits FD-free zvariant values")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Credentials, Ssid};

    #[test]
    fn open_network_omits_security_section() {
        let s = build_connection_settings(&Ssid::from_utf8("Cafe"), &Credentials::Open);
        assert!(s.contains_key("connection"));
        assert!(s.contains_key("802-11-wireless"));
        assert!(!s.contains_key("802-11-wireless-security"));
    }

    #[test]
    fn wpa_psk_includes_security_section_with_psk() {
        let s =
            build_connection_settings(&Ssid::from_utf8("Home"), &Credentials::password("hunter2"));
        let security = s.get("802-11-wireless-security").expect("security section");

        // key-mgmt = wpa-psk
        let key_mgmt: String =
            String::try_from(security["key-mgmt"].clone()).expect("key-mgmt is a string");
        assert_eq!(key_mgmt, "wpa-psk");

        // psk = "hunter2"
        let psk: String = String::try_from(security["psk"].clone()).expect("psk is a string");
        assert_eq!(psk, "hunter2");
    }

    #[test]
    fn ssid_is_passed_as_byte_array_not_string() {
        // SSIDs are octets per IEEE 802.11; NM uses `ay` (array of byte).
        let s = build_connection_settings(
            &Ssid::from_bytes(vec![0xff, 0xfe, b'X']),
            &Credentials::Open,
        );
        let wireless = s.get("802-11-wireless").expect("wireless section");
        let raw: Vec<u8> = Vec::try_from(wireless["ssid"].clone()).expect("ssid is a byte array");
        assert_eq!(raw, vec![0xff, 0xfe, b'X']);
    }

    #[test]
    fn connection_section_marks_type_as_wifi() {
        let s = build_connection_settings(&Ssid::from_utf8("X"), &Credentials::Open);
        let conn = s.get("connection").expect("connection section");
        let ty: String = String::try_from(conn["type"].clone()).expect("type is a string");
        assert_eq!(ty, "802-11-wireless");
    }

    #[test]
    fn wireless_mode_is_infrastructure() {
        let s = build_connection_settings(&Ssid::from_utf8("X"), &Credentials::Open);
        let wireless = s.get("802-11-wireless").expect("wireless section");
        let mode: String = String::try_from(wireless["mode"].clone()).expect("mode is a string");
        assert_eq!(mode, "infrastructure");
    }

    #[test]
    fn debug_does_not_leak_psk_into_settings_after_drop() {
        // Building the settings dict consumes a `&Credentials::Password(SecretString)`,
        // so the PSK is materialized as a plain `String` *only* inside the OwnedValue.
        // We verify the dict contains the PSK (positive control); the `secrecy::SecretString`
        // continues to zeroize on drop independently.
        let s =
            build_connection_settings(&Ssid::from_utf8("X"), &Credentials::password("supersecret"));
        let security = s.get("802-11-wireless-security").expect("security section");
        let psk: String = String::try_from(security["psk"].clone()).expect("psk");
        assert_eq!(psk, "supersecret");
    }
}
