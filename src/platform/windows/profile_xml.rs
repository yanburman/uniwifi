//! Profile XML builder for `WlanSetProfile`.
//!
//! See:
//! - WPA2-Personal sample: <https://learn.microsoft.com/en-us/windows/win32/nativewifi/wpa2-personal-profile-sample>
//! - Profile schema namespace: `http://www.microsoft.com/networking/WLAN/profile/v1`

use std::fmt::Write as _;

use crate::types::Ssid;

/// XML namespace declared by `WlanSetProfile` schema v1.
const NS: &str = "http://www.microsoft.com/networking/WLAN/profile/v1";

/// Build a temporary WPA2-PSK profile.
///
/// `passphrase` must be 8..=63 printable ASCII characters per IEEE 802.11i.
/// Length validation is the caller's responsibility; this function only
/// produces XML.
#[must_use]
pub fn build_wpa2_psk_profile(ssid: &Ssid, passphrase: &str) -> String {
    let name = profile_name(ssid);
    let escaped_name = xml_escape(&name);
    let escaped_pass = xml_escape(passphrase);
    let ssid_inner = ssid_inner_xml(ssid);

    format!(
        r#"<?xml version="1.0" encoding="US-ASCII"?>
<WLANProfile xmlns="{NS}">
  <name>{escaped_name}</name>
  <SSIDConfig>
    <SSID>
      {ssid_inner}
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <autoSwitch>false</autoSwitch>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{escaped_pass}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>"#
    )
}

/// Build a temporary open (no-auth) profile.
#[must_use]
pub fn build_open_profile(ssid: &Ssid) -> String {
    let name = profile_name(ssid);
    let escaped_name = xml_escape(&name);
    let ssid_inner = ssid_inner_xml(ssid);

    format!(
        r#"<?xml version="1.0" encoding="US-ASCII"?>
<WLANProfile xmlns="{NS}">
  <name>{escaped_name}</name>
  <SSIDConfig>
    <SSID>
      {ssid_inner}
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <autoSwitch>false</autoSwitch>
  <MSM>
    <security>
      <authEncryption>
        <authentication>open</authentication>
        <encryption>none</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
    </security>
  </MSM>
</WLANProfile>"#
    )
}

/// Choose the `<name>` text used as the profile name.
///
/// We use a lossy UTF-8 decode of the SSID bytes. Windows allows a wide
/// range of characters here; for non-UTF-8 SSIDs the lossy form lets us
/// still round-trip with `WlanDeleteProfile` later.
fn profile_name(ssid: &Ssid) -> String {
    String::from_utf8_lossy(ssid.as_bytes()).into_owned()
}

/// Build the inner XML of `<SSID>`.
///
/// For UTF-8 SSIDs we emit `<name>...</name>` (Windows can match it against
/// scan results). For non-UTF-8 SSIDs we emit `<hex>...</hex>` plus a
/// best-effort `<name>` (Windows requires a printable name; we use the lossy
/// decode).
fn ssid_inner_xml(ssid: &Ssid) -> String {
    std::str::from_utf8(ssid.as_bytes()).map_or_else(
        |_| {
            let lossy = String::from_utf8_lossy(ssid.as_bytes()).into_owned();
            let hex = bytes_to_upper_hex(ssid.as_bytes());
            format!(
                "<name>{name}</name>\n      <hex>{hex}</hex>",
                name = xml_escape(&lossy),
            )
        },
        |s| format!("<name>{}</name>", xml_escape(s)),
    )
}

fn bytes_to_upper_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
    out
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssid(s: &str) -> Ssid {
        Ssid::from_utf8(s)
    }

    #[test]
    fn wpa2_psk_includes_authentication_and_key() {
        let xml = build_wpa2_psk_profile(&ssid("Office"), "tea4two");
        assert!(xml.contains("<name>Office</name>"));
        assert!(xml.contains("<authentication>WPA2PSK</authentication>"));
        assert!(xml.contains("<encryption>AES</encryption>"));
        assert!(xml.contains("<keyType>passPhrase</keyType>"));
        assert!(xml.contains("<protected>false</protected>"));
        assert!(xml.contains("<keyMaterial>tea4two</keyMaterial>"));
        assert!(xml.contains("xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\""));
    }

    #[test]
    fn open_profile_omits_shared_key_block() {
        let xml = build_open_profile(&ssid("Hotspot"));
        assert!(xml.contains("<authentication>open</authentication>"));
        assert!(xml.contains("<encryption>none</encryption>"));
        assert!(!xml.contains("<sharedKey>"));
        assert!(!xml.contains("keyMaterial"));
    }

    #[test]
    fn xml_special_chars_in_ssid_are_escaped() {
        let xml = build_wpa2_psk_profile(&ssid("A&B<C>\"D'"), "pw");
        assert!(xml.contains("A&amp;B&lt;C&gt;&quot;D&apos;"));
        assert!(!xml.contains("A&B<C>"));
    }

    #[test]
    fn xml_special_chars_in_passphrase_are_escaped() {
        let xml = build_wpa2_psk_profile(&ssid("Net"), "p&w<x>\"'");
        assert!(xml.contains("p&amp;w&lt;x&gt;&quot;&apos;"));
    }

    #[test]
    fn non_utf8_ssid_is_hex_encoded_in_ssid_hex_block() {
        // SSIDs containing non-UTF-8 bytes use the <hex> child of <SSID>
        // instead of <name>. The profile <name> still uses the lossy UTF-8
        // form (since profile names must be a valid Windows string).
        let raw = Ssid::from_bytes(vec![0xff, 0x41, 0x42]); // 0xFF + "AB"
        let xml = build_wpa2_psk_profile(&raw, "pw");
        assert!(xml.contains("<hex>FF4142</hex>"));
        // The profile <name> is the lossy decode (replacement char + AB).
        assert!(xml.contains("<name>") && xml.contains("AB"));
    }
}
