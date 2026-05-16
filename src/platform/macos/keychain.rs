//! Wi-Fi keychain operations.
//!
//! Wraps `CWKeychainDeleteWiFiPassword` from `CoreWLAN`'s util layer.
//! `CoreWLAN` addresses the underlying `genp` keychain item with the same
//! attributes that `Keychain Access.app` shows (kSecAttrService =
//! `"AirPort"`, kSecAttrAccount = `<SSID>`), so we don't need a second
//! keychain crate.

use objc2_core_wlan::{CWKeychainDeleteWiFiPassword, CWKeychainDomain};
use objc2_foundation::NSData;

use crate::error::Error;
use crate::types::Ssid;

/// `errSecSuccess` from <Security/SecBase.h>.
const ERR_SEC_SUCCESS: i32 = 0;
/// `errSecItemNotFound` from <Security/SecBase.h>.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
/// `errSecAuthFailed` from <Security/SecBase.h>.
const ERR_SEC_AUTH_FAILED: i32 = -25_293;

/// Delete the user-domain Wi-Fi password keychain entry for `ssid`.
///
/// Returns `Ok(true)` if an entry was deleted, `Ok(false)` if no entry
/// existed (the operation is then a no-op).
///
/// # Errors
/// - `Error::PermissionDenied("Keychain")` for `errSecAuthFailed` (-25293) —
///   the user may have denied keychain access.
/// - `Error::Os(...)` for any other non-success / non-not-found `OSStatus`.
pub(super) fn delete_wifi_password(ssid: &Ssid) -> Result<bool, Error> {
    let bytes = ssid.as_bytes();
    let data = NSData::with_bytes(bytes);

    // SAFETY: CWKeychainDeleteWiFiPassword takes the domain enum by value
    // and a borrowed NSData; both are valid and not used past the call.
    let status = unsafe { CWKeychainDeleteWiFiPassword(CWKeychainDomain::User, &data) };

    match status {
        ERR_SEC_SUCCESS => Ok(true),
        ERR_SEC_ITEM_NOT_FOUND => Ok(false),
        // Most authn-related OSStatus codes are -25293..=-25241; we map
        // -25293 ("authentication failed") to PermissionDenied so apps can
        // prompt the user to re-authorise. Other codes flow through as Os.
        ERR_SEC_AUTH_FAILED => Err(Error::PermissionDenied("Keychain")),
        other => Err(Error::Os(Box::<dyn std::error::Error + Send + Sync>::from(
            format!("CWKeychainDeleteWiFiPassword failed: OSStatus {other}"),
        ))),
    }
}

/// Returns `true` if a Wi-Fi keychain entry exists for `ssid`. Used by the
/// connect-with-stored-credentials path to disambiguate "wrong password"
/// from "no entry".
pub(super) fn keychain_entry_exists(ssid: &Ssid) -> bool {
    use objc2::rc::Retained;
    use objc2_core_wlan::CWKeychainFindWiFiPassword;
    use objc2_foundation::NSString;
    use std::ptr;

    let bytes = ssid.as_bytes();
    let data = NSData::with_bytes(bytes);
    let mut password_out: *mut NSString = ptr::null_mut();
    // SAFETY: `password_out` is a valid writable double-pointer to an
    // initialised null pointer; CWKeychainFindWiFiPassword either populates
    // it with a +1-retained NSString on success or leaves it null. We
    // reclaim ownership below to avoid a leak.
    let status =
        unsafe { CWKeychainFindWiFiPassword(CWKeychainDomain::User, &data, &raw mut password_out) };
    // SAFETY: We just received a (possibly null) +1-retained pointer from
    // the function; `Retained::from_raw` returns `None` for null and
    // otherwise transfers ownership back to Rust, which will release on
    // drop. We discard the result either way.
    drop(unsafe { Retained::from_raw(password_out) });
    status == ERR_SEC_SUCCESS
}
