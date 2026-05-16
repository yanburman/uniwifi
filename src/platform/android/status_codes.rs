//! `STATUS_NETWORK_SUGGESTIONS_*` (from `android.net.wifi.WifiManager`)
//! mapped to `crate::error::Error` variants.
//!
//! Constant values verified against AOSP `android-29` and extended with
//! later API levels:
//! - 0..=5 from `android-29` (`WifiManager.java`).
//! - 6..=8 added in API 30 / 31 / 33 (admin restrictions, user
//!   approval, carrier suggestion limits). Values picked from AOSP
//!   `frameworks/base/wifi/java/android/net/wifi/WifiManager.java`.

use crate::error::Error;

pub(super) const STATUS_NETWORK_SUGGESTIONS_SUCCESS: i32 = 0;
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL: i32 = 1;
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED: i32 = 2;
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE: i32 = 3;
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP: i32 = 4;
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID: i32 = 5;
/// API 30+: app declared a network with privileged permissions it does
/// not actually hold.
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED: i32 = 6;
/// API 30+: device-owner / profile-owner forbids suggestions.
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_RESTRICTED_BY_ADMIN: i32 = 7;
/// API 31+: app is not allowed to add carrier suggestions.
pub(super) const STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID: i32 = 8;

/// Maps a status code returned by `WifiManager.addNetworkSuggestions`.
pub(super) fn map_add_status(status: i32) -> Result<(), Error> {
    match status {
        STATUS_NETWORK_SUGGESTIONS_SUCCESS => Ok(()),
        STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL => Err(Error::Os(boxed_msg(
            "WifiManager add: STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL",
        ))),
        STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED
        | STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED
        | STATUS_NETWORK_SUGGESTIONS_ERROR_RESTRICTED_BY_ADMIN => Err(Error::PermissionDenied(
            "network suggestions disallowed for this app",
        )),
        STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE => {
            // The OS already has this suggestion. Treat as success: we
            // couldn't have registered it on a previous backend call
            // without caching it, but a stale registration from a prior
            // process is fine — the connect-and-wait loop downstream
            // confirms the actual association.
            Ok(())
        }
        STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP => Err(Error::Os(boxed_msg(
            "WifiManager add: STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP",
        ))),
        STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID => Err(Error::Os(boxed_msg(
            "WifiManager add: STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID",
        ))),
        // REMOVE_INVALID is only meaningful for remove; surface it as
        // an internal os error if it ever appears here.
        STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID => Err(Error::Os(boxed_msg(
            "WifiManager add: unexpected STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID",
        ))),
        other => Err(Error::Os(boxed_msg(format!(
            "WifiManager add: unknown status {other}"
        )))),
    }
}

/// Outcome of `WifiManager.removeNetworkSuggestions`.
///
/// `WasRemoved` covers the OS removed something. `NotPresent` covers
/// `STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID` — the OS-side
/// suggestion was already gone (process restart, OS-side eviction, race
/// with another remove), which is *not* a failure but is observable as
/// "we did not actually remove anything" for `remove_profile`'s `bool`
/// return.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RemoveOutcome {
    WasRemoved,
    NotPresent,
}

/// Maps a status code returned by `WifiManager.removeNetworkSuggestions`.
pub(super) fn map_remove_status(status: i32) -> Result<RemoveOutcome, Error> {
    match status {
        STATUS_NETWORK_SUGGESTIONS_SUCCESS => Ok(RemoveOutcome::WasRemoved),
        STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID => Ok(RemoveOutcome::NotPresent),
        STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL => Err(Error::Os(boxed_msg(
            "WifiManager remove: STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL",
        ))),
        STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED
        | STATUS_NETWORK_SUGGESTIONS_ERROR_RESTRICTED_BY_ADMIN => Err(Error::PermissionDenied(
            "network suggestions disallowed for this app",
        )),
        other => Err(Error::Os(boxed_msg(format!(
            "WifiManager remove: unknown status {other}"
        )))),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct StatusErr(String);

fn boxed_msg<S: Into<String>>(s: S) -> crate::error::BoxedOsError {
    Box::new(StatusErr(s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_success_is_ok() {
        assert!(map_add_status(STATUS_NETWORK_SUGGESTIONS_SUCCESS).is_ok());
    }

    #[test]
    fn add_duplicate_is_ok() {
        assert!(map_add_status(STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE).is_ok());
    }

    #[test]
    fn add_app_disallowed_is_permission_denied() {
        let e = map_add_status(STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED).unwrap_err();
        assert!(matches!(e, Error::PermissionDenied(_)));
    }

    #[test]
    fn add_internal_is_os_error() {
        let e = map_add_status(STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL).unwrap_err();
        assert!(matches!(e, Error::Os(_)));
    }

    #[test]
    fn remove_success_is_was_removed() {
        let outcome = map_remove_status(STATUS_NETWORK_SUGGESTIONS_SUCCESS).unwrap();
        assert_eq!(outcome, RemoveOutcome::WasRemoved);
    }

    #[test]
    fn remove_invalid_is_not_present() {
        // The OS-side suggestion was already gone. Distinguishable from
        // success so `remove_profile` can return `Ok(false)` and the
        // contract holds.
        let outcome = map_remove_status(STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID).unwrap();
        assert_eq!(outcome, RemoveOutcome::NotPresent);
    }

    #[test]
    fn unknown_status_is_os_error() {
        assert!(matches!(map_add_status(999).unwrap_err(), Error::Os(_)));
        assert!(matches!(map_remove_status(999).unwrap_err(), Error::Os(_)));
    }

    #[test]
    fn add_restricted_by_admin_is_permission_denied() {
        let e = map_add_status(STATUS_NETWORK_SUGGESTIONS_ERROR_RESTRICTED_BY_ADMIN).unwrap_err();
        assert!(matches!(e, Error::PermissionDenied(_)));
    }
}
