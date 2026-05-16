//! Mapping `NetworkManager` `D-Bus` errors and active-connection state
//! reasons to `crate::error::Error` variants.

use crate::error::{BoxedOsError, Error};

// === NMActiveConnectionStateReason values we care about. ===
// Reference: NMActiveConnectionStateReason in nm-dbus-types.h.
pub const REASON_USER_DISCONNECTED: u32 = 2;
// REASON_DEVICE_DISCONNECTED and REASON_CONNECT_TIMEOUT are documented
// here for completeness and consumed by Tasks 15/16; allow until wired up.
#[allow(dead_code)]
pub const REASON_DEVICE_DISCONNECTED: u32 = 3;
#[allow(dead_code)]
pub const REASON_CONNECT_TIMEOUT: u32 = 6;
pub const REASON_NO_SECRETS: u32 = 9;
pub const REASON_LOGIN_FAILED: u32 = 10;

/// Map a `D-Bus` error name to a typed `Error` variant. Returns `None` for
/// names the caller should surface as `Error::Os(...)`.
#[must_use]
pub fn map_dbus_error_name(name: &str) -> Option<Error> {
    // NM-side polkit denials end with `.PermissionDenied` /
    // `.NotAuthorized`; bus-level denials surface as
    // `org.freedesktop.DBus.Error.AccessDenied` (no suffix match) when
    // the system bus policy rejects the call. Both are user-actionable
    // permission failures, so we collapse them under PermissionDenied
    // with a stable static reason.
    if name.ends_with(".PermissionDenied")
        || name.ends_with(".NotAuthorized")
        || name == "org.freedesktop.DBus.Error.AccessDenied"
    {
        return Some(Error::PermissionDenied("polkit"));
    }
    None
}

/// Map an `NMActiveConnectionStateReason` to a typed `Error` variant.
/// Returns `None` if the reason has no specific mapping (caller should
/// surface as `Error::Os(...)` or a generic `AuthenticationFailed`).
#[must_use]
pub const fn map_state_reason(reason: u32) -> Option<Error> {
    match reason {
        REASON_NO_SECRETS | REASON_LOGIN_FAILED => Some(Error::AuthenticationFailed),
        REASON_USER_DISCONNECTED => Some(Error::UserCancelled),
        _ => None,
    }
}

/// Convert a `zbus::Error` into an `Error`. If the underlying `D-Bus`
/// error has a recognized name (`map_dbus_error_name`), return the typed
/// variant; otherwise wrap it as `Error::Os(...)`.
#[must_use]
pub fn from_zbus(err: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, _, _) = &err
        && let Some(typed) = map_dbus_error_name(name.as_str())
    {
        return typed;
    }
    Error::Os(Box::new(err) as BoxedOsError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn permission_denied_dbus_name_maps_to_polkit() {
        let e = map_dbus_error_name("org.freedesktop.NetworkManager.Settings.PermissionDenied");
        assert!(matches!(e, Some(Error::PermissionDenied("polkit"))));
    }

    #[test]
    fn not_authorized_dbus_name_maps_to_polkit() {
        let e = map_dbus_error_name("org.freedesktop.NetworkManager.NotAuthorized");
        assert!(matches!(e, Some(Error::PermissionDenied("polkit"))));
    }

    #[test]
    fn unknown_dbus_name_returns_none() {
        let e = map_dbus_error_name("org.freedesktop.SomethingElse");
        assert!(e.is_none());
    }

    #[test]
    fn dbus_access_denied_maps_to_polkit() {
        // System-bus-level denial (e.g. service-side policy reject) does
        // not have the NM-side suffix patterns; verify the explicit match.
        let e = map_dbus_error_name("org.freedesktop.DBus.Error.AccessDenied");
        assert!(matches!(e, Some(Error::PermissionDenied("polkit"))));
    }

    #[test]
    fn no_secrets_state_reason_maps_to_auth_failed() {
        let e = map_state_reason(REASON_NO_SECRETS);
        assert!(matches!(e, Some(Error::AuthenticationFailed)));
    }

    #[test]
    fn login_failed_state_reason_maps_to_auth_failed() {
        let e = map_state_reason(REASON_LOGIN_FAILED);
        assert!(matches!(e, Some(Error::AuthenticationFailed)));
    }

    #[test]
    fn user_disconnected_state_reason_maps_to_user_cancelled() {
        let e = map_state_reason(REASON_USER_DISCONNECTED);
        assert!(matches!(e, Some(Error::UserCancelled)));
    }

    #[test]
    fn connect_timeout_state_reason_maps_to_os_error_unknown_otherwise() {
        // CONNECT_TIMEOUT is intentionally not promoted — the caller's own
        // `effective_timeout()` deadline drives `Error::Timeout`. Any
        // residual NM-side timeout is surfaced as a generic Os error.
        let e = map_state_reason(REASON_CONNECT_TIMEOUT);
        assert!(e.is_none());
    }

    #[test]
    fn unknown_state_reason_returns_none() {
        let e = map_state_reason(9999);
        assert!(e.is_none());
    }
}
