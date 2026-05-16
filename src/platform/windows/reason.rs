//! Map `WLAN_REASON_CODE` values into our typed `Error` variants.

use crate::error::{BoxedOsError, Error};

/// Numeric reason codes lifted from `wlanapi.h`.
mod codes {
    pub const SUCCESS: u32 = 0;

    // Automatic connection error codes.
    pub const NETWORK_NOT_AVAILABLE: u32 = 0x0002_8003;
    pub const NOT_VISIBLE: u32 = 0x0002_8002;
    pub const KEY_MISMATCH: u32 = 0x0002_800C;
    pub const PROFILE_CHANGED_OR_DELETED: u32 = 0x0002_800D;

    // MSM connection failure codes.
    pub const USER_CANCELLED: u32 = 0x0003_8001;
    pub const ASSOCIATION_TIMEOUT: u32 = 0x0003_8003;
    pub const SECURITY_FAILURE: u32 = 0x0003_8005;
    pub const SECURITY_TIMEOUT: u32 = 0x0003_8006;

    pub const PSK_MISMATCH_SUSPECTED: u32 = 0x0004_8011;
}

/// Convert a `WLAN_REASON_CODE` (raw `u32`) into `Result<(), Error>`.
///
/// # Errors
///
/// Returns the mapped `Error` variant for any non-success code.
pub fn map_reason_code(code: u32) -> Result<(), Error> {
    use codes::{
        ASSOCIATION_TIMEOUT, KEY_MISMATCH, NETWORK_NOT_AVAILABLE, NOT_VISIBLE,
        PROFILE_CHANGED_OR_DELETED, PSK_MISMATCH_SUSPECTED, SECURITY_FAILURE, SECURITY_TIMEOUT,
        SUCCESS, USER_CANCELLED,
    };

    match code {
        SUCCESS => Ok(()),
        PSK_MISMATCH_SUSPECTED | KEY_MISMATCH | SECURITY_FAILURE => {
            Err(Error::AuthenticationFailed)
        }
        NETWORK_NOT_AVAILABLE | NOT_VISIBLE | PROFILE_CHANGED_OR_DELETED => {
            Err(Error::SsidNotInRange)
        }
        USER_CANCELLED => Err(Error::UserCancelled),
        ASSOCIATION_TIMEOUT | SECURITY_TIMEOUT => {
            let boxed: BoxedOsError = Box::new(WlanReasonError(code));
            Err(Error::Os(boxed))
        }
        other => {
            let boxed: BoxedOsError = Box::new(WlanReasonError(other));
            Err(Error::Os(boxed))
        }
    }
}

#[derive(Debug)]
pub struct WlanReasonError(pub u32);

impl std::fmt::Display for WlanReasonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WLAN_REASON_CODE 0x{:08X}", self.0)
    }
}

impl std::error::Error for WlanReasonError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_ok() {
        assert!(map_reason_code(0).is_ok());
    }

    #[test]
    fn psk_mismatch_is_authentication_failed() {
        assert!(matches!(
            map_reason_code(codes::PSK_MISMATCH_SUSPECTED),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn network_not_available_is_ssid_not_in_range() {
        assert!(matches!(
            map_reason_code(codes::NETWORK_NOT_AVAILABLE),
            Err(Error::SsidNotInRange)
        ));
    }

    #[test]
    fn user_cancelled_is_user_cancelled() {
        assert!(matches!(
            map_reason_code(codes::USER_CANCELLED),
            Err(Error::UserCancelled)
        ));
    }

    #[test]
    fn unknown_code_is_os_error() {
        let err = map_reason_code(0xDEAD_BEEF).expect_err("expected error");
        assert!(matches!(err, Error::Os(_)));
        assert!(format!("{err}").contains("0xDEADBEEF"));
    }
}
