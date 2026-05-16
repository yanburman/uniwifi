//! `remove_profile` implementation. Wraps `WlanDeleteProfile`.

use std::sync::Arc;

use windows::Win32::NetworkManagement::WiFi::WlanDeleteProfile;
use windows::core::{GUID, PCWSTR};

use crate::error::Error;
use crate::platform::windows::connect::to_wide;
use crate::platform::windows::handle::WlanClient;
use crate::platform::windows::util::Win32Error;

/// Delete a profile by name.
///
/// Returns `Ok(true)` if the profile existed and was deleted, `Ok(false)`
/// if it did not exist.
///
/// # Errors
///
/// Returns `Error::Os(_)` for any Win32 status other than `ERROR_SUCCESS`
/// or `ERROR_NOT_FOUND`.
pub async fn run_remove_profile(
    client: Arc<WlanClient>,
    interface: GUID,
    profile_name: &str,
) -> Result<bool, Error> {
    const ERROR_NOT_FOUND: u32 = 0x490;
    let name_wide = to_wide(profile_name);
    let result = tokio::task::spawn_blocking(move || {
        // SAFETY: handle/interface/name_wide live across the call.
        unsafe {
            WlanDeleteProfile(
                client.handle(),
                &raw const interface,
                PCWSTR(name_wide.as_ptr()),
                Some(std::ptr::null::<core::ffi::c_void>()),
            )
        }
    })
    .await;

    let code =
        result.map_err(|e| Error::Os(Box::new(std::io::Error::other(format!("join: {e}")))))?;

    match code {
        0 => Ok(true),
        ERROR_NOT_FOUND => Ok(false),
        other => Err(Error::Os(Box::new(Win32Error {
            function: "WlanDeleteProfile",
            code: other,
        }))),
    }
}
