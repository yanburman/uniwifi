//! RAII wrapper around the Native Wifi client handle.
//!
//! `WlanClient` owns the handle returned by `WlanOpenHandle`; its `Drop` impl
//! calls `WlanCloseHandle`. All other windows-backend modules borrow the
//! `HANDLE` via `WlanClient::handle()` rather than touching the raw FFI.

use core::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::{
    WLAN_API_VERSION_2_0, WlanCloseHandle, WlanOpenHandle,
};

use crate::error::Error;
use crate::platform::windows::util::check_win32;

/// Owns a `WlanOpenHandle` session.
///
/// `WlanClient` is `Send + Sync` because the handle is thread-safe per
/// MSDN: callbacks dispatched by `WlanRegisterNotification` may run on
/// arbitrary thread-pool threads concurrently with calls from other
/// threads.
pub struct WlanClient {
    handle: HANDLE,
}

// SAFETY: The WLAN client handle is documented as thread-safe; multiple
// threads may invoke `Wlan*` functions on the same handle concurrently.
// See https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanopenhandle
unsafe impl Send for WlanClient {}
// SAFETY: see Send impl above.
unsafe impl Sync for WlanClient {}

impl WlanClient {
    /// Open a new client handle.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os(_)` if `WlanOpenHandle` fails (e.g., the
    /// `WlanSvc` service is stopped or access is denied).
    pub fn new() -> Result<Self, Error> {
        let mut negotiated_version: u32 = 0;
        let mut handle: HANDLE = HANDLE::default();
        // SAFETY: We pass valid stack pointers; `pReserved` is required to be
        // null. The handle is initialized only on success.
        let code = unsafe {
            WlanOpenHandle(
                WLAN_API_VERSION_2_0,
                Some(ptr::null::<c_void>()),
                &raw mut negotiated_version,
                &raw mut handle,
            )
        };
        check_win32(
            "WlanOpenHandle",
            windows::Win32::Foundation::WIN32_ERROR(code),
        )?;
        Ok(Self { handle })
    }

    /// Borrow the underlying `HANDLE`.
    #[must_use]
    pub const fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: `self.handle` was returned by a successful `WlanOpenHandle`
            // and has not been closed elsewhere.
            unsafe {
                let _ = WlanCloseHandle(self.handle, Some(ptr::null::<c_void>()));
            }
        }
    }
}
