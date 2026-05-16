//! `list_adapters` — wrap `WlanEnumInterfaces`.

use core::ffi::c_void;
use std::ptr;
use std::slice;

use windows::Win32::NetworkManagement::WiFi::{
    WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WlanEnumInterfaces, WlanFreeMemory,
};

use crate::backend::AdapterInfo;
use crate::error::Error;
use crate::platform::windows::handle::WlanClient;
use crate::platform::windows::util::{check_win32, guid_to_adapter_id};

/// Enumerate Wi-Fi adapters known to the WLAN service.
///
/// # Errors
///
/// Returns `Error::Os(_)` if `WlanEnumInterfaces` fails.
pub fn list_adapters(client: &WlanClient) -> Result<Vec<AdapterInfo>, Error> {
    let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
    // SAFETY: `client.handle()` is a valid open handle; `pReserved` is null
    // per the API contract; the out pointer is properly initialized.
    let code = unsafe {
        WlanEnumInterfaces(
            client.handle(),
            Some(ptr::null::<c_void>()),
            &raw mut list_ptr,
        )
    };
    check_win32(
        "WlanEnumInterfaces",
        windows::Win32::Foundation::WIN32_ERROR(code),
    )?;

    if list_ptr.is_null() {
        return Ok(Vec::new());
    }

    // SAFETY: list_ptr is non-null and produced by WlanEnumInterfaces; the
    // OS guarantees `dwNumberOfItems` matches the trailing-array length.
    let result = unsafe { collect_adapters(list_ptr) };

    // SAFETY: `list_ptr` was allocated by the WLAN runtime; `WlanFreeMemory`
    // is the correct deallocator.
    unsafe { WlanFreeMemory(list_ptr.cast()) };

    Ok(result)
}

/// # Safety
///
/// Caller must guarantee `list_ptr` is a valid, non-null pointer to a
/// `WLAN_INTERFACE_INFO_LIST` produced by the WLAN service.
unsafe fn collect_adapters(list_ptr: *const WLAN_INTERFACE_INFO_LIST) -> Vec<AdapterInfo> {
    // SAFETY: caller upholds non-null + valid invariants.
    let header = unsafe { &*list_ptr };
    let n = header.dwNumberOfItems as usize;
    if n == 0 {
        return Vec::new();
    }

    // The trailing flexible array starts at `InterfaceInfo[0]`.
    let entries: &[WLAN_INTERFACE_INFO] =
        // SAFETY: `n` is bounded by `dwNumberOfItems` which the OS sets to
        // the actual number of trailing entries.
        unsafe { slice::from_raw_parts(header.InterfaceInfo.as_ptr(), n) };

    entries
        .iter()
        .map(|info| AdapterInfo {
            id: guid_to_adapter_id(&info.InterfaceGuid),
            name: utf16_to_string(&info.strInterfaceDescription),
        })
        .collect()
}

/// Decode a `[u16; N]` UTF-16 buffer (NUL-terminated) into a Rust `String`.
///
/// Stops at the first NUL or at the end of the buffer, whichever comes
/// first. Invalid surrogate pairs are replaced with `U+FFFD`.
fn utf16_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}
