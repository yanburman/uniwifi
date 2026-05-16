//! `disconnect` implementation. Honors the trait contract that
//! disconnect is a no-op when the interface is connected to a different
//! SSID than the one the caller asked for.

use std::ptr;
use std::sync::Arc;

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::WiFi::{
    WLAN_CONNECTION_ATTRIBUTES, WLAN_OPCODE_VALUE_TYPE, WlanFreeMemory, WlanQueryInterface,
    wlan_intf_opcode_current_connection,
};
use windows::core::GUID;

use crate::error::Error;
use crate::platform::windows::connect::issue_disconnect;
use crate::platform::windows::handle::WlanClient;
use crate::types::Ssid;

/// `WindowsBackend::disconnect` body. Caller holds the per-adapter mutex.
///
/// Compares the interface's currently-associated SSID against `ssid`
/// before issuing `WlanDisconnect`, per the trait contract: "calling it
/// when not connected to `ssid` is treated as a no-op success."
///
/// # Errors
///
/// Returns `Error::Os(_)` if `WlanQueryInterface` or `WlanDisconnect`
/// fails.
pub async fn run_disconnect(
    client: Arc<WlanClient>,
    interface: GUID,
    ssid: Ssid,
) -> Result<(), Error> {
    tokio::task::spawn_blocking(move || run_disconnect_blocking(&client, interface, &ssid))
        .await
        .map_err(|e| Error::Os(Box::new(std::io::Error::other(format!("join: {e}")))))?
}

fn run_disconnect_blocking(client: &WlanClient, interface: GUID, ssid: &Ssid) -> Result<(), Error> {
    let current = current_ssid(client, interface)?;
    match current {
        Some(c) if c.as_bytes() == ssid.as_bytes() => issue_disconnect(client, interface),
        // Either disconnected, or connected to a different SSID — treat
        // as a no-op success per the trait contract.
        _ => Ok(()),
    }
}

fn current_ssid(client: &WlanClient, interface: GUID) -> Result<Option<Ssid>, Error> {
    let mut data_size: u32 = 0;
    let mut data: *mut core::ffi::c_void = ptr::null_mut();
    let mut opcode_kind = WLAN_OPCODE_VALUE_TYPE::default();
    // SAFETY: handle/interface valid; out-pointers initialized; reserved null.
    let code = unsafe {
        WlanQueryInterface(
            client.handle(),
            &raw const interface,
            wlan_intf_opcode_current_connection,
            Some(ptr::null::<core::ffi::c_void>()),
            &raw mut data_size,
            &raw mut data,
            Some(&raw mut opcode_kind),
        )
    };
    if code != 0 || data.is_null() {
        // Disconnected or query failed (1168 = ERROR_NOT_FOUND on
        // disconnected adapters); treat both as "no current SSID" so the
        // caller's no-op success path triggers.
        if !data.is_null() {
            // SAFETY: matches the WLAN allocator.
            unsafe { WlanFreeMemory(data) };
        }
        if code == 0 {
            return Ok(None);
        }
        // For other error codes, surface the failure rather than silently
        // returning None — callers expect to know if the query itself
        // broke.
        return crate::platform::windows::util::check_win32(
            "WlanQueryInterface(current_connection)",
            WIN32_ERROR(code),
        )
        .map(|()| None);
    }
    // SAFETY: per MSDN, WlanQueryInterface with
    // wlan_intf_opcode_current_connection allocates a single
    // WLAN_CONNECTION_ATTRIBUTES into *ppData on success.
    let attrs: &WLAN_CONNECTION_ATTRIBUTES = unsafe { &*data.cast() };
    let dot11 = attrs.wlanAssociationAttributes.dot11Ssid;
    let len = dot11.uSSIDLength as usize;
    let s = if len > 0 && len <= dot11.ucSSID.len() {
        Some(Ssid::from_bytes(dot11.ucSSID[..len].to_vec()))
    } else {
        None
    };
    // SAFETY: matches the WLAN allocator.
    unsafe { WlanFreeMemory(data) };
    Ok(s)
}
