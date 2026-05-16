//! `connect` and `connect_with_stored_credentials` implementations.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use tokio::time::timeout;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::WiFi::{
    WLAN_CONNECTION_PARAMETERS, WlanConnect, WlanDisconnect, WlanSetProfile,
    dot11_BSS_type_infrastructure, wlan_connection_mode_profile,
};
use windows::core::{GUID, PCWSTR};

use crate::error::Error;
use crate::platform::windows::handle::WlanClient;
use crate::platform::windows::notifications::{Dispatcher, PendingConnectGuard};
use crate::platform::windows::profile_xml::{build_open_profile, build_wpa2_psk_profile};
use crate::platform::windows::util::check_win32;
use crate::types::{Credentials, Ssid};

/// Convert a Rust `&str` into a NUL-terminated UTF-16 vector.
#[must_use]
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Install (or overwrite) a profile.
///
/// # Errors
///
/// Returns `Error::Os(_)` if `WlanSetProfile` reports failure.
pub fn install_profile(client: &WlanClient, interface: GUID, xml: &str) -> Result<(), Error> {
    let xml_wide = to_wide(xml);
    let mut reason_code: u32 = 0;
    // SAFETY: pointers all live for the duration of the call; pszProfileXml
    // is a NUL-terminated wide string.
    let code = unsafe {
        WlanSetProfile(
            client.handle(),
            &raw const interface,
            0, // dwFlags
            PCWSTR(xml_wide.as_ptr()),
            PCWSTR::null(), // strAllUserProfileSecurity
            true,           // bOverwrite (binding accepts `bool` and converts via `.into()`)
            Some(std::ptr::null::<core::ffi::c_void>()),
            &raw mut reason_code,
        )
    };
    check_win32("WlanSetProfile", WIN32_ERROR(code))?;
    if reason_code != 0 {
        return Err(Error::Os(Box::new(
            crate::platform::windows::reason::WlanReasonError(reason_code),
        )));
    }
    Ok(())
}

/// Build and issue `WlanConnect` against an already-installed profile.
///
/// # Errors
///
/// Returns `Error::Os(_)` for an immediate Win32 failure of `WlanConnect`.
pub fn issue_connect(
    client: &WlanClient,
    interface: GUID,
    profile_name_wide: &[u16],
) -> Result<(), Error> {
    let params = WLAN_CONNECTION_PARAMETERS {
        wlanConnectionMode: wlan_connection_mode_profile,
        strProfile: PCWSTR(profile_name_wide.as_ptr()),
        pDot11Ssid: std::ptr::null_mut(),
        pDesiredBssidList: std::ptr::null_mut(),
        dot11BssType: dot11_BSS_type_infrastructure,
        dwFlags: 0,
    };
    // SAFETY: `params` lives across the call; pointer fields point into our
    // local buffer for the duration.
    let code = unsafe {
        WlanConnect(
            client.handle(),
            &raw const interface,
            &raw const params,
            Some(std::ptr::null::<core::ffi::c_void>()),
        )
    };
    check_win32("WlanConnect", WIN32_ERROR(code))
}

/// Best-effort `WlanDisconnect`.
///
/// # Errors
///
/// Returns `Error::Os(_)` if `WlanDisconnect` fails.
pub fn issue_disconnect(client: &WlanClient, interface: GUID) -> Result<(), Error> {
    // SAFETY: handle valid, interface valid, reserved null.
    let code = unsafe {
        WlanDisconnect(
            client.handle(),
            &raw const interface,
            Some(std::ptr::null::<core::ffi::c_void>()),
        )
    };
    check_win32("WlanDisconnect", WIN32_ERROR(code))
}

/// `WindowsBackend::connect` body. Caller has already acquired the
/// per-adapter mutex.
///
/// # Errors
///
/// Maps Win32 / reason-code failures into our typed `Error` enum.
pub async fn run_connect(
    client: Arc<WlanClient>,
    dispatcher: Arc<Dispatcher>,
    interface: GUID,
    ssid: &Ssid,
    credentials: &Credentials,
    deadline: Duration,
) -> Result<(), Error> {
    let xml = match credentials {
        Credentials::Open => build_open_profile(ssid),
        Credentials::Password(secret) => build_wpa2_psk_profile(ssid, secret.expose_secret()),
    };

    let client_for_blocking = Arc::clone(&client);
    let xml_owned = xml;
    tokio::task::spawn_blocking(move || {
        install_profile(&client_for_blocking, interface, &xml_owned)
    })
    .await
    .map_err(|e| Error::Os(Box::new(std::io::Error::other(format!("join: {e}")))))??;

    let rx = dispatcher.pending_connect(interface);
    // Cancel-on-drop guard. If the future is dropped (timeout, select!,
    // or any caller-side cancellation) the registry entry is removed
    // before a late notification can fire it for a subsequent connect.
    // On the normal completion path the entry is already gone (the
    // dispatcher took it to fire the tx), so the guard's Drop is a
    // no-op.
    let _connect_guard = PendingConnectGuard::new(Arc::clone(&dispatcher), interface);

    let profile_name = profile_name_from_ssid(ssid);
    let profile_wide = to_wide(&profile_name);
    let client_for_connect = Arc::clone(&client);
    let rs = tokio::task::spawn_blocking(move || {
        issue_connect(&client_for_connect, interface, &profile_wide)
    })
    .await
    .map_err(|e| Error::Os(Box::new(std::io::Error::other(format!("join: {e}")))))?;
    rs?;

    let outcome = match timeout(deadline, rx).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_recv_err)) => {
            return Err(Error::Os(Box::new(std::io::Error::other(
                "wlan notification channel closed unexpectedly",
            ))));
        }
        Err(_) => {
            let _ = tokio::task::spawn_blocking(move || issue_disconnect(&client, interface)).await;
            return Err(Error::Timeout(deadline));
        }
    };

    outcome.into_result()
}

fn profile_name_from_ssid(ssid: &Ssid) -> String {
    String::from_utf8_lossy(ssid.as_bytes()).into_owned()
}

use windows::Win32::NetworkManagement::WiFi::{WlanFreeMemory, WlanGetProfile};
use windows::core::PWSTR;

/// Test whether a profile with `name` exists on `interface`.
///
/// # Errors
///
/// Returns `Error::Os(_)` for any Win32 status other than `ERROR_SUCCESS`
/// or `ERROR_NOT_FOUND`.
pub fn profile_exists(client: &WlanClient, interface: GUID, name: &str) -> Result<bool, Error> {
    const ERROR_NOT_FOUND: u32 = 0x490;
    let name_wide = to_wide(name);
    let mut profile_xml: PWSTR = PWSTR::null();
    let mut flags: u32 = 0;
    let mut access: u32 = 0;
    // SAFETY: handle/interface/name_wide live across the call.
    let code = unsafe {
        WlanGetProfile(
            client.handle(),
            &raw const interface,
            PCWSTR(name_wide.as_ptr()),
            Some(std::ptr::null::<core::ffi::c_void>()),
            &raw mut profile_xml,
            Some(&raw mut flags),
            Some(&raw mut access),
        )
    };
    if !profile_xml.is_null() {
        // SAFETY: `profile_xml` was returned by `WlanGetProfile` on success.
        unsafe { WlanFreeMemory(profile_xml.0.cast::<core::ffi::c_void>()) };
    }
    match code {
        0 => Ok(true),
        ERROR_NOT_FOUND => Ok(false),
        other => Err(Error::Os(Box::new(
            crate::platform::windows::util::Win32Error {
                function: "WlanGetProfile",
                code: other,
            },
        ))),
    }
}

/// Run a stored-credentials connect.
///
/// # Errors
///
/// - `Error::NoStoredCredentials(_)` if no profile is installed for `ssid`.
/// - mapped errors from `connect::run_connect` otherwise.
pub async fn run_connect_stored(
    client: Arc<WlanClient>,
    dispatcher: Arc<Dispatcher>,
    interface: GUID,
    ssid: &Ssid,
    deadline: Duration,
) -> Result<(), Error> {
    let name = profile_name_from_ssid(ssid);
    let client_check = Arc::clone(&client);
    let name_check = name.clone();
    let exists =
        tokio::task::spawn_blocking(move || profile_exists(&client_check, interface, &name_check))
            .await
            .map_err(|e| Error::Os(Box::new(std::io::Error::other(format!("join: {e}")))))??;

    if !exists {
        return Err(Error::NoStoredCredentials(ssid.to_string()));
    }

    let rx = dispatcher.pending_connect(interface);
    // See `run_connect` for the rationale on the cancel-on-drop guard.
    let _connect_guard = PendingConnectGuard::new(Arc::clone(&dispatcher), interface);
    let profile_wide = to_wide(&name);
    let client_for_connect = Arc::clone(&client);
    let issued = tokio::task::spawn_blocking(move || {
        issue_connect(&client_for_connect, interface, &profile_wide)
    })
    .await
    .map_err(|e| Error::Os(Box::new(std::io::Error::other(format!("join: {e}")))))?;
    issued?;

    let outcome = match tokio::time::timeout(deadline, rx).await {
        Ok(Ok(o)) => o,
        Ok(Err(_)) => {
            return Err(Error::Os(Box::new(std::io::Error::other(
                "wlan notification channel closed unexpectedly",
            ))));
        }
        Err(_) => {
            let _ = tokio::task::spawn_blocking(move || issue_disconnect(&client, interface)).await;
            return Err(Error::Timeout(deadline));
        }
    };

    outcome.into_result()
}
