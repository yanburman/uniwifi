//! `connect` and `connect_with_stored_credentials` (Task 11).

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::error::Error;
use crate::preflight::{ScanOutcome, wait_until_ssid_visible};
use crate::types::{AdapterId, ConnectOptions, Credentials, Ssid};

use super::adapters::resolve_device_path;
use super::backend::NmHandles;
use super::error_map::from_zbus;
use super::proxies::SettingsConnectionProxy;
use super::scan::LinuxScanProvider;
use super::settings::build_connection_settings;
use super::state_wait::wait_for_active_connection;

/// Connect with explicit credentials. Saves the connection profile by
/// default (`NetworkManager` behavior of `AddAndActivateConnection`),
/// matching the Windows/macOS saved-profile semantics from the design
/// spec.
///
/// # Errors
///
/// - [`Error::AdapterNotFound`] — the adapter id does not resolve to a
///   `NetworkManager` device.
/// - [`Error::SsidNotInRange`] — the SSID was not visible during the
///   pre-flight scan and the activation failed (or auth failed).
/// - [`Error::AuthenticationFailed`] — `NetworkManager` reported an
///   authentication failure (wrong key, EAP failure, etc.).
/// - [`Error::Timeout`] — the active connection did not reach a terminal
///   state within the configured timeout.
/// - `Error::PermissionDenied("polkit")` — the caller lacks the polkit
///   privileges to add/activate connections.
/// - [`Error::Os`] — an unmapped D-Bus or system error occurred.
pub async fn connect_with_credentials(
    handles: &NmHandles,
    adapter: &AdapterId,
    ssid: &Ssid,
    credentials: &Credentials,
    options: &ConnectOptions,
) -> Result<(), Error> {
    let timeout = options.effective_timeout();

    // 1. Resolve the device path.
    let device_path = resolve_device_path(handles, adapter).await?;

    // 2. Pre-flight scan. `NotVisible` promotes a later AuthFailed to
    //    `SsidNotInRange`. `Skipped` (e.g., NM permission errors) is
    //    benign.
    let provider = LinuxScanProvider { handles, adapter };
    let preflight = wait_until_ssid_visible(&provider, ssid, timeout / 4).await;

    // 3. Build settings dict and call `AddAndActivateConnection`. The
    //    proxy signature takes owned types directly; zbus serializes
    //    `OwnedValue` as the same `v` variant wire format that the
    //    NM `a{sa{sv}}` schema expects.
    let settings = build_connection_settings(ssid, credentials);

    let empty_specific =
        ObjectPath::try_from("/").expect("invariant: \"/\" is a valid root object path");

    let activate_result = handles
        .network_manager
        .add_and_activate_connection(settings, &device_path.as_ref(), &empty_specific)
        .await;

    let (_connection_path, active_path): (OwnedObjectPath, OwnedObjectPath) = match activate_result
    {
        Ok(pair) => pair,
        Err(e) => {
            // If we never saw the SSID in the pre-flight scan, promote
            // the typed error to `SsidNotInRange`.
            if matches!(preflight, ScanOutcome::NotVisible) {
                return Err(Error::SsidNotInRange);
            }
            return Err(from_zbus(e));
        }
    };

    // 4. Wait for the active connection to reach ACTIVATED / DEACTIVATED.
    match wait_for_active_connection(handles, &active_path, timeout).await {
        Ok(()) => Ok(()),
        Err(Error::AuthenticationFailed) if matches!(preflight, ScanOutcome::NotVisible) => {
            Err(Error::SsidNotInRange)
        }
        Err(other) => Err(other),
    }
}

/// Activate a previously-saved `NetworkManager` profile by SSID. Any
/// saved connection counts (including ones the user added through the
/// GUI).
///
/// Walks `Settings.ListConnections`, calls `Connection.GetSettings` on
/// each entry, and matches the requested SSID against the
/// `802-11-wireless.ssid` byte-array. The first match is activated via
/// `NetworkManager.ActivateConnection`.
///
/// # Errors
///
/// - [`Error::AdapterNotFound`] — the adapter id does not resolve to a
///   `NetworkManager` device.
/// - [`Error::NoStoredCredentials`] — no saved profile matches the
///   requested SSID.
/// - [`Error::AuthenticationFailed`] — `NetworkManager` reported an
///   authentication failure during activation.
/// - [`Error::Timeout`] — the active connection did not reach a
///   terminal state within the configured timeout.
/// - [`Error::Os`] — an unmapped D-Bus or system error occurred.
pub async fn connect_with_stored(
    handles: &NmHandles,
    adapter: &AdapterId,
    ssid: &Ssid,
    options: &ConnectOptions,
) -> Result<(), Error> {
    let timeout = options.effective_timeout();
    let device_path = resolve_device_path(handles, adapter).await?;

    let connection_paths = handles
        .settings
        .list_connections()
        .await
        .map_err(from_zbus)?;

    let mut matched: Option<OwnedObjectPath> = None;
    for path in connection_paths {
        let conn = SettingsConnectionProxy::builder(&handles.conn)
            .path(path.clone())
            .map_err(from_zbus)?
            .build()
            .await
            .map_err(from_zbus)?;

        // A connection that disappears mid-walk is benign.
        let Ok(settings) = conn.get_settings().await else {
            continue;
        };

        let Some(wireless) = settings.get("802-11-wireless") else {
            continue;
        };
        let Some(ssid_value) = wireless.get("ssid") else {
            continue;
        };
        let Ok(ssid_bytes) = Vec::<u8>::try_from(ssid_value.clone()) else {
            continue;
        };

        if ssid_bytes == ssid.as_bytes() {
            matched = Some(path);
            break;
        }
    }

    let connection_path = matched.ok_or_else(|| Error::NoStoredCredentials(ssid.to_string()))?;

    let empty_specific =
        ObjectPath::try_from("/").expect("invariant: \"/\" is a valid root object path");

    // NOTE: Task 10 found that the activate_connection /
    // add_and_activate_connection proxy methods require an extra `&`
    // prefix because `OwnedObjectPath::as_ref()` returns
    // `ObjectPath<'_>` by value, not by reference.
    let active_path = handles
        .network_manager
        .activate_connection(
            &connection_path.as_ref(),
            &device_path.as_ref(),
            &empty_specific,
        )
        .await
        .map_err(from_zbus)?;

    wait_for_active_connection(handles, &active_path, timeout).await
}
