//! `disconnect` and `remove_profile` for the Linux backend.

use crate::error::Error;
use crate::types::{AdapterId, Ssid};

use super::adapters::resolve_device_path;
use super::backend::NmHandles;
use super::error_map::from_zbus;
use super::proxies::{AccessPointProxy, ActiveConnectionProxy, SettingsConnectionProxy};

/// Find the active connection on `adapter` whose Wi-Fi SSID matches and
/// call `DeactivateConnection`. Idempotent: returns `Ok(())` if no
/// matching active connection exists.
///
/// # Errors
///
/// - [`Error::AdapterNotFound`] — the adapter id does not resolve to a
///   `NetworkManager` device.
/// - `Error::PermissionDenied("polkit")` — the caller lacks the polkit
///   privileges to deactivate connections.
/// - [`Error::Os`] — an unmapped D-Bus or system error occurred.
pub async fn disconnect_ssid(
    handles: &NmHandles,
    adapter: &AdapterId,
    ssid: &Ssid,
) -> Result<(), Error> {
    let device_path = resolve_device_path(handles, adapter).await?;
    let actives = handles
        .network_manager
        .active_connections()
        .await
        .map_err(from_zbus)?;

    for active_path in actives {
        let active = ActiveConnectionProxy::builder(&handles.conn)
            .path(active_path.clone())
            .map_err(from_zbus)?
            .build()
            .await
            .map_err(from_zbus)?;

        // First filter: this active connection must be bound to the
        // adapter the caller asked about. Connections that disappear
        // mid-walk are benign — skip them.
        let Ok(devices) = active.devices().await else {
            continue;
        };
        if !devices.iter().any(|d| d.as_str() == device_path.as_str()) {
            continue;
        }

        // Second filter: `SpecificObject` is the AP path. "/" means
        // "not yet known" (e.g., still activating); skip.
        let Ok(specific) = active.specific_object().await else {
            continue;
        };
        if specific.as_str() == "/" {
            continue;
        }

        let ap = AccessPointProxy::builder(&handles.conn)
            .path(specific)
            .map_err(from_zbus)?
            .build()
            .await
            .map_err(from_zbus)?;

        let Ok(ap_ssid) = ap.ssid().await else {
            continue;
        };
        if ap_ssid != ssid.as_bytes() {
            continue;
        }

        return handles
            .network_manager
            .deactivate_connection(&active_path.as_ref())
            .await
            .map_err(from_zbus);
    }

    Ok(())
}

/// Find the saved connection profile whose `802-11-wireless.ssid`
/// matches and call `Connection.Delete`. Returns `Ok(true)` if a
/// profile was deleted, `Ok(false)` if none existed.
///
/// # Errors
///
/// - `Error::PermissionDenied("polkit")` — the caller lacks the polkit
///   privileges to delete saved connections.
/// - [`Error::Os`] — an unmapped D-Bus or system error occurred.
pub async fn remove_profile_for_ssid(
    handles: &NmHandles,
    _adapter: &AdapterId,
    ssid: &Ssid,
) -> Result<bool, Error> {
    let connection_paths = handles
        .settings
        .list_connections()
        .await
        .map_err(from_zbus)?;

    for path in connection_paths {
        let conn = SettingsConnectionProxy::builder(&handles.conn)
            .path(path.clone())
            .map_err(from_zbus)?
            .build()
            .await
            .map_err(from_zbus)?;

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
            conn.delete().await.map_err(from_zbus)?;
            return Ok(true);
        }
    }

    Ok(false)
}
