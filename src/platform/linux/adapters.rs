//! Wi-Fi device enumeration and ifname-to-device-path resolution.

use zbus::zvariant::OwnedObjectPath;

use crate::backend::AdapterInfo;
use crate::error::Error;
use crate::types::AdapterId;

use super::backend::NmHandles;
use super::error_map::from_zbus;
use super::proxies::DeviceProxy;

/// `NMDeviceType::Wifi == 2`.
const NM_DEVICE_TYPE_WIFI: u32 = 2;

/// Enumerate every Wi-Fi `AdapterInfo` known to `NetworkManager`.
///
/// # Errors
///
/// Returns `Err` if the `D-Bus` `GetAllDevices` call fails, or if a
/// per-device `Interface` property read fails. A device that disappears
/// between `GetAllDevices` and the per-device property read is silently
/// skipped, since that is benign.
pub async fn list_wifi_adapters(handles: &NmHandles) -> Result<Vec<AdapterInfo>, Error> {
    let device_paths = handles
        .network_manager
        .get_all_devices()
        .await
        .map_err(from_zbus)?;

    let mut out = Vec::new();
    for path in device_paths {
        let device = DeviceProxy::builder(&handles.conn)
            .path(path.clone())
            .map_err(from_zbus)?
            .build()
            .await
            .map_err(from_zbus)?;

        // A device that disappears between `get_all_devices` and the
        // property read is benign — skip it.
        let Ok(ty) = device.device_type().await else {
            continue;
        };

        if ty != NM_DEVICE_TYPE_WIFI {
            continue;
        }

        let ifname = device.interface().await.map_err(from_zbus)?;
        out.push(AdapterInfo {
            id: AdapterId::new(ifname.clone()),
            name: format!("Wi-Fi ({ifname})"),
        });
    }

    Ok(out)
}

/// Resolve an `AdapterId` (kernel ifname) to its current `NetworkManager`
/// device path. Re-resolved on every call because `NetworkManager` device
/// paths renumber on daemon restart.
///
/// # Errors
///
/// Returns `Error::AdapterNotFound` if no Wi-Fi device with that ifname
/// is currently managed by `NetworkManager`. Returns other `Error`
/// variants if the `D-Bus` `GetAllDevices` call or a per-device
/// `Interface` property read fails.
pub async fn resolve_device_path(
    handles: &NmHandles,
    adapter: &AdapterId,
) -> Result<OwnedObjectPath, Error> {
    let device_paths = handles
        .network_manager
        .get_all_devices()
        .await
        .map_err(from_zbus)?;

    for path in device_paths {
        let device = DeviceProxy::builder(&handles.conn)
            .path(path.clone())
            .map_err(from_zbus)?
            .build()
            .await
            .map_err(from_zbus)?;

        let ty = device.device_type().await.unwrap_or(0);
        if ty != NM_DEVICE_TYPE_WIFI {
            continue;
        }

        let ifname = device.interface().await.map_err(from_zbus)?;
        if ifname == adapter.as_str() {
            return Ok(path);
        }
    }

    Err(Error::AdapterNotFound(adapter.to_string()))
}
