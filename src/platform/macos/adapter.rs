//! Adapter resolution helpers.

use objc2::rc::Retained;
use objc2_core_wlan::{CWInterface, CWWiFiClient};
use objc2_foundation::NSString;

use crate::error::Error;
use crate::types::AdapterId;

/// Resolve an `AdapterId` (BSD name) back to a `CWInterface` on the given
/// shared client.
///
/// Returns `Error::AdapterNotFound` if the OS no longer exposes the named
/// interface (e.g. USB Wi-Fi dongle was unplugged between `list_adapters`
/// and the operation).
///
/// # Errors
/// - `AdapterNotFound` if `interfaceWithName` returns `nil`.
pub(super) fn resolve_interface_by_id(
    client: &CWWiFiClient,
    adapter: &AdapterId,
) -> Result<Retained<CWInterface>, Error> {
    let name = NSString::from_str(adapter.as_str());
    // SAFETY: `interfaceWithName` accepts an optional NSString and returns
    // an optional Retained<CWInterface>. Both halves of the Option are
    // handled below.
    let iface = unsafe { client.interfaceWithName(Some(&name)) };
    iface.ok_or_else(|| Error::AdapterNotFound(adapter.to_string()))
}
