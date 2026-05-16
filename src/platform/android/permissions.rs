//! Permission checks via `Context.checkSelfPermission`.

use jni::objects::JValue;
use jni::{Env, jni_sig, jni_str};
use jni_min_helper::android_context;

use crate::error::Error;

use super::jni_helpers::{boxed, new_jstring};

/// `PackageManager.PERMISSION_GRANTED == 0` per the Android SDK.
const PERMISSION_GRANTED: i32 = 0;

/// Returns `true` if the host app holds *any* of the permissions that
/// gate `WifiManager.getScanResults()` access on the current Android
/// version.
///
/// The crate intentionally checks both legacy (`ACCESS_FINE_LOCATION`,
/// API 23+) and modern (`NEARBY_WIFI_DEVICES`, API 33+) permission
/// names. The OS only grants the one that matches the runtime API, so
/// "any" is the right reduction.
pub fn host_can_scan(env: &mut Env<'_>) -> Result<bool, Error> {
    let perms: [&str; 2] = [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.NEARBY_WIFI_DEVICES",
    ];
    for p in perms {
        if check_permission(env, p)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_permission(env: &mut Env<'_>, name: &str) -> Result<bool, Error> {
    let ctx = android_context();
    let perm_j = new_jstring(env, name)?;
    let res = env
        .call_method(
            ctx,
            jni_str!("checkSelfPermission"),
            jni_sig!((java.lang.String) -> int),
            &[JValue::Object(&perm_j)],
        )
        .map_err(|e| Error::Os(boxed(e)))?;
    let code = res.i().map_err(|e| Error::Os(boxed(e)))?;
    Ok(code == PERMISSION_GRANTED)
}
