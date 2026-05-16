//! Thin wrappers over the `WifiManager` calls used by the backend.

use jni::objects::{JObject, JString, JValue};
use jni::{Env, jni_sig, jni_str};
use jni_min_helper::android_context;

use crate::error::Error;

use super::jni_helpers::{boxed, singleton_arraylist};

/// Resolve `(WifiManager) ctx.getSystemService(Context.WIFI_SERVICE)`.
pub fn wifi_manager<'a>(env: &mut Env<'a>) -> Result<JObject<'a>, Error> {
    let ctx = android_context();
    let name = env.new_string("wifi").map_err(|e| Error::Os(boxed(e)))?;
    let res = env
        .call_method(
            ctx,
            jni_str!("getSystemService"),
            jni_sig!((java.lang.String) -> java.lang.Object),
            &[JValue::Object(&name)],
        )
        .map_err(|e| Error::Os(boxed(e)))?;
    res.l().map_err(|e| Error::Os(boxed(e)))
}

/// `wm.addNetworkSuggestions(List.of(suggestion))`. Returns the raw
/// `STATUS_NETWORK_SUGGESTIONS_*` integer.
pub fn add_one_suggestion<'a>(
    env: &mut Env<'a>,
    wm: &JObject<'_>,
    suggestion: &JObject<'a>,
) -> Result<i32, Error> {
    let list = singleton_arraylist(env, suggestion)?;
    let res = env
        .call_method(
            wm,
            jni_str!("addNetworkSuggestions"),
            jni_sig!((java.util.List) -> int),
            &[JValue::Object(&list)],
        )
        .map_err(|e| Error::Os(boxed(e)))?;
    res.i().map_err(|e| Error::Os(boxed(e)))
}

/// `wm.removeNetworkSuggestions(List.of(suggestion))`. Returns the raw
/// `STATUS_NETWORK_SUGGESTIONS_*` integer.
///
/// This is the single-arg form, used by `remove_profile`. It does *not*
/// disconnect the device if it's currently associated to the suggested
/// network; the OS only stops auto-connecting in the future. Use
/// [`remove_one_suggestion_disconnect`] if you need an active disconnect.
pub fn remove_one_suggestion<'a>(
    env: &mut Env<'a>,
    wm: &JObject<'_>,
    suggestion: &JObject<'a>,
) -> Result<i32, Error> {
    let list = singleton_arraylist(env, suggestion)?;
    let res = env
        .call_method(
            wm,
            jni_str!("removeNetworkSuggestions"),
            jni_sig!((java.util.List) -> int),
            &[JValue::Object(&list)],
        )
        .map_err(|e| {
            env.exception_clear();
            Error::Os(boxed(e))
        })?;
    res.i().map_err(|e| {
        env.exception_clear();
        Error::Os(boxed(e))
    })
}

/// `WifiManager.ACTION_REMOVE_SUGGESTION_DISCONNECT` per AOSP.
const ACTION_REMOVE_SUGGESTION_DISCONNECT: i32 = 1;

/// API 31+ form of `removeNetworkSuggestions`. Falls back to the
/// single-arg form on older API levels.
///
/// `removeNetworkSuggestions(List<WifiNetworkSuggestion>, int)` was
/// added in API 31 (Android 12). Calling the two-arg form on an older
/// device throws `NoSuchMethodError` on the JVM side. We attempt it
/// first; on `NoSuchMethodError` (surfaced as a JNI exception we
/// translate into a graceful fallback) we retry with the single-arg
/// form. The fallback case loses the active-disconnect guarantee but
/// preserves the rest of the disconnect contract (auto-connect is
/// suppressed).
pub fn remove_one_suggestion_disconnect<'a>(
    env: &mut Env<'a>,
    wm: &JObject<'_>,
    suggestion: &JObject<'a>,
) -> Result<i32, Error> {
    let list = singleton_arraylist(env, suggestion)?;
    let res = env.call_method(
        wm,
        jni_str!("removeNetworkSuggestions"),
        jni_sig!((java.util.List, int) -> int),
        &[
            JValue::Object(&list),
            JValue::Int(ACTION_REMOVE_SUGGESTION_DISCONNECT),
        ],
    );
    if let Ok(v) = res {
        v.i().map_err(|e| {
            env.exception_clear();
            Error::Os(boxed(e))
        })
    } else {
        // Two-arg form unavailable (likely API < 31). Clear the
        // pending NoSuchMethodError and fall back to the single-arg
        // form.
        env.exception_clear();
        remove_one_suggestion(env, wm, suggestion)
    }
}

/// Returns the SSID currently reported by `WifiManager.getConnectionInfo()`,
/// or `None` if the device is not associated.
///
/// Android wraps the SSID in literal double quotes when returning it
/// here ("`MySSID`"), and inserts the literal string `<unknown ssid>` when
/// the host app lacks the location permission. We strip the surrounding
/// quotes and treat the unknown sentinel as `None`.
pub fn current_ssid(env: &mut Env<'_>, wm: &JObject<'_>) -> Result<Option<String>, Error> {
    let info_val = env
        .call_method(
            wm,
            jni_str!("getConnectionInfo"),
            jni_sig!(() -> android.net.wifi.WifiInfo),
            &[],
        )
        .map_err(|e| Error::Os(boxed(e)))?;
    let info = info_val.l().map_err(|e| Error::Os(boxed(e)))?;
    if info.is_null() {
        return Ok(None);
    }
    let ssid_val = env
        .call_method(
            &info,
            jni_str!("getSSID"),
            jni_sig!(() -> java.lang.String),
            &[],
        )
        .map_err(|e| Error::Os(boxed(e)))?;
    let ssid_obj = ssid_val.l().map_err(|e| Error::Os(boxed(e)))?;
    if ssid_obj.is_null() {
        return Ok(None);
    }
    let ssid_str: JString<'_> = env
        .cast_local::<JString>(ssid_obj)
        .map_err(|e| Error::Os(boxed(e)))?;
    let s = ssid_str
        .try_to_string(env)
        .map_err(|e| Error::Os(boxed(e)))?;
    if s == "<unknown ssid>" {
        return Ok(None);
    }
    Ok(Some(strip_quotes(&s).to_string()))
}

fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}
