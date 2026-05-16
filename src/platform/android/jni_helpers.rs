//! Crate-specific JNI shims.
//!
//! Higher-level concerns — `JavaVM` acquisition, attaching the current
//! thread, holding a global ref to the host Context — are owned by the
//! `jni_min_helper` crate's top-level helpers (`jni_with_env`,
//! `android_context`, `jni_get_vm`). This module just provides the
//! pieces we don't get for free: an ndk-context readiness check, a
//! Java-string converter that surfaces non-UTF-8 SSIDs as a typed
//! error, and a single-element `java.util.ArrayList` builder used by
//! `addNetworkSuggestions` / `removeNetworkSuggestions`.

use jni::objects::{JObject, JString, JValue};
use jni::{Env, jni_sig, jni_str};

use crate::error::{BoxedOsError, Error};

/// Verifies that the host app has called
/// `ndk_context::initialize_android_context(...)`. Returns
/// `Error::Unsupported` if not. Cheap and idempotent — backends call
/// this from their constructor so `UniWifi::new()` fails fast rather
/// than blowing up on the first JNI call.
pub(super) fn require_ndk_context() -> Result<(), Error> {
    let ctx = ndk_context::android_context();
    if ctx.vm().is_null() {
        return Err(Error::Unsupported("ndk-context not initialized"));
    }
    if ctx.context().is_null() {
        return Err(Error::Unsupported("ndk-context Context is null"));
    }
    Ok(())
}

/// Build a Java `String` from a Rust `&str`.
pub(super) fn new_jstring<'a>(env: &mut Env<'a>, s: &str) -> Result<JString<'a>, Error> {
    env.new_string(s).map_err(|e| Error::Os(boxed(e)))
}

/// Build a Java `String` representing the SSID. SSIDs are octet strings;
/// platform `WifiNetworkSuggestion.Builder.setSsid(String)` requires UTF-8.
/// Non-UTF-8 SSIDs are rejected with a typed error so the backend can
/// surface a clean message rather than a JNI exception.
pub(super) fn ssid_jstring<'a>(
    env: &mut Env<'a>,
    ssid: &crate::types::Ssid,
) -> Result<JString<'a>, Error> {
    let s = ssid.as_str().ok_or(Error::Unsupported(
        "non-UTF8 SSIDs not supported on Android",
    ))?;
    new_jstring(env, s)
}

/// Build a `java.util.ArrayList<E>` containing exactly one element.
pub(super) fn singleton_arraylist<'a>(
    env: &mut Env<'a>,
    element: &JObject<'a>,
) -> Result<JObject<'a>, Error> {
    let list = env
        .new_object(jni_str!("java/util/ArrayList"), jni_sig!(() -> void), &[])
        .map_err(|e| Error::Os(boxed(e)))?;
    env.call_method(
        &list,
        jni_str!("add"),
        jni_sig!((java.lang.Object) -> boolean),
        &[JValue::Object(element)],
    )
    .map_err(|e| Error::Os(boxed(e)))?;
    Ok(list)
}

/// Box-and-erase a JNI error into a `BoxedOsError` for `Error::Os`.
pub(super) fn boxed<E: std::error::Error + Send + Sync + 'static>(e: E) -> BoxedOsError {
    Box::new(e)
}
