//! Builds an `android.net.wifi.WifiNetworkSuggestion` via JNI.

use jni::objects::{JObject, JValue};
use jni::{Env, jni_sig, jni_str};
use secrecy::ExposeSecret;

use crate::error::Error;
use crate::types::{Credentials, Ssid};

use super::jni_helpers::{boxed, new_jstring, ssid_jstring};

/// Construct a `WifiNetworkSuggestion` for the given SSID + credentials.
///
/// The returned `JObject<'env>` is a *local* ref tied to the current
/// JNI frame. Callers that need to keep the object across attach
/// sessions must promote it to a `GlobalRef` themselves.
pub fn build_suggestion<'env>(
    env: &mut Env<'env>,
    ssid: &Ssid,
    credentials: &Credentials,
) -> Result<JObject<'env>, Error> {
    // Builder builder = new WifiNetworkSuggestion.Builder();
    let builder = env
        .new_object(
            jni_str!("android/net/wifi/WifiNetworkSuggestion$Builder"),
            jni_sig!(() -> void),
            &[],
        )
        .map_err(|e| Error::Os(boxed(e)))?;

    // builder.setSsid(ssidString);
    let ssid_j = ssid_jstring(env, ssid)?;
    let _ = env
        .call_method(
            &builder,
            jni_str!("setSsid"),
            jni_sig!((java.lang.String) -> android.net.wifi.WifiNetworkSuggestion::Builder),
            &[JValue::Object(&ssid_j)],
        )
        .map_err(|e| Error::Os(boxed(e)))?;

    // builder.setWpa2Passphrase(...)  (Open networks: skip).
    if let Credentials::Password(secret) = credentials {
        let pw_j = new_jstring(env, secret.expose_secret())?;
        let _ = env
            .call_method(
                &builder,
                jni_str!("setWpa2Passphrase"),
                jni_sig!((java.lang.String) -> android.net.wifi.WifiNetworkSuggestion::Builder),
                &[JValue::Object(&pw_j)],
            )
            .map_err(|e| Error::Os(boxed(e)))?;
    }

    // builder.setIsAppInteractionRequired(true);
    //
    // Why: this flag is a precondition for receiving the
    // ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION broadcast on
    // successful connection. Without it the OS simply connects silently
    // and the backend would have to fall back to polling-only.
    let _ = env
        .call_method(
            &builder,
            jni_str!("setIsAppInteractionRequired"),
            jni_sig!((boolean) -> android.net.wifi.WifiNetworkSuggestion::Builder),
            &[JValue::Bool(true)],
        )
        .map_err(|e| Error::Os(boxed(e)))?;

    // WifiNetworkSuggestion suggestion = builder.build();
    let suggestion_val = env
        .call_method(
            &builder,
            jni_str!("build"),
            jni_sig!(() -> android.net.wifi.WifiNetworkSuggestion),
            &[],
        )
        .map_err(|e| Error::Os(boxed(e)))?;
    let suggestion = suggestion_val.l().map_err(|e| Error::Os(boxed(e)))?;
    Ok(suggestion)
}
