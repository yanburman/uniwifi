//! On-demand connect to a specific AP via `WifiNetworkSpecifier` +
//! `ConnectivityManager.requestNetwork`.
//!
//! Unlike the `WifiNetworkSuggestion` path (see `suggestion.rs`), this connects
//! to the target AP *on demand* even while the device is already associated to
//! another (internet-bearing) network — the OS will not drop an internet
//! network for an opportunistic suggestion, but a network *request* with a
//! specifier brings the AP up as an app-scoped network. The system shows a
//! one-time "Connect to <ssid>?" dialog the user must approve.
//!
//! We issue the callback-free `requestNetwork(NetworkRequest, PendingIntent)`
//! overload and read the satisfying `Network` from the operation broadcast's
//! `EXTRA_NETWORK`, then **bind the process to it inside `onReceive`** — i.e.
//! the instant the network is available. Binding immediately matters: a
//! specifier network that nothing holds/uses is torn down by the framework a
//! few seconds after it connects, so the SSID-polling approach (which can't see
//! the SSID anyway — `NetworkCapabilities` redacts it) loses the race. The
//! broadcast receiver must be registered `RECEIVER_NOT_EXPORTED` (the system
//! delivers our own `PendingIntent` within the app) because `targetSdk` 34
//! rejects the flagless `registerReceiver` for non-system actions.
//!
//! `NetworkCallback` (the textbook variant) is avoided because it's an abstract
//! Java class that can't be created from pure JNI without shipping a dex.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use jni::objects::{JObject, JString, JValue};
use jni::{Env, jni_sig, jni_str};
use jni_min_helper::{BroadcastReceiver, android_context, jni_with_env};
use secrecy::ExposeSecret;

use crate::error::Error;
use crate::types::{Credentials, Ssid};

use super::jni_helpers::boxed;

/// `NetworkCapabilities.TRANSPORT_WIFI`.
const TRANSPORT_WIFI: i32 = 1;
/// `PendingIntent.FLAG_UPDATE_CURRENT | FLAG_MUTABLE` — mutable is required on
/// API 31+ for `requestNetwork` to accept the operation intent.
const PENDING_INTENT_FLAGS: i32 = 0x0800_0000 | 0x0200_0000;
/// `Context.RECEIVER_NOT_EXPORTED` (API 33+).
const RECEIVER_NOT_EXPORTED: i32 = 4;
/// Private broadcast action carrying the `requestNetwork` result.
const RESULT_ACTION: &str = "uniwifi.WIFI_SPECIFIER_REQUEST";
/// `ConnectivityManager.EXTRA_NETWORK`.
const EXTRA_NETWORK: &str = "android.net.extra.NETWORK";
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Connects to `ssid`/`credentials` via a Wi-Fi network specifier, blocking
/// until the AP network is up (and this process bound to it) or `timeout`
/// elapses. Must be run off the main thread — it sleeps while polling, and both
/// the approval dialog and the result broadcast are driven on the main looper.
pub fn connect_via_specifier(
    ssid: &Ssid,
    credentials: &Credentials,
    timeout: Duration,
) -> Result<(), Error> {
    // Validate UTF-8 / extract the passphrase up front so the JNI helpers only
    // deal with native `jni` errors.
    let ssid_str = ssid
        .as_str()
        .ok_or(Error::Unsupported(
            "non-UTF8 SSIDs not supported on Android",
        ))?
        .to_owned();
    let password = match credentials {
        Credentials::Password(secret) => Some(secret.expose_secret().to_owned()),
        Credentials::Open => None,
    };

    // Set true by the receiver once it has bound the process to the network.
    let bound = Arc::new(AtomicBool::new(false));
    let bound_for_rx = Arc::clone(&bound);

    // Register before requesting so the result broadcast can't be missed.
    let receiver = BroadcastReceiver::build(move |env, _ctx, intent| {
        let name = JString::new(env, EXTRA_NETWORK)?;
        let net_cls = env.find_class(jni_str!("android/net/Network"))?;
        let network = intent.get_parcelable_extra(env, &name, &net_cls)?;
        if network.is_null() {
            log::warn!("wifi_specifier: result broadcast had no EXTRA_NETWORK");
            return Ok(());
        }
        // Bind here, on the main looper, the moment the network is available —
        // before the framework tears down an unheld specifier network.
        let cm = connectivity_manager(env)?;
        let ok = env
            .call_method(
                &cm,
                jni_str!("bindProcessToNetwork"),
                jni_sig!((android.net.Network) -> boolean),
                &[JValue::Object(&network)],
            )?
            .z()?;
        log::info!("wifi_specifier: bound process to specifier network (ok={ok})");
        bound_for_rx.store(ok, Ordering::SeqCst);
        Ok(())
    })
    .map_err(|e| Error::Os(boxed(e)))?;
    register_not_exported(&receiver, RESULT_ACTION).map_err(|e| Error::Os(boxed(e)))?;

    jni_with_env(|env| -> Result<(), jni::errors::Error> {
        request_network(env, &ssid_str, password.as_deref())
    })
    .map_err(|e| Error::Os(boxed(e)))?;

    let deadline = Instant::now() + timeout;
    while !bound.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            drop(receiver);
            return Err(Error::Timeout(timeout));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    drop(receiver);
    Ok(())
}

/// Registers `receiver` for `action` with `RECEIVER_NOT_EXPORTED`. The flagless
/// 2-arg `registerReceiver` (`jni_min_helper`'s `register_for_action`) throws on
/// `targetSdk` 34 for a non-system action, so we use the 3-arg form (API 33+).
fn register_not_exported(receiver: &BroadcastReceiver, action: &str) -> Result<(), jni::errors::Error> {
    jni_with_env(|env| {
        let action_j = JString::new(env, action)?;
        let filter = env.new_object(
            jni_str!("android/content/IntentFilter"),
            jni_sig!((java.lang.String) -> void),
            &[JValue::Object(&action_j)],
        )?;
        env.call_method(
            android_context(),
            jni_str!("registerReceiver"),
            jni_sig!(
                (android.content.BroadcastReceiver, android.content.IntentFilter, int)
                    -> android.content.Intent
            ),
            &[
                JValue::Object(receiver.as_ref()),
                JValue::Object(&filter),
                JValue::Int(RECEIVER_NOT_EXPORTED),
            ],
        )?;
        Ok(())
    })
}

/// Builds the specifier + request and calls `requestNetwork(request, pendingIntent)`.
fn request_network(
    env: &mut Env<'_>,
    ssid: &str,
    password: Option<&str>,
) -> Result<(), jni::errors::Error> {
    let specifier = build_specifier(env, ssid, password)?;

    // NetworkRequest.Builder().addTransportType(WIFI).setNetworkSpecifier(spec).build()
    let req_builder = env.new_object(
        jni_str!("android/net/NetworkRequest$Builder"),
        jni_sig!(() -> void),
        &[],
    )?;
    env.call_method(
        &req_builder,
        jni_str!("addTransportType"),
        jni_sig!((int) -> android.net.NetworkRequest::Builder),
        &[JValue::Int(TRANSPORT_WIFI)],
    )?;
    env.call_method(
        &req_builder,
        jni_str!("setNetworkSpecifier"),
        jni_sig!((android.net.NetworkSpecifier) -> android.net.NetworkRequest::Builder),
        &[JValue::Object(&specifier)],
    )?;
    let request = env
        .call_method(
            &req_builder,
            jni_str!("build"),
            jni_sig!(() -> android.net.NetworkRequest),
            &[],
        )?
        .l()?;

    let pending_intent = build_pending_intent(env)?;
    let cm = connectivity_manager(env)?;
    env.call_method(
        &cm,
        jni_str!("requestNetwork"),
        jni_sig!((android.net.NetworkRequest, android.app.PendingIntent) -> void),
        &[JValue::Object(&request), JValue::Object(&pending_intent)],
    )?;
    Ok(())
}

/// `new WifiNetworkSpecifier.Builder().setSsid(..).setWpa2Passphrase(..).build()`.
fn build_specifier<'a>(
    env: &mut Env<'a>,
    ssid: &str,
    password: Option<&str>,
) -> Result<JObject<'a>, jni::errors::Error> {
    let builder = env.new_object(
        jni_str!("android/net/wifi/WifiNetworkSpecifier$Builder"),
        jni_sig!(() -> void),
        &[],
    )?;
    let ssid_j = JString::new(env, ssid)?;
    env.call_method(
        &builder,
        jni_str!("setSsid"),
        jni_sig!((java.lang.String) -> android.net.wifi.WifiNetworkSpecifier::Builder),
        &[JValue::Object(&ssid_j)],
    )?;
    if let Some(pw) = password {
        let pw_j = JString::new(env, pw)?;
        env.call_method(
            &builder,
            jni_str!("setWpa2Passphrase"),
            jni_sig!((java.lang.String) -> android.net.wifi.WifiNetworkSpecifier::Builder),
            &[JValue::Object(&pw_j)],
        )?;
    }
    env.call_method(
        &builder,
        jni_str!("build"),
        jni_sig!(() -> android.net.wifi.WifiNetworkSpecifier),
        &[],
    )?
    .l()
}

/// `PendingIntent.getBroadcast(ctx, 0, new Intent(ACTION).setPackage(pkg), flags)`.
fn build_pending_intent<'a>(env: &mut Env<'a>) -> Result<JObject<'a>, jni::errors::Error> {
    let ctx = android_context();
    let action = JString::new(env, RESULT_ACTION)?;
    let intent = env.new_object(
        jni_str!("android/content/Intent"),
        jni_sig!((java.lang.String) -> void),
        &[JValue::Object(&action)],
    )?;
    let pkg = env
        .call_method(
            ctx,
            jni_str!("getPackageName"),
            jni_sig!(() -> java.lang.String),
            &[],
        )?
        .l()?;
    env.call_method(
        &intent,
        jni_str!("setPackage"),
        jni_sig!((java.lang.String) -> android.content.Intent),
        &[JValue::Object(&pkg)],
    )?;
    let pi_cls = env.find_class(jni_str!("android/app/PendingIntent"))?;
    env.call_static_method(
        &pi_cls,
        jni_str!("getBroadcast"),
        jni_sig!(
            (android.content.Context, int, android.content.Intent, int)
                -> android.app.PendingIntent
        ),
        &[
            JValue::Object(ctx),
            JValue::Int(0),
            JValue::Object(&intent),
            JValue::Int(PENDING_INTENT_FLAGS),
        ],
    )?
    .l()
}

/// `(ConnectivityManager) ctx.getSystemService("connectivity")`.
fn connectivity_manager<'a>(env: &mut Env<'a>) -> Result<JObject<'a>, jni::errors::Error> {
    let name = JString::new(env, "connectivity")?;
    env.call_method(
        android_context(),
        jni_str!("getSystemService"),
        jni_sig!((java.lang.String) -> java.lang.Object),
        &[JValue::Object(&name)],
    )?
    .l()
}
