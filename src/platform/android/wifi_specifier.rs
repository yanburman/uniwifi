//! On-demand connect to a specific AP via `WifiNetworkSpecifier` +
//! `ConnectivityManager.requestNetwork`.
//!
//! A `WifiNetworkSpecifier` network stays up only while its `NetworkRequest` is
//! held by a live, registered `NetworkCallback`. We issue the
//! `requestNetwork(NetworkRequest, NetworkCallback)` overload with a concrete
//! no-op `NetworkCallback` (instantiable from pure JNI — no Java subclass / dex)
//! and keep it registered for as long as the returned [`SpecifierGuard`] lives.
//! Dropping the guard `unregisterNetworkCallback`s and unbinds the process — the
//! framework then disconnects the AP. The callback-free `PendingIntent` overload
//! must NOT be used: the framework reaps it ~5 s after connect
//! (`ConnectivityService: ... releasing NetworkRequest ... (release request)` →
//! `no live requests ... disconnecting`).
//!
//! We don't override `onAvailable` (that would need a dex), so the `Network` to
//! bind is found by snapshotting the `Network` handles from `getAllNetworks()`
//! *before* the request, then binding the newly-appeared `TRANSPORT_WIFI`
//! network. The held callback keeps the network alive, so there's no teardown
//! race while we wait for user approval + L3 setup.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use jni::objects::{JObject, JObjectArray, JString, JValue};
use jni::refs::Global;
use jni::{Env, jni_sig, jni_str};
use jni_min_helper::{android_context, jni_with_env};
use secrecy::ExposeSecret;

use crate::connection::WifiConnection;
use crate::error::Error;
use crate::types::{Credentials, Ssid};

use super::jni_helpers::boxed;

/// `NetworkCapabilities.TRANSPORT_WIFI`.
const TRANSPORT_WIFI: i32 = 1;

const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// RAII guard holding the registered no-op `NetworkCallback`. While it lives the
/// specifier request is held and the camera network stays up. `Drop` releases
/// the request and unbinds the process.
struct SpecifierGuard {
    callback: Global<JObject<'static>>,
}

impl Drop for SpecifierGuard {
    fn drop(&mut self) {
        let callback = self.callback.as_obj();
        let _ = jni_with_env(|env| -> Result<(), jni::errors::Error> {
            let cm = connectivity_manager(env)?;
            env.call_method(
                &cm,
                jni_str!("unregisterNetworkCallback"),
                jni_sig!("(Landroid/net/ConnectivityManager$NetworkCallback;)V"),
                &[JValue::Object(callback)],
            )?;
            // Clear the process binding so later sockets use the default network.
            env.call_method(
                &cm,
                jni_str!("bindProcessToNetwork"),
                jni_sig!("(Landroid/net/Network;)Z"),
                &[JValue::Object(&JObject::null())],
            )?;
            log::info!("wifi_specifier: connection guard dropped (callback unregistered, unbound)");
            Ok(())
        });
    }
}

/// Connects to `ssid`/`credentials` via a Wi-Fi network specifier, blocking
/// until the AP network is up (and this process bound to it) or `timeout`
/// elapses. Must be run off the main thread — it sleeps while polling, and the
/// approval dialog is driven on the main looper. Returns a [`WifiConnection`]
/// whose `Drop` disconnects.
pub fn connect_via_specifier(
    ssid: &Ssid,
    credentials: &Credentials,
    timeout: Duration,
) -> Result<WifiConnection, Error> {
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

    // Snapshot existing Network handles so we can spot the one our request brings up.
    let before = jni_with_env(network_handles).map_err(|e| Error::Os(boxed(e)))?;

    // Issue the request with a live (no-op) NetworkCallback; hold its global ref.
    let callback = jni_with_env(|env| request_network(env, &ssid_str, password.as_deref()))
        .map_err(|e| Error::Os(boxed(e)))?;

    // Two-phase poll: (1) wait for a new TRANSPORT_WIFI network to appear and
    // bind the process to it, then (2) wait for DHCP to assign an IPv4 address.
    // bindProcessToNetwork succeeds at L2 association, but the kernel has no
    // route yet — TCP to 192.168.1.1 fails with ENETUNREACH until DHCP completes.
    // We keep a global ref to the bound network so we can call getLinkProperties
    // on it directly — getActiveNetwork() does not reliably return a
    // process-bound specifier network on all Android versions.
    let deadline = Instant::now() + timeout;
    let mut bound_network: Option<Global<JObject<'static>>> = None;
    loop {
        if bound_network.is_none() {
            bound_network = jni_with_env(|env| try_bind_new_wifi(env, &before))
                .map_err(|e| Error::Os(boxed(e)))?;
            if bound_network.is_some() {
                log::info!("wifi_specifier: network bound, waiting for DHCP...");
            }
        } else if let Some(ref net) = bound_network {
            let has_ip = jni_with_env(|env| network_has_ipv4(env, net.as_obj()))
                .map_err(|e| Error::Os(boxed(e)))?;
            if has_ip {
                log::info!("wifi_specifier: DHCP complete, IPv4 address assigned");
                return Ok(WifiConnection::new(SpecifierGuard { callback }));
            }
        }
        if Instant::now() >= deadline {
            drop(SpecifierGuard { callback });
            return Err(Error::Timeout(timeout));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Collects the `getNetworkHandle()` of every current `Network`.
fn network_handles(env: &mut Env<'_>) -> Result<HashSet<i64>, jni::errors::Error> {
    let mut set = HashSet::new();
    let cm = connectivity_manager(env)?;
    let arr_obj = env
        .call_method(
            &cm,
            jni_str!("getAllNetworks"),
            jni_sig!("()[Landroid/net/Network;"),
            &[],
        )?
        .l()?;
    if arr_obj.is_null() {
        return Ok(set);
    }
    let arr = JObjectArray::<JObject>::cast_local(env, arr_obj)?;
    let len = arr.len(env)?;
    for i in 0..len {
        let net = arr.get_element(env, i)?;
        if net.is_null() {
            continue;
        }
        let handle = env
            .call_method(&net, jni_str!("getNetworkHandle"), jni_sig!("()J"), &[])?
            .j()?;
        set.insert(handle);
    }
    Ok(set)
}

/// Builds the specifier + request and calls `requestNetwork(request, callback)`,
/// returning the callback's global ref (which holds the request).
fn request_network(
    env: &mut Env<'_>,
    ssid: &str,
    password: Option<&str>,
) -> Result<Global<JObject<'static>>, jni::errors::Error> {
    let specifier = build_specifier(env, ssid, password)?;

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

    let callback = env.new_object(
        jni_str!("android/net/ConnectivityManager$NetworkCallback"),
        jni_sig!("()V"),
        &[],
    )?;
    let cm = connectivity_manager(env)?;
    env.call_method(
        &cm,
        jni_str!("requestNetwork"),
        jni_sig!(
            "(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V"
        ),
        &[JValue::Object(&request), JValue::Object(&callback)],
    )?;

    log::info!("wifi_specifier: requestNetwork(NetworkCallback) issued, request held");
    env.new_global_ref(&callback)
}

/// Finds a `TRANSPORT_WIFI` network whose handle was not present in `before`,
/// binds the process to it, and returns a global ref to it for later IP checks.
fn try_bind_new_wifi(
    env: &mut Env<'_>,
    before: &HashSet<i64>,
) -> Result<Option<Global<JObject<'static>>>, jni::errors::Error> {
    let cm = connectivity_manager(env)?;
    let arr_obj = env
        .call_method(
            &cm,
            jni_str!("getAllNetworks"),
            jni_sig!("()[Landroid/net/Network;"),
            &[],
        )?
        .l()?;
    if arr_obj.is_null() {
        return Ok(None);
    }
    let arr = JObjectArray::<JObject>::cast_local(env, arr_obj)?;
    let len = arr.len(env)?;
    for i in 0..len {
        let net = arr.get_element(env, i)?;
        if net.is_null() {
            continue;
        }
        let handle = env
            .call_method(&net, jni_str!("getNetworkHandle"), jni_sig!("()J"), &[])?
            .j()?;
        if before.contains(&handle) {
            continue;
        }
        let caps = env
            .call_method(
                &cm,
                jni_str!("getNetworkCapabilities"),
                jni_sig!("(Landroid/net/Network;)Landroid/net/NetworkCapabilities;"),
                &[JValue::Object(&net)],
            )?
            .l()?;
        if caps.is_null() {
            continue;
        }
        let has_wifi = env
            .call_method(
                &caps,
                jni_str!("hasTransport"),
                jni_sig!("(I)Z"),
                &[JValue::Int(TRANSPORT_WIFI)],
            )?
            .z()?;
        if !has_wifi {
            continue;
        }
        let ok = env
            .call_method(
                &cm,
                jni_str!("bindProcessToNetwork"),
                jni_sig!("(Landroid/net/Network;)Z"),
                &[JValue::Object(&net)],
            )?
            .z()?;
        log::info!("wifi_specifier: bound process to new wifi network (ok={ok})");
        if ok {
            let global = env.new_global_ref(&net)?;
            return Ok(Some(global));
        }
    }
    Ok(None)
}

/// Returns `true` if `network` has an IPv4 link address — i.e. DHCP has
/// completed and the kernel has routes for the camera AP subnet.
fn network_has_ipv4(env: &mut Env<'_>, network: &JObject<'_>) -> Result<bool, jni::errors::Error> {
    let cm = connectivity_manager(env)?;
    let lp = env
        .call_method(
            &cm,
            jni_str!("getLinkProperties"),
            jni_sig!("(Landroid/net/Network;)Landroid/net/LinkProperties;"),
            &[JValue::Object(network)],
        )?
        .l()?;
    if lp.is_null() {
        return Ok(false);
    }
    let addrs = env
        .call_method(
            &lp,
            jni_str!("getLinkAddresses"),
            jni_sig!("()Ljava/util/List;"),
            &[],
        )?
        .l()?;
    if addrs.is_null() {
        return Ok(false);
    }
    let count = env
        .call_method(&addrs, jni_str!("size"), jni_sig!("()I"), &[])?
        .i()?;
    for i in 0..count {
        let link_addr = env
            .call_method(
                &addrs,
                jni_str!("get"),
                jni_sig!("(I)Ljava/lang/Object;"),
                &[JValue::Int(i)],
            )?
            .l()?;
        let inet_addr = env
            .call_method(
                &link_addr,
                jni_str!("getAddress"),
                jni_sig!("()Ljava/net/InetAddress;"),
                &[],
            )?
            .l()?;
        if env.is_instance_of(&inet_addr, jni_str!("java/net/Inet4Address"))? {
            return Ok(true);
        }
    }
    Ok(false)
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
