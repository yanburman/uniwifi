//! `ScanProvider` impl: drive `WifiManager.startScan` and a transient
//! `BroadcastReceiver` for `SCAN_RESULTS_AVAILABLE_ACTION`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use jni::objects::{JObject, JString, JValue};
use jni::{Env, jni_sig, jni_str};
use jni_min_helper::{BroadcastReceiver, jni_with_env};
use tokio::sync::oneshot;

use crate::preflight::{ScanError, ScanProvider};
use crate::scan_rollup::{RawBss, ScanContext, quality_from_dbm};
use crate::types::{ScanOptions, Ssid};

use super::permissions::host_can_scan;
use super::wifi_manager::wifi_manager;

/// Best-effort upper bound on how long we wait for a single
/// `SCAN_RESULTS_AVAILABLE` broadcast before falling back to
/// `getScanResults()` directly. Tuned to comfortably exceed
/// `WIFI_RESULT_AVAILABLE` latency (~2-4 s on real devices) while
/// leaving headroom for `wait_until_ssid_visible`'s outer timeout.
const PER_SCAN_DEADLINE: Duration = Duration::from_secs(6);

/// `ScanProvider` impl that lives on the `AndroidBackend`. The
/// implementation keeps no per-call state — every `scan()` call sets
/// up and tears down its own receiver — so it's `Send + Sync` for
/// free.
pub struct AndroidScanner;

#[async_trait]
impl ScanProvider for AndroidScanner {
    async fn scan(&self) -> Result<Vec<Ssid>, ScanError> {
        let opts = crate::types::ScanOptions { force_rescan: true };
        let work = move || fetch_bsses_blocking(&opts);

        #[cfg(feature = "tokio_rt")]
        let bsses = tokio::task::spawn_blocking(work)
            .await
            .map_err(|e| ScanError::Os(Box::new(std::io::Error::other(format!("join: {e}")))))?
            .map_err(crate::preflight::scan_error_from)?;
        #[cfg(not(feature = "tokio_rt"))]
        let bsses = {
            let (tx, rx) = tokio::sync::oneshot::channel::<
                Result<Vec<crate::scan_rollup::RawBss>, crate::error::Error>,
            >();
            std::thread::spawn(move || {
                let _ = tx.send(work());
            });
            rx.await
                .map_err(|_| ScanError::Os(Box::new(std::io::Error::other("worker dropped"))))?
                .map_err(crate::preflight::scan_error_from)?
        };
        Ok(bsses.into_iter().map(|b| b.ssid).collect())
    }
}

/// Wait on a oneshot for at most `dur`. Runs on the blocking thread,
/// so std-thread sleep is fine.
fn block_on_oneshot<T>(mut rx: oneshot::Receiver<T>, dur: Duration) -> Option<T> {
    let deadline = std::time::Instant::now() + dur;
    while std::time::Instant::now() < deadline {
        match rx.try_recv() {
            Ok(v) => return Some(v),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => return None,
        }
    }
    None
}

/// Single Android scan code path, used by both `Backend::list_visible_networks`
/// and the pre-flight `AndroidScanner::scan`. Requires `host_can_scan ==
/// true`; otherwise returns `Error::PermissionDenied` so the caller gets a
/// typed answer.
///
/// The pre-flight collapses any error to `ScanOutcome::Skipped` via
/// `preflight::scan_error_from`, which translates `Error::PermissionDenied`
/// to `ScanError::PermissionDenied` — preserving the spec-required silent
/// skip on missing permission.
pub(super) fn fetch_bsses_blocking(
    options: &ScanOptions,
) -> Result<Vec<RawBss>, crate::error::Error> {
    let force = options.force_rescan;
    // Outer Result is jni::errors::Error from jni_with_env; inner is our
    // typed error. Flatten on the outside.
    let res: Result<Result<Vec<RawBss>, crate::error::Error>, jni::errors::Error> =
        jni_with_env(|env| {
            match host_can_scan(env) {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(Err(crate::error::Error::PermissionDenied(
                        "ACCESS_FINE_LOCATION or NEARBY_WIFI_DEVICES",
                    )));
                }
                Err(e) => {
                    return Ok(Err(crate::error::Error::Os(Box::new(JniErrAdapter(
                        format!("{e:?}"),
                    )))));
                }
            }

            let wm = match wifi_manager(env) {
                Ok(wm) => wm,
                Err(e) => {
                    return Ok(Err(crate::error::Error::Os(Box::new(JniErrAdapter(
                        format!("{e:?}"),
                    )))));
                }
            };

            if force {
                // Set up receiver BEFORE startScan to avoid the race
                // where the OS broadcasts before we attach.
                //
                // The broadcast carries `EXTRA_RESULTS_UPDATED` (bool):
                // `true` means a fresh scan landed; `false` means the OS
                // throttled us (Q+ caps foreground apps at 4 scans / 2
                // min) and the broadcast carries the *previous* scan's
                // results. We forward this to the worker so the caller
                // can tell freshly-rescanned data from cached.
                let (tx, rx) = oneshot::channel::<bool>();
                let tx = Arc::new(Mutex::new(Some(tx)));
                let tx_for = Arc::clone(&tx);
                if let Ok(receiver) = BroadcastReceiver::build(move |env, _ctx, intent| {
                    let updated = read_results_updated_extra(env, &intent).unwrap_or(false);
                    if let Ok(mut g) = tx_for.lock()
                        && let Some(t) = g.take()
                    {
                        let _ = t.send(updated);
                    }
                    Ok(())
                }) {
                    if receiver
                        .register_for_action("android.net.wifi.SCAN_RESULTS_AVAILABLE")
                        .is_ok()
                    {
                        if env
                            .call_method(&wm, jni_str!("startScan"), jni_sig!(() -> boolean), &[])
                            .is_ok()
                        {
                            // Wait for the broadcast (or timeout); we
                            // proceed regardless to read whatever
                            // results are currently cached.
                            let _ = block_on_oneshot(rx, PER_SCAN_DEADLINE);
                        } else {
                            // startScan can throw SecurityException when
                            // location permission is missing. Clear the
                            // pending exception so subsequent JNI calls
                            // on this thread aren't poisoned.
                            env.exception_clear();
                        }
                    }
                    drop(receiver);
                }
            }

            // Read scan results regardless of whether the broadcast fired.
            let bsses = read_scan_results_rich(env, &wm).unwrap_or_default();
            Ok(Ok(bsses))
        });

    match res {
        Ok(inner) => inner,
        Err(e) => Err(crate::error::Error::Os(Box::new(JniErrAdapter(format!(
            "{e:?}"
        ))))),
    }
}

/// Build the per-adapter `ScanContext` for `list_visible_networks`.
///
/// `saved_ssids` is captured by the caller from the in-process
/// suggestion cache (Android has no API to enumerate previously-
/// registered suggestions, so the cache *is* the source of truth for
/// `has_saved_profile`).
pub(super) fn fetch_scan_context_blocking(
    saved_ssids: HashSet<Ssid>,
) -> Result<ScanContext, crate::error::Error> {
    // Move `saved_ssids` into the closure so it's consumed exactly once
    // by the constructed `ScanContext`. `wifi_manager` failure is treated
    // as "no connection info" rather than a hard error — the saved-SSID
    // half of the context is still valid.
    let res: Result<ScanContext, jni::errors::Error> = jni_with_env(|env| {
        let connected_ssid = wifi_manager(env)
            .ok()
            .and_then(|wm| read_connected_ssid(env, &wm).ok().flatten());
        Ok(ScanContext {
            connected_ssid,
            saved_ssids,
        })
    });
    res.map_err(|e| crate::error::Error::Os(Box::new(JniErrAdapter(format!("{e:?}")))))
}

/// Project `WifiManager.getScanResults()` to `Vec<RawBss>`. Both
/// `Backend::list_visible_networks` and the pre-flight `ScanProvider::scan`
/// (via `fetch_bsses_blocking`) consume this, projecting to a `Vec<Ssid>` at
/// the pre-flight boundary.
///
/// Each per-`ScanResult` iteration runs inside `with_local_frame` so the
/// JNI local-ref table doesn't accumulate ~7 references per scan entry —
/// previously a 50-AP scan could push past JNI's 16-ref minimum guarantee
/// in a single attached frame.
fn read_scan_results_rich(env: &mut Env<'_>, wm: &JObject<'_>) -> jni::errors::Result<Vec<RawBss>> {
    let list = env
        .call_method(
            wm,
            jni_str!("getScanResults"),
            jni_sig!(() -> java.util.List),
            &[],
        )?
        .l()?;
    let size = env
        .call_method(&list, jni_str!("size"), jni_sig!(() -> int), &[])?
        .i()?;
    let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    for i in 0..size {
        // Each ScanResult creates ~7 locals (item, SSID, BSSID, caps, +
        // their JString casts). Capping the frame at 16 is per-iteration
        // generous and ensures we never grow without bound.
        let next: jni::errors::Result<Option<RawBss>> =
            env.with_local_frame(16, |env| -> jni::errors::Result<Option<RawBss>> {
                let item: JObject<'_> = env
                    .call_method(
                        &list,
                        jni_str!("get"),
                        jni_sig!((int) -> java.lang.Object),
                        &[JValue::Int(i)],
                    )?
                    .l()?;

                let ssid_obj = env
                    .get_field(&item, jni_str!("SSID"), jni_sig!(java.lang.String))?
                    .l()?;
                if ssid_obj.is_null() {
                    return Ok(None);
                }
                let ssid_str: JString<'_> = env.cast_local::<JString>(ssid_obj)?;
                let ssid = ssid_str.try_to_string(env)?;

                let bssid_obj = env
                    .get_field(&item, jni_str!("BSSID"), jni_sig!(java.lang.String))?
                    .l()?;
                let bssid = if bssid_obj.is_null() {
                    None
                } else {
                    let s: JString<'_> = env.cast_local::<JString>(bssid_obj)?;
                    parse_bssid_str(&s.try_to_string(env)?)
                };

                // RSSI from `level` (int, dBm). The valid Wi-Fi RSSI range is
                // [-127, 0], so the i32 → i16 narrowing is safe in practice;
                // we still guard the cast for clippy.
                #[allow(clippy::cast_possible_truncation)]
                let level = env
                    .get_field(&item, jni_str!("level"), jni_sig!(int))?
                    .i()? as i16;
                let frequency_mhz = env
                    .get_field(&item, jni_str!("frequency"), jni_sig!(int))?
                    .i()?;

                let caps_obj = env
                    .get_field(&item, jni_str!("capabilities"), jni_sig!(java.lang.String))?
                    .l()?;
                let caps = if caps_obj.is_null() {
                    String::new()
                } else {
                    let s: JString<'_> = env.cast_local::<JString>(caps_obj)?;
                    s.try_to_string(env)?
                };

                Ok(Some(RawBss {
                    ssid: Ssid::from_utf8(&ssid),
                    security: super::security::security_from_capabilities(&caps),
                    rssi_dbm: Some(level),
                    quality: quality_from_dbm(level),
                    bssid,
                    frequency_mhz: u32::try_from(frequency_mhz).ok(),
                }))
            });
        // `with_local_frame_returning_local` proxies returns; if the
        // closure returned `Ok(None)` (null SSID) we skip; if Err we
        // propagate to the caller after clearing any leaked exception.
        match next {
            Ok(Some(bss)) => out.push(bss),
            Ok(None) => {}
            Err(e) => {
                env.exception_clear();
                return Err(e);
            }
        }
    }
    Ok(out)
}

/// Read the currently-connected SSID via `WifiInfo.getSSID()`, stripping
/// the surrounding quotes Android wraps it in and treating
/// `<unknown ssid>` as `None`.
fn read_connected_ssid(env: &mut Env<'_>, wm: &JObject<'_>) -> jni::errors::Result<Option<Ssid>> {
    let info = env
        .call_method(
            wm,
            jni_str!("getConnectionInfo"),
            jni_sig!(() -> android.net.wifi.WifiInfo),
            &[],
        )?
        .l()?;
    if info.is_null() {
        return Ok(None);
    }
    let ssid_obj = env
        .call_method(
            &info,
            jni_str!("getSSID"),
            jni_sig!(() -> java.lang.String),
            &[],
        )?
        .l()?;
    if ssid_obj.is_null() {
        return Ok(None);
    }
    let s: JString<'_> = env.cast_local::<JString>(ssid_obj)?;
    let raw = s.try_to_string(env)?;
    let stripped = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(&raw);
    if stripped.is_empty() || stripped == "<unknown ssid>" {
        return Ok(None);
    }
    Ok(Some(Ssid::from_utf8(stripped)))
}

/// Read `Intent.getBooleanExtra("resultsUpdated", false)` from a
/// `SCAN_RESULTS_AVAILABLE` broadcast. Returns `Ok(false)` (rather than
/// an error) if the extra is absent — the OS guarantees the extra on
/// API ≥ 23, but missing it just means "we don't know whether the scan
/// was fresh", which is the same observational outcome as `false`.
fn read_results_updated_extra(
    env: &mut Env<'_>,
    intent: &jni_min_helper::Intent<'_>,
) -> jni::errors::Result<bool> {
    let key = env.new_string("resultsUpdated")?;
    let intent_obj: &JObject<'_> = AsRef::<JObject<'_>>::as_ref(intent);
    let res = env.call_method(
        intent_obj,
        jni_str!("getBooleanExtra"),
        jni_sig!((java.lang.String, boolean) -> boolean),
        &[JValue::Object(&key), JValue::Bool(false)],
    )?;
    res.z()
}

/// Parse Android's `xx:xx:xx:xx:xx:xx` BSSID string into 6 bytes.
pub(super) fn parse_bssid_str(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

/// Boxes a `jni::errors::Error` as an opaque `std::error::Error` payload
/// for `crate::error::Error::Os`, so JNI failures don't leak the
/// `jni::errors::Error` type into the public API.
#[derive(Debug, thiserror::Error)]
#[error("jni error: {0}")]
struct JniErrAdapter(String);
