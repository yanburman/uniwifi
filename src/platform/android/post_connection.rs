//! Wait for the device to associate to the target SSID after a
//! successful `addNetworkSuggestions`.
//!
//! Strategy: race a `BroadcastReceiver` for
//! `ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION` against a poll of
//! `WifiManager.getConnectionInfo().getSSID()` against an overall
//! timeout. First signal wins.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jni::Env;
use jni_min_helper::BroadcastReceiver;
use tokio::sync::oneshot;

use crate::error::Error;
use crate::types::Ssid;

use super::jni_helpers::boxed;
use super::wifi_manager::{current_ssid, wifi_manager};

const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Waits up to `timeout` for the device to be associated to `target`.
/// Returns `Ok(())` once the SSID is observed; `Err(Timeout)` otherwise.
///
/// The receiver path is the canonical signal but only fires for
/// suggestions whose `setIsAppInteractionRequired(true)` flag was set
/// (we always set it — see `suggestion::build_suggestion`). The polling
/// path catches stragglers — e.g., older OS versions that drop the
/// directed broadcast, or scenarios where the host app is missing the
/// `ACCESS_FINE_LOCATION` permission required for the broadcast to
/// be delivered.
pub fn wait_for_post_connection(
    env: &mut Env<'_>,
    target: &Ssid,
    timeout: Duration,
) -> Result<(), Error> {
    let (tx, rx) = oneshot::channel::<()>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let tx_for_handler = Arc::clone(&tx);

    let receiver = BroadcastReceiver::build(move |_env, _ctx, _intent| {
        if let Ok(mut g) = tx_for_handler.lock()
            && let Some(t) = g.take()
        {
            let _ = t.send(());
        }
        Ok(())
    })
    .map_err(|e| Error::Os(boxed(JniProxyErr(format!("{e:?}")))))?;

    receiver
        .register_for_action("android.net.wifi.action.WIFI_NETWORK_SUGGESTION_POST_CONNECTION")
        .map_err(|e| Error::Os(boxed(JniProxyErr(format!("{e:?}")))))?;

    let deadline = Instant::now() + timeout;
    let target_str = target.as_str().ok_or(Error::Unsupported(
        "non-UTF8 SSIDs not supported on Android",
    ))?;

    // Poll loop. Each iteration: try receiver (non-blocking), then
    // poll WifiInfo, then sleep.
    let wm = wifi_manager(env)?;
    let mut rx = rx;
    loop {
        // 1. Receiver?
        match rx.try_recv() {
            Ok(()) => {
                // Broadcast fired; verify the active SSID matches before
                // declaring success — the broadcast can fire for ANY of
                // our suggestions, not just this one.
                if let Some(active) = current_ssid(env, &wm)?
                    && active == target_str
                {
                    return Ok(());
                }
                // Spurious match (different suggestion). Re-arm and
                // keep polling until deadline.
                let (new_tx, new_rx) = oneshot::channel::<()>();
                if let Ok(mut g) = tx.lock() {
                    *g = Some(new_tx);
                }
                rx = new_rx;
            }
            // Empty: no broadcast yet — keep polling.
            // Closed: channel closed without firing — fall back to polling
            // exclusively.
            Err(
                tokio::sync::oneshot::error::TryRecvError::Empty
                | tokio::sync::oneshot::error::TryRecvError::Closed,
            ) => {}
        }

        // 2. WifiInfo poll.
        if let Some(active) = current_ssid(env, &wm)?
            && active == target_str
        {
            return Ok(());
        }

        // 3. Deadline.
        if Instant::now() >= deadline {
            return Err(Error::Timeout(timeout));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("jni proxy error: {0}")]
struct JniProxyErr(String);
