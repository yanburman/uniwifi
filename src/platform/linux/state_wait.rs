//! Wait for an `ActiveConnection` to settle: ACTIVATED (success) or
//! DEACTIVATED (failure with a state-reason).

use std::time::Duration;

use futures_util::StreamExt;
use zbus::zvariant::OwnedObjectPath;

use crate::error::Error;

use super::backend::NmHandles;
use super::error_map::{from_zbus, map_state_reason};
use super::proxies::ActiveConnectionProxy;

/// `NMActiveConnectionState` discriminants.
const STATE_ACTIVATED: u32 = 2;
const STATE_DEACTIVATED: u32 = 4;

/// Subscribe to `ActiveConnection.StateChanged` and resolve when the
/// connection reaches ACTIVATED or DEACTIVATED, bounded by `timeout`.
///
/// # Errors
///
/// - [`Error::Timeout`] if the deadline fires before the connection settles.
/// - [`Error::AuthenticationFailed`] (or another typed [`Error`]) if
///   `NetworkManager` reports a deactivation reason — see
///   [`super::error_map::map_state_reason`] for the mapping.
/// - [`Error::Os`] if the `zbus` proxy build fails or the
///   `StateChanged` signal stream closes unexpectedly before reaching
///   a terminal state.
pub async fn wait_for_active_connection(
    handles: &NmHandles,
    active_path: &OwnedObjectPath,
    timeout: Duration,
) -> Result<(), Error> {
    let active = ActiveConnectionProxy::builder(&handles.conn)
        .path(active_path.clone())
        .map_err(from_zbus)?
        .build()
        .await
        .map_err(from_zbus)?;

    // Subscribe BEFORE reading the current state. If we read first and a
    // transition fires between read and subscribe, we'd miss it. The
    // signal stream has its own buffer.
    //
    // NOTE: this calls `receive_nm_state_changed` (NOT `receive_state_changed`)
    // because Task 3 renamed the signal's Rust method to avoid a collision
    // with the property-change subscriber. The wire signal name is still
    // `StateChanged`.
    let mut signals = active.receive_nm_state_changed().await.map_err(from_zbus)?;

    // Check the current state once — it may already be terminal. NM does
    // not expose the deactivation reason as a property, so for the
    // already-terminal case we pass `None` to distinguish it from a
    // signal-derived terminal state with a known reason.
    if let Ok(current) = active.state().await
        && let Some(err) = terminal_state_to_error(current, None)
    {
        return err;
    }

    let wait = async {
        while let Some(signal) = signals.next().await {
            let Ok(args) = signal.args() else { continue };
            if let Some(err) = terminal_state_to_error(args.state, Some(args.reason)) {
                return err;
            }
        }
        // Stream closed before reaching a terminal state — treat as os error.
        Err(Error::Os(Box::new(std::io::Error::other(
            "ActiveConnection.StateChanged stream closed unexpectedly",
        ))))
    };

    tokio::time::timeout(timeout, wait)
        .await
        .unwrap_or_else(|_| Err(Error::Timeout(timeout)))
}

/// Map an `(state, reason)` pair into either:
/// - `Some(Ok(()))` if the connection reached ACTIVATED,
/// - `Some(Err(typed_error))` if the connection reached DEACTIVATED,
/// - `None` if the connection is still in progress.
///
/// `reason` is `None` when called from the property-read path (NM does
/// not expose the deactivation reason as a property — only as the trailing
/// argument of the `StateChanged` signal). In that case a DEACTIVATED
/// state is reported as an opaque `Os` error rather than an arbitrary
/// guess like `AuthenticationFailed`, which would otherwise mislead
/// callers when the deactivation was caused by something else (user
/// disconnect, device down, etc.).
fn terminal_state_to_error(state: u32, reason: Option<u32>) -> Option<Result<(), Error>> {
    match state {
        STATE_ACTIVATED => Some(Ok(())),
        STATE_DEACTIVATED => {
            let err = reason.map_or_else(
                || {
                    Error::Os(Box::new(std::io::Error::other(
                        "ActiveConnection deactivated before observing state-change reason",
                    )))
                },
                |r| map_state_reason(r).unwrap_or(Error::AuthenticationFailed),
            );
            Some(Err(err))
        }
        _ => None,
    }
}
