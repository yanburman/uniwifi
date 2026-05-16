//! Foreground check via `UIApplication.applicationState`.
//!
//! Apple's `NEHotspotConfigurationManager.applyConfiguration:` requires the
//! caller's app to be the foreground app; otherwise the apply returns
//! `NEHotspotConfigurationError.applicationIsNotInForeground`. We probe the
//! state *before* the apply so we can fail fast with a typed error and
//! avoid showing the system "Join Network?" prompt that the OS would
//! attempt to display on a backgrounded app.
//!
//! The `UIApplication` API is documented as main-thread-only. Because the
//! iOS backend is invoked from `async fn`s that tokio drives on background
//! worker threads, we hop the property read onto the main queue via
//! `dispatch2::DispatchQueue::main().exec_sync(...)`. When already on the
//! main thread (e.g. a `current_thread` runtime polled from
//! `UIApplicationMain`), we read inline to avoid a deadlock on
//! `dispatch_sync_to_self`.

use std::sync::{Arc, Mutex};

use dispatch2::DispatchQueue;
use objc2::MainThreadMarker;
use objc2_ui_kit::{UIApplication, UIApplicationState};

use crate::error::Error;

/// Returns `Ok(())` iff the host app is currently the foreground / active app.
/// Returns `Err(Error::Unsupported("requires foreground app"))` otherwise.
pub fn ensure_foreground() -> Result<(), Error> {
    // Fast path: already on main thread (e.g. current-thread tokio runtime
    // polled from UIApplicationMain).
    if let Some(mtm) = MainThreadMarker::new() {
        return read_state(mtm);
    }

    // Worker-thread path: hop to the main queue. `exec_sync` blocks the
    // calling thread until the closure returns, so the result becomes
    // observable through the shared `Mutex`.
    //
    // Deadlock note: `dispatch_sync` from the main queue *to* the main
    // queue would deadlock — that's why the fast path above takes the
    // inline read when MainThreadMarker is available.
    let result: Arc<Mutex<Option<Result<(), Error>>>> = Arc::new(Mutex::new(None));
    let result_inner = Arc::clone(&result);
    DispatchQueue::main().exec_sync(move || {
        // SAFETY: the closure body runs on the main queue, so a
        // `MainThreadMarker` is constructible and `sharedApplication`
        // is callable.
        let r = MainThreadMarker::new().map_or(
            Err(Error::Unsupported("requires foreground app")),
            read_state,
        );
        *result_inner
            .lock()
            .expect("foreground result mutex poisoned") = Some(r);
    });
    result
        .lock()
        .expect("foreground result mutex poisoned")
        .take()
        .unwrap_or(Err(Error::Unsupported("requires foreground app")))
}

fn read_state(mtm: MainThreadMarker) -> Result<(), Error> {
    let app = UIApplication::sharedApplication(mtm);
    let state = app.applicationState();
    if state == UIApplicationState::Active {
        Ok(())
    } else {
        // `Inactive` (e.g. transitioning, system alert visible) and
        // `Background` both fail. The error message is identical because
        // the user-visible remedy is the same: bring the app to the
        // foreground.
        Err(Error::Unsupported("requires foreground app"))
    }
}
