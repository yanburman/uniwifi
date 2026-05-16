//! Low-level wrappers around `NEHotspotConfiguration` /
//! `NEHotspotConfigurationManager`. Holds the synchronous builders, the
//! async wrappers that bridge Objective-C completion handlers to
//! `tokio::sync::oneshot`, and the `BlockChannelDropped` sentinel.

use std::ptr::NonNull;

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::{AnyThread, MainThreadMarker};
use objc2_foundation::{NSArray, NSError, NSString};
use objc2_network_extension::{NEHotspotConfiguration, NEHotspotConfigurationManager};
use secrecy::ExposeSecret;
use tokio::sync::oneshot;

use crate::error::Error;
use crate::platform::ios::error_map::{MappedError, map_ne_error};
use crate::types::{Credentials, Ssid};

/// Run `f` on the main queue. Apple documents
/// `NEHotspotConfigurationManager`'s mutators (`applyConfiguration:`,
/// `removeConfigurationForSSID:`, `getConfiguredSSIDsWithCompletionHandler:`)
/// as main-thread-targeted; invoking from a tokio worker thread without
/// hopping to the main queue has produced reports of dropped completion
/// handlers on certain iOS versions.
///
/// `exec_sync` blocks until `f` returns. When already on the main thread
/// (e.g. a `current_thread` tokio runtime polled from `UIApplicationMain`),
/// we run `f` inline to avoid `dispatch_sync(main, ...)` deadlocking on
/// itself.
fn run_on_main<F>(f: F)
where
    F: FnOnce() + Send,
{
    if MainThreadMarker::new().is_some() {
        f();
    } else {
        DispatchQueue::main().exec_sync(f);
    }
}

/// Build an `NEHotspotConfiguration` from an SSID + credentials.
///
/// # Errors
/// Returns `Error::Unsupported(...)` if the SSID can't be expressed as
/// UTF-8: `NEHotspotConfiguration` only accepts `NSString` SSIDs, and there
/// is no public API to pass arbitrary bytes. In practice almost every
/// real-world SSID is UTF-8; non-UTF-8 SSIDs are rejected at this layer
/// rather than translated lossily.
pub fn build_configuration(
    ssid: &Ssid,
    credentials: &Credentials,
) -> Result<Retained<NEHotspotConfiguration>, Error> {
    let ssid_str = ssid.as_str().ok_or(Error::Unsupported(
        "ios backend requires utf-8 ssid (no public api for raw bytes)",
    ))?;
    let ns_ssid = NSString::from_str(ssid_str);

    let alloc = NEHotspotConfiguration::alloc();

    let configured = match credentials {
        Credentials::Open => {
            // SAFETY: `initWithSSID:` is a designated initializer for open
            // networks. We pass a non-null `&NSString`; ownership follows
            // the standard alloc/init pattern.
            unsafe { NEHotspotConfiguration::initWithSSID(alloc, &ns_ssid) }
        }
        Credentials::Password(secret) => {
            let pass_str = secret.expose_secret();
            let ns_pass = NSString::from_str(pass_str);
            // SAFETY: `initWithSSID:passphrase:isWEP:` is a designated
            // initializer; `false` selects WPA/WPA2 Personal (the default
            // case for password-protected networks; WEP is legacy and
            // intentionally unsupported by this crate).
            unsafe {
                NEHotspotConfiguration::initWithSSID_passphrase_isWEP(
                    alloc, &ns_ssid, &ns_pass, false,
                )
            }
        }
    };

    Ok(configured)
}

/// Build an SSID-only `NEHotspotConfiguration`, used for re-applying a
/// previously-installed profile (the stored-credentials path).
///
/// Per Apple docs, applying an SSID-only configuration causes the OS to
/// look up the existing entitled configuration (if any) and re-associate.
/// If no such configuration exists, `applyConfiguration:` returns
/// `NEHotspotConfigurationError.invalidSSID` or similar — but the caller
/// (Task 8) probes `getConfiguredSSIDsWithCompletionHandler:` first so we
/// can surface a clean `Error::NoStoredCredentials` before the apply.
///
/// # Errors
/// Returns `Error::Unsupported(...)` if the SSID isn't UTF-8 (same reason
/// as `build_configuration`).
pub fn build_ssid_only_configuration(
    ssid: &Ssid,
) -> Result<Retained<NEHotspotConfiguration>, Error> {
    let ssid_str = ssid.as_str().ok_or(Error::Unsupported(
        "ios backend requires utf-8 ssid (no public api for raw bytes)",
    ))?;
    let ns_ssid = NSString::from_str(ssid_str);
    let alloc = NEHotspotConfiguration::alloc();
    // SAFETY: `initWithSSID:` is the same designated initializer used in
    // the open-network case; an SSID-only config is valid per the
    // NetworkExtension framework.
    Ok(unsafe { NEHotspotConfiguration::initWithSSID(alloc, &ns_ssid) })
}

/// Helper: obtain the shared manager. Cheap; the runtime caches the
/// singleton on first call.
fn shared_manager() -> Retained<NEHotspotConfigurationManager> {
    // SAFETY: `sharedManager` is a documented singleton getter; safe on
    // any thread. (Property mutations like apply / remove target the main
    // queue internally, but the singleton getter itself has no thread
    // affinity.)
    unsafe { NEHotspotConfigurationManager::sharedManager() }
}

/// Kick off an apply: build the configuration, acquire the manager
/// singleton, install the completion-handler block, fire
/// `applyConfiguration:completionHandler:`, and return the receiver half
/// of the oneshot.
///
/// The configuration build and the manager call both run on the main
/// queue (see [`run_on_main`]). The returned receiver is `Send` because
/// `NSError: Send + Sync` per `objc2-foundation`, which keeps any outer
/// `await rx` future `Send` and satisfies the crate-internal
/// `Backend: Send + Sync` bound.
///
/// # Errors
/// Returns the error produced by [`build_configuration`] if the SSID is
/// not UTF-8.
///
/// Call sites pair this with [`map_apply_received`] to translate the
/// awaited value into a typed `Result<(), Error>`.
pub fn apply_configuration_kickoff(
    ssid: &Ssid,
    credentials: &Credentials,
) -> Result<oneshot::Receiver<Option<Retained<NSError>>>, Error> {
    let (tx, rx) = oneshot::channel::<Option<Retained<NSError>>>();
    // We thread the result of `build_configuration` out of the closure
    // through this slot so an SSID/encoding failure surfaces as the same
    // typed `Error` the inline caller would have seen.
    let build_result: std::sync::Mutex<Option<Result<(), Error>>> = std::sync::Mutex::new(None);

    run_on_main(|| {
        let config = match build_configuration(ssid, credentials) {
            Ok(c) => c,
            Err(e) => {
                *build_result.lock().expect("build_result mutex poisoned") = Some(Err(e));
                return;
            }
        };

        let manager = shared_manager();

        // The block must be `'static` and is bound by `RcBlock::new` as
        // `Fn(*mut NSError)`. We move `tx` into a `Mutex<Option<...>>` and
        // `take` it on first call so the closure satisfies `Fn`. Apple
        // documents that the block is invoked exactly once; the take()-or-
        // no-op pattern is a defensive measure against a hypothetical
        // double-fire bug rather than a real expected case.
        let tx_cell = std::sync::Mutex::new(Some(tx));
        let block = RcBlock::new(move |err_ptr: *mut NSError| {
            let mapped = if err_ptr.is_null() {
                None
            } else {
                // SAFETY: the runtime guarantees `err_ptr` is a valid `NSError`
                // when non-null; we retain it (+1) so it keeps living once the
                // callback frame returns. `Retained::retain` returns `None`
                // only for null pointers, which we already filtered out.
                unsafe { Retained::retain(err_ptr) }
            };
            if let Ok(mut guard) = tx_cell.lock()
                && let Some(sender) = guard.take()
            {
                let _ = sender.send(mapped);
            }
        });

        // SAFETY: `applyConfiguration:completionHandler:` accepts an optional
        // block; we pass `Some(&block)`. The Objective-C runtime copies the
        // block onto the heap when the manager accepts it (`Block_copy`
        // semantics), so it is safe to drop our local `RcBlock` when this
        // function returns — the manager keeps its own reference until the
        // completion handler fires.
        unsafe {
            manager.applyConfiguration_completionHandler(&config, Some(&block));
        }
        *build_result.lock().expect("build_result mutex poisoned") = Some(Ok(()));
    });

    let outcome = build_result
        .into_inner()
        .expect("build_result mutex poisoned")
        .expect("run_on_main always populates build_result");
    outcome.map(|()| rx)
}

/// Variant of [`apply_configuration_kickoff`] that uses an SSID-only
/// configuration (caller already verified a stored profile exists).
pub fn apply_ssid_only_kickoff(
    ssid: &Ssid,
) -> Result<oneshot::Receiver<Option<Retained<NSError>>>, Error> {
    let (tx, rx) = oneshot::channel::<Option<Retained<NSError>>>();
    let build_result: std::sync::Mutex<Option<Result<(), Error>>> = std::sync::Mutex::new(None);

    run_on_main(|| {
        let config = match build_ssid_only_configuration(ssid) {
            Ok(c) => c,
            Err(e) => {
                *build_result.lock().expect("build_result mutex poisoned") = Some(Err(e));
                return;
            }
        };
        let manager = shared_manager();
        let tx_cell = std::sync::Mutex::new(Some(tx));
        let block = RcBlock::new(move |err_ptr: *mut NSError| {
            let mapped = if err_ptr.is_null() {
                None
            } else {
                // SAFETY: identical contract to `apply_configuration_kickoff`.
                unsafe { Retained::retain(err_ptr) }
            };
            if let Ok(mut guard) = tx_cell.lock()
                && let Some(sender) = guard.take()
            {
                let _ = sender.send(mapped);
            }
        });
        // SAFETY: same as `apply_configuration_kickoff`.
        unsafe {
            manager.applyConfiguration_completionHandler(&config, Some(&block));
        }
        *build_result.lock().expect("build_result mutex poisoned") = Some(Ok(()));
    });

    let outcome = build_result
        .into_inner()
        .expect("build_result mutex poisoned")
        .expect("run_on_main always populates build_result");
    outcome.map(|()| rx)
}

/// Translate the value coming out of `apply_configuration_kickoff`'s
/// receiver into a typed `Result<(), Error>`. Centralised here so call
/// sites that drive the receiver themselves don't reimplement the
/// `RecvError` -> `Error::Os(BlockChannelDropped)` translation or the
/// `NEHotspotConfigurationError` -> typed-`Error` mapping.
pub fn map_apply_received(
    received: Result<Option<Retained<NSError>>, oneshot::error::RecvError>,
) -> Result<(), Error> {
    let received = received.map_err(|_| Error::Os(Box::new(BlockChannelDropped("apply"))))?;
    received.map_or(Ok(()), |err| match map_ne_error(&err) {
        MappedError::Surface(e) => Err(e),
        MappedError::AlreadyAssociated => Ok(()),
    })
}

/// Remove a configuration. Synchronous and idempotent per Apple docs;
/// removing a non-existent SSID is a no-op. The manager call runs on
/// the main queue (see [`run_on_main`]).
///
/// # Errors
/// Returns `Error::Unsupported(...)` if the SSID isn't UTF-8 (same
/// reason as `build_configuration`).
pub fn remove_configuration_for_ssid(ssid: &Ssid) -> Result<(), Error> {
    let ssid_str = ssid.as_str().ok_or(Error::Unsupported(
        "ios backend requires utf-8 ssid (no public api for raw bytes)",
    ))?;
    run_on_main(|| {
        let ns_ssid = NSString::from_str(ssid_str);
        let manager = shared_manager();
        // SAFETY: `removeConfigurationForSSID:` is a stable, documented
        // method taking a non-null `NSString`. No completion handler.
        unsafe {
            manager.removeConfigurationForSSID(&ns_ssid);
        }
    });
    Ok(())
}

/// Kick off a `getConfiguredSSIDsWithCompletionHandler:` query on the
/// main queue. The receiver is `Send` because `Vec<String>: Send`.
///
/// Call sites pair this with [`map_get_configured_received`] to translate
/// the awaited value into a typed `Result<Vec<String>, Error>`.
pub fn get_configured_ssids_kickoff() -> oneshot::Receiver<Vec<String>> {
    let (tx, rx) = oneshot::channel::<Vec<String>>();
    run_on_main(|| {
        let manager = shared_manager();
        let tx_cell = std::sync::Mutex::new(Some(tx));

        let block = RcBlock::new(move |arr_ptr: NonNull<NSArray<NSString>>| {
            // SAFETY: Apple's contract: the array pointer is non-null and
            // valid for the duration of the callback. We copy the strings
            // out before the callback returns.
            let arr = unsafe { arr_ptr.as_ref() };
            // `NSEnumerator` cargo feature isn't enabled (`iter()` is gated
            // on it), so we use `to_vec()` which is always available. Each
            // entry is a `Retained<NSString>` we then convert via `Display`.
            let out: Vec<String> = arr.to_vec().iter().map(ToString::to_string).collect();
            if let Ok(mut guard) = tx_cell.lock()
                && let Some(sender) = guard.take()
            {
                let _ = sender.send(out);
            }
        });

        // SAFETY: documented method; takes a non-optional block. The block
        // is retained by the manager until invoked.
        unsafe {
            manager.getConfiguredSSIDsWithCompletionHandler(&block);
        }
    });
    rx
}

/// Translate the value coming out of `get_configured_ssids_kickoff`'s
/// receiver into a typed `Result<Vec<String>, Error>`. Centralised here
/// so call sites that drive the receiver themselves don't reimplement
/// the `RecvError` -> `Error::Os(BlockChannelDropped)` translation.
pub fn map_get_configured_received(
    received: Result<Vec<String>, oneshot::error::RecvError>,
) -> Result<Vec<String>, Error> {
    received.map_err(|_| Error::Os(Box::new(BlockChannelDropped("getConfiguredSSIDs"))))
}

/// Sentinel error: oneshot Sender dropped before the completion handler
/// fired. This *should* never happen in practice (the block holds the
/// sender; the manager owns the block until it invokes it). We surface
/// it as `Error::Os` rather than panicking so a misbehaving runtime is
/// observable.
#[derive(Debug)]
struct BlockChannelDropped(&'static str);

impl std::fmt::Display for BlockChannelDropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ios completion block channel dropped (op: {})", self.0)
    }
}

impl std::error::Error for BlockChannelDropped {}
