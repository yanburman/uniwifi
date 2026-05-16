//! Thin wrapper around the `CWWiFiClient` singleton.

use std::sync::{Arc, Mutex};

use objc2::rc::Retained;
use objc2_core_wlan::CWWiFiClient;

/// `Retained<CWWiFiClient>` is `!Send + !Sync` because `CWWiFiClient` is
/// not generally thread-safe. We wrap it in this newtype and assert
/// `Send + Sync` so we can park the singleton inside an `Arc<Mutex<...>>`
/// shared across the async runtime's worker threads. Safety relies on
/// `SharedClient` only ever exposing the inner client through the mutex
/// guard returned by `with`, which serializes all access.
struct ThreadSafeClient(Retained<CWWiFiClient>);

// SAFETY: the only way to access the wrapped `Retained<CWWiFiClient>` is
// through `SharedClient::with`, which holds a `Mutex` guard for the
// duration of the closure. Apple documents the `sharedWiFiClient`
// singleton as callable from any thread provided callers serialize use of
// the returned object, which is exactly what this wrapper enforces.
//
// `non_send_fields_in_send_ty` flags that the wrapped `Retained` field is
// itself `!Send`; that is precisely the condition under which `unsafe
// impl Send` exists, so the lint is a false positive here.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for ThreadSafeClient {}
// SAFETY: see `Send` impl above; `&ThreadSafeClient` is never exposed
// outside the mutex-guarded closure in `SharedClient::with`.
unsafe impl Sync for ThreadSafeClient {}

/// Process-global Wi-Fi client. Hold one of these in `MacosBackend`.
///
/// `CoreWLAN` documents `CWWiFiClient` as a "heavy object" that callers
/// should share, and as not thread-safe; we serialize all access through
/// the internal `Mutex`.
#[derive(Clone)]
pub(super) struct SharedClient {
    inner: Arc<Mutex<ThreadSafeClient>>,
}

impl SharedClient {
    /// Acquire (or initialise) the shared `CWWiFiClient`.
    ///
    /// # Safety
    /// `CWWiFiClient::sharedWiFiClient` is an unsafe FFI call on an
    /// Objective-C class method that returns the process singleton; calling
    /// it on any thread is documented as safe by Apple, and the returned
    /// `Retained` reference is the only one we keep.
    pub(super) fn new() -> Self {
        // SAFETY: `sharedWiFiClient` is a class method that returns the
        // process-global singleton; calling it from any thread is safe.
        let client = unsafe { CWWiFiClient::sharedWiFiClient() };
        Self {
            inner: Arc::new(Mutex::new(ThreadSafeClient(client))),
        }
    }

    /// Run the closure with exclusive access to the underlying client.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned. We treat poisoning as a
    /// programmer bug because every call site holds the lock for a single
    /// non-panicking Objective-C method.
    pub(super) fn with<R>(&self, f: impl FnOnce(&CWWiFiClient) -> R) -> R {
        let guard = self.inner.lock().expect("CWWiFiClient mutex poisoned");
        f(&guard.0)
    }
}
