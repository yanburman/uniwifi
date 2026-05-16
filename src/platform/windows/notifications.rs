//! Bridge `WlanRegisterNotification` callbacks into `tokio::sync::oneshot`s.

use std::collections::HashMap;
use std::ptr;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use windows::Win32::NetworkManagement::WiFi::{
    L2_NOTIFICATION_DATA, WLAN_CONNECTION_NOTIFICATION_DATA, WLAN_NOTIFICATION_SOURCE_ACM,
    WLAN_NOTIFICATION_SOURCE_NONE, WlanRegisterNotification,
};
use windows::core::GUID;

use crate::error::Error;
use crate::platform::windows::handle::WlanClient;
use crate::platform::windows::reason::map_reason_code;
use crate::platform::windows::util::check_win32;

// ACM notification code values from MSDN's WLAN_NOTIFICATION_ACM enum.
// Hardcoded as `u32` because in `windows = "0.62"` the
// `L2_NOTIFICATION_DATA::NotificationCode` field is `u32` (the
// `WLAN_NOTIFICATION_ACM` enum members in the binding are `i32`-typed
// newtypes, so comparing them directly would require a cast every time —
// we just inline the numeric values).
mod acm_codes {
    pub const SCAN_COMPLETE: u32 = 7;
    pub const SCAN_FAIL: u32 = 8;
    pub const CONNECTION_COMPLETE: u32 = 10;
    pub const CONNECTION_ATTEMPT_FAIL: u32 = 11;
}

/// Outcome of a connect attempt as reported by the callback.
#[derive(Debug)]
pub enum ConnectOutcome {
    Connected,
    Failed(u32),
}

impl ConnectOutcome {
    /// Translate to a `Result<(), Error>` using the reason-code mapper.
    ///
    /// # Errors
    ///
    /// Returns the mapped `Error` for any failure outcome.
    pub fn into_result(self) -> Result<(), Error> {
        match self {
            Self::Connected => Ok(()),
            Self::Failed(code) => map_reason_code(code),
        }
    }
}

type ConnectSender = oneshot::Sender<ConnectOutcome>;
type ScanSender = oneshot::Sender<Result<(), Error>>;

#[derive(Default)]
struct Registry {
    connect: HashMap<GUID, ConnectSender>,
    scan: HashMap<GUID, ScanSender>,
}

/// Long-lived dispatcher; one per `WindowsBackend`.
pub struct Dispatcher {
    inner: Mutex<Registry>,
}

impl Dispatcher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Registry::default()),
        }
    }

    /// Register the global notification callback.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os(_)` if `WlanRegisterNotification` fails.
    pub fn register(self: &Arc<Self>, client: &WlanClient) -> Result<(), Error> {
        let ctx_arc: Arc<Self> = Arc::clone(self);
        let ctx_ptr = Arc::into_raw(ctx_arc).cast::<core::ffi::c_void>();

        // SAFETY: ctx_ptr is a strong-count-1 Arc obtained from `into_raw`;
        // the callback re-materialises a temporary &Dispatcher each invocation
        // and the caller (us) keeps the owning Arc alive via WindowsBackend.
        let code = unsafe {
            WlanRegisterNotification(
                client.handle(),
                WLAN_NOTIFICATION_SOURCE_ACM,
                true,
                Some(notification_thunk),
                Some(ctx_ptr),
                Some(ptr::null::<core::ffi::c_void>()),
                None,
            )
        };
        check_win32(
            "WlanRegisterNotification",
            windows::Win32::Foundation::WIN32_ERROR(code),
        )
    }

    /// Unregister the notification callback. After this returns, no further
    /// callbacks will fire. The caller is responsible for reclaiming the
    /// `Arc<Self>` strong count that was leaked into the callback context
    /// at registration time.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os(_)` if `WlanRegisterNotification` fails.
    pub fn unregister(client: &WlanClient) -> Result<(), Error> {
        // SAFETY: handle valid; passing SOURCE_NONE unregisters per MSDN.
        let code = unsafe {
            WlanRegisterNotification(
                client.handle(),
                WLAN_NOTIFICATION_SOURCE_NONE,
                false,
                None,
                None,
                Some(ptr::null::<core::ffi::c_void>()),
                None,
            )
        };
        check_win32(
            "WlanRegisterNotification(NONE)",
            windows::Win32::Foundation::WIN32_ERROR(code),
        )
    }

    /// Insert a pending connect-attempt waiter for `interface`.
    pub fn pending_connect(&self, interface: GUID) -> oneshot::Receiver<ConnectOutcome> {
        let (tx, rx) = oneshot::channel();
        let mut g = self.inner.lock().expect("registry mutex poisoned");
        let _ = g.connect.insert(interface, tx);
        rx
    }

    /// Insert a pending scan waiter for `interface`.
    pub fn pending_scan(&self, interface: GUID) -> oneshot::Receiver<Result<(), Error>> {
        let (tx, rx) = oneshot::channel();
        let mut g = self.inner.lock().expect("registry mutex poisoned");
        let _ = g.scan.insert(interface, tx);
        rx
    }

    /// Remove a pending connect waiter without firing it (used on cancel).
    pub fn drop_pending_connect(&self, interface: GUID) {
        let mut g = self.inner.lock().expect("registry mutex poisoned");
        g.connect.remove(&interface);
    }

    /// Remove a pending scan waiter without firing it (used after a wait
    /// timeout or `spawn_blocking` join failure, so a late
    /// `wlan_notification_acm_scan_complete` cannot mistakenly fire a
    /// subsequent scan call's tx).
    pub fn drop_pending_scan(&self, interface: GUID) {
        let mut g = self.inner.lock().expect("registry mutex poisoned");
        g.scan.remove(&interface);
    }
}

/// Cancel-on-drop guard for a pending-connect registration. Constructed
/// after `pending_connect` so dropping the surrounding future (e.g. via
/// `tokio::select!` or any other future-cancellation path) reliably
/// removes the entry. On the normal completion path the registry entry
/// is already gone (the dispatcher pulled it out to fire the tx), so
/// the guard's Drop is a harmless no-op.
pub struct PendingConnectGuard {
    dispatcher: Arc<Dispatcher>,
    interface: GUID,
}

impl PendingConnectGuard {
    pub const fn new(dispatcher: Arc<Dispatcher>, interface: GUID) -> Self {
        Self {
            dispatcher,
            interface,
        }
    }
}

impl Drop for PendingConnectGuard {
    fn drop(&mut self) {
        self.dispatcher.drop_pending_connect(self.interface);
    }
}

impl Dispatcher {
    fn dispatch(&self, data: &L2_NOTIFICATION_DATA) {
        enum Pending {
            Connect(ConnectSender),
            Scan(ScanSender),
        }

        // `NotificationSource` is `WLAN_NOTIFICATION_SOURCES(pub u32)` in
        // windows = "0.62", so we must compare the inner `u32`.
        if data.NotificationSource.0 != WLAN_NOTIFICATION_SOURCE_ACM.0 {
            return;
        }
        let interface = data.InterfaceGuid;
        let code: u32 = data.NotificationCode;

        let pending = {
            let mut g = self.inner.lock().expect("registry mutex poisoned");
            if code == acm_codes::CONNECTION_COMPLETE || code == acm_codes::CONNECTION_ATTEMPT_FAIL
            {
                g.connect.remove(&interface).map(Pending::Connect)
            } else if code == acm_codes::SCAN_COMPLETE || code == acm_codes::SCAN_FAIL {
                g.scan.remove(&interface).map(Pending::Scan)
            } else {
                None
            }
        };

        match pending {
            Some(Pending::Connect(tx)) => {
                // SAFETY: For CONNECTION_* codes, pData points to a valid
                // WLAN_CONNECTION_NOTIFICATION_DATA per MSDN.
                let reason = unsafe { read_reason_code(data) };
                let outcome = if code == acm_codes::CONNECTION_COMPLETE && reason == 0 {
                    ConnectOutcome::Connected
                } else {
                    ConnectOutcome::Failed(reason)
                };
                let _ = tx.send(outcome);
            }
            Some(Pending::Scan(tx)) => {
                let payload = if code == acm_codes::SCAN_COMPLETE {
                    Ok(())
                } else {
                    // SCAN_FAIL's pData carries a WLAN_REASON_CODE in the
                    // same shape as CONNECTION_*. Forwarding it preserves
                    // the actual failure reason instead of fabricating a
                    // sentinel that the user-facing error layer would
                    // mis-render as `WlanScan: 0x00000001` ("incorrect
                    // function").
                    // SAFETY: identical contract to the connect branch
                    // above.
                    let reason = unsafe { read_reason_code(data) };
                    Err(Error::Os(Box::new(
                        crate::platform::windows::util::Win32Error {
                            function: "WlanScan",
                            code: reason,
                        },
                    )))
                };
                let _ = tx.send(payload);
            }
            None => {}
        }
    }
}

/// # Safety
///
/// `data.pData` must point to a valid `WLAN_CONNECTION_NOTIFICATION_DATA`
/// for the lifetime of this call.
unsafe fn read_reason_code(data: &L2_NOTIFICATION_DATA) -> u32 {
    if data.pData.is_null() {
        return 0xFFFF_FFFF;
    }
    // SAFETY: caller invariant.
    let payload = unsafe { &*data.pData.cast::<WLAN_CONNECTION_NOTIFICATION_DATA>() };
    payload.wlanReasonCode
}

/// `WLAN_NOTIFICATION_CALLBACK` thunk.
///
/// Note: in `windows = "0.62"` the callback parameter type is
/// `*mut L2_NOTIFICATION_DATA` (the binding generator deduplicated
/// `WLAN_NOTIFICATION_DATA` and `L2_NOTIFICATION_DATA` since they have
/// identical layout). The two are the same struct on the wire.
extern "system" fn notification_thunk(
    data: *mut L2_NOTIFICATION_DATA,
    context: *mut core::ffi::c_void,
) {
    if data.is_null() || context.is_null() {
        return;
    }
    // SAFETY: `context` was obtained via `Arc::into_raw` and the owning
    // dispatcher is still alive while WindowsBackend holds it.
    let dispatcher: &Dispatcher = unsafe { &*context.cast::<Dispatcher>() };
    // SAFETY: `data` is non-null and points to a valid L2_NOTIFICATION_DATA.
    let data_ref: &L2_NOTIFICATION_DATA = unsafe { &*data };
    dispatcher.dispatch(data_ref);
}
