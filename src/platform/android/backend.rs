//! `AndroidBackend`: the cfg-gated `Backend` impl for `target_os = "android"`.

#[cfg(target_os = "android")]
use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
#[cfg(target_os = "android")]
use jni::objects::JObject;
#[cfg(target_os = "android")]
use jni::refs::Global;

use crate::backend::{AdapterInfo, Backend};
use crate::connection::WifiConnection;
use crate::error::Error;
use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

#[cfg(target_os = "android")]
use super::jni_helpers;

/// Synthetic adapter id reported on Android.
#[cfg(target_os = "android")]
pub const SYNTHETIC_ADAPTER_ID: &str = "wlan0";
#[cfg(target_os = "android")]
pub const SYNTHETIC_ADAPTER_NAME: &str = "Wi-Fi";

/// Type alias to keep the cache map's signatures readable. The
/// suggestion object's runtime type is `WifiNetworkSuggestion`, but at
/// the JNI layer we just hold it as a generic `JObject` global.
///
/// `Global<T>` itself is not `Clone` (cloning a JNI global ref requires
/// an attached env), so we wrap it in `Arc` to make the cache's value
/// type cheaply cloneable when callers fetch it.
#[cfg(target_os = "android")]
pub type SuggestionRef = Arc<Global<JObject<'static>>>;

/// The Android backend.
///
/// Holds the in-memory profile cache keyed by SSID. Android does not
/// expose any API to read back a previously-registered suggestion's
/// passphrase, so this cache is the only place the passphrase lives
/// after `connect`. The cache is *not* persisted: it lives only for
/// the lifetime of this `AndroidBackend` (and therefore the owning
/// `UniWifi`). On process restart, callers must re-supply credentials.
#[cfg(target_os = "android")]
pub struct AndroidBackend {
    /// Per-adapter serializer. Android only ever exposes one virtual
    /// adapter, but using a map keeps the shape symmetric with other
    /// backends and makes the locking story unambiguous.
    locks: StdMutex<HashMap<AdapterId, Arc<tokio::sync::Mutex<()>>>>,

    /// Profile cache: SSID → global ref to the `WifiNetworkSuggestion`.
    /// We keep the suggestion around (rather than re-building it from
    /// cached SSID + password) because re-registration with the *same*
    /// builder output is the documented way to refresh a suggestion.
    profiles: StdMutex<HashMap<Ssid, SuggestionRef>>,
}

/// Test-only variant of `AndroidBackend` for host builds.
#[cfg(not(target_os = "android"))]
pub struct AndroidBackend {
    /// Minimal fields for `list_adapters` test.
    _marker: std::marker::PhantomData<()>,
}

impl AndroidBackend {
    /// Construct a new backend.
    ///
    /// # Errors
    ///
    /// Fails fast with `Error::Unsupported("ndk-context not initialized")`
    /// if the host app has not called
    /// `ndk_context::initialize_android_context(...)` before this point.
    #[cfg(target_os = "android")]
    pub fn new() -> Result<Self, Error> {
        jni_helpers::require_ndk_context()?;
        Ok(Self {
            locks: StdMutex::new(HashMap::new()),
            profiles: StdMutex::new(HashMap::new()),
        })
    }

    /// Acquire the per-adapter lock, lazily creating it if needed.
    #[cfg(target_os = "android")]
    pub(crate) fn adapter_lock(&self, adapter: &AdapterId) -> Arc<tokio::sync::Mutex<()>> {
        let mut guard = self.locks.lock().expect("locks mutex poisoned");
        guard
            .entry(adapter.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Fetch the cached suggestion ref for `ssid`, if any.
    #[must_use]
    #[cfg(target_os = "android")]
    pub(crate) fn cached_suggestion(&self, ssid: &Ssid) -> Option<SuggestionRef> {
        self.profiles
            .lock()
            .expect("profiles mutex poisoned")
            .get(ssid)
            .cloned()
    }

    /// Insert or replace the cached suggestion for `ssid`.
    #[cfg(target_os = "android")]
    pub(crate) fn cache_suggestion(&self, ssid: Ssid, suggestion: SuggestionRef) {
        self.profiles
            .lock()
            .expect("profiles mutex poisoned")
            .insert(ssid, suggestion);
    }

    /// Forget the cached suggestion for `ssid`. Returns `true` if a
    /// suggestion was present.
    #[cfg(target_os = "android")]
    pub(crate) fn evict_suggestion(&self, ssid: &Ssid) -> bool {
        self.profiles
            .lock()
            .expect("profiles mutex poisoned")
            .remove(ssid)
            .is_some()
    }

    /// Snapshot the SSIDs present in the in-process suggestion cache.
    ///
    /// Android exposes no API to enumerate previously-registered
    /// `WifiNetworkSuggestion` objects, so this cache is the only source
    /// of truth for `VisibleNetwork::has_saved_profile`. The snapshot is
    /// taken under the cache lock and returned by value so the JNI
    /// blocking worker can use it without further locking.
    #[cfg(target_os = "android")]
    pub(crate) fn cached_suggestion_ssids(&self) -> std::collections::HashSet<Ssid> {
        self.profiles
            .lock()
            .expect("profiles mutex poisoned")
            .keys()
            .cloned()
            .collect()
    }
}

#[cfg(target_os = "android")]
#[async_trait]
impl Backend for AndroidBackend {
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
        Ok(vec![AdapterInfo {
            id: AdapterId::new(SYNTHETIC_ADAPTER_ID),
            name: SYNTHETIC_ADAPTER_NAME.to_string(),
        }])
    }

    async fn connect(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        credentials: &Credentials,
        options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        if adapter.as_str() != SYNTHETIC_ADAPTER_ID {
            return Err(Error::AdapterNotFound(adapter.to_string()));
        }
        let lock = self.adapter_lock(adapter);
        let _guard = lock.lock().await;

        // Connect on-demand via a Wi-Fi network specifier rather than a
        // suggestion: a suggestion is opportunistic and the OS will not drop an
        // active internet-bearing network for it, whereas a network *request*
        // with a specifier brings the target AP up as an app-scoped network
        // (after a one-time user-approval dialog) and binds this process to it.
        let ssid_owned = ssid.clone();
        let creds_owned = credentials.clone();
        let timeout = options.effective_timeout();
        jni_blocking(move || {
            super::wifi_specifier::connect_via_specifier(&ssid_owned, &creds_owned, timeout)
        })
        .await
    }

    async fn connect_with_stored_credentials(
        &self,
        adapter: &AdapterId,
        ssid: &Ssid,
        options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        if adapter.as_str() != SYNTHETIC_ADAPTER_ID {
            return Err(Error::AdapterNotFound(adapter.to_string()));
        }
        let lock = self.adapter_lock(adapter);
        let _guard = lock.lock().await;

        let cached = self
            .cached_suggestion(ssid)
            .ok_or_else(|| Error::NoStoredCredentials(ssid.to_string()))?;

        let ssid_owned = ssid.clone();
        let opts_owned = options.clone();
        let connected: Result<(), Error> = jni_blocking(move || {
            let outcome: Result<Result<(), Error>, jni::errors::Error> =
                jni_min_helper::jni_with_env(|env| {
                    let wm = match super::wifi_manager::wifi_manager(env) {
                        Ok(w) => w,
                        Err(e) => return Ok(Err(e)),
                    };
                    // Best-effort: remove any existing registration first so
                    // the OS treats this as a fresh suggestion. We ignore the
                    // status; remove-of-not-present is harmless here.
                    //
                    // `cached: Arc<Global<JObject<'static>>>` so `(*cached).as_ref()`
                    // delivers the `&JObject<'_>` the wrapper expects.
                    let _ =
                        super::wifi_manager::remove_one_suggestion(env, &wm, (*cached).as_ref());

                    let status =
                        match super::wifi_manager::add_one_suggestion(env, &wm, (*cached).as_ref())
                        {
                            Ok(s) => s,
                            Err(e) => return Ok(Err(e)),
                        };
                    if let Err(e) = super::status_codes::map_add_status(status) {
                        return Ok(Err(e));
                    }

                    let timeout = opts_owned.effective_timeout();
                    if let Err(e) =
                        super::post_connection::wait_for_post_connection(env, &ssid_owned, timeout)
                    {
                        return Ok(Err(e));
                    }
                    Ok(Ok(()))
                });
            match outcome {
                Ok(inner) => inner,
                Err(jni_err) => Err(Error::Os(super::jni_helpers::boxed(jni_err))),
            }
        })
        .await;
        connected.map(|()| WifiConnection::inert())
    }

    async fn disconnect(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<(), Error> {
        if adapter.as_str() != SYNTHETIC_ADAPTER_ID {
            return Err(Error::AdapterNotFound(adapter.to_string()));
        }
        let lock = self.adapter_lock(adapter);
        let _guard = lock.lock().await;

        // Idempotent: removing an unknown SSID is not an error.
        let Some(cached) = self.cached_suggestion(ssid) else {
            return Ok(());
        };

        jni_blocking(move || {
            let outcome: Result<Result<(), Error>, jni::errors::Error> =
                jni_min_helper::jni_with_env(|env| {
                    let wm = match super::wifi_manager::wifi_manager(env) {
                        Ok(w) => w,
                        Err(e) => return Ok(Err(e)),
                    };
                    // disconnect: use the API 31+ two-arg form with
                    // ACTION_REMOVE_SUGGESTION_DISCONNECT so the OS
                    // actually tears down any current connection to
                    // the suggested network. On older API levels, fall
                    // back to the single-arg form (best-effort: the
                    // suggestion is removed but the device may stay
                    // connected until the next idle / RSSI loss).
                    let status = match super::wifi_manager::remove_one_suggestion_disconnect(
                        env,
                        &wm,
                        (*cached).as_ref(),
                    ) {
                        Ok(s) => s,
                        Err(e) => return Ok(Err(e)),
                    };
                    // For disconnect we accept both WasRemoved and
                    // NotPresent as success — the post-condition is
                    // "you are not connected to ssid", not "we found
                    // the suggestion".
                    Ok(super::status_codes::map_remove_status(status).map(|_| ()))
                });
            match outcome {
                Ok(inner) => inner,
                Err(jni_err) => Err(Error::Os(super::jni_helpers::boxed(jni_err))),
            }
        })
        .await?;

        self.evict_suggestion(ssid);
        Ok(())
    }

    async fn remove_profile(&self, adapter: &AdapterId, ssid: &Ssid) -> Result<bool, Error> {
        if adapter.as_str() != SYNTHETIC_ADAPTER_ID {
            return Err(Error::AdapterNotFound(adapter.to_string()));
        }
        let lock = self.adapter_lock(adapter);
        let _guard = lock.lock().await;

        let Some(cached) = self.cached_suggestion(ssid) else {
            // Nothing in the cache; nothing to remove on the OS side either
            // (we can't have registered it without going through this
            // backend). Match the cross-platform contract: false.
            return Ok(false);
        };

        let removed = jni_blocking(move || {
            let outcome: Result<Result<bool, Error>, jni::errors::Error> =
                jni_min_helper::jni_with_env(|env| {
                    let wm = match super::wifi_manager::wifi_manager(env) {
                        Ok(w) => w,
                        Err(e) => return Ok(Err(e)),
                    };
                    let status = match super::wifi_manager::remove_one_suggestion(
                        env,
                        &wm,
                        (*cached).as_ref(),
                    ) {
                        Ok(s) => s,
                        Err(e) => return Ok(Err(e)),
                    };
                    match super::status_codes::map_remove_status(status) {
                        Ok(super::status_codes::RemoveOutcome::WasRemoved) => Ok(Ok(true)),
                        Ok(super::status_codes::RemoveOutcome::NotPresent) => {
                            // OS-side suggestion was already gone (process
                            // restart, OS-side eviction, or race with
                            // another remove). Honor the contract: report
                            // false and let the caller see no profile was
                            // actually removed.
                            Ok(Ok(false))
                        }
                        Err(e) => Ok(Err(e)),
                    }
                });
            match outcome {
                Ok(inner) => inner,
                Err(jni_err) => Err(Error::Os(super::jni_helpers::boxed(jni_err))),
            }
        })
        .await?;

        if removed {
            self.evict_suggestion(ssid);
        }
        Ok(removed)
    }

    async fn list_visible_networks(
        &self,
        adapter: &AdapterId,
        options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        if adapter.as_str() != SYNTHETIC_ADAPTER_ID {
            return Err(Error::AdapterNotFound(adapter.to_string()));
        }
        let opts = options.clone();
        let saved_ssids = self.cached_suggestion_ssids();

        let bsses = jni_blocking(move || super::scan_receiver::fetch_bsses_blocking(&opts)).await?;
        let ctx =
            jni_blocking(move || super::scan_receiver::fetch_scan_context_blocking(saved_ssids))
                .await?;

        Ok(crate::scan_rollup::rollup(bsses, &ctx))
    }
}

#[cfg(not(target_os = "android"))]
#[async_trait]
impl Backend for AndroidBackend {
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
        Ok(vec![AdapterInfo {
            id: AdapterId::new("wlan0"),
            name: "Wi-Fi".to_string(),
        }])
    }

    async fn connect(
        &self,
        _adapter: &AdapterId,
        _ssid: &Ssid,
        _credentials: &Credentials,
        _options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        Err(Error::Unsupported(
            "AndroidBackend::connect not implemented",
        ))
    }

    async fn connect_with_stored_credentials(
        &self,
        _adapter: &AdapterId,
        _ssid: &Ssid,
        _options: &ConnectOptions,
    ) -> Result<WifiConnection, Error> {
        Err(Error::Unsupported(
            "AndroidBackend::connect_with_stored_credentials not implemented",
        ))
    }

    async fn disconnect(&self, _adapter: &AdapterId, _ssid: &Ssid) -> Result<(), Error> {
        Err(Error::Unsupported(
            "AndroidBackend::disconnect not implemented",
        ))
    }

    async fn remove_profile(&self, _adapter: &AdapterId, _ssid: &Ssid) -> Result<bool, Error> {
        Err(Error::Unsupported(
            "AndroidBackend::remove_profile not implemented",
        ))
    }

    async fn list_visible_networks(
        &self,
        _adapter: &AdapterId,
        _options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        Err(Error::Unsupported(
            "AndroidBackend::list_visible_networks not implemented",
        ))
    }
}

#[cfg(test)]
#[cfg(target_os = "android")]
impl AndroidBackend {
    /// Test-only constructor that skips `ndk-context` initialization.
    /// `list_adapters` does not touch the JVM, so it works even on a
    /// host build.
    pub(crate) fn new_for_test() -> Self {
        Self {
            locks: StdMutex::new(HashMap::new()),
            profiles: StdMutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
#[cfg(not(target_os = "android"))]
impl AndroidBackend {
    /// Test-only constructor for host builds.
    pub(crate) fn new_for_test() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_adapters_returns_synthetic_wlan0() {
        let b = AndroidBackend::new_for_test();
        let adapters = b.list_adapters().await.unwrap();
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].id.as_str(), "wlan0");
        assert_eq!(adapters[0].name, "Wi-Fi");
    }
}

#[cfg(test)]
mod permission_layering_tests {
    // The actual JNI call cannot run in unit tests (no JVM); the
    // observable contract this test pins is that the permission-denied
    // path of fetch_bsses_blocking returns Err(PermissionDenied), and
    // that scan_error_from translates that to ScanError::PermissionDenied.
    //
    // We verify the second half (translation) here; the first half is
    // exercised on a real device via examples/scan.rs.

    use crate::error::Error;
    use crate::preflight::{ScanError, scan_error_from};

    #[test]
    fn permission_denied_translates_to_permission_denied() {
        let e = Error::PermissionDenied("ACCESS_FINE_LOCATION or NEARBY_WIFI_DEVICES");
        assert!(matches!(scan_error_from(e), ScanError::PermissionDenied));
    }
}

/// Build, register, and confirm a `WifiNetworkSuggestion` synchronously.
///
/// Pulled out as a free function (rather than inlined as a closure in
/// `connect`) so the JNI-bound types it manipulates internally never
/// surface in the surrounding async future's auto-trait analysis. Run
/// from a worker thread by `jni_blocking`.
#[cfg(target_os = "android")]
fn blocking_connect(
    ssid: &Ssid,
    credentials: &Credentials,
    options: &ConnectOptions,
) -> Result<SuggestionRef, Error> {
    // `jni_with_env` returns Result<R, jni::errors::Error>, so we pack
    // our `crate::error::Error`-typed result into the success channel:
    // Ok(Ok(_)) on success, Ok(Err(_)) for our domain errors that
    // happened inside the closure, Err(_) for attach/JNI errors.
    // Flatten on the outside.
    let outcome: Result<Result<SuggestionRef, Error>, jni::errors::Error> =
        jni_min_helper::jni_with_env(|env| {
            let suggestion = match super::suggestion::build_suggestion(env, ssid, credentials) {
                Ok(s) => s,
                Err(e) => return Ok(Err(e)),
            };
            let suggestion_global = env.new_global_ref(&suggestion)?;

            let wm = match super::wifi_manager::wifi_manager(env) {
                Ok(w) => w,
                Err(e) => return Ok(Err(e)),
            };
            let status =
                match super::wifi_manager::add_one_suggestion(env, &wm, suggestion_global.as_ref())
                {
                    Ok(s) => s,
                    Err(e) => return Ok(Err(e)),
                };
            if let Err(e) = super::status_codes::map_add_status(status) {
                return Ok(Err(e));
            }

            let timeout = options.effective_timeout();
            let post_timeout = timeout
                .saturating_sub(timeout / 3)
                .max(std::time::Duration::from_secs(1));
            if let Err(e) =
                super::post_connection::wait_for_post_connection(env, ssid, post_timeout)
            {
                return Ok(Err(e));
            }

            // SuggestionRef is `Arc<Global<JObject<'static>>>` — wrap
            // the freshly-minted global ref in an Arc so the cache can
            // hand out cheap clones to subsequent
            // `connect_with_stored_credentials` callers without needing
            // an attached env.
            Ok(Ok(std::sync::Arc::new(suggestion_global)))
        });
    match outcome {
        Ok(inner) => inner,
        Err(jni_err) => Err(Error::Os(super::jni_helpers::boxed(jni_err))),
    }
}

/// Run a JNI-touching closure off the async runtime.
///
/// On `tokio_rt`-enabled builds we use `spawn_blocking` so the runtime
/// can park the worker. On default builds we spawn a real OS thread
/// and bridge via `oneshot`.
///
/// The returned future is boxed as `dyn Future + Send` because Rust's
/// auto-trait analysis cannot prove `Send` for the desugared async fn
/// when `T` contains a `jni::refs::Global<JObject<'static>>` — the
/// HRTB-shaped bounds in `Global`'s `Send` impl trip it up. Boxing
/// behind an explicit `+ Send` trait object lets us assert the bound
/// at the point where it's known to hold.
#[cfg(target_os = "android")]
fn jni_blocking<F, T>(
    f: F,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Error>> + Send>>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    Box::pin(async move {
        #[cfg(feature = "tokio_rt")]
        {
            match tokio::task::spawn_blocking(f).await {
                Ok(res) => res,
                Err(join_err) => Err(Error::Os(jni_helpers::boxed(JoinErr(join_err.to_string())))),
            }
        }
        #[cfg(not(feature = "tokio_rt"))]
        {
            let (tx, rx) = tokio::sync::oneshot::channel::<Result<T, Error>>();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.await.unwrap_or_else(|_| {
                Err(Error::Os(jni_helpers::boxed(JoinErr(
                    "worker thread dropped sender".to_string(),
                ))))
            })
        }
    })
}

#[cfg(target_os = "android")]
#[derive(Debug, thiserror::Error)]
#[error("worker join error: {0}")]
struct JoinErr(String);
