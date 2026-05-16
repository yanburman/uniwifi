//! Android backend for `uniwifi`.
//!
//! The `backend` module is always compiled (even under host tests) because
//! `list_adapters` doesn't touch the JVM. All JNI-using submodules are
//! gated by `cfg(target_os = "android")` so they don't cause import errors
//! on the host.
//!
//! # Host-app integration
//!
//! This crate is intended for an embedded-Rust application loaded into
//! an Android host (typically as a `cdylib` packaged into an APK). The
//! host is responsible for two things:
//!
//! ## 1. Manifest permissions
//!
//! Add the following to `AndroidManifest.xml`. The first two are
//! mandatory; `ACCESS_FINE_LOCATION` enables the pre-flight scan and
//! the post-connection broadcast on API 29-32; `NEARBY_WIFI_DEVICES`
//! does the same on API 33+.
//!
//! ```xml
//! <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
//! <uses-permission android:name="android.permission.CHANGE_WIFI_STATE" />
//! <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
//! <uses-permission
//!     android:name="android.permission.NEARBY_WIFI_DEVICES"
//!     android:usesPermissionFlags="neverForLocation" />
//!
//! <uses-sdk android:minSdkVersion="29" />
//! ```
//!
//! `ACCESS_FINE_LOCATION` and `NEARBY_WIFI_DEVICES` are *runtime*
//! permissions. The host must request them with the standard
//! `ActivityCompat.requestPermissions(...)` flow; this crate does not
//! prompt the user. If neither is granted at the time `connect` is
//! called, the pre-flight scan is silently skipped and the
//! post-connection wait falls back to `WifiInfo` polling only (the
//! `POST_CONNECTION` broadcast is gated by location permission).
//!
//! ## 2. `ndk-context` initialization
//!
//! Before constructing a `UniWifi` the host must install the `JavaVM`
//! and `Context` globals:
//!
//! ```text
//! // From a JNI_OnLoad in the host's bridge:
//! ndk_context::initialize_android_context(java_vm_ptr, context_ptr);
//! ```
//!
//! `UniWifi::new()` returns
//! `Err(Error::Unsupported("ndk-context not initialized"))` if this
//! has not happened yet. The crate (via `jni-min-helper`) caches the
//! `JavaVM` and a global ref to the `Context` once on first use.
//!
//! # In-memory profile cache
//!
//! Android does not expose any API to read back the passphrase of a
//! previously-registered `WifiNetworkSuggestion`. As a result, this
//! backend caches the suggestion (as an `Arc<Global<JObject<'static>>>`)
//! keyed by SSID whenever `connect` succeeds.
//! `connect_with_stored_credentials` re-registers the cached
//! suggestion. **The cache is in-process only — it does not survive a
//! host-app restart.** Persistent credential storage is the host
//! app's responsibility.

#[cfg(target_os = "android")]
mod jni_helpers;
#[cfg(target_os = "android")]
mod permissions;
#[cfg(target_os = "android")]
mod post_connection;
#[cfg(target_os = "android")]
mod scan_receiver;
mod security;
mod status_codes;
#[cfg(target_os = "android")]
mod suggestion;
#[cfg(target_os = "android")]
mod wifi_manager;

mod backend;
// Re-export only on android — the host-tests cfg-relaxation compiles
// `mod backend` for `list_adapters` testing, but nothing on the host
// goes through `default_backend()` for the android branch, so the
// re-export would be flagged unused.
#[cfg(target_os = "android")]
pub use backend::AndroidBackend;
