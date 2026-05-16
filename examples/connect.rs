//! Manual end-to-end smoke test for the active platform backend.
//!
//! Exercises the full public API cycle:
//! `UniWifi::new` -> `list_adapters` -> `connect` -> sleep ->
//! `connect_with_stored_credentials` -> `disconnect` -> `remove_profile`.
//!
//! Usage:
//!   `cargo run --example connect --features tokio_rt -- <ssid> <password>`
//!
//! Run from a terminal that won't lose its connectivity when the program
//! disassociates the radio (e.g. one over a wired uplink, or any terminal
//! that survives a brief Wi-Fi bounce).
//!
//! # Platform notes
//!
//! ## macOS
//! - Requires Location Services authorisation; without it, `connect` will
//!   surface `Error::PermissionDenied("Location Services")`. Grant access
//!   via System Settings > Privacy & Security > Location Services.
//! - `remove_profile` deletes the entry from the user keychain. In a
//!   sandboxed runner without keychain XPC access the call may surface
//!   `Error::PermissionDenied("Keychain")` or an `Error::Os(...)`.
//!
//! ## Windows
//! - The example uses positional `<ssid> <password>` args (consistent
//!   across platforms). On Windows the example always passes a password
//!   string, so it targets WPA2-PSK profiles; an open-network connect via
//!   `Credentials::Open` is not exposed through this example and must be
//!   exercised programmatically.
//! - `WlanConnect` requires the calling user to have permission to manage
//!   WLAN profiles. On a standard interactive desktop session this is
//!   granted by default; in restricted SKUs or service contexts an
//!   `Error::PermissionDenied("WLAN")` may surface.
//! - `remove_profile` deletes the per-user profile installed during
//!   `connect`. On a host where the profile was installed by another user
//!   or by Group Policy, the call returns `Ok(false)` (no per-user entry
//!   to delete) — that is expected, not a bug.
//! - Cross-compile from a non-Windows host with
//!   `cargo build --example connect --target x86_64-pc-windows-gnu --features tokio_rt`;
//!   running the example requires a Windows host with a Wi-Fi NIC.
//!
//! ## Android
//! - Requires a `JavaVM` + `Context` to be installed before
//!   `UniWifi::new()`; the host app must call
//!   `ndk_context::initialize_android_context(java_vm_ptr, context_ptr)`
//!   from its `JNI_OnLoad` (or any code path that runs before the first
//!   `UniWifi::new()`). Without it, `UniWifi::new()` returns
//!   `Error::Unsupported("ndk-context not initialized")`.
//! - `connect` requires the host app to hold a runtime location
//!   permission (`ACCESS_FINE_LOCATION` on API 29-32, or
//!   `NEARBY_WIFI_DEVICES` on API 33+) and to declare
//!   `ACCESS_WIFI_STATE` + `CHANGE_WIFI_STATE` in `AndroidManifest.xml`.
//!   See the rustdoc on `wifi_hal::platform::android` for the full
//!   manifest snippet.
//! - The example is a `#[tokio::main]` binary, so it can't be invoked
//!   directly from a host APK (Java callers need a JNI entry point).
//!   Two ways to exercise it on a device:
//!   1. Cross-compile to a static binary and push via adb:
//!      `cargo build --example connect --target aarch64-linux-android --features tokio_rt`
//!      then `adb push target/aarch64-linux-android/debug/examples/connect /data/local/tmp/`
//!      and run via `adb shell`. This path can't initialize the JVM
//!      and so cannot exercise the JNI-touching backend operations
//!      directly — useful for build verification only.
//!   2. From an APK, write a 5-line Java/Kotlin bridge that calls
//!      `System.loadLibrary` on a wifi_hal-linked cdylib and invokes
//!      a `#[no_mangle] extern "system" fn` whose body re-uses this
//!      example's flow. The bridge takes responsibility for
//!      `ndk_context` initialization (typically in `JNI_OnLoad`).
//!
//! ## iOS
//! - This `#[tokio::main]` CLI example cannot be invoked directly on iOS
//!   — there is no equivalent of a `cargo run --example` flow on a
//!   device or simulator. iOS Wi-Fi configuration runs only inside an
//!   app bundle. Two ways to exercise the iOS backend end-to-end:
//!   1. Cross-compile and link `wifi_hal` as a static library
//!      (`crate-type = ["staticlib"]`) into a host iOS app bundle, expose
//!      a C-ABI entry point, and call into a Rust function whose body
//!      mirrors the `main()` below from the host's foreground view
//!      controller.
//!   2. If the host is itself a Rust iOS app (e.g. via `cargo-mobile`),
//!      invoke the same flow from an `async` task on a tokio runtime.
//! - `connect` requires the host app to be in the foreground when
//!   invoked (`UIApplication.applicationState == .active`). Background
//!   or app-extension contexts surface
//!   `Error::Unsupported("requires foreground app")`. The iOS backend
//!   probes `UIApplication.applicationState` synchronously *before*
//!   calling `applyConfiguration:completionHandler:` so the failure is
//!   typed and avoids surfacing the system "Join Network?" prompt on a
//!   backgrounded app.
//! - The host bundle must declare the
//!   `com.apple.developer.networking.HotspotConfiguration` entitlement
//!   in its `.entitlements` file, and the matching App ID must have
//!   the **Hotspot Configuration** capability enabled in the Apple
//!   Developer portal. Without these, the OS surfaces
//!   `userUnauthorized` (mapped to
//!   `Error::PermissionDenied("hotspot configuration not entitled")`).
//! - On the first apply per app per SSID, iOS shows a system "Join
//!   Network?" confirmation dialog. User dismissal maps to
//!   `Error::UserCancelled`.
//! - `disconnect` and `remove_profile` are semantically equivalent on
//!   iOS: both call `NEHotspotConfigurationManager.removeConfigurationForSSID:`
//!   (the only public primitive — there is no API to disconnect without
//!   forgetting the network). `disconnect` returns `Ok(())` regardless;
//!   `remove_profile` pre-checks
//!   `getConfiguredSSIDsWithCompletionHandler:` and returns
//!   `Ok(true)`/`Ok(false)` based on whether a profile existed before
//!   the call. Consequence for this example's ordering: the
//!   `disconnect` step removes the profile, so the subsequent
//!   `remove_profile` step will return `Ok(false)` (printed as
//!   `expected: true` in the example's output line — that's accurate
//!   on Windows / macOS / Android but misleading on iOS, by design).
//! - There is no API to keep the profile installed across a
//!   `disconnect` on iOS. Consumers wanting desktop-style
//!   disconnect-but-keep-profile semantics cannot achieve them through
//!   the public API.
//! - There is no public iOS scan API; the iOS backend deliberately does
//!   not implement `ScanProvider` and the pre-flight scan step is
//!   silently skipped inside `connect`.
//! - WPA Enterprise, hidden SSIDs, and `NEHotspotHelper`-based join
//!   handling are out of scope for this crate.
//!
//! ## Linux (`NetworkManager`)
//!
//! Requires `NetworkManager` to be running on the system bus
//! (`org.freedesktop.NetworkManager`). On a logged-in desktop session
//! the default Polkit policy grants `network-control` to the active
//! user, so connecting / disconnecting works without an interactive
//! Polkit prompt. From a headless session (e.g., SSH without a seat),
//! Polkit will deny and the call surfaces as
//! `Error::PermissionDenied("polkit")`.
//!
//! Run the example:
//! ```text
//! cargo run --example connect --features tokio_rt -- "MyAP" "hunter2"
//! ```
//!
//! The connection profile is saved to
//! `/etc/NetworkManager/system-connections/` by NM and persists across
//! reboots. Use the `remove_profile` step to delete it.

// This is a developer-facing CLI example: writing to stdout/stderr is the
// program's whole purpose, and `process::exit` is the natural way to bail
// on a usage error before constructing any HAL state. The arg-parsing
// `match` has a `_` arm that diverges via `process::exit`, which clippy
// flags under `single_match_else`; an `if let` rewrite is no clearer here.
#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::exit,
    clippy::single_match_else
)]

use std::env;
use std::time::Duration;

use uniwifi::{ConnectOptions, Credentials, Ssid, UniWifi};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let (ssid_str, password) = match args.as_slice() {
        [_, ssid, pw] => (ssid.clone(), pw.clone()),
        _ => {
            eprintln!("usage: {} <ssid> <password>", args[0]);
            std::process::exit(2);
        }
    };

    let hal = UniWifi::new()?;
    let adapters = hal.list_adapters().await?;
    let adapter = adapters
        .into_iter()
        .next()
        .ok_or("no Wi-Fi adapters found")?;

    println!("using adapter: {} ({})", adapter.id(), adapter.name());

    let ssid = Ssid::from_utf8(&ssid_str);
    let opts = ConnectOptions {
        timeout: Some(Duration::from_secs(20)),
    };

    println!("connecting to {ssid_str}...");
    adapter
        .connect(&ssid, Credentials::password(password), opts.clone())
        .await?;
    println!("connected.");

    tokio::time::sleep(Duration::from_secs(3)).await;

    println!("re-connecting via stored credentials...");
    adapter
        .connect_with_stored_credentials(&ssid, opts.clone())
        .await?;
    println!("re-connected.");

    println!("disconnecting...");
    adapter.disconnect(&ssid).await?;
    println!("disconnected.");

    println!("removing stored profile...");
    let removed = adapter.remove_profile(&ssid).await?;
    println!("remove_profile returned {removed} (expected: true)");

    Ok(())
}
