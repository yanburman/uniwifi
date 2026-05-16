//! Connect / disconnect implementations.

use objc2_foundation::NSString;
use secrecy::ExposeSecret;

use crate::error::Error;
use crate::preflight::{ScanOutcome, wait_until_ssid_visible};
use crate::types::{AdapterId, ConnectOptions, Credentials, Ssid};

use super::adapter::resolve_interface_by_id;
use super::client::SharedClient;
use super::error::map_associate_nserror;
use super::scan::make_scan_provider;
use super::threading::run_blocking;

/// Synchronous body of `connect`. Runs entirely on the worker thread.
///
/// # Errors
/// - [`Error::AdapterNotFound`] if the adapter has gone away between
///   `list_adapters` and the connect call.
/// - [`Error::Unsupported`] if the SSID is not valid UTF-8 (`CoreWLAN`'s
///   `scanForNetworksWithName` takes an `NSString`; non-UTF-8 SSIDs are
///   not yet routed through a bytes-based path).
/// - [`Error::SsidNotInRange`] if the in-worker rescan returns no matching
///   network.
/// - [`Error::Os`] if `scanForNetworksWithName:error:` itself failed.
/// - Any [`Error`] variant produced by [`map_associate_nserror`] when the
///   `associate` call returned an `NSError`.
fn connect_blocking(
    client: &SharedClient,
    adapter: &AdapterId,
    ssid: &Ssid,
    password: Option<&str>,
) -> Result<(), Error> {
    client.with(|client| {
        let iface = resolve_interface_by_id(client, adapter)?;

        // Re-scan to obtain a fresh CWNetwork. CoreWLAN's `associate`
        // requires a network object from a recent scan.
        let ssid_str = ssid.as_str().ok_or(Error::Unsupported(
            "macos: associate currently requires UTF-8 SSIDs (non-UTF-8 not yet supported)",
        ))?;
        let nsname = NSString::from_str(ssid_str);
        // SAFETY: `scanForNetworksWithName_error` returns Result via the
        // objc2 NSError-out-param sugar.
        let networks =
            unsafe { iface.scanForNetworksWithName_error(Some(&nsname)) }.map_err(|e| {
                Error::Os(Box::<dyn std::error::Error + Send + Sync>::from(
                    e.to_string(),
                ))
            })?;

        // Pick the first matching network. (CoreWLAN guarantees all entries
        // here have the SSID we asked for; in practice multiple BSSIDs of
        // the same ESS can show up.) We use `allObjects().to_vec()` rather
        // than `&networks` iteration because the borrowed-NSSet iterator
        // lives behind the `NSEnumerator` cargo feature on
        // `objc2-foundation`, which this crate does not enable (mirroring
        // the workaround used elsewhere in this module — see
        // `fetch_bsses_blocking` in `scan.rs`).
        let nets_vec = networks.allObjects().to_vec();
        let target = nets_vec.into_iter().next().ok_or(Error::SsidNotInRange)?;

        // SAFETY: associateToNetwork_password_error returns
        // `Result<(), Retained<NSError>>` via objc2's NSError-out-param sugar.
        // `Retained<NSString>` derefs to `&NSString`, so `pw_ns.as_deref()`
        // gives us the `Option<&NSString>` the FFI signature expects.
        let pw_ns = password.map(NSString::from_str);
        let result = unsafe { iface.associateToNetwork_password_error(&target, pw_ns.as_deref()) };
        result.map_err(|e| map_associate_nserror(&e))
    })
}

/// Public entry point invoked by `MacosBackend::connect`.
///
/// # Errors
/// Forwards [`connect_blocking`]'s errors. Adds a deadline-driven
/// [`Error::Timeout`] if the worker thread is still running when
/// `options.effective_timeout()` expires.
pub(super) async fn connect(
    client: SharedClient,
    adapter: AdapterId,
    ssid: Ssid,
    credentials: &Credentials,
    options: &ConnectOptions,
) -> Result<(), Error> {
    let timeout = options.effective_timeout();

    // Pre-flight scan via the foundation helper. Best-effort: if the scan
    // provider errors we proceed anyway and let `associate` produce the
    // canonical error.
    let preflight_provider = make_scan_provider(client.clone(), adapter.clone());
    let preflight_budget = std::cmp::min(timeout / 2, std::time::Duration::from_secs(5));
    let preflight_start = std::time::Instant::now();
    let outcome = wait_until_ssid_visible(&*preflight_provider, &ssid, preflight_budget).await;
    if outcome == ScanOutcome::NotVisible {
        return Err(Error::SsidNotInRange);
    }
    // Use actual elapsed pre-flight time (not the full budget) so an
    // early-success scan leaves more of the user's timeout for associate.
    let preflight_elapsed = preflight_start.elapsed();

    let password = match credentials {
        Credentials::Open => None,
        Credentials::Password(s) => Some(s.expose_secret().to_owned()),
    };

    let blocking = run_blocking({
        let client = client.clone();
        let adapter = adapter.clone();
        let ssid = ssid.clone();
        move || connect_blocking(&client, &adapter, &ssid, password.as_deref())
    });

    // Apply the remaining timeout budget around the blocking work.
    //
    // Cancellation semantics: associate is non-cancellable. When the
    // outer future is dropped on timeout, the `run_blocking` worker
    // continues to completion in the background and its result is
    // discarded. CoreWLAN's `associateToNetwork:password:error:` is a
    // synchronous, non-interruptible call — there is no API to abort it
    // mid-flight, so the spawned worker thread runs until CoreWLAN
    // returns. This matches the documented design in
    // `super::threading` (see `run_blocking`).
    //
    // Plan literal used a `match` here, but clippy's `option_if_let_else`
    // (nursery, deny) and `unnecessary_result_map_or_else` (all, deny)
    // together steer us to `unwrap_or_else` — adopted per the plan's
    // "if clippy requires changes" note.
    let remaining = timeout.saturating_sub(preflight_elapsed);
    tokio::time::timeout(remaining, blocking)
        .await
        .unwrap_or_else(|_| Err(Error::Timeout(timeout)))
}

/// Public entry point for `connect_with_stored_credentials`.
///
/// # Errors
/// - [`Error::SsidNotInRange`] if the pre-flight scan returns `NotVisible`
///   or the in-worker rescan finds no matching network.
/// - [`Error::NoStoredCredentials`] if `associate` failed with
///   `AuthenticationFailed` and the keychain has no entry for `ssid`.
/// - [`Error::AuthenticationFailed`] / [`Error::Os`] / [`Error::Timeout`]
///   under the same conditions documented on [`connect`].
pub(super) async fn connect_with_stored(
    client: SharedClient,
    adapter: AdapterId,
    ssid: Ssid,
    options: &ConnectOptions,
) -> Result<(), Error> {
    let timeout = options.effective_timeout();

    // Same pre-flight as `connect`.
    let preflight_provider = make_scan_provider(client.clone(), adapter.clone());
    let preflight_budget = std::cmp::min(timeout / 2, std::time::Duration::from_secs(5));
    let preflight_start = std::time::Instant::now();
    let outcome = wait_until_ssid_visible(&*preflight_provider, &ssid, preflight_budget).await;
    if outcome == ScanOutcome::NotVisible {
        return Err(Error::SsidNotInRange);
    }
    let preflight_elapsed = preflight_start.elapsed();

    let blocking = run_blocking({
        let client = client.clone();
        let adapter = adapter.clone();
        let ssid = ssid.clone();
        // None password = look up stored credentials in keychain.
        move || connect_blocking(&client, &adapter, &ssid, None)
    });

    // Cancellation semantics: associate is non-cancellable. Same as
    // `connect` — see the comment there for the full rationale.
    //
    // We use the same `unwrap_or_else` shape as `connect` to dodge clippy's
    // `option_if_let_else` / `unnecessary_result_map_or_else` lints, then
    // match on the resulting `Result` to re-classify `AuthenticationFailed`
    // when the keychain has no entry for `ssid`.
    let remaining = timeout.saturating_sub(preflight_elapsed);
    let result = tokio::time::timeout(remaining, blocking)
        .await
        .unwrap_or_else(|_| Err(Error::Timeout(timeout)));
    match result {
        Ok(()) => Ok(()),
        Err(Error::AuthenticationFailed) => {
            // CoreWLAN distinguishes "wrong password" from "no entry" only
            // by the OSStatus from the underlying keychain lookup; if no
            // entry was found, `associate` typically surfaces an
            // unspecified-failure CWErr that we map to AuthenticationFailed.
            // Re-classify to NoStoredCredentials when we can verify the
            // keychain has no entry (best-effort).
            //
            // The probe runs on a worker thread because the Security
            // framework can synchronously trigger UI prompts (revoked
            // ACL, denied access). Calling it directly on the tokio task
            // would stall the executor for the duration of any prompt.
            let ssid_for_probe = ssid.clone();
            let exists =
                run_blocking(move || super::keychain::keychain_entry_exists(&ssid_for_probe)).await;
            if exists {
                Err(Error::AuthenticationFailed)
            } else {
                Err(Error::NoStoredCredentials(ssid.to_string()))
            }
        }
        Err(other) => Err(other),
    }
}

/// Synchronous body of `disconnect`.
///
/// Honors the trait contract: "calling it when not connected to `ssid`
/// is treated as a no-op success." We compare the interface's currently
/// associated SSID against `ssid` and only disassociate on a match.
///
/// # Errors
/// - [`Error::AdapterNotFound`] if the adapter has gone away between
///   `list_adapters` and the disconnect call.
fn disconnect_blocking(
    client: &SharedClient,
    adapter: &AdapterId,
    ssid: &Ssid,
) -> Result<(), Error> {
    client.with(|client| {
        let iface = resolve_interface_by_id(client, adapter)?;
        // SAFETY: `ssidData` returns Option<Retained<NSData>>; nil means
        // the interface is currently disassociated.
        let current = unsafe { iface.ssidData() }.map(|d| Ssid::from_bytes(d.to_vec()));
        if current.as_ref() != Some(ssid) {
            // Not connected to the requested SSID — treat as no-op success.
            return Ok(());
        }
        // SAFETY: `disassociate` returns void and is documented as safe to
        // call regardless of the current association state.
        unsafe { iface.disassociate() };
        Ok(())
    })
}

/// Public entry point invoked by `MacosBackend::disconnect`.
///
/// # Errors
/// Forwards [`disconnect_blocking`]'s errors.
pub(super) async fn disconnect(
    client: SharedClient,
    adapter: AdapterId,
    ssid: Ssid,
) -> Result<(), Error> {
    run_blocking(move || disconnect_blocking(&client, &adapter, &ssid)).await
}
