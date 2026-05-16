//! `NSError` / `OSStatus` -> [`crate::error::Error`] mapping.
//!
//! `CWInterface` operations (scan, associate) report failures as `NSError`
//! values whose `domain` and `code` together identify the underlying cause.
//! This module converts those values into the strongly-typed
//! [`crate::error::Error`] enum used by the rest of the crate. The
//! pre-flight scan path further projects `Error` to
//! [`crate::preflight::ScanError`] via
//! [`crate::preflight::scan_error_from`], so there is exactly one
//! `NSError -> Error` mapping per `CoreWLAN` call site.
//!
//! Two domains are recognised:
//! * `CWErrorDomain` — `CoreWLAN`'s own errors. Each numeric code maps to a
//!   `CWErr::*` constant exported by `objc2-core-wlan`.
//! * `kCLErrorDomain` — Core Location's domain. `macOS` surfaces "user has
//!   not authorised Wi-Fi info" failures here when an app tries to read
//!   scan results without Location Services permission.
//!
//! Anything else falls through to `Error::Os` carrying the original
//! `NSError` description.

use objc2_core_wlan::CWErr;
use objc2_foundation::{NSError, NSString};

use crate::error::{BoxedOsError, Error};

// `CWErrorDomain` is gated behind the `CoreWLANConstants` feature in
// `objc2-core-wlan`, which is not enabled by this crate. Rather than
// pulling in the whole feature for one symbol, we redeclare it here —
// the dynamic linker resolves it from CoreWLAN at load time, exactly like
// the upstream binding does. This keeps the symbol type-checked as
// `&'static NSString` without changing `Cargo.toml`.
unsafe extern "C" {
    static CWErrorDomain: &'static NSString;
}

/// Map an `NSError` returned by
/// `CWInterface::associateToNetwork_password_error` into a typed
/// [`Error`].
///
/// Decision tree:
/// 1. If the error's domain is `CWErrorDomain`, branch on the `CWErr` code.
/// 2. If the domain is `kCLErrorDomain` (Core Location) — the user has not
///    granted Location Services permission, which `CoreWLAN` requires for
///    Wi-Fi info — return `Error::PermissionDenied("Location Services")`.
/// 3. Otherwise wrap the description as `Error::Os`.
pub(super) fn map_associate_nserror(err: &NSError) -> Error {
    if is_cwerror_domain(err) {
        return map_cwerr_code(err.code());
    }
    if is_location_error_domain(err) {
        return Error::PermissionDenied("Location Services");
    }
    Error::Os(BoxedOsError::from(err.to_string()))
}

/// Map an `NSError` returned by `scanForNetworksWithName_error` (or
/// equivalent `cachedScanResults` failure paths) into a typed [`Error`]
/// suitable for the public `list_visible_networks` API.
///
/// Detects `kCLErrorDomain` (Core Location) and surfaces it as
/// `Error::PermissionDenied("Location Services")`. Other failures fall
/// through to `Error::Os`. The pre-flight scan path then projects this
/// `Error` back to a `ScanError` via `crate::preflight::scan_error_from`,
/// so there is exactly one `NSError -> Error` mapping for the scan path.
pub(super) fn map_scan_nserror_to_error(err: &NSError) -> Error {
    if is_location_error_domain(err) {
        return Error::PermissionDenied("Location Services");
    }
    Error::Os(BoxedOsError::from(err.to_string()))
}

/// Returns true when the error's `domain` is `CoreWLAN`'s `CWErrorDomain`.
///
/// Compares `NSStrings` via `isEqualToString`, which is the safe, sugared
/// form of Objective-C's `-isEqual:` for two strings.
fn is_cwerror_domain(err: &NSError) -> bool {
    let domain = err.domain();
    // SAFETY: `CWErrorDomain` is a `&'static NSString` symbol exported by
    // CoreWLAN. The framework guarantees it is initialised before any of
    // its APIs (which would have produced `err`) can be called, and it is
    // never mutated. Reading the reference is therefore safe.
    let cwerror_domain: &NSString = unsafe { CWErrorDomain };
    domain.isEqualToString(cwerror_domain)
}

/// Returns true when the error's `domain` is Core Location's
/// `kCLErrorDomain`.
///
/// The `kCLErrorDomain` constant isn't exported by `objc2-core-wlan` and
/// pulling in `objc2-core-location` for one string is overkill — comparing
/// by string content is safe (`NSError` domains are documented constants)
/// and forward-compatible.
fn is_location_error_domain(err: &NSError) -> bool {
    let domain = err.domain();
    domain.to_string() == "kCLErrorDomain"
}

/// Map a `CWErr` numeric code (as carried by `NSError::code()`) to a
/// typed [`Error`] variant.
///
/// Codes are matched against the `CWErr::*` constants exported by
/// `objc2-core-wlan`; the binding represents `CWErr` as a tuple struct
/// `CWErr(pub NSInteger)` so the inner value is accessed as `.0`.
fn map_cwerr_code(code: isize) -> Error {
    // `CWErr` is `repr(transparent)` over `NSInteger` (== `isize` on the
    // platforms we target), so comparing the raw `isize` directly to each
    // constant's inner value is exact — no truncation, no `as` casts.
    match code {
        c if c == CWErr::CWNoErr.0 => {
            // `associate` only surfaces a non-nil NSError on failure; a
            // success code arriving here is a CoreWLAN bug, not ours.
            Error::Os(BoxedOsError::from("CWErr::CWNoErr surfaced as failure"))
        }

        // Authentication / cipher / association failures all collapse to
        // `AuthenticationFailed` — callers retry with new credentials, not
        // by inspecting the precise sub-reason.
        c if c == CWErr::CWUnspecifiedFailureErr.0
            || c == CWErr::CWAuthenticationAlgorithmUnsupportedErr.0
            || c == CWErr::CWChallengeFailureErr.0
            || c == CWErr::CWInvalidPMKErr.0
            || c == CWErr::CWSupplicantTimeoutErr.0
            || c == CWErr::CWInvalidGroupCipherErr.0
            || c == CWErr::CWInvalidPairwiseCipherErr.0
            || c == CWErr::CWInvalidAKMPErr.0
            || c == CWErr::CWCipherSuiteRejectedErr.0
            || c == CWErr::CWAssociationDeniedErr.0
            || c == CWErr::CWReassociationDeniedErr.0 =>
        {
            Error::AuthenticationFailed
        }

        // CoreWLAN-side permission denial (rare; usually the OS returns
        // `kCLErrorDomain` instead, but we cover this for completeness).
        c if c == CWErr::CWOperationNotPermittedErr.0 => Error::PermissionDenied("CoreWLAN"),

        // Driver-level timeout — distinct from our async wait-loop timeout.
        // We surface a zero `Duration` because CoreWLAN doesn't tell us how
        // long it waited; callers care about the variant, not the value.
        c if c == CWErr::CWTimeoutErr.0 => Error::Timeout(std::time::Duration::from_secs(0)),

        // The driver rejected the `CWNetwork` we passed (typically because
        // the entry was evicted between scan and associate). We always pass
        // a freshly-scanned network, so the practical outcome is "the AP is
        // no longer in range".
        c if c == CWErr::CWInvalidParameterErr.0 => Error::SsidNotInRange,

        // Anything else: surface the raw code so it shows up in logs.
        other => Error::Os(BoxedOsError::from(format!(
            "CoreWLAN association failed: CWErr({other})"
        ))),
    }
}
