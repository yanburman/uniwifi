//! Translation from `NEHotspotConfigurationError` (`NSError`) to `uniwifi::Error`.

use objc2::Message;
use objc2::rc::Retained;
use objc2_foundation::NSError;

use crate::error::{BoxedOsError, Error};

/// The Objective-C domain name for `NEHotspotConfigurationError`. Apple
/// publishes this as `NEHotspotConfigurationErrorDomain`; we hard-code the
/// string because the `objc2-network-extension` crate exposes it only via
/// an `extern "C"` symbol that is awkward to dereference in `match` arms.
///
/// Declared `pub` (rather than `pub(crate)`) because this module itself is
/// already private (`mod error_map;` in `ios/mod.rs`), so `pub(crate)` here
/// would trip `clippy::redundant_pub_crate` from the `nursery` group.
/// Sibling modules under `ios/` reach this via `super::error_map::*`.
pub const NE_HOTSPOT_DOMAIN: &str = "NEHotspotConfigurationErrorDomain";

/// Result of mapping a non-nil `NSError` returned by `applyConfiguration:`.
///
/// `AlreadyAssociated` is its own variant (rather than a successful mapping)
/// so the caller can disambiguate "the OS reported a benign 'already on
/// the target network' status" from "no error at all" without needing a
/// sentinel `Error` variant in the public API.
#[derive(Debug)]
pub enum MappedError {
    /// Caller should propagate this as the `connect` / etc. result.
    Surface(Error),
    /// Caller should treat the operation as successful (`Ok(())`).
    AlreadyAssociated,
}

/// Translate an `NSError` from a `NEHotspotConfigurationManager` callback
/// into a typed `uniwifi::Error` (or the `AlreadyAssociated` sentinel).
///
/// Comparison against `NE_HOTSPOT_DOMAIN` is done by *value* (via
/// `domain().to_string()`); comparing `&NSString` directly with `==` would
/// fall through to pointer-identity, which is not what we want.
pub fn map_ne_error(err: &NSError) -> MappedError {
    let domain_owned = err.domain().to_string();
    if domain_owned != NE_HOTSPOT_DOMAIN {
        return MappedError::Surface(Error::Os(wrap_ns_error(err)));
    }

    // Match on the literal numeric code rather than the `objc2-network-extension`
    // associated constants (e.g. `NEHotspotConfigurationError::UserDenied`).
    // Apple's `NEHotspotConfigurationError` raw values are stable across iOS
    // versions, but the Rust constant names track Swift case names that have
    // shifted across `objc2-network-extension` releases — pinning to the
    // numeric encoding keeps this mapping resilient to crate-version churn.
    match err.code() {
        // Codes 0-1, 4-6, 8-12, 15, and anything >=18 fall through to the
        // `_` arm and are bucketed as `Error::Os(...)` (Apple-internal,
        // recoverable, or otherwise not worth surfacing as a typed variant).
        2 | 3 => MappedError::Surface(Error::AuthenticationFailed),
        7 => MappedError::Surface(Error::UserCancelled),
        13 => MappedError::AlreadyAssociated,
        14 => MappedError::Surface(Error::Unsupported("requires foreground app")),
        16 => MappedError::Surface(Error::PermissionDenied(
            "hotspot configuration not entitled",
        )),
        17 => MappedError::Surface(Error::PermissionDenied(
            "system denied hotspot configuration",
        )),
        _ => MappedError::Surface(Error::Os(wrap_ns_error(err))),
    }
}

/// Wrap an `NSError` in our `BoxedOsError`. We retain the `NSError` so the
/// downstream `Error::Os` lives independently of the Objective-C call frame.
fn wrap_ns_error(err: &NSError) -> BoxedOsError {
    Box::new(NsErrorWrapper {
        domain: err.domain().to_string(),
        code: err.code(),
        description: err.localizedDescription().to_string(),
        // Hold the retained NSError to keep its memory alive in case the
        // caller wants to downcast (we don't currently expose downcast,
        // but it's cheap to retain and prevents subtle UB).
        _retained: err.retain(),
    })
}

/// Internal `std::error::Error` wrapper around an `NSError`.
///
/// Named `NsErrorWrapper` (camel-case `Ns`, not `NSError…`) so
/// `clippy::module_name_repetitions` doesn't fire on it. Kept module-private
/// because the only consumer is `wrap_ns_error`.
#[derive(Debug)]
struct NsErrorWrapper {
    domain: String,
    code: isize,
    description: String,
    _retained: Retained<NSError>,
}

impl std::fmt::Display for NsErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (domain={}, code={})",
            self.description, self.domain, self.code
        )
    }
}

impl std::error::Error for NsErrorWrapper {}

#[cfg(test)]
mod tests {
    use super::{MappedError, NE_HOTSPOT_DOMAIN, map_ne_error};
    use objc2_foundation::{NSError, NSString};

    fn ne_error(code: isize) -> objc2::rc::Retained<NSError> {
        // SAFETY: `NSError::errorWithDomain:code:userInfo:` is a class
        // factory; passing `None` for `userInfo` is well-defined per Apple
        // docs. The `dict` generic parameter is unused when `None`, so the
        // generic-correctness safety condition is vacuously satisfied.
        unsafe {
            NSError::errorWithDomain_code_userInfo(
                &NSString::from_str(NE_HOTSPOT_DOMAIN),
                code,
                None,
            )
        }
    }

    #[test]
    fn user_denied_maps_to_user_cancelled() {
        let err = ne_error(7);
        let mapped = map_ne_error(&err);
        assert!(matches!(
            mapped,
            MappedError::Surface(crate::error::Error::UserCancelled)
        ));
    }

    #[test]
    fn invalid_wpa_passphrase_maps_to_authentication_failed() {
        let err = ne_error(2);
        assert!(matches!(
            map_ne_error(&err),
            MappedError::Surface(crate::error::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn invalid_wep_passphrase_maps_to_authentication_failed() {
        let err = ne_error(3);
        assert!(matches!(
            map_ne_error(&err),
            MappedError::Surface(crate::error::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn application_not_in_foreground_maps_to_unsupported() {
        let err = ne_error(14);
        assert!(matches!(
            map_ne_error(&err),
            MappedError::Surface(crate::error::Error::Unsupported("requires foreground app"))
        ));
    }

    #[test]
    fn already_associated_maps_to_already_associated_sentinel() {
        let err = ne_error(13);
        assert!(matches!(map_ne_error(&err), MappedError::AlreadyAssociated));
    }

    #[test]
    fn user_unauthorized_maps_to_permission_denied() {
        let err = ne_error(16);
        assert!(matches!(
            map_ne_error(&err),
            MappedError::Surface(crate::error::Error::PermissionDenied(_))
        ));
    }

    #[test]
    fn system_denied_maps_to_permission_denied() {
        let err = ne_error(17);
        assert!(matches!(
            map_ne_error(&err),
            MappedError::Surface(crate::error::Error::PermissionDenied(_))
        ));
    }

    #[test]
    fn unknown_code_routes_to_os() {
        let err = ne_error(11);
        assert!(matches!(
            map_ne_error(&err),
            MappedError::Surface(crate::error::Error::Os(_))
        ));
    }

    #[test]
    fn other_domain_routes_to_os() {
        // An NSError with a domain that isn't NE's still becomes Error::Os.
        // SAFETY: same as `ne_error` — `userInfo: None` is well-defined.
        let other = unsafe {
            NSError::errorWithDomain_code_userInfo(
                &NSString::from_str("SomeOtherDomain"),
                7, // would be userDenied if NE domain
                None,
            )
        };
        assert!(matches!(
            map_ne_error(&other),
            MappedError::Surface(crate::error::Error::Os(_))
        ));
    }
}
