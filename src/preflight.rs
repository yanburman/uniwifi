//! Internal helper: best-effort wait for an SSID to appear in scan results,
//! used by backends to enrich error messages on connect failures.
//!
//! Not exposed on the public API (per design: "internal step when supported
//! to make the connect flow more verbose in case of error").

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::types::Ssid;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("permission denied for scanning")]
    #[allow(dead_code)] // Reserved for backends that distinguish permission errors.
    PermissionDenied,
    #[error("scan unsupported on this platform")]
    Unsupported,
    #[error("os error during scan: {0}")]
    Os(#[source] crate::error::BoxedOsError),
}

/// Trait implemented by each backend that supports scanning. The generic
/// helper below polls this trait until the SSID is visible or a timeout
/// expires.
#[async_trait]
pub trait ScanProvider: Send + Sync {
    async fn scan(&self) -> Result<Vec<Ssid>, ScanError>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The SSID was observed within the timeout.
    Visible,
    /// The SSID was not observed within the timeout (any successful scan
    /// returned, just without the target SSID).
    NotVisible,
    /// The provider reported an error (e.g., missing permission or no scan
    /// API on this platform). Backends should treat this as "skip the
    /// pre-flight" rather than failing the connect.
    Skipped,
}

/// Internal helper. Polls `provider.scan()` every ~250ms until either the
/// target SSID appears, the deadline expires, or the provider errors.
///
/// The first scan attempt is issued immediately (no leading sleep). After a
/// scan returns without the target, the helper sleeps for `POLL_INTERVAL`
/// or the remaining budget, whichever is smaller, so that short timeouts
/// still get a final retry rather than being preempted mid-sleep.
pub async fn wait_until_ssid_visible(
    provider: &dyn ScanProvider,
    target: &Ssid,
    timeout: Duration,
) -> ScanOutcome {
    const POLL_INTERVAL: Duration = Duration::from_millis(250);

    if timeout.is_zero() {
        return ScanOutcome::NotVisible;
    }

    let deadline = Instant::now() + timeout;
    loop {
        match provider.scan().await {
            Ok(results) => {
                if results.iter().any(|s| s == target) {
                    return ScanOutcome::Visible;
                }
            }
            Err(_) => return ScanOutcome::Skipped,
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return ScanOutcome::NotVisible;
        }
        tokio::time::sleep(std::cmp::min(POLL_INTERVAL, remaining)).await;
    }
}

/// Translate a public `Error` from the rich scan path back to the
/// pre-flight's `ScanError` family. Used by each backend's
/// `ScanProvider::scan` impl after it projects from `fetch_bsses`.
///
/// Declared `pub` (rather than `pub(crate)`) because this module is
/// already private (`mod preflight;` in `lib.rs`), so `pub(crate)` here
/// would trip `clippy::redundant_pub_crate` from the `nursery` group.
#[allow(dead_code)] // wired in Tasks 9, 12, 16, 19 (per-backend ScanProvider::scan)
pub fn scan_error_from(err: crate::error::Error) -> ScanError {
    match err {
        crate::error::Error::PermissionDenied(_) => ScanError::PermissionDenied,
        crate::error::Error::Unsupported(_) => ScanError::Unsupported,
        crate::error::Error::Os(inner) => ScanError::Os(inner),
        // Anything else (AdapterNotFound, Timeout, ...) the rich path
        // could surface is collapsed to ScanError::Os. The outer
        // `wait_until_ssid_visible` helper folds every ScanError into
        // ScanOutcome::Skipped, so the precise variant is observability
        // only.
        other => ScanError::Os(Box::new(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Ssid;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Test-only scan provider: returns whatever SSIDs the test scripts.
    struct FakeScan {
        results: Arc<Mutex<Vec<Vec<Ssid>>>>, // one Vec<Ssid> per scan() call
    }

    #[async_trait::async_trait]
    impl ScanProvider for FakeScan {
        async fn scan(&self) -> Result<Vec<Ssid>, ScanError> {
            let mut q = self.results.lock().unwrap();
            if q.is_empty() {
                Ok(vec![])
            } else {
                Ok(q.remove(0))
            }
        }
    }

    fn provider(scripted: Vec<Vec<Ssid>>) -> FakeScan {
        FakeScan {
            results: Arc::new(Mutex::new(scripted)),
        }
    }

    #[tokio::test]
    async fn returns_visible_when_ssid_in_first_scan() {
        let p = provider(vec![vec![Ssid::from_utf8("home")]]);
        let res =
            wait_until_ssid_visible(&p, &Ssid::from_utf8("home"), Duration::from_millis(500)).await;
        assert_eq!(res, ScanOutcome::Visible);
    }

    #[tokio::test]
    async fn returns_visible_when_ssid_in_later_scan() {
        let p = provider(vec![vec![], vec![Ssid::from_utf8("home")]]);
        let res =
            wait_until_ssid_visible(&p, &Ssid::from_utf8("home"), Duration::from_millis(500)).await;
        assert_eq!(res, ScanOutcome::Visible);
    }

    #[tokio::test]
    async fn returns_not_visible_after_timeout() {
        let p = provider(vec![vec![]; 10]);
        let res =
            wait_until_ssid_visible(&p, &Ssid::from_utf8("home"), Duration::from_millis(120)).await;
        assert_eq!(res, ScanOutcome::NotVisible);
    }

    #[tokio::test]
    async fn returns_skipped_when_provider_errors() {
        struct Err1;
        #[async_trait::async_trait]
        impl ScanProvider for Err1 {
            async fn scan(&self) -> Result<Vec<Ssid>, ScanError> {
                Err(ScanError::PermissionDenied)
            }
        }
        let res =
            wait_until_ssid_visible(&Err1, &Ssid::from_utf8("home"), Duration::from_millis(120))
                .await;
        assert_eq!(res, ScanOutcome::Skipped);
    }

    #[tokio::test]
    async fn returns_not_visible_when_timeout_is_zero() {
        // Even with a permissive provider, zero timeout should return NotVisible
        // immediately (or very nearly so) without consulting the provider.
        let p = provider(vec![vec![Ssid::from_utf8("home")]]);
        let res = wait_until_ssid_visible(&p, &Ssid::from_utf8("home"), Duration::ZERO).await;
        assert_eq!(res, ScanOutcome::NotVisible);
    }

    use crate::error::Error;

    #[test]
    fn scan_error_from_permission_denied() {
        let e = Error::PermissionDenied("Location");
        assert!(matches!(scan_error_from(e), ScanError::PermissionDenied));
    }

    #[test]
    fn scan_error_from_unsupported() {
        let e = Error::Unsupported("nope");
        assert!(matches!(scan_error_from(e), ScanError::Unsupported));
    }

    #[test]
    fn scan_error_from_os_passes_through() {
        let inner: crate::error::BoxedOsError = Box::new(std::io::Error::other("boom"));
        let e = Error::Os(inner);
        assert!(matches!(scan_error_from(e), ScanError::Os(_)));
    }

    #[test]
    fn scan_error_from_other_variants_become_os() {
        let e = Error::AdapterNotFound("wlan0".to_string());
        assert!(matches!(scan_error_from(e), ScanError::Os(_)));
    }
}
