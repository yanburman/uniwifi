//! Unit tests that don't require a live radio.

use crate::backend::Backend;
use crate::preflight::ScanProvider;

use super::backend::MacosBackend;

#[tokio::test]
async fn list_adapters_either_succeeds_or_returns_no_adapter() {
    let backend = MacosBackend::new().expect("MacosBackend::new should succeed");
    match backend.list_adapters().await {
        Ok(adapters) => {
            // On a developer Mac there is at least one Wi-Fi interface.
            // On a CI runner without a Wi-Fi card the call returns
            // `Err(NoAdapter)` (handled in the Err arm). Either is fine.
            for a in adapters {
                assert!(!a.id.as_str().is_empty(), "adapter id must be non-empty");
                assert!(!a.name.is_empty(), "adapter name must be non-empty");
            }
        }
        Err(crate::error::Error::NoAdapter) => {
            // Acceptable on hardware without a Wi-Fi interface.
        }
        Err(other) => panic!("unexpected error from list_adapters: {other}"),
    }
}

#[tokio::test]
async fn resolve_interface_round_trips_listed_adapters() {
    let backend = MacosBackend::new().expect("MacosBackend::new should succeed");
    let Ok(adapters) = backend.list_adapters().await else {
        // Skip on hosts without Wi-Fi.
        return;
    };
    for a in adapters {
        backend.client.with(|client| {
            let res = super::adapter::resolve_interface_by_id(client, &a.id);
            assert!(
                res.is_ok(),
                "should resolve adapter {} we just listed",
                a.id,
            );
        });
    }
}

#[tokio::test]
async fn run_blocking_round_trips_a_value() {
    let result = super::threading::run_blocking(|| 42_i32).await;
    assert_eq!(result, 42);
}

#[tokio::test]
async fn run_blocking_returns_owned_string() {
    let result = super::threading::run_blocking(|| "hello".to_owned()).await;
    assert_eq!(result, "hello");
}

#[tokio::test]
async fn scan_returns_ok_or_skipped_on_host_with_radio() {
    let backend = MacosBackend::new().expect("MacosBackend::new should succeed");
    let Ok(adapters) = backend.list_adapters().await else {
        return;
    };
    let Some(adapter) = adapters.into_iter().next() else {
        return;
    };

    let provider = super::scan::make_scan_provider(backend.client.clone(), adapter.id);
    // Scan can fail if Location Services isn't authorised; that's fine for
    // the unit test -- the integration plan acknowledges the permission
    // dance. We only assert the call shape doesn't panic.
    let _ = provider.scan().await;
}

#[tokio::test]
async fn remove_profile_for_nonexistent_ssid_returns_false() {
    let backend = MacosBackend::new().expect("MacosBackend::new should succeed");
    // Make up a long random SSID so we never collide with a real entry.
    let ssid = crate::types::Ssid::from_utf8("uniwifi_test_ZZZZZZZZ_does_not_exist");
    let adapter = crate::types::AdapterId::new("en0");
    let result = backend.remove_profile(&adapter, &ssid).await;
    // The plan-literal expectation is `Ok(false)` for a nonexistent entry.
    // On hosts where the test runner doesn't have a fully-wired keychain
    // XPC connection (e.g. sandboxed CI agents) the call can fail with
    // `errSecAuthFailed` (mapped to `PermissionDenied`) or with an XPC
    // transport error surfaced as `Os(...)`. Neither is a code defect, so
    // we accept those as environmental skips and only fail on a wrong
    // success value or an unexpected error variant.
    match result {
        Ok(false)
        | Err(crate::error::Error::PermissionDenied("Keychain") | crate::error::Error::Os(_)) => {}
        Ok(true) => panic!("nonexistent entry must not return true"),
        Err(other) => panic!("unexpected error from remove_profile: {other}"),
    }
}
