#[cfg(feature = "mock")]
pub mod mock;

#[cfg(test)]
pub mod stub;

// Compile the android module on android targets, AND under host tests
// so we can exercise the parts that don't actually need the JVM
// (list_adapters, status_codes mapping, etc.).
#[cfg(any(target_os = "android", test))]
pub mod android;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "ios")]
pub mod ios;

use crate::backend::Backend;
use crate::error::Error;

/// Returns the platform-default backend. The signature is fallible
/// because real-backend constructors need to acquire OS handles (Windows
/// WLAN handle, Android JavaVM/Context, etc.) that can fail at startup.
///
/// # Errors
///
/// Returns the platform backend's construction error. On unsupported
/// targets returns [`Error::Unsupported`]. The currently-supported
/// `target_os` values are `windows`, `macos`, `linux`, `android`, and
/// `ios`; on each, the per-backend `new()` may surface OS-startup
/// failures.
// `unnecessary_wraps` is suppressed deliberately: clippy only sees the
// active `cfg` branch and on most branches concludes that branch can't
// fail (e.g. `IosBackend::new` is currently infallible). The fallible
// signature is part of the cross-platform contract — Windows acquires a
// WLAN handle, Android needs the JavaVM / Context — so the `Result`
// shape stays even when individual branches are presently infallible.
#[allow(clippy::unnecessary_wraps)]
pub fn default_backend() -> Result<Box<dyn Backend + Send + Sync>, Error> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsBackend::new()?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacosBackend::new()?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxBackend::new()?))
    }
    #[cfg(target_os = "android")]
    {
        Ok(Box::new(android::AndroidBackend::new()?))
    }
    #[cfg(target_os = "ios")]
    {
        Ok(Box::new(ios::IosBackend::new()?))
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "android",
        target_os = "ios"
    )))]
    {
        Err(Error::Unsupported("no backend for this target_os"))
    }
}
