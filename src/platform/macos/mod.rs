//! macOS backend: `CoreWLAN` via objc2 + objc2-core-wlan.
//!
//! Public surface is `MacosBackend`. Everything else stays private to this
//! module tree.

mod adapter;
mod backend;
mod client;
mod connect;
mod error;
mod keychain;
mod scan;
mod threading;

#[cfg(test)]
mod tests;

pub use self::backend::MacosBackend;
