//! Linux backend: `NetworkManager` via the system D-Bus.
//!
//! All submodules live under this directory and are implicitly gated by
//! `#[cfg(target_os = "linux")]` from the parent `platform/mod.rs`.

// Submodules. Each lands in a later task.
pub mod adapters;
pub mod backend;
pub mod connect;
pub mod disconnect;
pub mod error_map;
pub mod proxies;
pub mod scan;
pub mod settings;
pub mod state_wait;

#[cfg(test)]
mod tests;

pub use self::backend::LinuxBackend;
