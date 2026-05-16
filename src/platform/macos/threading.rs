//! Worker-thread offload for blocking `CoreWLAN` calls.
//!
//! Strategy:
//! - When the `tokio_rt` feature is on (and a tokio runtime is detected),
//!   use `tokio::task::spawn_blocking`. This integrates with tokio's
//!   blocking thread pool and gives us automatic shutdown semantics.
//! - Otherwise, fall back to `std::thread::spawn` and pipe the result back
//!   through a `tokio::sync::oneshot` channel. This keeps the API
//!   `async fn` everywhere even without a multi-threaded tokio runtime.
//!
//! No autoreleasepool wrapping is needed for `associate` / `disassociate`
//! /`scan` because those `CoreWLAN` methods do not return autoreleased
//! objects we hold across awaits — every `Retained<T>` we keep was returned
//! through the `Result` return path and carries its own +1 reference.

use std::future::Future;

/// Run a blocking closure on a worker thread, then await its result on the
/// current async task.
///
/// # Panics
/// Panics if the worker thread itself panics. Callers should design the
/// closure to be panic-free; the wrapped `CoreWLAN` calls are.
pub(super) fn run_blocking<F, T>(f: F) -> impl Future<Output = T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(feature = "tokio_rt")]
    {
        async move {
            tokio::task::spawn_blocking(f)
                .await
                .expect("spawn_blocking worker panicked")
        }
    }
    #[cfg(not(feature = "tokio_rt"))]
    {
        async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let result = f();
                // If the receiver was dropped (future cancelled), discard.
                let _ = tx.send(result);
            });
            rx.await
                .expect("worker thread dropped sender without sending")
        }
    }
}
