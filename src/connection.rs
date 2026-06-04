pub struct WifiConnection {
    // Boxed platform guard. Dropping the box drops the concrete guard, running
    // its `Drop` (the teardown). `dyn Send + Sync` keeps `WifiConnection`
    // `Send + Sync` so callers can hold it across threads for a session.
    _inner: Box<dyn Send + Sync>,
}

impl WifiConnection {
    /// Wrap a platform guard whose own `Drop` performs the teardown.
    pub(crate) fn new<G: Send + Sync + 'static>(guard: G) -> Self {
        Self {
            _inner: Box::new(guard),
        }
    }

    /// An inert handle for platforms where the OS owns the connection.
    pub(crate) fn inert() -> Self {
        Self {
            _inner: Box::new(()),
        }
    }
}

impl std::fmt::Debug for WifiConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WifiConnection")
    }
}
