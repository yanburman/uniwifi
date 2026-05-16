use async_trait::async_trait;

use crate::backend::{AdapterInfo, Backend};
use crate::error::Error;
use crate::types::{AdapterId, ConnectOptions, Credentials, ScanOptions, Ssid, VisibleNetwork};

/// Backend that returns `Error::Unsupported(reason)` for every operation.
/// Used as a placeholder until the real platform backend lands in a
/// follow-up plan.
pub struct StubBackend {
    reason: &'static str,
}

impl StubBackend {
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

#[async_trait]
impl Backend for StubBackend {
    async fn list_adapters(&self) -> Result<Vec<AdapterInfo>, Error> {
        Err(Error::Unsupported(self.reason))
    }

    async fn connect(
        &self,
        _adapter: &AdapterId,
        _ssid: &Ssid,
        _credentials: &Credentials,
        _options: &ConnectOptions,
    ) -> Result<(), Error> {
        Err(Error::Unsupported(self.reason))
    }

    async fn connect_with_stored_credentials(
        &self,
        _adapter: &AdapterId,
        _ssid: &Ssid,
        _options: &ConnectOptions,
    ) -> Result<(), Error> {
        Err(Error::Unsupported(self.reason))
    }

    async fn disconnect(&self, _adapter: &AdapterId, _ssid: &Ssid) -> Result<(), Error> {
        Err(Error::Unsupported(self.reason))
    }

    async fn remove_profile(&self, _adapter: &AdapterId, _ssid: &Ssid) -> Result<bool, Error> {
        Err(Error::Unsupported(self.reason))
    }

    async fn list_visible_networks(
        &self,
        _adapter: &AdapterId,
        _options: &ScanOptions,
    ) -> Result<Vec<VisibleNetwork>, Error> {
        Err(Error::Unsupported("scan not implemented on this platform"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::types::{ConnectOptions, Credentials, Ssid};

    fn make_stub() -> StubBackend {
        StubBackend::new("test stub")
    }

    #[tokio::test]
    async fn list_adapters_returns_unsupported() {
        let s = make_stub();
        let res = s.list_adapters().await;
        assert!(matches!(res, Err(crate::error::Error::Unsupported(msg)) if msg == "test stub"));
    }

    #[tokio::test]
    async fn connect_returns_unsupported() {
        let s = make_stub();
        let res = s
            .connect(
                &crate::types::AdapterId::new("x"),
                &Ssid::from_utf8("y"),
                &Credentials::Open,
                &ConnectOptions::default(),
            )
            .await;
        assert!(matches!(res, Err(crate::error::Error::Unsupported(_))));
    }

    #[tokio::test]
    async fn other_methods_return_unsupported() {
        let s = make_stub();
        let id = crate::types::AdapterId::new("x");
        let ssid = Ssid::from_utf8("y");
        assert!(matches!(
            s.connect_with_stored_credentials(&id, &ssid, &ConnectOptions::default())
                .await,
            Err(crate::error::Error::Unsupported(_))
        ));
        assert!(matches!(
            s.disconnect(&id, &ssid).await,
            Err(crate::error::Error::Unsupported(_))
        ));
        assert!(matches!(
            s.remove_profile(&id, &ssid).await,
            Err(crate::error::Error::Unsupported(_))
        ));
    }
}
