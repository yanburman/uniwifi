#![cfg(feature = "mock")]

use uniwifi::{ConnectOptions, Credentials, MockBackend, Ssid, UniWifi};

#[tokio::test]
async fn happy_path_connect_disconnect_remove() {
    let mock = MockBackend::new();
    mock.state()
        .add_visible_ssid(Ssid::from_utf8("Office"), "tea4two");
    let hal = UniWifi::with_mock(mock);

    let adapters = hal.list_adapters().await.expect("list_adapters failed");
    let adapter = adapters.into_iter().next().expect("expected one adapter");

    adapter
        .connect(
            &Ssid::from_utf8("Office"),
            Credentials::password("tea4two"),
            ConnectOptions::default(),
        )
        .await
        .expect("connect failed");

    adapter
        .connect_with_stored_credentials(&Ssid::from_utf8("Office"), ConnectOptions::default())
        .await
        .expect("stored-credentials connect failed");

    adapter
        .disconnect(&Ssid::from_utf8("Office"))
        .await
        .expect("disconnect failed");

    let removed = adapter
        .remove_profile(&Ssid::from_utf8("Office"))
        .await
        .expect("remove_profile failed");
    assert!(removed);
}

#[tokio::test]
async fn wrong_password_returns_authentication_failed() {
    let mock = MockBackend::new();
    mock.state()
        .add_visible_ssid(Ssid::from_utf8("Cafe"), "secret");
    let hal = UniWifi::with_mock(mock);

    let adapter = hal
        .list_adapters()
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let err = adapter
        .connect(
            &Ssid::from_utf8("Cafe"),
            Credentials::password("WRONG"),
            ConnectOptions::default(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, uniwifi::Error::AuthenticationFailed));
}

#[tokio::test]
async fn invisible_ssid_returns_not_in_range() {
    let mock = MockBackend::new();
    let hal = UniWifi::with_mock(mock);

    let adapter = hal
        .list_adapters()
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let err = adapter
        .connect(
            &Ssid::from_utf8("ghost"),
            Credentials::password("x"),
            ConnectOptions::default(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, uniwifi::Error::SsidNotInRange));
}

#[tokio::test]
async fn list_visible_networks_returns_scripted_networks() {
    use uniwifi::{MockBackend, ScanOptions, SecurityFlags, Ssid, UniWifi, VisibleNetworkProps};

    let mock = MockBackend::new();
    mock.state().add_visible_ssid(Ssid::from_utf8("home"), "pw");
    mock.state().add_visible_network(
        Ssid::from_utf8("guest"),
        "pw2",
        VisibleNetworkProps {
            signal_quality: 95,
            security: SecurityFlags::OPEN,
            rssi_dbm: Some(-45),
            bssid: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            frequency_mhz: Some(5180),
            bss_count: 1,
        },
    );
    let hal = UniWifi::with_mock(mock);
    let adapters = hal.list_adapters().await.unwrap();
    let nets = adapters[0]
        .list_visible_networks(ScanOptions::default())
        .await
        .unwrap();
    assert_eq!(nets.len(), 2);
    // Sort order: highest quality first; "guest"=95, "home"=75.
    assert_eq!(nets[0].ssid.as_str(), Some("guest"));
    assert_eq!(nets[0].signal_quality, 95);
    assert_eq!(nets[0].security, SecurityFlags::OPEN);
    assert_eq!(nets[0].rssi_dbm, Some(-45));
    assert_eq!(nets[0].band(), Some(uniwifi::Band::Ghz5));
    assert_eq!(nets[1].ssid.as_str(), Some("home"));
    assert!(!nets[0].is_connected);
    assert!(!nets[0].has_saved_profile);
}

#[tokio::test]
async fn list_visible_networks_stamps_is_connected_and_saved() {
    use uniwifi::{ConnectOptions, Credentials, MockBackend, ScanOptions, Ssid, UniWifi};

    let mock = MockBackend::new();
    mock.state().add_visible_ssid(Ssid::from_utf8("home"), "pw");
    let hal = UniWifi::with_mock(mock);
    let adapters = hal.list_adapters().await.unwrap();

    // After connect, the next scan should mark `home` as connected and
    // having a saved profile.
    adapters[0]
        .connect(
            &Ssid::from_utf8("home"),
            Credentials::password("pw"),
            ConnectOptions::default(),
        )
        .await
        .unwrap();

    let nets = adapters[0]
        .list_visible_networks(ScanOptions::default())
        .await
        .unwrap();
    let home = nets
        .iter()
        .find(|n| n.ssid.as_str() == Some("home"))
        .unwrap();
    assert!(home.is_connected);
    assert!(home.has_saved_profile);
}

#[tokio::test]
async fn list_visible_networks_returns_empty_for_no_visible_ssids() {
    use uniwifi::{MockBackend, ScanOptions, UniWifi};

    let mock = MockBackend::new();
    let hal = UniWifi::with_mock(mock);
    let adapters = hal.list_adapters().await.unwrap();
    let nets = adapters[0]
        .list_visible_networks(ScanOptions::default())
        .await
        .unwrap();
    assert!(nets.is_empty());
}
