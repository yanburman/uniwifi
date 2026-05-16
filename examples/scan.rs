//! Live exerciser: list visible networks on the first adapter.
//!
//! ```text
//! cargo run --example scan
//! cargo run --example scan -- --rescan
//! ```

// Developer-facing CLI example: writing to stdout/stderr is the program's
// whole purpose, so the matching clippy lints are allowed (mirrors the
// `connect.rs` example).
#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::error::Error;

use uniwifi::{ScanOptions, UniWifi};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let force_rescan = std::env::args().any(|a| a == "--rescan");
    let hal = UniWifi::new()?;
    let adapters = hal.list_adapters().await?;
    let Some(adapter) = adapters.first() else {
        eprintln!("no wifi adapters");
        return Ok(());
    };
    println!("scanning on {} ({})", adapter.name(), adapter.id());

    let nets = adapter
        .list_visible_networks(ScanOptions { force_rescan })
        .await?;
    println!("found {} networks:", nets.len());
    for n in &nets {
        let ssid = n.ssid.as_str().unwrap_or("<non-utf8>");
        let band = n
            .band()
            .map_or_else(|| "?".to_string(), |b| format!("{b:?}"));
        let bssid = n.bssid.map_or_else(
            || "?".to_string(),
            |b| {
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    b[0], b[1], b[2], b[3], b[4], b[5]
                )
            },
        );
        let rssi = n
            .rssi_dbm
            .map_or_else(|| "?".to_string(), |r| format!("{r}dBm"));
        println!(
            "  {ssid:30} q={:3} {rssi} {band:?} bssid={bssid} bsses={} sec={:?} conn={} saved={}",
            n.signal_quality, n.bss_count, n.security, n.is_connected, n.has_saved_profile
        );
    }
    Ok(())
}
