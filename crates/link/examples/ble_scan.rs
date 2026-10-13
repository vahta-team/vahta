//! Lists nearby devices that advertise the Vahta GATT service.
//!
//!     cargo run -p vahta-link --example ble_scan -- [adapter] [seconds]
//!
//! Needs BlueZ on the system bus. It starts and stops LE discovery on the
//! adapter and changes nothing else.

#[cfg(target_os = "linux")]
fn main() {
    let mut args = std::env::args().skip(1);
    let adapter = args.next().unwrap_or_else(|| "hci0".into());
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(8);
    println!(
        "scanning {adapter} for {secs}s for service {}",
        vahta_link::ble::SERVICE_UUID
    );
    match vahta_link::ble::scan(&adapter, std::time::Duration::from_secs(secs)) {
        Ok(devs) if devs.is_empty() => println!("no Vahta devices in range"),
        Ok(devs) => {
            for d in devs {
                println!("{}  {:?}  rssi {:?}", d.address, d.name, d.rssi);
            }
        }
        Err(e) => {
            eprintln!("scan failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ble_scan is Linux only");
}
