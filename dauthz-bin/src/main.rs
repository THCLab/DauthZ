mod dkms;
mod scenarios;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("test-registration") => {
            scenarios::test_registration().await;
        }
        Some("test-login") => {
            scenarios::test_login().await;
        }
        Some("test-rotation") => {
            scenarios::test_rotation().await;
        }
        Some("test-full") => {
            scenarios::test_full_flow().await;
        }
        _ => {
            println!("DAuthZ Test Binary");
            println!();
            println!("Usage: dauthz-bin <command>");
            println!();
            println!("Commands:");
            println!("  test-registration   Run registration ceremony test");
            println!("  test-login          Run login ceremony test");
            println!("  test-rotation       Run key rotation ceremony test");
            println!("  test-full           Run full end-to-end test");
            println!();
            println!("Environment:");
            println!("  DKMS_BINARY         Path to dkms binary (default: dkms)");
        }
    }
}
