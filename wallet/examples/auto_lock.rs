//! Example: Wallet auto-lock for security

use std::sync::Arc;
use std::time::Duration;
use wallet::{AutoLockConfig, AutoLockManager, NetworkType, SecurePassword, Wallet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Wallet Auto-Lock Example ===\n");

    // 1. Create wallet and auto-lock manager
    println!("1. Creating wallet with auto-lock (10 second timeout)...");
    let wallet = Wallet::new(NetworkType::Testnet)?;
    let _password = SecurePassword::new("TestPassword123".to_string());

    let config = AutoLockConfig::with_timeout(Duration::from_secs(10));
    let lock_manager = Arc::new(AutoLockManager::new(config));

    println!("   Wallet: {}", wallet.address_string());
    println!("   Auto-lock timeout: 10 seconds\n");

    // 2. Set up lock callback
    println!("2. Setting up lock callback...");
    lock_manager
        .set_on_lock(|| {
            println!("   🔒 WALLET LOCKED! (due to inactivity)");
        })
        .await;

    // 3. Start auto-lock monitor
    println!("3. Starting auto-lock monitor...\n");
    let monitor_handle = lock_manager.clone().start_monitor();

    // 4. Simulate wallet activity
    println!("4. Simulating wallet activity...");
    for i in 1..=3 {
        println!("   Activity #{} - Checking balance...", i);
        lock_manager.update_activity().await;

        let time_left = lock_manager.time_until_lock().await;
        if let Some(duration) = time_left {
            println!("   Time until auto-lock: {:.1}s", duration.as_secs_f32());
        }

        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    // 5. Let wallet become inactive
    println!("\n5. Stopping activity (letting auto-lock trigger)...");
    println!("   Waiting for auto-lock...");

    // Wait for auto-lock to trigger
    while !lock_manager.is_locked().await {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!("   Wallet is now locked!\n");

    // 6. Try to access locked wallet
    println!("6. Attempting to use locked wallet...");
    if lock_manager.is_locked().await {
        println!("   ❌ Wallet is locked - authentication required");
        println!("   Enter password to unlock...");
    }

    // 7. Unlock wallet
    println!("\n7. Unlocking wallet...");
    lock_manager.unlock().await;
    println!("   ✅ Wallet unlocked!");
    println!("   Lock state: {:?}\n", lock_manager.lock_state().await);

    // 8. Manual lock
    println!("8. Testing manual lock...");
    lock_manager.lock().await;
    println!("   ✅ Wallet manually locked");
    println!("   Lock state: {:?}\n", lock_manager.lock_state().await);

    // 9. Configuration update
    println!("9. Updating auto-lock configuration...");
    let new_config = AutoLockConfig::with_timeout(Duration::from_secs(300));
    lock_manager.update_config(new_config).await;
    let current_config = lock_manager.get_config().await;
    println!(
        "   New timeout: {} seconds\n",
        current_config.timeout.as_secs()
    );

    // 10. Disable auto-lock
    println!("10. Disabling auto-lock...");
    let disabled_config = AutoLockConfig::disabled();
    lock_manager.update_config(disabled_config).await;
    println!("   Auto-lock disabled");

    let time_left = lock_manager.time_until_lock().await;
    println!("   Time until lock: {:?}\n", time_left);

    // Cleanup
    monitor_handle.abort();
    println!("=== Example Complete ===");

    Ok(())
}
