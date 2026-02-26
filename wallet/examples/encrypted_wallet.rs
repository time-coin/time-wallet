//! Example: Using encrypted wallet with password protection

use wallet::{NetworkType, SecurePassword, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TIME Coin Encrypted Wallet Example ===\n");

    // 1. Create a new wallet
    println!("1. Creating new wallet...");
    let wallet = Wallet::new(NetworkType::Testnet)?;
    println!("   Address: {}", wallet.address_string());
    println!("   Public Key: {}\n", wallet.public_key_hex());

    // 2. Save wallet with password encryption
    println!("2. Saving encrypted wallet...");
    let password = SecurePassword::new("MySecurePassword123!".to_string());
    wallet.save_encrypted("example_wallet.enc", &password)?;
    println!("   ✅ Wallet saved to: example_wallet.enc\n");

    // 3. Verify password (without loading full wallet)
    println!("3. Verifying password...");
    let correct_pwd = SecurePassword::new("MySecurePassword123!".to_string());
    let wrong_pwd = SecurePassword::new("WrongPassword".to_string());

    if Wallet::verify_encrypted_password("example_wallet.enc", &correct_pwd)? {
        println!("   ✅ Correct password verified");
    }

    if !Wallet::verify_encrypted_password("example_wallet.enc", &wrong_pwd)? {
        println!("   ✅ Wrong password correctly rejected\n");
    }

    // 4. Load encrypted wallet
    println!("4. Loading encrypted wallet...");
    let loaded_wallet = Wallet::load_encrypted("example_wallet.enc", &password)?;
    println!("   ✅ Wallet loaded successfully");
    println!("   Address: {}\n", loaded_wallet.address_string());

    // 5. Change password
    println!("5. Changing password...");
    let new_password = SecurePassword::new("NewPassword456!".to_string());
    Wallet::change_encrypted_password("example_wallet.enc", &password, &new_password)?;
    println!("   ✅ Password changed successfully\n");

    // 6. Load with new password
    println!("6. Loading with new password...");
    let reloaded_wallet = Wallet::load_encrypted("example_wallet.enc", &new_password)?;
    println!("   ✅ Wallet loaded with new password");
    println!("   Address: {}\n", reloaded_wallet.address_string());

    // 7. Try loading with old password (should fail)
    println!("7. Testing old password (should fail)...");
    match Wallet::load_encrypted("example_wallet.enc", &password) {
        Ok(_) => println!("   ❌ ERROR: Old password should not work!"),
        Err(_) => println!("   ✅ Old password correctly rejected\n"),
    }

    // Cleanup
    std::fs::remove_file("example_wallet.enc").ok();
    println!("=== Example Complete ===");

    Ok(())
}
