//! Example: PIN and Biometric Authentication

use wallet::{
    BiometricAuth, BiometricAuthenticator, BiometricConfig, MockBiometricAuth, NetworkType,
    PinAuth, PinConfig, SecurePin, Wallet,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PIN and Biometric Authentication Example ===\n");

    // 1. Create wallet
    println!("1. Creating wallet...");
    let wallet = Wallet::new(NetworkType::Testnet)?;
    println!("   Wallet: {}\n", wallet.address_string());

    // === PIN AUTHENTICATION ===
    println!("=== PIN Authentication ===\n");

    // 2. Set up PIN
    println!("2. Setting up PIN...");
    let config = PinConfig::default();
    let user_pin = SecurePin::new("5678".to_string())?;

    // Check if PIN is weak
    if PinAuth::is_weak_pin(&user_pin) {
        println!("   ⚠️  Warning: This PIN is considered weak");
    }

    let mut stored_pin = PinAuth::hash_pin(&user_pin, &config)?;
    println!("   ✅ PIN set successfully");
    println!("   Max attempts: {}", config.max_attempts);
    println!(
        "   Lockout duration: {} seconds\n",
        config.lockout_duration_secs
    );

    // 3. Verify correct PIN
    println!("3. Verifying correct PIN...");
    match PinAuth::verify_pin(&user_pin, &mut stored_pin) {
        Ok(()) => println!("   ✅ PIN verified successfully\n"),
        Err(e) => println!("   ❌ PIN verification failed: {}\n", e),
    }

    // 4. Test wrong PIN
    println!("4. Testing wrong PIN...");
    let wrong_pin = SecurePin::new("0000".to_string())?;
    match PinAuth::verify_pin(&wrong_pin, &mut stored_pin) {
        Ok(()) => println!("   ❌ Should have failed!"),
        Err(e) => {
            println!("   ✅ Correctly rejected: {}", e);
            println!(
                "   Remaining attempts: {}\n",
                PinAuth::remaining_attempts(&stored_pin)
            );
        }
    }

    // 5. Test lockout
    println!("5. Testing lockout mechanism...");
    for i in 1..=2 {
        let _ = PinAuth::verify_pin(&wrong_pin, &mut stored_pin);
        println!("   Failed attempt #{}", i + 1);
    }

    if let Some(remaining) = PinAuth::lockout_remaining(&stored_pin) {
        println!("   🔒 Account locked for {} seconds\n", remaining);
    }

    // 6. Generate random PIN
    println!("6. Generating random PIN...");
    let random_pin = PinAuth::generate_random_pin(6);
    println!("   Random 6-digit PIN generated: {}\n", random_pin.as_str());

    // 7. Test weak PIN detection
    println!("7. Testing weak PIN detection...");
    let weak_pins = vec!["1234", "0000", "1111"];
    for pin_str in weak_pins {
        let pin = SecurePin::new(pin_str.to_string())?;
        let is_weak = PinAuth::is_weak_pin(&pin);
        println!(
            "   PIN {}: {}",
            pin_str,
            if is_weak { "❌ Weak" } else { "✅ Strong" }
        );
    }

    // === BIOMETRIC AUTHENTICATION ===
    println!("\n=== Biometric Authentication ===\n");

    // 8. Check biometric capability
    println!("8. Checking biometric capability...");
    let bio_auth = BiometricAuth::new();
    match bio_auth.check_capability() {
        Ok(capability) => {
            println!("   Available: {}", capability.available);
            println!("   Enrolled: {}", capability.enrolled);
            if let Some(bio_type) = capability.biometric_type {
                println!("   Type: {:?}", bio_type);
            }
            println!("   Hardware: {}\n", capability.hardware_present);
        }
        Err(e) => println!("   Error: {}\n", e),
    }

    // 9. Test biometric authentication (using mock)
    println!("9. Testing biometric authentication...");
    let mock_success = MockBiometricAuth::success();
    let bio_config = BiometricConfig {
        title: "Unlock Wallet".to_string(),
        subtitle: "Authenticate to access your TIME Coin wallet".to_string(),
        description: "Use your fingerprint or face to unlock".to_string(),
        allow_fallback: true,
        timeout_secs: 30,
    };

    match mock_success.authenticate(&bio_config) {
        Ok(()) => println!("   ✅ Biometric authentication successful\n"),
        Err(e) => println!("   ❌ Biometric authentication failed: {}\n", e),
    }

    // 10. Test failed biometric
    println!("10. Testing failed biometric authentication...");
    let mock_failure = MockBiometricAuth::failure();
    match mock_failure.authenticate(&bio_config) {
        Ok(()) => println!("   ❌ Should have failed!"),
        Err(e) => println!("   ✅ Correctly rejected: {}\n", e),
    }

    // 11. Platform support check
    println!("11. Platform biometric support:");
    println!(
        "   Supported: {}",
        if BiometricAuth::is_supported() {
            "✅ Yes"
        } else {
            "❌ No (mock mode)"
        }
    );

    println!("\n=== Example Complete ===");
    println!("\n💡 Integration Tips:");
    println!("   - Use PIN for quick unlocking (4-8 digits)");
    println!("   - Use biometric for seamless authentication");
    println!("   - Fallback to password for maximum security");
    println!("   - Implement auto-lock with PIN/biometric unlock");

    Ok(())
}
