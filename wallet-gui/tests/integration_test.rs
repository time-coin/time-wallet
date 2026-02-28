//! Integration test for wallet-gui components
//! Tests the complete flow of wallet creation, transaction creation, and key management

use wallet::{NetworkType, UTXO};

// We need to include the modules from the main binary
// For this integration test, we'll test the underlying wallet library directly
// since the GUI is hard to test without a display

#[test]
fn test_mnemonic_generation() {
    use wallet::generate_mnemonic;

    println!("Testing mnemonic generation...");

    // Generate 12-word mnemonic
    let mnemonic = generate_mnemonic(12).expect("Failed to generate mnemonic");
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    assert_eq!(words.len(), 12, "Mnemonic should have 12 words");
    println!("Generated mnemonic: {}", mnemonic);
    println!("✅ Mnemonic generation test passed");
}

#[test]
fn test_wallet_from_mnemonic() {
    use wallet::{generate_mnemonic, Wallet};

    println!("Testing wallet creation from mnemonic...");

    // Generate mnemonic
    let mnemonic = generate_mnemonic(12).expect("Failed to generate mnemonic");

    // Create wallet from mnemonic
    let wallet = Wallet::from_mnemonic(&mnemonic, "", NetworkType::Testnet)
        .expect("Failed to create wallet from mnemonic");

    let address = wallet.address_string();
    println!("Created wallet with address: {}", address);

    assert!(!address.is_empty());
    println!("✅ Wallet from mnemonic test passed");
}

#[test]
fn test_mnemonic_deterministic() {
    use wallet::Wallet;

    println!("Testing mnemonic determinism...");

    // Use a known mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Create two wallets from same mnemonic
    let wallet1 = Wallet::from_mnemonic(mnemonic, "", NetworkType::Testnet)
        .expect("Failed to create wallet 1");
    let wallet2 = Wallet::from_mnemonic(mnemonic, "", NetworkType::Testnet)
        .expect("Failed to create wallet 2");

    // They should have identical addresses
    assert_eq!(wallet1.address_string(), wallet2.address_string());
    assert_eq!(wallet1.public_key(), wallet2.public_key());

    println!("Wallet 1 address: {}", wallet1.address_string());
    println!("Wallet 2 address: {}", wallet2.address_string());
    println!("✅ Mnemonic determinism test passed");
}

#[test]
fn test_mnemonic_validation() {
    use wallet::validate_mnemonic;

    println!("Testing mnemonic validation...");

    // Valid mnemonic
    let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(validate_mnemonic(valid).is_ok());

    // Invalid mnemonic (wrong words)
    let invalid = "invalid word word word word word word word word word word word";
    assert!(validate_mnemonic(invalid).is_err());

    // Invalid mnemonic (wrong count)
    let invalid_count = "abandon abandon abandon";
    assert!(validate_mnemonic(invalid_count).is_err());

    println!("✅ Mnemonic validation test passed");
}

#[test]
fn test_complete_wallet_flow() {
    use wallet::Wallet;

    println!("Testing complete wallet flow...");

    // Create sender wallet
    let mut sender = Wallet::new(NetworkType::Testnet).expect("Failed to create sender wallet");
    let sender_address = sender.address_string();
    println!("Sender address: {}", sender_address);

    // Add funds via UTXO (10 TIME = 1_000_000_000 satoshis)
    let utxo = UTXO {
        tx_hash: [1u8; 32],
        output_index: 0,
        amount: 1_000_000_000,
        address: sender_address.clone(),
    };
    sender.add_utxo(utxo);
    assert_eq!(sender.balance(), 1_000_000_000);

    // Create recipient wallet
    let recipient = Wallet::new(NetworkType::Testnet).expect("Failed to create recipient wallet");
    let recipient_address = recipient.address_string();
    println!("Recipient address: {}", recipient_address);

    // Create transaction (send 1 TIME = 100_000_000 satoshis)
    let send_amount = 100_000_000u64;
    let tx = sender
        .create_transaction(&recipient_address, send_amount, 0)
        .expect("Failed to create transaction");

    // Fee is calculated internally (1% for < 100 TIME, min 0.01 TIME)
    let fee = wallet::calculate_fee(send_amount);

    // Verify transaction
    assert_eq!(tx.outputs.len(), 2); // recipient + change
    assert_eq!(tx.outputs[0].value, send_amount);
    assert_eq!(tx.outputs[1].value, 1_000_000_000 - send_amount - fee);

    println!("✅ Complete wallet flow test passed");
}

#[test]
fn test_key_import_export() {
    use wallet::Wallet;

    // Create original wallet
    let wallet1 = Wallet::new(NetworkType::Testnet).expect("Failed to create wallet");
    let private_key = wallet1.export_private_key();
    let address1 = wallet1.address_string();

    // Import to new wallet
    let wallet2 = Wallet::from_private_key_hex(&private_key, NetworkType::Testnet)
        .expect("Failed to import private key");
    let address2 = wallet2.address_string();

    // Verify addresses match
    assert_eq!(address1, address2);
    assert_eq!(wallet1.public_key(), wallet2.public_key());

    println!("✅ Key import/export test passed");
}

#[test]
fn test_multiple_utxos() {
    use wallet::Wallet;

    let mut wallet = Wallet::new(NetworkType::Testnet).expect("Failed to create wallet");
    let address = wallet.address_string();

    // Add multiple UTXOs (each 1 TIME = 100_000_000 satoshis)
    for i in 0..5 {
        let utxo = UTXO {
            tx_hash: [i; 32],
            output_index: i as u32,
            amount: 100_000_000,
            address: address.clone(),
        };
        wallet.add_utxo(utxo);
    }

    assert_eq!(wallet.balance(), 500_000_000);
    assert_eq!(wallet.utxos().len(), 5);

    // Create transaction that needs multiple UTXOs (send 4.5 TIME)
    let recipient = Wallet::new(NetworkType::Testnet).expect("Failed to create recipient");
    let send_amount = 450_000_000u64;
    let tx = wallet
        .create_transaction(&recipient.address_string(), send_amount, 0)
        .expect("Failed to create transaction");

    // Should use all 5 UTXOs
    assert_eq!(tx.inputs.len(), 5);
    assert_eq!(tx.outputs.len(), 2); // recipient + change

    println!("✅ Multiple UTXOs test passed");
}

#[test]
fn test_insufficient_funds() {
    use wallet::Wallet;

    let mut wallet = Wallet::new(NetworkType::Testnet).expect("Failed to create wallet");
    let address = wallet.address_string();

    // Add small UTXO
    let utxo = UTXO {
        tx_hash: [1u8; 32],
        output_index: 0,
        amount: 100,
        address: address.clone(),
    };
    wallet.add_utxo(utxo);

    // Try to send more than available
    let recipient = Wallet::new(NetworkType::Testnet).expect("Failed to create recipient");
    let result = wallet.create_transaction(&recipient.address_string(), 1000, 10);

    assert!(result.is_err());
    println!("✅ Insufficient funds test passed");
}

#[test]
fn test_wallet_persistence() {
    use std::fs;
    use wallet::Wallet;

    let temp_path = "/tmp/test_wallet_persist.json";

    // Create and save wallet
    let wallet1 = Wallet::new(NetworkType::Testnet).expect("Failed to create wallet");
    let address1 = wallet1.address_string();
    wallet1
        .save_to_file(temp_path)
        .expect("Failed to save wallet");

    // Load wallet
    let wallet2 = Wallet::load_from_file(temp_path).expect("Failed to load wallet");
    let address2 = wallet2.address_string();

    // Verify they match
    assert_eq!(address1, address2);
    assert_eq!(wallet1.public_key(), wallet2.public_key());

    // Cleanup
    fs::remove_file(temp_path).ok();

    println!("✅ Wallet persistence test passed");
}

#[test]
fn test_wallet_manager_mnemonic_create() {
    use std::fs;

    println!("Testing WalletManager mnemonic creation...");

    // Clean up any existing test wallet
    let test_dir = std::env::temp_dir().join("time-coin-test-mnemonic");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    // This test would require importing WalletManager which is part of the binary
    // For now, we test through the wallet library which is what WalletManager uses

    // Generate mnemonic
    let mnemonic = wallet::generate_mnemonic(12).expect("Failed to generate mnemonic");
    println!("Generated mnemonic: {}", mnemonic);

    // Validate it
    wallet::validate_mnemonic(&mnemonic).expect("Mnemonic should be valid");

    // Create wallet from it
    let wallet = wallet::Wallet::from_mnemonic(&mnemonic, "", NetworkType::Testnet)
        .expect("Failed to create wallet from mnemonic");

    println!("Created wallet with address: {}", wallet.address_string());

    // Verify we can recreate the same wallet
    let wallet2 = wallet::Wallet::from_mnemonic(&mnemonic, "", NetworkType::Testnet)
        .expect("Failed to create second wallet");

    assert_eq!(wallet.address_string(), wallet2.address_string());

    println!("✅ WalletManager mnemonic creation test passed");
}
