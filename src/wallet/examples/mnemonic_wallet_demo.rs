//! BIP-39 Mnemonic Wallet Demo
//!
//! Demonstrates how to create and restore a wallet using BIP-39 mnemonic phrases.
//! Run with: cargo run --example mnemonic_wallet_demo

use wallet::{generate_mnemonic, NetworkType, Wallet, UTXO};

fn main() {
    println!("==========================================");
    println!("  TIME Coin BIP-39 Mnemonic Wallet Demo");
    println!("==========================================\n");

    // 1. Generate a new mnemonic phrase
    println!("1. Generating a new 12-word mnemonic phrase...");
    let mnemonic_12 = generate_mnemonic(12).unwrap();
    println!("   Mnemonic (12 words):");
    println!("   {}", mnemonic_12);
    println!("   ⚠️  IMPORTANT: Save this phrase securely!");
    println!();

    // 2. Create a wallet from the mnemonic
    println!("2. Creating wallet from mnemonic...");
    let wallet = Wallet::from_mnemonic(&mnemonic_12, "", NetworkType::Mainnet).unwrap();
    println!("   Address: {}", wallet.address());
    println!("   Public Key: {}", wallet.public_key_hex());
    println!();

    // 3. Restore wallet from the same mnemonic (demonstrates deterministic recovery)
    println!("3. Restoring wallet from the same mnemonic...");
    let restored_wallet = Wallet::from_mnemonic(&mnemonic_12, "", NetworkType::Mainnet).unwrap();
    println!("   Restored Address: {}", restored_wallet.address());
    println!(
        "   ✓ Addresses match: {}",
        wallet.address_string() == restored_wallet.address_string()
    );
    println!();

    // 4. Generate 24-word mnemonic (more secure)
    println!("4. Generating a 24-word mnemonic phrase (higher security)...");
    let mnemonic_24 = generate_mnemonic(24).unwrap();
    println!("   Mnemonic (24 words):");
    println!("   {}", mnemonic_24);
    println!();

    let wallet_24 = Wallet::from_mnemonic(&mnemonic_24, "", NetworkType::Mainnet).unwrap();
    println!("   Wallet Address: {}", wallet_24.address());
    println!();

    // 5. Using a passphrase for additional security
    println!("5. Creating wallet with passphrase (additional security layer)...");
    let passphrase = "my-secure-passphrase";
    let wallet_with_pass =
        Wallet::from_mnemonic(&mnemonic_12, passphrase, NetworkType::Mainnet).unwrap();
    println!("   Wallet with passphrase: {}", wallet_with_pass.address());
    println!("   Wallet without passphrase: {}", wallet.address());
    println!("   ✓ Different addresses (same mnemonic, different passphrase)");
    println!();

    // 6. Demonstrate transaction creation with mnemonic wallet
    println!("6. Creating a transaction with mnemonic-based wallet...");
    let mut sender = Wallet::from_mnemonic(&mnemonic_12, "", NetworkType::Mainnet).unwrap();

    // Add some UTXOs for demonstration
    let utxo = UTXO {
        tx_hash: [1u8; 32],
        output_index: 0,
        amount: 100000,
        address: sender.address_string(),
    };
    sender.add_utxo(utxo);
    println!("   Balance: {} TIME", sender.balance());

    let recipient = Wallet::new(NetworkType::Mainnet).unwrap();
    let tx = sender
        .create_transaction(&recipient.address_string(), 1000, 50)
        .unwrap();

    println!("   Transaction created successfully!");
    println!("   TXID: {}", tx.txid());
    println!("   Outputs: {}", tx.outputs.len());
    println!();

    // 7. Test wallet recovery scenario
    println!("7. Testing wallet recovery scenario...");
    println!("   Original wallet address: {}", wallet.address());
    println!("   Original wallet public key: {}", wallet.public_key_hex());

    // Simulate losing the wallet and recovering it
    println!("   [Simulating wallet loss...]");
    println!("   [Recovering from mnemonic phrase...]");

    let recovered = Wallet::from_mnemonic(&mnemonic_12, "", NetworkType::Mainnet).unwrap();
    println!("   Recovered wallet address: {}", recovered.address());
    println!(
        "   Recovered wallet public key: {}",
        recovered.public_key_hex()
    );

    assert_eq!(wallet.address_string(), recovered.address_string());
    assert_eq!(wallet.public_key(), recovered.public_key());
    assert_eq!(wallet.secret_key(), recovered.secret_key());
    println!("   ✓ Full wallet recovery successful!");
    println!();

    // 8. Summary and best practices
    println!("==========================================");
    println!("  ✓ BIP-39 Mnemonic Features Demonstrated");
    println!("==========================================");
    println!();
    println!("Features:");
    println!("  ✅ Generate 12 or 24-word mnemonic phrases");
    println!("  ✅ Deterministic wallet creation from mnemonic");
    println!("  ✅ Optional passphrase for additional security");
    println!("  ✅ Full wallet recovery from mnemonic");
    println!("  ✅ Compatible with TimeCoin's hot wallet");
    println!();
    println!("Best Practices:");
    println!("  📝 Write down your mnemonic phrase on paper");
    println!("  🔒 Store it in a secure, offline location");
    println!("  ❌ Never store it digitally (no photos, no cloud)");
    println!("  🔑 Use a passphrase for extra security (optional)");
    println!("  ✅ 24 words provide higher security than 12 words");
    println!("  🚫 Never share your mnemonic phrase with anyone");
    println!();
}
