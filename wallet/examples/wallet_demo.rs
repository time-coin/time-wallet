//! Improved wallet demonstration
//! Run with: cargo run --example wallet_demo

use wallet::{NetworkType, Wallet, UTXO};

fn main() {
    println!("========================================");
    println!("  TIME Coin Wallet - Improved Demo");
    println!("========================================\n");

    // 1. Create wallet with NetworkType enum
    println!("1. Creating wallet with NetworkType::Mainnet...");
    let mut sender = Wallet::new(NetworkType::Mainnet).unwrap();
    println!("   Address: {}", sender.address());
    println!("   Network: {:?}", sender.network());
    println!();

    // 2. Export/import private key
    println!("2. Testing key export/import...");
    let private_key = sender.export_private_key();
    println!("   Private key: {}...", &private_key[..16]);

    let restored = Wallet::from_private_key_hex(&private_key, NetworkType::Mainnet).unwrap();
    println!("   Restored address: {}", restored.address());
    assert_eq!(sender.address_string(), restored.address_string());
    println!("   ✓ Export/import works!");
    println!();

    // 3. Add UTXO
    println!("3. Adding UTXO to wallet...");
    let utxo = UTXO {
        tx_hash: [1u8; 32],
        output_index: 0,
        amount: 100000,
        address: sender.address_string(),
    };
    sender.add_utxo(utxo);
    println!("   Balance: {} TIME", sender.balance());
    println!();

    // 4. Create transaction WITH FEE
    println!("4. Creating transaction with fee...");
    let recipient = Wallet::new(NetworkType::Mainnet).unwrap();
    println!("   Recipient: {}", recipient.address());

    let amount = 1000;
    let fee = 50;
    println!("   Sending {} TIME with {} TIME fee", amount, fee);

    let tx = sender
        .create_transaction(&recipient.address_string(), amount, fee)
        .unwrap();

    println!("   Transaction created!");
    println!("   TXID: {}", tx.txid());
    println!("   Inputs: {}", tx.inputs.len());
    println!("   Outputs: {}", tx.outputs.len());
    println!(
        "   Output amounts: {:?}",
        tx.outputs.iter().map(|o| o.value).collect::<Vec<_>>()
    );
    println!();

    // 5. Check wallet state
    println!("5. Checking wallet state after transaction...");
    println!("   New nonce: {} (auto-incremented!)", sender.nonce());
    println!();

    // 6. Test insufficient funds with clear error
    println!("6. Testing insufficient funds error...");
    let result = sender.create_transaction(&recipient.address_string(), 200000, 100);

    match result {
        Err(e) => println!("   ✓ Got expected error: {}", e),
        Ok(_) => println!("   ✗ Should have failed!"),
    }
    println!();

    // 7. Save wallet
    println!("7. Saving wallet...");
    let path = "/tmp/time_wallet_improved.json";
    sender.save_to_file(path).unwrap();
    println!("   Saved to: {}", path);
    println!();

    println!("========================================");
    println!("  ✓ All improvements working!");
    println!("========================================");
    println!();
    println!("Improvements added:");
    println!("  ✅ Fee support in transactions");
    println!("  ✅ NetworkType enum (no more bool)");
    println!("  ✅ thiserror for better errors");
    println!("  ✅ Auto-incrementing nonce");
    println!("  ✅ Private key export/import");
    println!();

    // Cleanup
    std::fs::remove_file(path).ok();
}
