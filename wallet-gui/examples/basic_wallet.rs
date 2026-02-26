//! Example: Create and use a TIME Coin wallet programmatically
//!
//! This example shows how to use the wallet components without the GUI.
//! Run with: cargo run --example basic_wallet

use wallet::{NetworkType, Wallet, UTXO};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TIME Coin Wallet Example ===\n");

    // 1. Create a new wallet
    println!("Creating new wallet...");
    let mut alice = Wallet::new(NetworkType::Testnet)?;
    println!("Alice's address: {}", alice.address_string());
    println!("Alice's public key: {}\n", alice.public_key_hex());

    // 2. Create another wallet (recipient)
    println!("Creating recipient wallet...");
    let bob = Wallet::new(NetworkType::Testnet)?;
    println!("Bob's address: {}\n", bob.address_string());

    // 3. Add funds to Alice's wallet (simulate receiving coins)
    println!("Adding funds to Alice's wallet...");
    let utxo = UTXO {
        tx_hash: [1u8; 32],
        output_index: 0,
        amount: 10000,
        address: alice.address_string(),
    };
    alice.add_utxo(utxo);
    println!("Alice's balance: {} TIME\n", alice.balance());

    // 4. Create a transaction from Alice to Bob
    println!("Creating transaction: Alice -> Bob");
    let amount = 2500;
    let fee = 10;
    let tx = alice.create_transaction(&bob.address_string(), amount, fee)?;

    println!("Transaction created!");
    println!("  Inputs: {}", tx.inputs.len());
    println!("  Outputs: {}", tx.outputs.len());
    println!("  Amount sent: {} TIME", amount);
    println!("  Fee: {} TIME", fee);
    println!(
        "  Change: {} TIME\n",
        tx.outputs.get(1).map(|o| o.amount).unwrap_or(0)
    );

    // 5. Export and import private key
    println!("Exporting Alice's private key...");
    let private_key = alice.export_private_key();
    println!("Private key (hex): {}...\n", &private_key[..16]);

    println!("Importing private key to create Alice2...");
    let alice2 = Wallet::from_private_key_hex(&private_key, NetworkType::Testnet)?;
    println!("Alice2's address: {}", alice2.address_string());
    println!(
        "Addresses match: {}\n",
        alice.address_string() == alice2.address_string()
    );

    // 6. Save wallet to file
    println!("Saving Alice's wallet to file...");
    let wallet_path = "/tmp/alice_wallet.json";
    alice.save_to_file(wallet_path)?;
    println!("Wallet saved to: {}\n", wallet_path);

    // 7. Load wallet from file
    println!("Loading wallet from file...");
    let loaded_wallet = Wallet::load_from_file(wallet_path)?;
    println!("Loaded address: {}", loaded_wallet.address_string());
    println!(
        "Addresses match: {}\n",
        alice.address_string() == loaded_wallet.address_string()
    );

    println!("=== Example completed successfully! ===");

    Ok(())
}
