// Test to reproduce the UTXO snapshot issue

use time_core::block::Block;
use time_core::state::BlockchainState;
use time_core::transaction::{Transaction, TxOutput};

fn main() {
    println!("Testing UTXO snapshot persistence issue...\n");

    // Create a temporary database path
    let db_dir = std::env::temp_dir().join(format!(
        "time_coin_snapshot_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let db_path = db_dir.to_str().unwrap().to_string();
    let _ = std::fs::remove_dir_all(&db_path);

    // Create genesis block
    let outputs = vec![TxOutput::new(100_000_000_000, "genesis".to_string())];
    let counts = time_core::block::MasternodeCounts {
        free: 0,
        bronze: 0,
        silver: 0,
        gold: 0,
    };
    let genesis = Block::new(
        0,
        "0".repeat(64),
        "genesis_validator".to_string(),
        outputs,
        &counts,
    );

    // Initialize blockchain state
    let mut state = BlockchainState::new(genesis, &db_path).unwrap();

    println!("Initial state:");
    println!("  Genesis balance: {}", state.get_balance("genesis"));
    println!("  Total UTXOs: {}\n", state.utxo_set().len());

    // Simulate multiple mint transactions being finalized (like in testnet)
    println!("Simulating 3 mint transactions...");

    // Mint 1: Create and apply transaction for address1
    let tx1 = Transaction {
        txid: "mint_tx_1".to_string(),
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(1_000_000, "address1".to_string())],
        lock_time: 0,
        timestamp: chrono::Utc::now().timestamp(),
    };

    state.utxo_set_mut().apply_transaction(&tx1).unwrap();
    println!("  Transaction 1 applied to UTXO set");
    println!("    address1 balance: {}", state.get_balance("address1"));
    println!("    Total UTXOs: {}", state.utxo_set().len());

    // Save snapshot after first transaction
    state.save_utxo_snapshot().unwrap();
    println!("    Snapshot saved\n");

    // Mint 2: Create and apply transaction for address2
    let tx2 = Transaction {
        txid: "mint_tx_2".to_string(),
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(2_000_000, "address2".to_string())],
        lock_time: 0,
        timestamp: chrono::Utc::now().timestamp(),
    };

    state.utxo_set_mut().apply_transaction(&tx2).unwrap();
    println!("  Transaction 2 applied to UTXO set");
    println!("    address2 balance: {}", state.get_balance("address2"));
    println!("    Total UTXOs: {}", state.utxo_set().len());

    // Save snapshot after second transaction
    state.save_utxo_snapshot().unwrap();
    println!("    Snapshot saved\n");

    // Mint 3: Create and apply transaction for address3
    let tx3 = Transaction {
        txid: "mint_tx_3".to_string(),
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(3_000_000, "address3".to_string())],
        lock_time: 0,
        timestamp: chrono::Utc::now().timestamp(),
    };

    state.utxo_set_mut().apply_transaction(&tx3).unwrap();
    println!("  Transaction 3 applied to UTXO set");
    println!("    address3 balance: {}", state.get_balance("address3"));
    println!("    Total UTXOs: {}", state.utxo_set().len());

    // Save snapshot after third transaction
    state.save_utxo_snapshot().unwrap();
    println!("    Snapshot saved\n");

    println!("Before restart:");
    println!("  address1 balance: {}", state.get_balance("address1"));
    println!("  address2 balance: {}", state.get_balance("address2"));
    println!("  address3 balance: {}", state.get_balance("address3"));
    println!("  genesis balance: {}", state.get_balance("genesis"));
    println!("  Total UTXOs: {}\n", state.utxo_set().len());

    // Drop state to simulate restart
    drop(state);

    println!("Simulating node restart...\n");

    // Recreate state (simulating restart)
    let outputs = vec![TxOutput::new(100_000_000_000, "genesis".to_string())];
    let counts = time_core::block::MasternodeCounts {
        free: 0,
        bronze: 0,
        silver: 0,
        gold: 0,
    };
    let genesis = Block::new(
        0,
        "0".repeat(64),
        "genesis_validator".to_string(),
        outputs,
        &counts,
    );
    let state = BlockchainState::new(genesis, &db_path).unwrap();

    println!("After restart:");
    println!("  address1 balance: {}", state.get_balance("address1"));
    println!("  address2 balance: {}", state.get_balance("address2"));
    println!("  address3 balance: {}", state.get_balance("address3"));
    println!("  genesis balance: {}", state.get_balance("genesis"));
    println!("  Total UTXOs: {}\n", state.utxo_set().len());

    // Check if all transactions persisted
    if state.get_balance("address1") == 1_000_000
        && state.get_balance("address2") == 2_000_000
        && state.get_balance("address3") == 3_000_000
    {
        println!("✅ TEST PASSED: All transactions persisted correctly!");
    } else {
        println!("❌ TEST FAILED: Some transactions were lost after restart!");
        println!("   Expected: address1=1000000, address2=2000000, address3=3000000");
        println!(
            "   Got: address1={}, address2={}, address3={}",
            state.get_balance("address1"),
            state.get_balance("address2"),
            state.get_balance("address3")
        );
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&db_path);
}
