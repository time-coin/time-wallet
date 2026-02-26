//! Test for UTXO snapshot persistence bug
//!
//! This test reproduces the issue where UTXOs from blocks added after snapshot
//! are lost when the snapshot is restored, because restore() replaces instead of merges.

use time_core::block::{Block, MasternodeCounts, MasternodeTier};
use time_core::state::BlockchainState;
use time_core::transaction::{Transaction, TxOutput};

/// Test the bug: block finalized after snapshot causes UTXO loss on restart
#[test]
fn test_block_after_snapshot_causes_utxo_loss() {
    let db_dir = std::env::temp_dir().join(format!(
        "time_coin_snapshot_bug_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let db_path = db_dir.to_str().unwrap().to_string();
    let _ = std::fs::remove_dir_all(&db_path);

    // Create a fixed genesis block (same instance will be serialized/deserialized)
    let outputs = vec![TxOutput::new(100_000_000_000, "genesis".to_string())];
    let counts = MasternodeCounts {
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
    let genesis_hash = genesis.hash.clone();

    let expected_finalized_balance: u64;
    let expected_block_balance: u64;

    // Phase 1: Initialize, add finalized transactions, save snapshot
    {
        let mut state = BlockchainState::new(genesis.clone(), &db_path).unwrap();

        // Finalize a transaction (not in a block yet)
        let tx1 = Transaction {
            txid: "finalized_tx_1".to_string(),
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput::new(1_000_000, "finalized_address".to_string())],
            lock_time: 0,
            timestamp: chrono::Utc::now().timestamp(),
        };
        state.utxo_set_mut().apply_transaction(&tx1).unwrap();
        expected_finalized_balance = 1_000_000;

        // Save snapshot (contains genesis + finalized tx)
        state.save_utxo_snapshot().unwrap();
        println!("✅ Phase 1: Snapshot saved with genesis + finalized tx");
        println!("   UTXOs in snapshot: {}", state.utxo_set().len());
        println!(
            "   finalized_address: {}",
            state.get_balance("finalized_address")
        );
    }

    // Phase 2: Add a block (simulating daily block finalization AFTER snapshot)
    {
        let mut state = BlockchainState::new(genesis.clone(), &db_path).unwrap();

        // Register a masternode
        state
            .register_masternode(
                "node1".to_string(),
                MasternodeTier::Free,
                "collateral1".to_string(),
                "miner1".to_string(),
            )
            .unwrap();

        // Add block 1 (simulating daily block finalization)
        let counts = MasternodeCounts {
            free: 1,
            bronze: 0,
            silver: 0,
            gold: 0,
        };
        let base_reward = time_core::block::calculate_total_masternode_reward(&counts);
        let treasury_allocation = time_core::block::calculate_treasury_allocation(base_reward);
        let masternode_share = time_core::block::calculate_masternode_share(base_reward);
        expected_block_balance = masternode_share;

        let block_outputs = vec![
            TxOutput::new(treasury_allocation, "TREASURY".to_string()),
            TxOutput::new(masternode_share, "block_miner".to_string()),
        ];
        let block1 = Block::new(
            1,
            genesis_hash.clone(),
            "miner1".to_string(),
            block_outputs,
            &counts,
        );
        state.add_block(block1).unwrap();

        println!("\n✅ Phase 2: Block 1 added with payment to block_miner");
        println!(
            "   block_miner balance: {}",
            state.get_balance("block_miner")
        );
        println!(
            "   finalized_address balance: {}",
            state.get_balance("finalized_address")
        );
        println!("   Total UTXOs: {}", state.utxo_set().len());

        // Node crashes before saving another snapshot!
        // So the snapshot on disk is still the old one (genesis + finalized tx)
        // But the blockchain on disk now has block 1
    }

    // Phase 3: Restart - THIS IS WHERE THE BUG OCCURS
    {
        let state = BlockchainState::new(genesis.clone(), &db_path).unwrap();

        println!("\n📋 Phase 3: After restart:");
        println!(
            "   block_miner balance: {}",
            state.get_balance("block_miner")
        );
        println!(
            "   finalized_address balance: {}",
            state.get_balance("finalized_address")
        );
        println!("   Total UTXOs: {}", state.utxo_set().len());

        // What should happen with the FIX:
        // 1. Blocks loaded: genesis + block 1 → UTXOs: [genesis, treasury, block_miner]
        // 2. Snapshot merged (not replaced): adds [finalized_address] → UTXOs: [genesis, treasury, block_miner, finalized_address]
        // 3. Result: ALL UTXOs are preserved!

        let block_balance = state.get_balance("block_miner");
        let finalized_balance = state.get_balance("finalized_address");

        println!("\n🔍 Bug Detection:");
        println!(
            "   Expected block_miner balance: {}",
            expected_block_balance
        );
        println!("   Actual block_miner balance: {}", block_balance);
        println!(
            "   Expected finalized_address balance: {}",
            expected_finalized_balance
        );
        println!("   Actual finalized_address balance: {}", finalized_balance);

        if block_balance == 0 && finalized_balance > 0 {
            println!("\n❌ BUG REPRODUCED: Block UTXOs were lost when snapshot was restored!");
            println!("   The snapshot REPLACED the UTXOs from blocks instead of MERGING.");
            panic!("Bug confirmed: snapshot replaces block UTXOs instead of merging");
        } else if block_balance > 0 && finalized_balance > 0 {
            println!("\n✅ Bug is FIXED: Both block and finalized UTXOs are present!");
            assert_eq!(
                block_balance, expected_block_balance,
                "Block balance should be correct"
            );
            assert_eq!(
                finalized_balance, expected_finalized_balance,
                "Finalized balance should be correct"
            );
        } else {
            panic!(
                "Unexpected state: block_balance={}, finalized_balance={}",
                block_balance, finalized_balance
            );
        }
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&db_path);
}
