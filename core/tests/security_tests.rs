//! Security Integration Tests
//!
//! Comprehensive tests for critical security features implemented in
//! the security hardening phase.

use std::collections::HashMap;
use time_core::{OutPoint, Transaction, TxInput, TxOutput};

/// Test that unsigned transactions are rejected
#[test]
fn test_reject_unsigned_transaction() {
    // Create a transaction with empty signature
    let input = TxInput {
        previous_output: OutPoint::new("prev_tx".to_string(), 0),
        public_key: vec![0u8; 32],
        signature: vec![], // Empty signature - should be rejected
        sequence: 0xFFFFFFFF,
    };

    let output = TxOutput::new(1000, "TIME1test".to_string());

    let tx = Transaction::new(vec![input], vec![output]);

    // Should fail structure validation
    let utxo_set = HashMap::new();
    let result = tx.verify_signatures(&utxo_set);
    assert!(
        result.is_err(),
        "Should reject transaction with empty signature"
    );
}

/// Test that forged transactions with wrong signature are rejected
#[test]
fn test_reject_forged_transaction() {
    // Create a transaction with invalid signature
    let input = TxInput {
        previous_output: OutPoint::new("prev_tx".to_string(), 0),
        public_key: vec![0u8; 32],
        signature: vec![0u8; 64], // Invalid signature
        sequence: 0xFFFFFFFF,
    };

    let output = TxOutput::new(1000, "TIME1test".to_string());

    let tx = Transaction::new(vec![input], vec![output]);

    // Create dummy UTXO set
    let mut utxo_set = HashMap::new();
    utxo_set.insert(
        OutPoint::new("prev_tx".to_string(), 0),
        TxOutput::new(1000, "TIME1test".to_string()),
    );

    let result = tx.verify_signatures(&utxo_set);
    assert!(
        result.is_err(),
        "Should reject transaction with invalid signature"
    );
}

/// Test timestamp validation - future timestamps rejected
#[test]
fn test_reject_future_timestamp() {
    use chrono::{Duration, Utc};
    use time_core::block::{Block, BlockHeader, MasternodeCounts};

    // Create block with timestamp 10 minutes in future
    let future_time = Utc::now() + Duration::minutes(10);

    let header = BlockHeader {
        block_number: 1,
        timestamp: future_time,
        previous_hash: "0".repeat(64),
        merkle_root: "0".repeat(64),
        validator_signature: "test".to_string(),
        validator_address: "TIME1test".to_string(),
        masternode_counts: MasternodeCounts {
            free: 0,
            bronze: 0,
            silver: 0,
            gold: 0,
        },
        proof_of_time: None,
        checkpoints: vec![],
    };

    let coinbase = Transaction {
        txid: "coinbase_1".to_string(),
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(1000, "TIME1test".to_string())],
        lock_time: 0,
        timestamp: future_time.timestamp(),
    };

    let block = Block {
        header,
        transactions: vec![coinbase],
        hash: "test_hash".to_string(),
    };

    // Should reject block with future timestamp (even when allowing historical)
    let result = block.validate_timestamp(None, false);
    assert!(
        result.is_err(),
        "Should reject block with far-future timestamp"
    );
}

/// Test timestamp validation - past timestamps rejected
#[test]
fn test_reject_old_timestamp() {
    use chrono::{Duration, Utc};
    use time_core::block::{Block, BlockHeader, MasternodeCounts};

    // Create block with timestamp 3 hours in past (exceeds 2-hour limit)
    let past_time = Utc::now() - Duration::hours(3);

    let header = BlockHeader {
        block_number: 1,
        timestamp: past_time,
        previous_hash: "0".repeat(64),
        merkle_root: "0".repeat(64),
        validator_signature: "test".to_string(),
        validator_address: "TIME1test".to_string(),
        masternode_counts: MasternodeCounts {
            free: 0,
            bronze: 0,
            silver: 0,
            gold: 0,
        },
        proof_of_time: None,
        checkpoints: vec![],
    };

    let coinbase = Transaction {
        txid: "coinbase_1".to_string(),
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(1000, "TIME1test".to_string())],
        lock_time: 0,
        timestamp: past_time.timestamp(),
    };

    let block = Block {
        header,
        transactions: vec![coinbase],
        hash: "test_hash".to_string(),
    };

    // Should reject block with old timestamp (when not allowing historical)
    let result = block.validate_timestamp(None, false);
    assert!(result.is_err(), "Should reject block with old timestamp");

    // But should accept when allowing historical blocks
    let result_historical = block.validate_timestamp(None, true);
    assert!(
        result_historical.is_ok(),
        "Should accept old block when allow_historical=true"
    );
}

/// Test timestamp validation - monotonic increase required
#[test]
fn test_reject_nonmonotonic_timestamp() {
    use chrono::Utc;
    use time_core::block::{Block, BlockHeader, MasternodeCounts};

    let now = Utc::now();

    let header = BlockHeader {
        block_number: 2,
        timestamp: now,
        previous_hash: "0".repeat(64),
        merkle_root: "0".repeat(64),
        validator_signature: "test".to_string(),
        validator_address: "TIME1test".to_string(),
        masternode_counts: MasternodeCounts {
            free: 0,
            bronze: 0,
            silver: 0,
            gold: 0,
        },
        proof_of_time: None,
        checkpoints: vec![],
    };

    let coinbase = Transaction {
        txid: "coinbase_2".to_string(),
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(1000, "TIME1test".to_string())],
        lock_time: 0,
        timestamp: now.timestamp(),
    };

    let block = Block {
        header,
        transactions: vec![coinbase],
        hash: "test_hash".to_string(),
    };

    // Previous block has same or later timestamp
    let prev_timestamp = now.timestamp();

    let result = block.validate_timestamp(Some(prev_timestamp), false);
    assert!(
        result.is_err(),
        "Should reject block with non-increasing timestamp"
    );
}

/// Test block structure validation - merkle root
#[test]
fn test_reject_invalid_merkle_root() {
    use chrono::Utc;
    use time_core::block::{Block, BlockHeader, MasternodeCounts};

    let header = BlockHeader {
        block_number: 1,
        timestamp: Utc::now(),
        previous_hash: "0".repeat(64),
        merkle_root: "invalid_merkle".to_string(), // Wrong merkle root
        validator_signature: "test".to_string(),
        validator_address: "TIME1test".to_string(),
        masternode_counts: MasternodeCounts {
            free: 0,
            bronze: 0,
            silver: 0,
            gold: 0,
        },
        proof_of_time: None,
        checkpoints: vec![],
    };

    let coinbase = Transaction {
        txid: "coinbase_1".to_string(),
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(1000, "TIME1test".to_string())],
        lock_time: 0,
        timestamp: Utc::now().timestamp(),
    };

    let mut block = Block {
        header,
        transactions: vec![coinbase],
        hash: String::new(),
    };

    // Calculate proper hash
    block.hash = block.calculate_hash();

    // Should reject due to invalid merkle root
    let result = block.validate_structure();
    assert!(
        result.is_err(),
        "Should reject block with invalid merkle root"
    );
}

/// Test coinbase validation - must be first transaction
#[test]
fn test_reject_misplaced_coinbase() {
    use chrono::Utc;
    use time_core::block::{Block, BlockHeader, MasternodeCounts};

    let coinbase = Transaction {
        txid: "coinbase_1".to_string(),
        version: 1,
        inputs: vec![], // Coinbase has no inputs
        outputs: vec![TxOutput::new(1000, "TIME1test".to_string())],
        lock_time: 0,
        timestamp: Utc::now().timestamp(),
    };

    let regular_tx = Transaction {
        txid: "tx_1".to_string(),
        version: 1,
        inputs: vec![TxInput {
            previous_output: OutPoint::new("prev".to_string(), 0),
            public_key: vec![0u8; 32],
            signature: vec![0u8; 64],
            sequence: 0xFFFFFFFF,
        }],
        outputs: vec![TxOutput::new(500, "TIME1test".to_string())],
        lock_time: 0,
        timestamp: Utc::now().timestamp(),
    };

    let header = BlockHeader {
        block_number: 1,
        timestamp: Utc::now(),
        previous_hash: "0".repeat(64),
        merkle_root: "0".repeat(64),
        validator_signature: "test".to_string(),
        validator_address: "TIME1test".to_string(),
        masternode_counts: MasternodeCounts {
            free: 0,
            bronze: 0,
            silver: 0,
            gold: 0,
        },
        proof_of_time: None,
        checkpoints: vec![],
    };

    // Put coinbase as second transaction (wrong!)
    let mut block = Block {
        header,
        transactions: vec![regular_tx, coinbase],
        hash: String::new(),
    };

    block.hash = block.calculate_hash();

    // Should reject - first transaction must be coinbase
    let result = block.validate_structure();
    assert!(
        result.is_err(),
        "Should reject block with coinbase not as first transaction"
    );
}
