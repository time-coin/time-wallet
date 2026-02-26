//! Core blockchain components for TIME Coin

pub mod block;
pub mod chain_selection;
pub mod checkpoint;
pub mod constants;
pub mod db;
pub mod finalizer;
pub mod masternode_tx;
pub mod masternode_uptime;
pub mod mempool;
pub mod merkle;
pub mod snapshot;
pub mod snapshot_service;
pub mod state;
pub mod time_validator;
pub mod transaction;
pub mod treasury_manager;
pub mod utxo_disk_backed;
pub mod utxo_locker;
pub mod utxo_set;
pub mod utxo_state_manager; // UTXO State Protocol for instant finality
pub mod vdf;
pub mod vdf_integration;

// Re-export commonly used types
pub use block::{
    calculate_masternode_share, calculate_total_masternode_reward, calculate_treasury_allocation,
    create_treasury_grant_transaction, Block, BlockHeader, MasternodeCounts, MasternodeTier,
    TREASURY_PERCENTAGE,
};
pub use chain_selection::{
    calculate_cumulative_work, find_fork_point, is_reorg_safe, select_best_chain,
    validate_chain_vdf_proofs, ChainError, ChainSelection, ForkInfo,
};
pub use masternode_uptime::MasternodeUptimeTracker;
pub use merkle::{calculate_utxo_merkle_root, MerkleProof, MerkleTree};
pub use time_validator::{
    current_timestamp, CatchUpInfo, TimeValidationError, TimeValidator, GENESIS_TIMESTAMP,
    MAINNET_BLOCK_TIME_SECONDS, TESTNET_BLOCK_TIME_SECONDS,
};
pub use transaction::{
    OutPoint, SpecialTransaction, Transaction, TransactionError, TxInput, TxOutput,
};
pub use utxo_locker::{CoinSelector, UTXOLocker, UTXOLockerError, UTXOStateUpdate};
pub use utxo_set::{UTXOSet, UTXOSetSnapshot};
pub use utxo_state_manager::{UTXOState, UTXOStateManager};
pub use vdf::{compute_vdf, generate_vdf_input, verify_vdf, VDFError, VDFProof};
pub use vdf_integration::{can_create_block, compute_block_vdf, validate_block_vdf, VDFConfig};

// Note: Mempool and BlockchainState will be re-exported once they're properly defined
// pub use mempool::{Mempool, MempoolError, MempoolStats};
pub use state::{
    BlockchainState, ChainStats, MasternodeInfo, StateError, Treasury, TreasuryAllocation,
    TreasurySource, TreasuryStats, TreasuryWithdrawal,
};
