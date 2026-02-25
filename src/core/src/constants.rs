//! TIME Coin Protocol Constants

use std::time::Duration;

// Block Constants
pub const BLOCK_TIME: Duration = Duration::from_secs(86400); // 24 hours
pub const BLOCK_REWARD: u64 = 100 * COIN; // 100 TIME per block
pub const MASTERNODE_REWARD: u64 = 95 * COIN; // 95 TIME to masternodes
pub const TREASURY_REWARD: u64 = 5 * COIN; // 5 TIME to treasury

// Timestamp Validation (SECURITY)
pub const MAX_FUTURE_DRIFT_SECS: i64 = 300; // 5 minutes - blocks can't be too far in future
pub const MAX_PAST_DRIFT_SECS: i64 = 7200; // 2 hours - blocks can't be too far in past

// Transaction Constants
pub const MAX_TRANSACTION_SIZE: usize = 100_000; // 100 KB
pub const MIN_TRANSACTION_FEE: u64 = 1000; // 0.00001 TIME
pub const TRANSACTION_FINALITY_TIME: Duration = Duration::from_secs(3); // 3 seconds

// Coin Constants
pub const COIN: u64 = 100_000_000; // 1 TIME = 100 million satoshis
pub const MAX_SUPPLY: u64 = 1_000_000_000 * COIN; // 1 billion TIME

// Network Constants
pub const MIN_MASTERNODE_COLLATERAL: u64 = 1_000 * COIN; // Bronze tier
pub const DEFAULT_PORT: u16 = 9876;
pub const MAX_PEERS: usize = 125;
pub const MAINNET_P2P_PORT: u16 = 24000;
pub const TESTNET_P2P_PORT: u16 = 24100;

// Consensus Constants
pub const BFT_THRESHOLD: f64 = 0.67; // 67% for Byzantine Fault Tolerance
pub const MIN_VALIDATORS: usize = 3; // Minimum for BFT consensus (tolerates 0 Byzantine failures)
pub const MAX_VALIDATORS: usize = 10_000;
pub const CONSENSUS_TIMEOUT_SECS: u64 = 30;

// Treasury Constants
pub const TREASURY_MULTISIG_THRESHOLD: usize = 670; // 67% of masternodes
pub const MIN_PROPOSAL_AMOUNT: u64 = 100 * COIN;
pub const PROPOSAL_VOTING_PERIOD: Duration = Duration::from_secs(86400 * 14); // 14 days

// Rate Limiting (SECURITY)
pub const MAX_REQUESTS_PER_MINUTE: u32 = 60;
pub const MAX_BYTES_PER_MINUTE: u64 = 1_000_000; // 1MB
