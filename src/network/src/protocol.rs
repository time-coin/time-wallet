//! Network protocol for peer communication
//!
//! Handles handshakes, version exchange, and peer identification

use crate::discovery::NetworkType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub timestamp: u64,
    pub block_height: u64,
    pub confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: u64,
    pub block_height: Option<u64>,
    pub confirmations: u64,
}

/// Current TIME Coin version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Git information (set at build time)
pub const GIT_HASH: &str = env!("GIT_HASH");
pub const GIT_BRANCH: &str = env!("GIT_BRANCH");
pub const GIT_COMMIT_DATE: &str = env!("GIT_COMMIT_DATE");
pub const GIT_COMMIT_COUNT: &str = env!("GIT_COMMIT_COUNT");

/// Build information (set at build time)
pub const BUILD_TIMESTAMP: &str = env!("BUILD_TIMESTAMP");
pub const GIT_MESSAGE: &str = env!("GIT_MESSAGE");

/// Get full version with git hash
pub fn full_version() -> String {
    // Try to get current git hash at runtime for freshness
    let runtime_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        });

    let hash = runtime_hash.unwrap_or_else(|| GIT_HASH.to_string());
    format!("{}-{}", VERSION, hash)
}

/// Get version with complete build information
pub fn version_with_build_info() -> String {
    format!(
        "v{} | Branch: {} | Committed: {} | Commits: {}",
        full_version(),
        GIT_BRANCH,
        GIT_COMMIT_DATE,
        GIT_COMMIT_COUNT
    )
}

/// Get detailed build information
pub fn build_info_detailed() -> String {
    format!(
        "Version:        {}\n\
         Git Branch:    {}\n\
         Git Commit:    {} (#{})\n\
         Commit Date:   {}\n\
         Message:       {}",
        full_version(),
        GIT_BRANCH,
        GIT_HASH,
        GIT_COMMIT_COUNT,
        GIT_COMMIT_DATE,
        GIT_MESSAGE
    )
}

/// Get version for API/handshake (without build time for deterministic responses)
pub fn version_for_handshake() -> String {
    full_version()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    pub git_hash: String,
    pub git_branch: String,
    pub commit_date: String,
    pub git_commit_count: u64,
}

impl BuildInfo {
    /// Create build info from compile-time constants
    pub fn current() -> Self {
        BuildInfo {
            version: full_version(),
            git_hash: GIT_HASH.to_string(),
            git_branch: GIT_BRANCH.to_string(),
            commit_date: GIT_COMMIT_DATE.to_string(),
            git_commit_count: GIT_COMMIT_COUNT.parse().unwrap_or(0),
        }
    }
}

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

/// Magic bytes for network message identification (inspired by Bitcoin)
/// These 4-byte sequences appear at the start of every network message
/// to help nodes synchronize and identify valid messages in the data stream
pub mod magic_bytes {
    /// Mainnet magic bytes: 0xC01D7E4D ("COLD TIME" mnemonic - C0 1D 7E 4D)
    /// Represents the frozen time concept of 24-hour blocks
    pub const MAINNET: [u8; 4] = [0xC0, 0x1D, 0x7E, 0x4D];

    /// Testnet magic bytes: 0x7E577E4D ("TEST TIME" mnemonic - 7E 57 7E 4D)
    /// Distinct from mainnet to prevent accidental cross-network messages
    pub const TESTNET: [u8; 4] = [0x7E, 0x57, 0x7E, 0x4D];
}

impl crate::discovery::NetworkType {
    /// Get the magic bytes for this network type
    pub fn magic_bytes(&self) -> [u8; 4] {
        match self {
            crate::discovery::NetworkType::Mainnet => magic_bytes::MAINNET,
            crate::discovery::NetworkType::Testnet => magic_bytes::TESTNET,
        }
    }
}

/// Handshake message sent when connecting to peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// Software version (e.g., "0.1.0-9569fe2")
    pub version: String,

    /// Git commit date (e.g., "2025-11-07T15:09:21Z")
    #[serde(default)]
    pub commit_date: Option<String>,

    /// Git commit count
    #[serde(default)]
    pub commit_count: Option<String>,

    /// Protocol version for compatibility
    pub protocol_version: u32,

    /// Network type (Mainnet or Testnet)
    pub network: NetworkType,

    /// Peer's listening address
    pub listen_addr: SocketAddr,

    /// Timestamp of connection
    pub timestamp: u64,

    /// Node capabilities (future use)
    pub capabilities: Vec<String>,

    /// Wallet address for masternode rewards
    #[serde(default)]
    pub wallet_address: Option<String>,

    /// Genesis block hash for chain validation
    #[serde(default)]
    pub genesis_hash: Option<String>,
}

impl HandshakeMessage {
    /// Create a new handshake message with optional wallet
    pub fn new(network: NetworkType, listen_addr: SocketAddr) -> Self {
        Self::new_with_genesis(network, listen_addr, None)
    }

    /// Create a new handshake message with genesis hash
    pub fn new_with_genesis(
        network: NetworkType,
        listen_addr: SocketAddr,
        genesis_hash: Option<String>,
    ) -> Self {
        let wallet_address = std::env::var("MASTERNODE_WALLET").ok();

        HandshakeMessage {
            version: version_for_handshake(),
            commit_date: Some(GIT_COMMIT_DATE.to_string()),
            commit_count: Some(GIT_COMMIT_COUNT.to_string()),
            protocol_version: PROTOCOL_VERSION,
            network,
            listen_addr,
            timestamp: current_timestamp(),
            capabilities: vec!["masternode".to_string(), "sync".to_string()],
            wallet_address,
            genesis_hash,
        }
    }

    /// Validate handshake from peer
    pub fn validate(&self, expected_network: &NetworkType) -> Result<(), String> {
        if &self.network != expected_network {
            return Err(format!(
                "Network mismatch: expected {:?}, got {:?}",
                expected_network, self.network
            ));
        }

        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "Protocol version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, self.protocol_version
            ));
        }

        Ok(())
    }

    /// Validate handshake with genesis block verification
    pub fn validate_with_genesis(
        &self,
        expected_network: &NetworkType,
        expected_genesis_hash: Option<&str>,
    ) -> Result<(), String> {
        // First perform standard validation
        self.validate(expected_network)?;

        // Then validate genesis block if both sides provide it
        if let (Some(their_genesis), Some(our_genesis)) =
            (&self.genesis_hash, expected_genesis_hash)
        {
            if their_genesis != our_genesis {
                return Err(format!(
                    "Genesis block mismatch: expected {}..., got {}...",
                    &our_genesis[..16],
                    &their_genesis[..16]
                ));
            }
        }

        Ok(())
    }

    /// Check if versions are compatible
    pub fn is_compatible(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

/// Protocol version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub software_version: String,
    pub commit_date: Option<String>,
    pub protocol_version: u32,
}

impl ProtocolVersion {
    pub fn current() -> Self {
        ProtocolVersion {
            software_version: VERSION.to_string(),
            commit_date: Some(GIT_COMMIT_DATE.to_string()),
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Check if a peer version is outdated
/// Takes peer_version and returns true if versions differ
pub fn is_version_outdated(peer_version: &str) -> bool {
    is_version_outdated_with_build(peer_version, None)
}

/// Check if a peer version is outdated with optional build timestamp
pub fn is_version_outdated_with_build(peer_version: &str, peer_build: Option<&str>) -> bool {
    if peer_version == "unknown" {
        return false;
    }

    let current_hash = GIT_HASH;
    let peer_hash = peer_version.split('-').next_back().unwrap_or("");

    // Different git commits mean different versions
    if current_hash != peer_hash && !peer_hash.is_empty() {
        return true;
    }

    // Same commit - check build time if available
    if let Some(_peer_build_str) = peer_build {
        // Same commit and similar build times = not outdated
        // Different build times from same commit = may indicate different builds
        // For now, same commit = compatible
        return false;
    }

    false
}

/// Get a detailed version mismatch message
pub fn version_mismatch_message_detailed(
    peer_addr: &str,
    peer_version: &str,
    peer_build: Option<&str>,
) -> String {
    match peer_build {
        Some(build_str) => format!(
            "⚠️  Peer {} is running v{} (committed: {}). \
             You are running {} (committed: {}). \
             Please ensure versions match!",
            peer_addr,
            peer_version,
            build_str,
            full_version(),
            GIT_COMMIT_DATE
        ),
        None => format!(
            "⚠️  Peer {} is running version {} (current: {}). Please update!",
            peer_addr,
            peer_version,
            full_version()
        ),
    }
}

/// Get a user-friendly version mismatch message (backward compatible)
pub fn version_mismatch_message(peer_addr: &str, peer_version: &str) -> String {
    version_mismatch_message_detailed(peer_addr, peer_version, None)
}

// ═══════════════════════════════════════════════════════════════
// VERSION COMPARISON AND UPDATE DETECTION
// ═══════════════════════════════════════════════════════════════

/// Compare two timestamps in ISO 8601 format and return true if remote is newer
pub fn is_remote_version_newer(local_timestamp: &str, remote_timestamp: &str) -> bool {
    use chrono::DateTime;

    // Parse ISO 8601 format (e.g., "2025-11-07T15:09:21Z")
    let local_dt = DateTime::parse_from_rfc3339(local_timestamp).ok();
    let remote_dt = DateTime::parse_from_rfc3339(remote_timestamp).ok();

    match (local_dt, remote_dt) {
        (Some(local), Some(remote)) => remote > local,
        _ => false,
    }
}

/// Compare two git commit counts and return true if remote is newer
pub fn is_remote_commit_newer(local_count: &str, remote_count: &str) -> bool {
    let local: u64 = local_count.parse().unwrap_or(0);
    let remote: u64 = remote_count.parse().unwrap_or(0);
    remote > local
}

/// Get a detailed version comparison message
pub fn version_update_warning(
    peer_addr: &str,
    peer_version: &str,
    peer_commit_date: &str,
    peer_commit_count: &str,
) -> String {
    format!(
        "⚠️  Update available: Peer {} running {} (commit #{}, {}). Your version: {} (commit #{}, {}). Run: git pull && cargo build --release",
        peer_addr,
        peer_version,
        peer_commit_count,
        peer_commit_date,
        full_version(),
        GIT_COMMIT_COUNT,
        GIT_COMMIT_DATE
    )
}

/// Check if we should warn about version mismatch (only warn for newer versions)
pub fn should_warn_version_update(
    peer_build: Option<&str>,
    peer_commit_count: Option<&str>,
) -> bool {
    // First check commit counts - this is the primary version indicator
    if let Some(peer_commits) = peer_commit_count {
        if is_remote_commit_newer(GIT_COMMIT_COUNT, peer_commits) {
            return true;
        }
        // If peer has same or older commit count, no update needed
        if peer_commits == GIT_COMMIT_COUNT {
            return false;
        }
    }

    // Only check commit date if commit count is unavailable or older
    if let Some(peer_commit_date) = peer_build {
        if is_remote_version_newer(GIT_COMMIT_DATE, peer_commit_date) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_creation() {
        let addr = "127.0.0.1:24100".parse().unwrap();
        let handshake = HandshakeMessage::new(NetworkType::Testnet, addr);

        assert_eq!(handshake.version, full_version());
        assert_eq!(handshake.protocol_version, PROTOCOL_VERSION);
        assert_eq!(handshake.network, NetworkType::Testnet);
        assert!(handshake.commit_date.is_some());
    }

    #[test]
    fn test_handshake_validation() {
        let addr = "127.0.0.1:24100".parse().unwrap();
        let handshake = HandshakeMessage::new(NetworkType::Testnet, addr);

        assert!(handshake.validate(&NetworkType::Testnet).is_ok());
        assert!(handshake.validate(&NetworkType::Mainnet).is_err());
    }

    #[test]
    fn test_protocol_version() {
        let version = ProtocolVersion::current();
        assert_eq!(version.software_version, VERSION);
        assert_eq!(version.protocol_version, PROTOCOL_VERSION);
        assert!(version.commit_date.is_some());
    }

    #[test]
    fn test_build_info() {
        let info = BuildInfo::current();
        assert!(!info.version.is_empty());
        assert_eq!(info.git_branch, GIT_BRANCH);
    }

    #[test]
    fn test_version_outdated_same_hash() {
        // If hashes are the same, not outdated
        assert!(!is_version_outdated(&format!("0.1.0-{}", GIT_HASH)));
    }

    #[test]
    fn test_version_outdated_different_hash() {
        // If hashes are different, is outdated
        assert!(is_version_outdated("0.1.0-abc1234"));
    }

    #[test]
    fn test_version_outdated_with_build() {
        // Same hash with different build times = not outdated
        let result = is_version_outdated_with_build(
            &format!("0.1.0-{}", GIT_HASH),
            Some("2025-11-07 14:00:00"),
        );
        assert!(!result);
    }

    #[test]
    fn test_version_mismatch_message() {
        let msg = version_mismatch_message("127.0.0.1", "0.1.0-abc1234");
        assert!(msg.contains("Peer 127.0.0.1"));
        assert!(msg.contains("0.1.0-abc1234"));
    }

    #[test]
    fn test_iso_date_comparison() {
        // Test ISO 8601 format dates
        let older_iso = "2025-11-07T15:09:21Z";
        let newer_iso = "2025-11-08T15:09:21Z";
        assert!(is_remote_version_newer(older_iso, newer_iso));
        assert!(!is_remote_version_newer(newer_iso, older_iso));
    }

    #[test]
    fn test_same_date_comparison() {
        // Same commit date should not be considered newer
        let date = "2025-11-07T15:09:21Z";
        assert!(!is_remote_version_newer(date, date));
    }

    #[test]
    fn test_handshake_genesis_validation() {
        let addr = "127.0.0.1:24100".parse().unwrap();
        let genesis_hash = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";

        let handshake = HandshakeMessage::new_with_genesis(
            NetworkType::Testnet,
            addr,
            Some(genesis_hash.to_string()),
        );

        // Should succeed with matching genesis
        assert!(handshake
            .validate_with_genesis(&NetworkType::Testnet, Some(genesis_hash))
            .is_ok());

        // Should fail with mismatched genesis
        let different_genesis = "00000000000000000000000000000000000000000000000000000000deadbeef";
        assert!(handshake
            .validate_with_genesis(&NetworkType::Testnet, Some(different_genesis))
            .is_err());

        // Should succeed when one side doesn't provide genesis (backward compatibility)
        assert!(handshake
            .validate_with_genesis(&NetworkType::Testnet, None)
            .is_ok());
    }

    #[test]
    fn test_handshake_genesis_mismatch_error_message() {
        let addr = "127.0.0.1:24100".parse().unwrap();
        let genesis_hash = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";

        let handshake = HandshakeMessage::new_with_genesis(
            NetworkType::Testnet,
            addr,
            Some(genesis_hash.to_string()),
        );

        let different_genesis = "0000000000000000000000000000000000000000000000000000000011111111";
        let result =
            handshake.validate_with_genesis(&NetworkType::Testnet, Some(different_genesis));

        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("Genesis block mismatch"));
        assert!(err_msg.contains("00000000839a8e68")); // First 16 chars of actual genesis
        assert!(err_msg.contains("0000000000000000")); // First 16 chars of different genesis
    }

    #[test]
    fn test_network_message_serialization() {
        // Test Ping message
        let ping = NetworkMessage::Ping;
        let serialized = ping.serialize().unwrap();
        let deserialized = NetworkMessage::deserialize(&serialized).unwrap();
        match deserialized {
            NetworkMessage::Ping => (),
            _ => panic!("Expected Ping message"),
        }
    }

    #[test]
    fn test_instant_finality_vote_message() {
        // Test InstantFinalityVote message
        let vote = NetworkMessage::InstantFinalityVote {
            txid: "test_txid_123".to_string(),
            voter: "voter_address".to_string(),
            approve: true,
            timestamp: 1234567890,
        };

        let serialized = vote.serialize().unwrap();
        let deserialized = NetworkMessage::deserialize(&serialized).unwrap();

        match deserialized {
            NetworkMessage::InstantFinalityVote {
                txid,
                voter,
                approve,
                timestamp,
            } => {
                assert_eq!(txid, "test_txid_123");
                assert_eq!(voter, "voter_address");
                assert!(approve);
                assert_eq!(timestamp, 1234567890);
            }
            _ => panic!("Expected InstantFinalityVote message"),
        }
    }

    #[test]
    fn test_mempool_query_message() {
        // Test MempoolQuery message
        let query = NetworkMessage::MempoolQuery;
        let serialized = query.serialize().unwrap();
        let deserialized = NetworkMessage::deserialize(&serialized).unwrap();

        match deserialized {
            NetworkMessage::MempoolQuery => (),
            _ => panic!("Expected MempoolQuery message"),
        }
    }
}

/// Transaction broadcast message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMessage {
    pub txid: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: i64,
    pub signature: String,
    pub nonce: u64,
}

/// Transaction validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionValidation {
    pub txid: String,
    pub validator: String,
    pub approved: bool,
    pub timestamp: u64,
}

/// Block data for sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub block: Vec<u8>,
    pub height: u64,
}

/// Network message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Ping,
    Pong,

    // Time synchronization messages
    TimeRequest {
        request_time_ms: i64, // Milliseconds since Unix epoch
    },
    TimeResponse {
        request_time_ms: i64, // Echo back requester's timestamp
        peer_time_ms: i64,    // Peer's current time in milliseconds since Unix epoch
    },

    Transaction(TransactionMessage),
    ValidationResponse(TransactionValidation),
    BlockProposal(Vec<u8>),
    GetBlockchainHeight,
    BlockchainHeight(u64),
    GetBlocks {
        start_height: u64,
        end_height: u64,
    },
    BlocksData(Vec<BlockData>),
    Blocks {
        blocks: Vec<time_core::block::Block>,
    },

    // Catch-up coordination messages
    CatchUpRequest {
        requester: String,
        current_height: u64,
        expected_height: u64,
    },
    CatchUpAcknowledge {
        responder: String,
    },

    // New message types for unified TCP communication
    TransactionBroadcast(time_core::Transaction),
    FinalizedTransactionBroadcast(time_core::Transaction), // 🆕 Broadcast finalized tx to sync UTXO sets
    InstantFinalityRequest(time_core::Transaction),
    InstantFinalityVote {
        txid: String,
        voter: String,
        approve: bool,
        timestamp: u64,
    },
    MempoolAdd(time_core::Transaction),
    MempoolQuery,
    MempoolResponse(Vec<time_core::Transaction>),

    // Consensus messages for TCP communication
    ConsensusBlockProposal(String), // JSON serialized BlockProposal
    ConsensusBlockVote(String),     // JSON serialized BlockVote
    ConsensusVoteAck {
        block_hash: String,
        voter: String,
        received_at: u64,
    },

    // Transaction sync for block proposals
    RequestMissingTransactions {
        txids: Vec<String>,
        requester: String,
        block_height: u64,
    },
    MissingTransactionsResponse {
        transactions: Vec<time_core::Transaction>,
        block_height: u64,
    },
    TransactionRejection {
        txid: String,
        reason: String, // "double_spend", "invalid_signature", etc.
        wallet_address: String,
    },

    // Leader election notification
    RequestBlockProposal {
        block_height: u64,
        leader_ip: String,
        requester_ip: String,
    },

    // Chain tip update notification
    UpdateTip {
        height: u64,
        hash: String,
    },

    // Wallet transaction sync
    RegisterXpub {
        xpub: String,
    },
    XpubRegistered {
        success: bool,
        message: String,
    },
    UtxoUpdate {
        xpub: String,
        utxos: Vec<UtxoInfo>,
    },
    RequestWalletTransactions {
        xpub: String,
    },
    WalletTransactionsResponse {
        transactions: Vec<WalletTransaction>,
        last_synced_height: u64,
    },
    // Peer list request for wallet GUI
    GetPeerList,
    // Real-time notification when a wallet receives a new transaction
    NewTransactionNotification {
        transaction: WalletTransaction,
    },

    // Additional message types for full TCP communication
    GetGenesis,
    GenesisBlock(String), // JSON serialized genesis block
    GetMempool,
    GetBlockchainInfo,
    BlockchainInfo {
        height: Option<u64>, // None = no genesis yet, Some(0) = genesis exists
        best_block_hash: String,
    },

    // ═══════════════════════════════════════════════════════════════
    // NETWORK SYNCHRONIZATION MESSAGES (Three-Tier Sync Strategy)
    // ═══════════════════════════════════════════════════════════════

    // Tier 1: Height Synchronization
    /// Request current blockchain height from peer
    HeightRequest,
    /// Response with current blockchain height
    HeightResponse {
        height: u64,
        best_block_hash: String,
    },

    // Tier 2: Block Synchronization
    /// Request a specific block by height
    BlockRequest {
        height: u64,
    },
    /// Response with requested block
    BlockResponse {
        block: Option<time_core::block::Block>,
    },

    // Tier 3: Full Chain Synchronization
    /// Request entire chain from genesis
    ChainRequest {
        from_height: u64,
    },
    /// Response with blocks starting from requested height
    ChainResponse {
        blocks: Vec<time_core::block::Block>,
        complete: bool, // true if this is the final batch
    },

    // State Snapshot Synchronization (fastest initial sync)
    /// Request state snapshot at specific height
    StateSnapshotRequest {
        height: u64,
    },
    /// Response with compressed state snapshot
    StateSnapshotResponse {
        height: u64,
        utxo_merkle_root: String,
        state_data: Vec<u8>, // Compressed UTXO state
        compressed: bool,
        snapshot_size_bytes: u64,
    },

    PeerList(Vec<PeerAddress>),

    // Transaction consensus messages
    ConsensusTxProposal(String), // JSON serialized tx proposal

    // Instant finality sync protocol
    RequestFinalizedTransactions {
        since_timestamp: i64, // Request finalized txs after this timestamp
    },
    FinalizedTransactionsResponse {
        transactions: Vec<time_core::Transaction>,
        finalized_at: Vec<i64>, // Timestamp when each tx was finalized
    },
    ConsensusTxVote(String), // JSON serialized tx vote

    // Transaction approval/rejection messages
    TransactionApproved {
        txid: String,
        approver: String,
        timestamp: i64,
    },
    TransactionRejected {
        txid: String,
        rejector: String,
        reason: String,
        timestamp: i64,
    },
    TransactionRejectedByNetwork {
        txid: String,
        rejections: Vec<String>, // List of rejector addresses
        reasons: Vec<String>,    // Corresponding rejection reasons
        timestamp: i64,
    },

    // UTXO State Protocol messages
    UTXOStateQuery {
        outpoints: Vec<String>, // JSON serialized OutPoints
    },
    UTXOStateResponse {
        states: String, // JSON serialized Vec<(OutPoint, UTXOState)>
    },
    UTXOStateNotification {
        notification: String, // JSON serialized UTXOStateNotification
    },
    UTXOSubscribe {
        outpoints: Vec<String>, // JSON serialized OutPoints
        addresses: Vec<String>, // Addresses to watch
        subscriber_id: String,
    },
    UTXOUnsubscribe {
        subscriber_id: String,
    },

    // UTXO Instant Synchronization messages
    UtxoLockBroadcast {
        txid: String,
        inputs: Vec<String>,  // JSON serialized UtxoInput
        outputs: Vec<String>, // JSON serialized UtxoOutput
        timestamp: i64,
        proposer: String,
        signature: String,
    },
    UtxoLockAcknowledge {
        txid: String,
        masternode: String,
        tier: String,
        success: bool,
        conflict: Option<String>, // JSON serialized ConflictInfo
        timestamp: i64,
    },
    UtxoCommit {
        txid: String,
        status: String, // "Approved" or "Rejected"
        ack_count: u32,
        total_weight: f64,
        timestamp: i64,
        reason: Option<String>, // For rejections
    },
    UtxoConflictResolution {
        winner_txid: String,
        loser_txid: String,
        resolution_rule: String,
        timestamp: i64,
    },

    // Masternode synchronization protocol
    GetMasternodeList,
    MasternodeList {
        masternodes: Vec<MasternodeInfo>,
    },
    MasternodeAnnouncement {
        masternode: MasternodeInfo,
    },
    GetMasternodeHash,
    MasternodeHash {
        hash: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeInfo {
    pub node_id: String,
    pub wallet_address: String,
    pub tier: String, // "Free", "Basic", "Standard", "Premium", "Enterprise"
    pub is_active: bool,
    pub registered_at: i64,
}

impl NetworkMessage {
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerAddress {
    pub ip: String,
    pub port: u16,
    pub version: String,
}

/// Ping message for latency measurement
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ping {
    pub timestamp: i64,
}

/// Pong response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Pong {
    pub timestamp: i64,
}
