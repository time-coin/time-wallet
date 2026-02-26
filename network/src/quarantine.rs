//! Peer quarantine system for nodes on different chains or forks
//!
//! Tracks and isolates peers that are detected to be on:
//! - Different genesis blocks
//! - Forked chains
//! - Invalid chains with suspicious heights
//! - Invalid blocks or transactions
//! - Protocol violations
//! - Excessive connection failures

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Severity level of quarantine offense
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineSeverity {
    /// Minor offenses: 5-15 minutes
    Minor,
    /// Moderate offenses: 1-24 hours  
    Moderate,
    /// Severe offenses: 7-30 days
    Severe,
    /// Permanent ban
    Permanent,
}

impl QuarantineSeverity {
    /// Get the base duration for this severity level
    pub fn base_duration(&self) -> Duration {
        match self {
            QuarantineSeverity::Minor => Duration::from_secs(5 * 60), // 5 minutes
            QuarantineSeverity::Moderate => Duration::from_secs(3600), // 1 hour
            QuarantineSeverity::Severe => Duration::from_secs(7 * 24 * 3600), // 7 days
            QuarantineSeverity::Permanent => Duration::from_secs(365 * 24 * 3600), // 1 year (effectively permanent)
        }
    }

    /// Calculate duration with exponential backoff based on attempts
    pub fn duration_with_backoff(&self, attempts: u32) -> Duration {
        let base = self.base_duration();
        if *self == QuarantineSeverity::Permanent {
            return base;
        }

        // Exponential backoff: base * 2^(attempts-1), capped at 30 days
        let multiplier = 2u64.saturating_pow(attempts.saturating_sub(1));
        let duration_secs = base.as_secs().saturating_mul(multiplier);
        let max_secs = 30 * 24 * 3600; // 30 days max
        Duration::from_secs(duration_secs.min(max_secs))
    }
}

#[derive(Debug, Clone)]
pub enum QuarantineReason {
    /// Peer has different genesis block (different chain)
    GenesisMismatch {
        our_genesis: String,
        their_genesis: String,
    },
    /// Peer detected on a fork
    ForkDetected {
        height: u64,
        our_hash: String,
        their_hash: String,
    },
    /// Peer reported suspicious/impossible blockchain height
    SuspiciousHeight {
        their_height: u64,
        max_expected: u64,
    },
    /// General consensus protocol violation
    ConsensusViolation { reason: String },
    /// Peer sent an invalid block
    InvalidBlock { height: u64, reason: String },
    /// Peer sent an invalid transaction
    InvalidTransaction { txid: String, reason: String },
    /// Protocol version mismatch
    ProtocolMismatch {
        our_version: u32,
        their_version: u32,
    },
    /// Excessive connection failures
    ConnectionFailures { count: u32 },
    /// Peer exceeded rate limits (too many requests)
    RateLimitExceeded { requests_per_second: u32 },
    /// Peer timed out excessively
    ExcessiveTimeouts { count: u32 },
}

impl QuarantineReason {
    /// Get the severity level for this quarantine reason
    pub fn severity(&self) -> QuarantineSeverity {
        match self {
            QuarantineReason::GenesisMismatch { .. } => QuarantineSeverity::Permanent,
            QuarantineReason::ForkDetected { .. } => QuarantineSeverity::Severe,
            QuarantineReason::SuspiciousHeight { .. } => QuarantineSeverity::Severe,
            QuarantineReason::ConsensusViolation { .. } => QuarantineSeverity::Severe,
            QuarantineReason::InvalidBlock { .. } => QuarantineSeverity::Moderate,
            QuarantineReason::InvalidTransaction { .. } => QuarantineSeverity::Minor,
            QuarantineReason::ProtocolMismatch { .. } => QuarantineSeverity::Moderate,
            QuarantineReason::ConnectionFailures { .. } => QuarantineSeverity::Minor,
            QuarantineReason::RateLimitExceeded { .. } => QuarantineSeverity::Minor,
            QuarantineReason::ExcessiveTimeouts { .. } => QuarantineSeverity::Minor,
        }
    }
}

impl std::fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            QuarantineReason::GenesisMismatch {
                our_genesis,
                their_genesis,
            } => {
                let our_display = if our_genesis.len() >= 16 {
                    &our_genesis[..16]
                } else {
                    our_genesis
                };
                let their_display = if their_genesis.len() >= 16 {
                    &their_genesis[..16]
                } else {
                    their_genesis
                };
                write!(
                    f,
                    "Genesis mismatch: ours={}..., theirs={}...",
                    our_display, their_display
                )
            }
            QuarantineReason::ForkDetected {
                height,
                our_hash,
                their_hash,
            } => {
                let our_display = if our_hash.len() >= 16 {
                    &our_hash[..16]
                } else {
                    our_hash
                };
                let their_display = if their_hash.len() >= 16 {
                    &their_hash[..16]
                } else {
                    their_hash
                };
                write!(
                    f,
                    "Fork at height {}: ours={}..., theirs={}...",
                    height, our_display, their_display
                )
            }
            QuarantineReason::SuspiciousHeight {
                their_height,
                max_expected,
            } => write!(
                f,
                "Suspicious height {} (max expected: {})",
                their_height, max_expected
            ),
            QuarantineReason::ConsensusViolation { reason } => {
                write!(f, "Consensus violation: {}", reason)
            }
            QuarantineReason::InvalidBlock { height, reason } => {
                write!(f, "Invalid block at height {}: {}", height, reason)
            }
            QuarantineReason::InvalidTransaction { txid, reason } => {
                let txid_display = if txid.len() >= 16 { &txid[..16] } else { txid };
                write!(f, "Invalid transaction {}...: {}", txid_display, reason)
            }
            QuarantineReason::ProtocolMismatch {
                our_version,
                their_version,
            } => write!(
                f,
                "Protocol mismatch: ours={}, theirs={}",
                our_version, their_version
            ),
            QuarantineReason::ConnectionFailures { count } => {
                write!(f, "Connection failures: {}", count)
            }
            QuarantineReason::RateLimitExceeded {
                requests_per_second,
            } => write!(f, "Rate limit exceeded: {} req/s", requests_per_second),
            QuarantineReason::ExcessiveTimeouts { count } => {
                write!(f, "Excessive timeouts: {}", count)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub peer_ip: IpAddr,
    pub reason: QuarantineReason,
    pub quarantined_at: Instant,
    pub attempts: u32,
    pub expires_at: Instant,
}

/// Configuration for the quarantine system
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    /// Maximum number of peers to track in quarantine (prevents DoS via memory exhaustion)
    pub max_quarantine_size: usize,
    /// Default quarantine duration (used as fallback)
    pub default_duration: Duration,
    /// Whether to use severity-based durations
    pub use_severity_based_durations: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            max_quarantine_size: 10000,
            default_duration: Duration::from_secs(3600), // 1 hour
            use_severity_based_durations: true,
        }
    }
}

pub struct PeerQuarantine {
    quarantined: Arc<RwLock<HashMap<IpAddr, QuarantineEntry>>>,
    whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    config: QuarantineConfig,
    /// Statistics
    stats: Arc<RwLock<QuarantineStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct QuarantineStats {
    pub total_quarantined: usize,
    pub genesis_mismatch: usize,
    pub fork_detected: usize,
    pub suspicious_height: usize,
    pub consensus_violation: usize,
    pub invalid_block: usize,
    pub invalid_transaction: usize,
    pub protocol_mismatch: usize,
    pub connection_failures: usize,
    pub rate_limit_exceeded: usize,
    pub excessive_timeouts: usize,
}

impl PeerQuarantine {
    /// Create a new peer quarantine system with default configuration
    pub fn new() -> Self {
        Self::with_config(QuarantineConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: QuarantineConfig) -> Self {
        Self {
            quarantined: Arc::new(RwLock::new(HashMap::new())),
            whitelist: Arc::new(RwLock::new(HashSet::new())),
            config,
            stats: Arc::new(RwLock::new(QuarantineStats::default())),
        }
    }

    /// Create with custom quarantine duration (legacy method)
    pub fn with_duration(duration: Duration) -> Self {
        let config = QuarantineConfig {
            default_duration: duration,
            use_severity_based_durations: false,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Add a peer to the whitelist (trusted peers)
    pub async fn add_to_whitelist(&self, peer_ip: IpAddr) {
        let mut whitelist = self.whitelist.write().await;
        whitelist.insert(peer_ip);
        info!("🔓 Peer {} added to whitelist", peer_ip);
    }

    /// Remove a peer from the whitelist
    pub async fn remove_from_whitelist(&self, peer_ip: &IpAddr) {
        let mut whitelist = self.whitelist.write().await;
        whitelist.remove(peer_ip);
        info!("🔒 Peer {} removed from whitelist", peer_ip);
    }

    /// Check if a peer is whitelisted
    pub async fn is_whitelisted(&self, peer_ip: &IpAddr) -> bool {
        let whitelist = self.whitelist.read().await;
        whitelist.contains(peer_ip)
    }

    /// Update statistics for a quarantine reason
    async fn update_stats(&self, reason: &QuarantineReason) {
        let mut stats = self.stats.write().await;
        stats.total_quarantined += 1;

        match reason {
            QuarantineReason::GenesisMismatch { .. } => stats.genesis_mismatch += 1,
            QuarantineReason::ForkDetected { .. } => stats.fork_detected += 1,
            QuarantineReason::SuspiciousHeight { .. } => stats.suspicious_height += 1,
            QuarantineReason::ConsensusViolation { .. } => stats.consensus_violation += 1,
            QuarantineReason::InvalidBlock { .. } => stats.invalid_block += 1,
            QuarantineReason::InvalidTransaction { .. } => stats.invalid_transaction += 1,
            QuarantineReason::ProtocolMismatch { .. } => stats.protocol_mismatch += 1,
            QuarantineReason::ConnectionFailures { .. } => stats.connection_failures += 1,
            QuarantineReason::RateLimitExceeded { .. } => stats.rate_limit_exceeded += 1,
            QuarantineReason::ExcessiveTimeouts { .. } => stats.excessive_timeouts += 1,
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> QuarantineStats {
        self.stats.read().await.clone()
    }

    /// Add a peer to quarantine
    pub async fn quarantine_peer(&self, peer_ip: IpAddr, reason: QuarantineReason) {
        // Check whitelist first
        if self.is_whitelisted(&peer_ip).await {
            info!("⚠️  Peer {} is whitelisted, skipping quarantine", peer_ip);
            return;
        }

        let mut quarantined = self.quarantined.write().await;

        // Check maximum size limit
        if quarantined.len() >= self.config.max_quarantine_size
            && !quarantined.contains_key(&peer_ip)
        {
            warn!(
                "⚠️  Quarantine list full ({} entries), cannot add {}",
                self.config.max_quarantine_size, peer_ip
            );
            return;
        }

        let severity = reason.severity();
        let now = Instant::now();

        let entry = quarantined.entry(peer_ip).or_insert_with(|| {
            let duration = if self.config.use_severity_based_durations {
                severity.base_duration()
            } else {
                self.config.default_duration
            };

            QuarantineEntry {
                peer_ip,
                reason: reason.clone(),
                quarantined_at: now,
                attempts: 0,
                expires_at: now + duration,
            }
        });

        entry.attempts += 1;
        entry.quarantined_at = now;
        entry.reason = reason.clone();

        // Apply exponential backoff on repeated offenses
        let duration = if self.config.use_severity_based_durations {
            severity.duration_with_backoff(entry.attempts)
        } else {
            self.config.default_duration
        };
        entry.expires_at = now + duration;

        warn!(
            "🚫 Peer {} quarantined: {} (attempt #{}, expires in {}s)",
            peer_ip,
            reason,
            entry.attempts,
            duration.as_secs()
        );

        drop(quarantined);
        self.update_stats(&reason).await;
    }

    /// Check if a peer is quarantined
    pub async fn is_quarantined(&self, peer_ip: &IpAddr) -> bool {
        // Whitelisted peers are never quarantined
        if self.is_whitelisted(peer_ip).await {
            return false;
        }

        let quarantined = self.quarantined.read().await;
        if let Some(entry) = quarantined.get(peer_ip) {
            // Check if quarantine has expired
            if Instant::now() < entry.expires_at {
                return true;
            }
        }
        false
    }

    /// Get quarantine reason for a peer
    pub async fn get_reason(&self, peer_ip: &IpAddr) -> Option<QuarantineReason> {
        let quarantined = self.quarantined.read().await;
        quarantined.get(peer_ip).map(|e| e.reason.clone())
    }

    /// Get quarantine entry for a peer
    pub async fn get_entry(&self, peer_ip: &IpAddr) -> Option<QuarantineEntry> {
        let quarantined = self.quarantined.read().await;
        quarantined.get(peer_ip).cloned()
    }

    /// Remove a peer from quarantine (manual override)
    pub async fn release_peer(&self, peer_ip: &IpAddr) {
        let mut quarantined = self.quarantined.write().await;
        if quarantined.remove(peer_ip).is_some() {
            info!("✅ Peer {} released from quarantine", peer_ip);
        }
    }

    /// Clear all quarantined peers (useful for fresh starts after blockchain reset)
    pub async fn clear_all(&self) {
        let mut quarantined = self.quarantined.write().await;
        let count = quarantined.len();
        quarantined.clear();
        if count > 0 {
            info!("🔓 Cleared {} peer(s) from quarantine", count);
        }
    }

    /// Get all quarantined peers
    pub async fn get_quarantined_peers(&self) -> Vec<QuarantineEntry> {
        let quarantined = self.quarantined.read().await;
        quarantined.values().cloned().collect()
    }

    /// Clean up expired quarantine entries
    pub async fn cleanup_expired(&self) {
        let mut quarantined = self.quarantined.write().await;
        let now = Instant::now();
        let initial_count = quarantined.len();
        quarantined.retain(|_, entry| now < entry.expires_at);
        let removed = initial_count - quarantined.len();
        if removed > 0 {
            info!("🧹 Cleaned up {} expired quarantine entries", removed);
        }
    }

    /// Get count of quarantined peers
    pub async fn count(&self) -> usize {
        let quarantined = self.quarantined.read().await;
        quarantined.len()
    }

    /// Check if peer should be excluded from consensus
    pub async fn should_exclude_from_consensus(&self, peer_ip: &IpAddr) -> bool {
        if let Some(reason) = self.get_reason(peer_ip).await {
            match reason {
                QuarantineReason::GenesisMismatch { .. } => true, // Always exclude
                QuarantineReason::ForkDetected { .. } => true,    // Always exclude
                QuarantineReason::SuspiciousHeight { .. } => true, // Always exclude
                QuarantineReason::ConsensusViolation { .. } => true, // Always exclude
                QuarantineReason::InvalidBlock { .. } => true,    // Exclude for invalid blocks
                QuarantineReason::InvalidTransaction { .. } => false, // Don't exclude for tx issues
                QuarantineReason::ProtocolMismatch { .. } => true, // Exclude for protocol issues
                QuarantineReason::ConnectionFailures { .. } => false, // Don't exclude for connection issues
                QuarantineReason::RateLimitExceeded { .. } => false, // Don't exclude for rate limits
                QuarantineReason::ExcessiveTimeouts { .. } => false, // Don't exclude for timeouts
            }
        } else {
            false
        }
    }

    /// Start a background task to periodically clean up expired entries
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                self.cleanup_expired().await;
            }
        });
    }
}

impl Default for PeerQuarantine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_quarantine_peer() {
        let quarantine = PeerQuarantine::new();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(!quarantine.is_quarantined(&peer_ip).await);

        quarantine
            .quarantine_peer(
                peer_ip,
                QuarantineReason::GenesisMismatch {
                    our_genesis: "abc123".to_string(),
                    their_genesis: "def456".to_string(),
                },
            )
            .await;

        assert!(quarantine.is_quarantined(&peer_ip).await);
    }

    #[tokio::test]
    async fn test_quarantine_expiry() {
        let config = QuarantineConfig {
            default_duration: Duration::from_millis(100),
            use_severity_based_durations: false,
            ..Default::default()
        };
        let quarantine = PeerQuarantine::with_config(config);
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        quarantine
            .quarantine_peer(peer_ip, QuarantineReason::ConnectionFailures { count: 3 })
            .await;

        assert!(quarantine.is_quarantined(&peer_ip).await);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(!quarantine.is_quarantined(&peer_ip).await);
    }

    #[tokio::test]
    async fn test_release_peer() {
        let quarantine = PeerQuarantine::new();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        quarantine
            .quarantine_peer(
                peer_ip,
                QuarantineReason::SuspiciousHeight {
                    their_height: 1000,
                    max_expected: 100,
                },
            )
            .await;

        assert!(quarantine.is_quarantined(&peer_ip).await);

        quarantine.release_peer(&peer_ip).await;

        assert!(!quarantine.is_quarantined(&peer_ip).await);
    }

    #[tokio::test]
    async fn test_should_exclude_from_consensus() {
        let quarantine = PeerQuarantine::new();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(!quarantine.should_exclude_from_consensus(&peer_ip).await);

        quarantine
            .quarantine_peer(
                peer_ip,
                QuarantineReason::GenesisMismatch {
                    our_genesis: "abc123".to_string(),
                    their_genesis: "def456".to_string(),
                },
            )
            .await;

        assert!(quarantine.should_exclude_from_consensus(&peer_ip).await);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let config = QuarantineConfig {
            default_duration: Duration::from_millis(100),
            use_severity_based_durations: false,
            ..Default::default()
        };
        let quarantine = PeerQuarantine::with_config(config);
        let peer1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        quarantine
            .quarantine_peer(peer1, QuarantineReason::ConnectionFailures { count: 3 })
            .await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        quarantine
            .quarantine_peer(peer2, QuarantineReason::ConnectionFailures { count: 3 })
            .await;

        assert_eq!(quarantine.count().await, 2);

        tokio::time::sleep(Duration::from_millis(60)).await;
        quarantine.cleanup_expired().await;

        // peer1 should be expired, peer2 should remain
        assert_eq!(quarantine.count().await, 1);
        assert!(!quarantine.is_quarantined(&peer1).await);
        assert!(quarantine.is_quarantined(&peer2).await);
    }

    #[tokio::test]
    async fn test_whitelist() {
        let quarantine = PeerQuarantine::new();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Add to whitelist
        quarantine.add_to_whitelist(peer_ip).await;
        assert!(quarantine.is_whitelisted(&peer_ip).await);

        // Try to quarantine - should be ignored
        quarantine
            .quarantine_peer(
                peer_ip,
                QuarantineReason::InvalidBlock {
                    height: 100,
                    reason: "test".to_string(),
                },
            )
            .await;

        assert!(!quarantine.is_quarantined(&peer_ip).await);
    }

    #[tokio::test]
    async fn test_severity_based_duration() {
        let quarantine = PeerQuarantine::new();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Minor offense
        quarantine
            .quarantine_peer(peer_ip, QuarantineReason::ConnectionFailures { count: 3 })
            .await;

        let entry = quarantine.get_entry(&peer_ip).await.unwrap();
        let duration = entry.expires_at.duration_since(entry.quarantined_at);

        // Should be around 5 minutes for minor offense
        assert!(duration.as_secs() >= 250 && duration.as_secs() <= 350);
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        let quarantine = PeerQuarantine::new();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First offense
        quarantine
            .quarantine_peer(
                peer_ip,
                QuarantineReason::InvalidTransaction {
                    txid: "test123".to_string(),
                    reason: "test".to_string(),
                },
            )
            .await;

        let entry1 = quarantine.get_entry(&peer_ip).await.unwrap();
        let duration1 = entry1.expires_at.duration_since(entry1.quarantined_at);

        // Second offense - should have longer duration
        tokio::time::sleep(Duration::from_millis(10)).await;
        quarantine
            .quarantine_peer(
                peer_ip,
                QuarantineReason::InvalidTransaction {
                    txid: "test456".to_string(),
                    reason: "test".to_string(),
                },
            )
            .await;

        let entry2 = quarantine.get_entry(&peer_ip).await.unwrap();
        let duration2 = entry2.expires_at.duration_since(entry2.quarantined_at);

        // Second offense should have at least 2x the duration
        assert!(duration2 >= duration1 * 2);
        assert_eq!(entry2.attempts, 2);
    }

    #[tokio::test]
    async fn test_max_quarantine_size() {
        let config = QuarantineConfig {
            max_quarantine_size: 2,
            ..Default::default()
        };
        let quarantine = PeerQuarantine::with_config(config);

        let peer1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let peer3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        quarantine
            .quarantine_peer(
                peer1,
                QuarantineReason::InvalidBlock {
                    height: 100,
                    reason: "test".to_string(),
                },
            )
            .await;

        quarantine
            .quarantine_peer(
                peer2,
                QuarantineReason::InvalidBlock {
                    height: 101,
                    reason: "test".to_string(),
                },
            )
            .await;

        // Third peer should not be added due to size limit
        quarantine
            .quarantine_peer(
                peer3,
                QuarantineReason::InvalidBlock {
                    height: 102,
                    reason: "test".to_string(),
                },
            )
            .await;

        assert_eq!(quarantine.count().await, 2);
        assert!(quarantine.is_quarantined(&peer1).await);
        assert!(quarantine.is_quarantined(&peer2).await);
        assert!(!quarantine.is_quarantined(&peer3).await);
    }

    #[tokio::test]
    async fn test_statistics() {
        let quarantine = PeerQuarantine::new();
        let peer1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let peer3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        quarantine
            .quarantine_peer(
                peer1,
                QuarantineReason::InvalidBlock {
                    height: 100,
                    reason: "test".to_string(),
                },
            )
            .await;

        quarantine
            .quarantine_peer(
                peer2,
                QuarantineReason::InvalidTransaction {
                    txid: "test".to_string(),
                    reason: "test".to_string(),
                },
            )
            .await;

        quarantine
            .quarantine_peer(
                peer3,
                QuarantineReason::GenesisMismatch {
                    our_genesis: "abc".to_string(),
                    their_genesis: "def".to_string(),
                },
            )
            .await;

        let stats = quarantine.get_stats().await;
        assert_eq!(stats.total_quarantined, 3);
        assert_eq!(stats.invalid_block, 1);
        assert_eq!(stats.invalid_transaction, 1);
        assert_eq!(stats.genesis_mismatch, 1);
    }
}
