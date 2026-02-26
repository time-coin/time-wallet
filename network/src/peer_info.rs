use crate::NetworkType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Canonical peer information structure for the network layer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    pub address: SocketAddr,
    pub last_seen: u64,
    pub version: String,
    pub network: NetworkType,

    #[serde(default)]
    pub commit_date: Option<String>,

    #[serde(default)]
    pub commit_count: Option<String>,

    #[serde(default)]
    pub wallet_address: Option<String>,

    #[serde(default)]
    pub latency_ms: Option<u32>,

    #[serde(default)]
    pub successful_connections: u32,

    #[serde(default)]
    pub failed_connections: u32,
}

impl PeerInfo {
    /// Create a new peer with unknown version
    pub fn new(address: SocketAddr, network: NetworkType) -> Self {
        PeerInfo {
            address,
            network,
            last_seen: chrono::Utc::now().timestamp() as u64,
            version: "unknown".to_string(),
            commit_date: None,
            commit_count: None,
            wallet_address: None,
            latency_ms: None,
            successful_connections: 0,
            failed_connections: 0,
        }
    }

    /// Create a new peer with a specific version
    pub fn with_version(address: SocketAddr, network: NetworkType, version: String) -> Self {
        let mut peer = Self::new(address, network);
        peer.version = version;
        peer
    }

    /// Update last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = chrono::Utc::now().timestamp() as u64;
    }

    /// Record successful connection
    pub fn record_success(&mut self) {
        self.successful_connections += 1;
        self.update_last_seen();
    }

    /// Record failed connection
    pub fn record_failure(&mut self) {
        self.failed_connections += 1;
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_connections + self.failed_connections;
        if total == 0 {
            0.0
        } else {
            self.successful_connections as f64 / total as f64
        }
    }

    /// Update the peer's version (called after handshake)
    pub fn update_version(&mut self, version: String) {
        self.version = version;
        self.update_last_seen();
    }

    /// Update the peer's version with commit info (called after handshake)
    pub fn update_version_with_build_info(
        &mut self,
        version: String,
        commit_date: Option<String>,
        commit_count: Option<String>,
    ) {
        self.version = version;
        self.commit_date = commit_date;
        self.commit_count = commit_count;
        self.update_last_seen();
    }

    /// Alias for update_last_seen() for compatibility
    pub fn touch(&mut self) {
        self.update_last_seen();
    }

    /// Check if peer is likely still alive based on last seen
    pub fn is_stale(&self, stale_threshold_secs: u64) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.last_seen) > stale_threshold_secs
    }
}
