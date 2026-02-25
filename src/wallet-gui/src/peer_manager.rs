//! Peer Manager for GUI Wallet
//!
//! Manages masternode peers, discovers new peers, and maintains connections.

use crate::wallet_db::{PeerRecord, WalletDb};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: String,
    pub latency_ms: f64,
    pub success_rate: f64,
    pub request_count: u32,
    pub failure_count: u32,
}

#[derive(Debug)]
pub struct PeerManager {
    wallet_db: Arc<RwLock<Option<WalletDb>>>,
    network: wallet::NetworkType,
}

impl PeerManager {
    pub fn new(network: wallet::NetworkType) -> Self {
        Self {
            wallet_db: Arc::new(RwLock::new(None)),
            network,
        }
    }

    /// Set the wallet database (called after wallet is initialized)
    pub async fn set_wallet_db(&self, db: WalletDb) {
        let mut wallet_db = self.wallet_db.write().await;
        *wallet_db = Some(db);
        log::info!("📂 Wallet database connected to PeerManager");
    }

    /// Helper to convert PeerRecord to display format
    fn peer_to_info(peer: &PeerRecord) -> (String, u16, i64) {
        (peer.address.clone(), peer.port, peer.last_seen as i64)
    }

    /// Helper to calculate peer score with enhanced metrics
    /// Returns higher score for better peers
    fn calculate_score(peer: &PeerRecord) -> i64 {
        // Base score from successful connections
        let base_score = peer.successful_connections as i64 * 10;

        // Heavy penalty for failures
        let failure_penalty = peer.failed_connections as i64 * 20;

        // Latency bonus (lower is better)
        let latency_bonus = if peer.latency_ms > 0 && peer.latency_ms < 100 {
            50 // Fast peer bonus
        } else if peer.latency_ms >= 100 && peer.latency_ms < 500 {
            10 // Moderate peer
        } else {
            0 // Slow or unknown
        };

        // Age penalty (prefer recently seen peers)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let hours_since_seen = (now as i64 - peer.last_seen as i64) / 3600;
        let age_penalty = hours_since_seen.min(24); // Max 24 point penalty

        // Calculate final score
        let score = base_score - failure_penalty + latency_bonus - age_penalty;

        // Ensure minimum viable peers aren't completely excluded
        if peer.successful_connections > 0 && peer.failed_connections < 3 {
            score.max(10) // Minimum score for potentially good peers
        } else {
            score
        }
    }

    /// Get peer health status
    pub fn get_peer_health(peer: &PeerRecord) -> &'static str {
        let success_rate = if peer.successful_connections + peer.failed_connections > 0 {
            (peer.successful_connections as f32
                / (peer.successful_connections + peer.failed_connections) as f32)
                * 100.0
        } else {
            0.0
        };

        if success_rate >= 80.0 && peer.latency_ms < 200 {
            "Excellent"
        } else if success_rate >= 60.0 && peer.latency_ms < 500 {
            "Good"
        } else if success_rate >= 40.0 {
            "Fair"
        } else {
            "Poor"
        }
    }

    /// Add a peer
    pub async fn add_peer(&self, address: String, port: u16) {
        let db_guard = self.wallet_db.read().await;
        if let Some(db) = db_guard.as_ref() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let peer = PeerRecord {
                address: address.clone(),
                port,
                version: None,
                last_seen: now,
                first_seen: now,
                successful_connections: 0,
                failed_connections: 0,
                latency_ms: 0,
            };

            if let Err(e) = db.save_peer(&peer) {
                log::error!("❌ Failed to save peer: {}", e);
            } else {
                log::info!("➕ Added new peer: {}:{}", address, port);
            }
        }
    }

    /// Add multiple peers
    pub async fn add_peers(&self, new_peers: Vec<(String, u16)>) {
        let db_guard = self.wallet_db.read().await;
        if let Some(db) = db_guard.as_ref() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut added = 0;
            for (address, port) in new_peers {
                let peer = PeerRecord {
                    address: address.clone(),
                    port,
                    version: None,
                    last_seen: now,
                    first_seen: now,
                    successful_connections: 0,
                    failed_connections: 0,
                    latency_ms: 0,
                };

                if db.save_peer(&peer).is_ok() {
                    added += 1;
                }
            }

            if added > 0 {
                if let Ok(total) = db.get_all_peers() {
                    log::info!("➕ Added {} new peers (total: {})", added, total.len());
                }
            }
        }
    }

    /// Record successful connection with latency
    pub async fn record_success(&self, address: &str, port: u16) {
        self.record_success_with_latency(address, port, 0).await;
    }

    /// Record successful connection with measured latency
    pub async fn record_success_with_latency(&self, address: &str, port: u16, latency_ms: u64) {
        let db_guard = self.wallet_db.read().await;
        if let Some(db) = db_guard.as_ref() {
            if let Ok(peers) = db.get_all_peers() {
                if let Some(mut peer) = peers
                    .into_iter()
                    .find(|p| p.address == address && p.port == port)
                {
                    peer.successful_connections += 1;
                    peer.failed_connections = 0; // Reset failures on success
                    peer.last_seen = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    // Update latency with exponential moving average
                    if latency_ms > 0 {
                        if peer.latency_ms == 0 {
                            peer.latency_ms = latency_ms;
                        } else {
                            // EMA: new = 0.3 * current + 0.7 * old
                            peer.latency_ms =
                                ((latency_ms as f32 * 0.3) + (peer.latency_ms as f32 * 0.7)) as u64;
                        }
                    }

                    let _ = db.save_peer(&peer);
                    log::debug!(
                        "✓ Updated peer {}:{} - latency: {}ms, health: {}",
                        address,
                        port,
                        peer.latency_ms,
                        Self::get_peer_health(&peer)
                    );
                }
            }
        }
    }

    /// Record failed connection
    pub async fn record_failure(&self, address: &str, port: u16) {
        let db_guard = self.wallet_db.read().await;
        if let Some(db) = db_guard.as_ref() {
            if let Ok(peers) = db.get_all_peers() {
                if let Some(mut peer) = peers
                    .into_iter()
                    .find(|p| p.address == address && p.port == port)
                {
                    peer.failed_connections += 1;
                    if peer.failed_connections < 5 {
                        let _ = db.save_peer(&peer);
                    } else {
                        log::warn!("🗑️ Removing unhealthy peer: {}:{}", address, port);
                        let _ = db.delete_peer(address, port);
                    }
                }
            }
        }
    }

    /// Get all healthy peers sorted by score
    pub async fn get_healthy_peers(&self) -> Vec<PeerRecord> {
        self.get_healthy_peers_with_min_count(5).await
    }

    /// Get healthy peers with minimum required count
    /// If not enough excellent peers, includes fair peers to meet minimum
    pub async fn get_healthy_peers_with_min_count(&self, min_count: usize) -> Vec<PeerRecord> {
        let db_guard = self.wallet_db.read().await;
        if let Some(db) = db_guard.as_ref() {
            if let Ok(peers) = db.get_all_peers() {
                // First try to get only good peers
                let mut excellent: Vec<_> = peers
                    .iter()
                    .filter(|p| p.failed_connections < 3)
                    .cloned()
                    .collect();
                excellent.sort_by_key(|p| -Self::calculate_score(p));

                if excellent.len() >= min_count {
                    return excellent;
                }

                // If not enough good peers, include marginal ones
                let mut all_viable: Vec<_> = peers
                    .into_iter()
                    .filter(|p| p.failed_connections < 5)
                    .collect();
                all_viable.sort_by_key(|p| -Self::calculate_score(p));

                log::warn!(
                    "⚠️ Only {} excellent peers found, including {} total viable peers",
                    excellent.len(),
                    all_viable.len()
                );

                return all_viable;
            }
        }
        Vec::new()
    }

    /// Get best peer to connect to (async version)
    pub async fn get_best_peer_async(&self) -> Option<PeerRecord> {
        self.get_healthy_peers().await.into_iter().next()
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        let db_guard = self.wallet_db.read().await;
        if let Some(db) = db_guard.as_ref() {
            if let Ok(peers) = db.get_all_peers() {
                return peers.len();
            }
        }
        0
    }

    /// Get connected peer count for UI
    pub fn connected_peer_count(&self) -> usize {
        // This is sync - use runtime block_on
        tokio::runtime::Handle::current().block_on(async { self.peer_count().await })
    }

    /// Get average latency across all peers
    pub fn get_average_latency(&self) -> f64 {
        tokio::runtime::Handle::current().block_on(async {
            let db_guard = self.wallet_db.read().await;
            if let Some(db) = db_guard.as_ref() {
                if let Ok(peers) = db.get_all_peers() {
                    let valid_peers: Vec<_> = peers.iter().filter(|p| p.latency_ms > 0).collect();

                    if !valid_peers.is_empty() {
                        let total: u64 = valid_peers.iter().map(|p| p.latency_ms).sum();
                        return total as f64 / valid_peers.len() as f64;
                    }
                }
            }
            0.0
        })
    }

    /// Get best peer (lowest latency with good success rate) for UI
    pub fn get_best_peer(&self) -> Option<PeerInfo> {
        tokio::runtime::Handle::current().block_on(async {
            let db_guard = self.wallet_db.read().await;
            if let Some(db) = db_guard.as_ref() {
                if let Ok(peers) = db.get_all_peers() {
                    let mut best_peer: Option<&PeerRecord> = None;
                    let mut best_score = 0i64;

                    for peer in &peers {
                        let score = Self::calculate_score(peer);
                        if score > best_score {
                            best_score = score;
                            best_peer = Some(peer);
                        }
                    }

                    return best_peer.map(|p| {
                        let total = p.successful_connections + p.failed_connections;
                        let success_rate = if total > 0 {
                            p.successful_connections as f64 / total as f64
                        } else {
                            0.0
                        };

                        PeerInfo {
                            address: format!("{}:{}", p.address, p.port),
                            latency_ms: p.latency_ms as f64,
                            success_rate,
                            request_count: p.successful_connections,
                            failure_count: p.failed_connections,
                        }
                    });
                }
            }
            None
        })
    }

    /// Get connected peers for UI display
    pub fn get_connected_peers(&self) -> Vec<PeerInfo> {
        tokio::runtime::Handle::current().block_on(async {
            let db_guard = self.wallet_db.read().await;
            if let Some(db) = db_guard.as_ref() {
                if let Ok(peers) = db.get_all_peers() {
                    return peers
                        .iter()
                        .map(|p| {
                            let total = p.successful_connections + p.failed_connections;
                            let success_rate = if total > 0 {
                                p.successful_connections as f64 / total as f64
                            } else {
                                0.0
                            };

                            PeerInfo {
                                address: format!("{}:{}", p.address, p.port),
                                latency_ms: p.latency_ms as f64,
                                success_rate,
                                request_count: p.successful_connections,
                                failure_count: p.failed_connections,
                            }
                        })
                        .collect();
                }
            }
            Vec::new()
        })
    }

    /// Get failed connection count
    pub fn get_failed_connection_count(&self) -> u32 {
        tokio::runtime::Handle::current().block_on(async {
            let db_guard = self.wallet_db.read().await;
            if let Some(db) = db_guard.as_ref() {
                if let Ok(peers) = db.get_all_peers() {
                    return peers.iter().map(|p| p.failed_connections).sum();
                }
            }
            0
        })
    }

    /// Clean up peers with ephemeral ports and normalize to port 24100
    pub async fn cleanup_ephemeral_ports(&self) {
        let db_guard = self.wallet_db.read().await;
        if let Some(db) = db_guard.as_ref() {
            if let Ok(peers) = db.get_all_peers() {
                let mut cleaned = 0;
                for peer in peers {
                    // Skip if already on standard port
                    if peer.port == 24100 {
                        continue;
                    }

                    // Delete peer with ephemeral port
                    if let Err(e) = db.delete_peer(&peer.address, peer.port) {
                        log::warn!(
                            "Failed to delete ephemeral peer {}:{}: {}",
                            peer.address,
                            peer.port,
                            e
                        );
                    } else {
                        cleaned += 1;

                        // Add it back with standard port 24100
                        let normalized_peer = PeerRecord {
                            address: peer.address.clone(),
                            port: 24100,
                            version: peer.version,
                            last_seen: peer.last_seen,
                            first_seen: peer.first_seen,
                            successful_connections: peer.successful_connections,
                            failed_connections: peer.failed_connections,
                            latency_ms: peer.latency_ms,
                        };

                        if let Err(e) = db.save_peer(&normalized_peer) {
                            log::warn!(
                                "Failed to save normalized peer {}:24100: {}",
                                peer.address,
                                e
                            );
                        }
                    }
                }

                if cleaned > 0 {
                    log::info!(
                        "🧹 Cleaned {} ephemeral port entries, normalized to port 24100",
                        cleaned
                    );
                }
            }
        }
    }

    /// Bootstrap from seed peers
    pub async fn bootstrap(&self) -> Result<(), Box<dyn std::error::Error>> {
        // First clean up any ephemeral ports from previous sessions
        self.cleanup_ephemeral_ports().await;

        let peer_count = self.peer_count().await;

        if peer_count == 0 {
            log::warn!("⚠️  No peers available! Please configure peers in wallet.conf using 'addnode' or via API endpoint");
            return Ok(());
        }

        log::debug!("Using {} configured peers", peer_count);

        // Immediately try to get more peers from the network
        log::debug!("Discovering peers from network");
        if let Some(new_peers) = self.try_get_peer_list().await {
            self.add_peers(new_peers).await;
            log::debug!("Peer discovery complete");
        } else {
            log::warn!("⚠️ Could not discover peers from network, will retry periodically");
        }

        Ok(())
    }

    /// Request peer list from a connected peer
    pub async fn request_peer_list(
        &self,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<Vec<(String, u16)>, String> {
        use time_network::protocol::{HandshakeMessage, NetworkMessage};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Perform handshake first (required by masternode protocol)
        let network_type = match self.network {
            wallet::NetworkType::Mainnet => time_network::discovery::NetworkType::Mainnet,
            wallet::NetworkType::Testnet => time_network::discovery::NetworkType::Testnet,
        };

        // Create a dummy listen address since we're a client
        let our_addr = "0.0.0.0:0".parse().unwrap();
        let handshake = HandshakeMessage::new(network_type, our_addr);

        // Send our handshake with magic bytes
        let magic = network_type.magic_bytes();
        let handshake_json = serde_json::to_vec(&handshake).map_err(|e| e.to_string())?;
        let handshake_len = handshake_json.len() as u32;

        stream
            .write_all(&magic)
            .await
            .map_err(|e| format!("Failed to send magic bytes: {}", e))?;
        stream
            .write_all(&handshake_len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to send handshake length: {}", e))?;
        stream
            .write_all(&handshake_json)
            .await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush handshake: {}", e))?;

        // Receive their handshake (with magic bytes)
        let mut their_magic = [0u8; 4];
        stream
            .read_exact(&mut their_magic)
            .await
            .map_err(|e| format!("Failed to read handshake magic bytes: {}", e))?;

        if their_magic != magic {
            return Err(format!(
                "Invalid magic bytes in handshake response: expected {:?}, got {:?}",
                magic, their_magic
            ));
        }

        let mut their_len_bytes = [0u8; 4];
        stream
            .read_exact(&mut their_len_bytes)
            .await
            .map_err(|e| format!("Failed to read handshake response length: {}", e))?;
        let their_len = u32::from_be_bytes(their_len_bytes) as usize;

        if their_len > 10 * 1024 {
            return Err(format!("Handshake response too large: {} bytes", their_len));
        }

        let mut their_handshake_bytes = vec![0u8; their_len];
        stream
            .read_exact(&mut their_handshake_bytes)
            .await
            .map_err(|e| format!("Failed to read handshake response: {}", e))?;

        let _their_handshake: HandshakeMessage = serde_json::from_slice(&their_handshake_bytes)
            .map_err(|e| format!("Failed to parse handshake response: {}", e))?;

        // Now send GetPeerList request
        let request = NetworkMessage::GetPeerList;
        let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let len = request_bytes.len() as u32;

        log::debug!("Request JSON: {}", String::from_utf8_lossy(&request_bytes));

        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write length: {}", e))?;
        stream
            .write_all(&request_bytes)
            .await
            .map_err(|e| format!("Failed to write request: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush: {}", e))?;

        // Read response with timeout

        let mut len_bytes = [0u8; 4];

        // Add timeout for reading response
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut len_bytes)
        ).await {
            Ok(Ok(_)) => {
                let response_len = u32::from_be_bytes(len_bytes) as usize;

                if response_len > 10 * 1024 * 1024 {
                    return Err(format!("Response too large: {} bytes", response_len));
                }

                let mut response_bytes = vec![0u8; response_len];
                stream
                    .read_exact(&mut response_bytes)
                    .await
                    .map_err(|e| format!("Failed to read response body: {}", e))?;

                log::debug!("Response JSON: {}", String::from_utf8_lossy(&response_bytes));

                let response: NetworkMessage = serde_json::from_slice(&response_bytes)
                    .map_err(|e| format!("Failed to parse response: {}", e))?;

                match response {
                    NetworkMessage::PeerList(peer_addresses) => {
                        let peers: Vec<_> = peer_addresses
                            .into_iter()
                            .map(|pa| (pa.ip, pa.port))
                            .collect();

                        Ok(peers)
                    }
                    _ => Err("Unexpected response to GetPeerList".into()),
                }
            }
            Ok(Err(e)) => {
                Err(format!("Failed to read response length: {}", e))
            }
            Err(_) => {
                Err("Timeout waiting for response from masternode - masternode may not be responding to GetPeerList".to_string())
            }
        }
    }

    /// Try to get peer list from multiple peers until one succeeds
    pub async fn try_get_peer_list(&self) -> Option<Vec<(String, u16)>> {
        let healthy_peers = self.get_healthy_peers().await;

        if healthy_peers.is_empty() {
            log::warn!("⚠️ No healthy peers available");
            return None;
        }

        // Try up to 3 peers
        for peer in healthy_peers.iter().take(3) {
            let endpoint = format!("{}:{}", peer.address, peer.port);
            log::debug!("Requesting peers from {}", endpoint);

            match tokio::net::TcpStream::connect(&endpoint).await {
                Ok(mut stream) => {
                    log::debug!("Connected to {}", endpoint);

                    match self.request_peer_list(&mut stream).await {
                        Ok(new_peers) => {
                            log::debug!("Received {} peers from {}", new_peers.len(), endpoint);
                            self.record_success(&peer.address, peer.port).await;
                            return Some(new_peers);
                        }
                        Err(e) => {
                            log::error!("❌ Failed to get peer list from {}: {}", endpoint, e);
                            log::error!("   This means the masternode at {} is NOT running the latest code with GetPeerList handler", endpoint);
                            log::error!("   The masternode needs to be rebuilt and restarted!");
                            self.record_failure(&peer.address, peer.port).await;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("⚠️ Failed to connect to peer {}: {}", endpoint, e);
                    self.record_failure(&peer.address, peer.port).await;
                }
            }
        }

        None
    }

    /// Start periodic peer discovery and cleanup
    pub fn start_maintenance(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(300)); // Every 5 minutes

            loop {
                tick.tick().await;

                // Try to discover new peers from healthy peers
                if let Some(new_peers) = self.try_get_peer_list().await {
                    self.add_peers(new_peers).await;
                } else {
                    log::warn!("⚠️ Failed to get peer list from any peer, will retry in 5 minutes");
                }

                // Peers are automatically saved to database, no periodic save needed
            }
        });
    }

    /// Get peer statistics for monitoring
    pub async fn get_peer_statistics(&self) -> PeerStatistics {
        let peers = self.get_healthy_peers_with_min_count(0).await;

        let total_peers = peers.len();
        let excellent = peers
            .iter()
            .filter(|p| Self::get_peer_health(p) == "Excellent")
            .count();
        let good = peers
            .iter()
            .filter(|p| Self::get_peer_health(p) == "Good")
            .count();
        let fair = peers
            .iter()
            .filter(|p| Self::get_peer_health(p) == "Fair")
            .count();
        let poor = peers
            .iter()
            .filter(|p| Self::get_peer_health(p) == "Poor")
            .count();

        let avg_latency = if !peers.is_empty() {
            let sum: u64 = peers.iter().map(|p| p.latency_ms).sum();
            sum / peers.len() as u64
        } else {
            0
        };

        let best_latency = peers
            .iter()
            .map(|p| p.latency_ms)
            .filter(|&l| l > 0)
            .min()
            .unwrap_or(0);

        PeerStatistics {
            total_peers,
            excellent_peers: excellent,
            good_peers: good,
            fair_peers: fair,
            poor_peers: poor,
            avg_latency_ms: avg_latency,
            best_latency_ms: best_latency,
        }
    }

    /// Get diverse set of peers for consensus validation
    /// Returns up to `count` peers with best scores
    pub async fn get_diverse_peers(&self, count: usize) -> Vec<PeerRecord> {
        let mut peers = self.get_healthy_peers().await;
        peers.truncate(count);
        peers
    }
}

#[derive(Debug, Clone)]
pub struct PeerStatistics {
    pub total_peers: usize,
    pub excellent_peers: usize,
    pub good_peers: usize,
    pub fair_peers: usize,
    pub poor_peers: usize,
    pub avg_latency_ms: u64,
    pub best_latency_ms: u64,
}
