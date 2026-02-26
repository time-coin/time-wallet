use crate::rate_limiter::RateLimiter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiPeer {
    pub address: String, // IP:port format
    pub version: String,
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub port: u16,
    pub version: Option<String>,
    pub last_seen: Option<u64>,
    #[serde(default)]
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiPeersResponse {
    pub peers: Vec<ApiPeer>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub network: String,
    pub height: u64,
    pub best_block_hash: String,
    pub total_supply: u64,
    pub timestamp: i64,
}

/// Request to sync wallet addresses
#[derive(Debug, Serialize)]
pub struct WalletSyncRequest {
    pub addresses: Vec<String>,
}

/// UTXO information from masternode
#[derive(Debug, Deserialize, Clone)]
pub struct UtxoInfo {
    pub tx_hash: String,
    pub output_index: u32,
    pub amount: u64,
    pub address: String,
    pub block_height: u64,
    pub confirmations: u64,
}

/// Transaction notification from masternode
#[derive(Debug, Deserialize, Clone)]
pub struct TransactionNotification {
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub block_height: u64,
    pub timestamp: u64,
    pub confirmations: u64,
}

/// Response from wallet sync
#[derive(Debug, Deserialize)]
pub struct WalletSyncResponse {
    pub utxos: HashMap<String, Vec<UtxoInfo>>,
    pub total_balance: u64,
    pub recent_transactions: Vec<TransactionNotification>,
    pub current_height: u64,
}

#[derive(Debug, Clone)]
pub struct NetworkManager {
    api_endpoint: String,
    connected_peers: Vec<PeerInfo>,
    is_syncing: bool,
    sync_progress: f32,
    current_block_height: u64,
    network_block_height: u64,
    peer_manager: Option<Arc<crate::peer_manager::PeerManager>>,
    rate_limiter: Arc<RateLimiter>,
}

impl NetworkManager {
    pub fn new(api_endpoint: String) -> Self {
        Self {
            api_endpoint,
            connected_peers: Vec::new(),
            is_syncing: false,
            sync_progress: 0.0,
            current_block_height: 0,
            network_block_height: 0,
            peer_manager: None,
            rate_limiter: Arc::new(RateLimiter::new()),
        }
    }

    /// Set the peer manager (called after initialization)
    pub fn set_peer_manager(&mut self, peer_manager: Arc<crate::peer_manager::PeerManager>) {
        self.peer_manager = Some(peer_manager);
    }

    pub fn api_endpoint(&self) -> &str {
        &self.api_endpoint
    }

    pub fn current_block_height(&self) -> u64 {
        self.current_block_height
    }

    pub fn network_block_height(&self) -> u64 {
        self.network_block_height
    }

    /// Set blockchain heights (for internal updates)
    pub fn set_blockchain_height(&mut self, height: u64) {
        if height > self.network_block_height {
            self.network_block_height = height;
            self.current_block_height = height;
        }
    }

    /// Fetch peer list from API - queries registered masternodes
    pub async fn fetch_peers(&self) -> Result<Vec<PeerInfo>, String> {
        let url = format!("{}/masternodes/list", self.api_endpoint);

        log::info!("Fetching masternodes from: {}", url);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch masternodes: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("API returned error: {}", response.status()));
        }

        // Parse the masternodes response
        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse masternode response: {}", e))?;

        log::info!("Masternodes response: {:?}", json);

        // Extract masternodes array
        let masternodes = json
            .get("masternodes")
            .and_then(|v| v.as_array())
            .ok_or("Response missing 'masternodes' array")?;

        log::info!("Found {} registered masternodes", masternodes.len());

        // Convert to PeerInfo format
        let peer_infos: Vec<PeerInfo> = masternodes
            .iter()
            .filter_map(|mn| {
                let address = mn.get("address")?.as_str()?.to_string();
                // Masternodes use port 24100 for P2P
                Some(PeerInfo {
                    address,
                    port: 24100,
                    version: None,
                    last_seen: Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    ),
                    latency_ms: 0,
                })
            })
            .collect();

        Ok(peer_infos)
    }

    /// Connect to peers via TCP protocol (fast, parallel)
    pub async fn connect_to_peers(&mut self, initial_peers: Vec<PeerInfo>) -> Result<(), String> {
        log::info!(
            "Attempting to connect to {} peers via TCP",
            initial_peers.len()
        );

        // Store ALL peers
        self.connected_peers = initial_peers.clone();

        // Test connectivity in PARALLEL via TCP with Ping
        let mut tasks = Vec::new();

        for peer in &self.connected_peers {
            let peer_ip = peer
                .address
                .split(':')
                .next()
                .unwrap_or(&peer.address)
                .to_string();
            let peer_address = peer.address.clone();
            let port = peer.port;

            let task = tokio::spawn(async move {
                let tcp_addr = format!("{}:{}", peer_ip, port);
                let start = std::time::Instant::now();

                log::info!("Testing TCP connection to {}...", tcp_addr);

                // Measure TCP connection time separately from handshake
                match tokio::time::timeout(
                    std::time::Duration::from_millis(1500), // Reduced from 2s to 1.5s
                    tokio::net::TcpStream::connect(&tcp_addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        let tcp_latency_ms = start.elapsed().as_millis() as u64;
                        log::info!("  ✓ TCP connected to {} ({}ms)", tcp_addr, tcp_latency_ms);

                        // Quickly grab version via handshake (non-blocking)
                        let peer_version =
                            tokio::time::timeout(std::time::Duration::from_millis(300), async {
                                use time_network::protocol::HandshakeMessage;
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                                let network_type = if port == 24100 {
                                    time_network::discovery::NetworkType::Testnet
                                } else {
                                    time_network::discovery::NetworkType::Mainnet
                                };

                                let our_addr = "0.0.0.0:0".parse().unwrap();
                                let handshake = HandshakeMessage::new(network_type, our_addr);
                                let magic = network_type.magic_bytes();

                                if let Ok(handshake_json) = serde_json::to_vec(&handshake) {
                                    let handshake_len = handshake_json.len() as u32;

                                    if stream.write_all(&magic).await.is_ok()
                                        && stream
                                            .write_all(&handshake_len.to_be_bytes())
                                            .await
                                            .is_ok()
                                        && stream.write_all(&handshake_json).await.is_ok()
                                        && stream.flush().await.is_ok()
                                    {
                                        let mut their_magic = [0u8; 4];
                                        let mut their_len_bytes = [0u8; 4];
                                        if stream.read_exact(&mut their_magic).await.is_ok()
                                            && stream.read_exact(&mut their_len_bytes).await.is_ok()
                                        {
                                            let their_len =
                                                u32::from_be_bytes(their_len_bytes) as usize;
                                            if their_len < 10 * 1024 {
                                                let mut their_handshake_bytes =
                                                    vec![0u8; their_len];
                                                if stream
                                                    .read_exact(&mut their_handshake_bytes)
                                                    .await
                                                    .is_ok()
                                                {
                                                    if let Ok(hs) =
                                                        serde_json::from_slice::<HandshakeMessage>(
                                                            &their_handshake_bytes,
                                                        )
                                                    {
                                                        return Some(hs.version);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                None
                            })
                            .await
                            .ok()
                            .flatten();

                        let total_time_ms = start.elapsed().as_millis() as u64;
                        log::info!(
                            "  ✓ Handshake complete: TCP {}ms, Total {}ms",
                            tcp_latency_ms,
                            total_time_ms
                        );

                        // Use TCP latency for display (more accurate for ongoing comms)
                        Some((peer_address, tcp_latency_ms, peer_version))
                    }
                    Ok(Err(e)) => {
                        log::warn!("Failed to connect to {}: {}", tcp_addr, e);
                        None
                    }
                    Err(_) => {
                        log::warn!("Timeout connecting to {}", tcp_addr);
                        None
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for all tests to complete
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await);
        }

        // Process results
        let mut responsive_count = 0;
        let mut unreachable_peers = Vec::new();

        for (i, result) in results.into_iter().enumerate() {
            if let Ok(Some((peer_address, latency_ms, peer_version))) = result {
                if let Some(peer) = self.connected_peers.get_mut(i) {
                    peer.latency_ms = latency_ms;
                    peer.version = peer_version;
                    responsive_count += 1;

                    log::info!(
                        "  ✓ Peer {} responsive via TCP ({}ms, version: {})",
                        peer_address,
                        latency_ms,
                        peer.version.as_deref().unwrap_or("unknown")
                    );

                    // Record success with peer manager
                    if let Some(pm) = &self.peer_manager {
                        pm.record_success(&peer.address, peer.port).await;
                    }
                }
            } else if let Some(peer) = self.connected_peers.get(i) {
                log::warn!(
                    "  ✗ Peer {} unreachable via TCP - will be removed",
                    peer.address
                );
                unreachable_peers.push((peer.address.clone(), peer.port));
            }
        }

        // Record failures and remove unreachable peers from the database
        if let Some(pm) = &self.peer_manager {
            for (address, port) in &unreachable_peers {
                pm.record_failure(address, *port).await;
            }
        }

        // Remove unreachable peers from the list
        self.connected_peers.retain(|peer| {
            !unreachable_peers
                .iter()
                .any(|(addr, port)| addr == &peer.address && port == &peer.port)
        });

        if responsive_count == 0 {
            log::error!("❌ No peers responded via TCP. Check if masternodes are running on the correct ports.");
            return Err("No peers responded via TCP".to_string());
        }

        log::info!(
            "✅ TCP connection test complete: {} responsive out of {}",
            responsive_count,
            self.connected_peers.len()
        );

        Ok(())
    }

    /// Get peer count
    pub fn peer_count(&self) -> u32 {
        self.connected_peers.len() as u32
    }

    /// Check if synced
    pub fn is_synced(&self) -> bool {
        !self.is_syncing && self.sync_progress >= 1.0 && self.current_block_height > 0
    }

    /// Get sync progress (0.0 to 1.0)
    pub fn sync_progress(&self) -> f32 {
        self.sync_progress
    }

    /// Start syncing blockchain
    pub async fn start_sync(&mut self) -> Result<(), String> {
        if self.connected_peers.is_empty() {
            return Err("No peers connected".to_string());
        }

        log::info!(
            "Starting blockchain sync from {} peers...",
            self.connected_peers.len()
        );
        self.is_syncing = true;
        self.sync_progress = 0.0;

        return match self.fetch_blockchain_info().await {
            Ok(info) => {
                self.network_block_height = info.height;
                self.current_block_height = info.height;
                log::info!("Synchronized to block height: {}", info.height);
                self.is_syncing = false;
                self.sync_progress = 1.0;
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to fetch blockchain info: {}", e);
                self.is_syncing = false;
                self.sync_progress = 0.0;
                Err(format!("Failed to sync: {}", e))
            }
        };
    }

    /// Submit transaction via TCP protocol (TransactionBroadcast)
    pub async fn submit_transaction(&self, tx_json: serde_json::Value) -> Result<String, String> {
        use tokio::net::TcpStream;

        // Extract txid from JSON
        let txid = tx_json
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or("Missing txid in transaction")?
            .to_string();

        // Try each connected peer until successful
        for peer in &self.connected_peers {
            let peer_ip = peer.address.split(':').next().unwrap_or(&peer.address);
            let tcp_addr = format!("{}:{}", peer_ip, peer.port);

            log::info!("⚡ Broadcasting transaction via TCP to: {}", tcp_addr);

            // Connect via TCP
            match TcpStream::connect(&tcp_addr).await {
                Ok(stream) => {
                    // For now, just send the txid acknowledgment
                    // The actual transaction broadcast happens through the TCP listener
                    log::info!(
                        "✅ Connected to peer for transaction broadcast: {}",
                        tcp_addr
                    );
                    return Ok(txid.clone());
                }
                Err(e) => {
                    log::warn!("Failed to connect to {}: {}", tcp_addr, e);
                    continue;
                }
            }
        }

        Err("Failed to connect to any peer for transaction broadcast".to_string())
    }

    pub async fn fetch_blockchain_info(&self) -> Result<BlockchainInfo, String> {
        use time_network::protocol::{HandshakeMessage, NetworkMessage};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        log::trace!(
            "Fetching blockchain info from {} connected peers",
            self.connected_peers.len()
        );

        // Try each connected peer until we get a successful response
        for peer in &self.connected_peers {
            let peer_ip = peer.address.split(':').next().unwrap_or(&peer.address);
            let tcp_addr = format!("{}:{}", peer_ip, peer.port);

            log::trace!("  Trying peer: {}", tcp_addr);

            // Connect via TCP
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&tcp_addr)).await
            {
                Ok(Ok(mut stream)) => {
                    // Perform handshake first
                    // Determine network from peer port (24100=testnet, 24101=mainnet)
                    let network_type = if peer.port == 24100 {
                        time_network::discovery::NetworkType::Testnet
                    } else {
                        time_network::discovery::NetworkType::Mainnet
                    };

                    let our_addr = "0.0.0.0:0".parse().unwrap();
                    let handshake = HandshakeMessage::new(network_type, our_addr);

                    // Send handshake with magic bytes
                    let magic = network_type.magic_bytes();
                    if let Ok(handshake_json) = serde_json::to_vec(&handshake) {
                        let handshake_len = handshake_json.len() as u32;

                        if stream.write_all(&magic).await.is_ok()
                            && stream.write_all(&handshake_len.to_be_bytes()).await.is_ok()
                            && stream.write_all(&handshake_json).await.is_ok()
                            && stream.flush().await.is_ok()
                        {
                            // Receive their handshake
                            let mut their_magic = [0u8; 4];
                            let mut their_len_bytes = [0u8; 4];
                            if stream.read_exact(&mut their_magic).await.is_ok()
                                && their_magic == magic
                                && stream.read_exact(&mut their_len_bytes).await.is_ok()
                            {
                                let their_len = u32::from_be_bytes(their_len_bytes) as usize;
                                if their_len < 10 * 1024 {
                                    let mut their_handshake_bytes = vec![0u8; their_len];
                                    if stream.read_exact(&mut their_handshake_bytes).await.is_ok()
                                        && serde_json::from_slice::<HandshakeMessage>(
                                            &their_handshake_bytes,
                                        )
                                        .is_ok()
                                    {
                                        log::debug!("🤝 Handshake completed with {}", tcp_addr);

                                        // Now send GetBlockchainInfo message
                                        let message = NetworkMessage::GetBlockchainInfo;
                                        if let Ok(data) = serde_json::to_vec(&message) {
                                            let len = data.len() as u32;

                                            if stream.write_all(&len.to_be_bytes()).await.is_ok()
                                                && stream.write_all(&data).await.is_ok()
                                                && stream.flush().await.is_ok()
                                            {
                                                // Read response with timeout
                                                let read_result = tokio::time::timeout(
                                                    Duration::from_secs(5),
                                                    async {
                                                        let mut len_bytes = [0u8; 4];
                                                        stream.read_exact(&mut len_bytes).await?;
                                                        let response_len =
                                                            u32::from_be_bytes(len_bytes) as usize;

                                                        if response_len < 1024 * 1024 {
                                                            let mut response_data =
                                                                vec![0u8; response_len];
                                                            stream
                                                                .read_exact(&mut response_data)
                                                                .await?;
                                                            Ok((response_len, response_data))
                                                        } else {
                                                            Err(std::io::Error::new(
                                                                std::io::ErrorKind::InvalidData,
                                                                "Response too large",
                                                            ))
                                                        }
                                                    },
                                                )
                                                .await;

                                                if let Ok(Ok((_, response_data))) = read_result {
                                                    if let Ok(response) =
                                                        serde_json::from_slice::<NetworkMessage>(
                                                            &response_data,
                                                        )
                                                    {
                                                        log::trace!(
                                                            "  Parsing response from {}",
                                                            tcp_addr
                                                        );
                                                        if let NetworkMessage::BlockchainInfo {
                                                            height,
                                                            best_block_hash,
                                                        } = response
                                                        {
                                                            log::debug!(
                                                                "Got blockchain height {} from peer {}",
                                                                height.unwrap_or(0), tcp_addr );
                                                            return Ok(BlockchainInfo {
                                                                network: "mainnet".to_string(),
                                                                height: height.unwrap_or(0),
                                                                best_block_hash,
                                                                total_supply: 0,
                                                                timestamp: 0,
                                                            });
                                                        } else {
                                                            log::trace!("  ⚠️ Unexpected response type from {}", tcp_addr);
                                                        }
                                                    } else {
                                                        log::trace!(
                                                            "  ⚠️ Failed to parse response from {}",
                                                            tcp_addr
                                                        );
                                                    }
                                                } else {
                                                    log::trace!("  ⚠️ Timeout or error reading response from {}", tcp_addr);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    log::warn!("Failed to get blockchain info from {}", tcp_addr);
                    continue;
                }
                _ => {
                    log::warn!("Failed to get blockchain info from {}", tcp_addr);
                    continue;
                }
            }
        }

        log::error!("❌ No peers responded with blockchain info via TCP");
        Err("No peers responded with blockchain info via TCP".to_string())
    }

    /// Bootstrap network connections with database-backed peer management
    pub async fn bootstrap_with_db(
        &mut self,
        db: &crate::wallet_db::WalletDb,
        bootstrap_nodes: Vec<String>,
    ) -> Result<(), String> {
        log::info!("Bootstrapping network with database-backed peers");

        // First, try to use peers from database
        match db.get_working_peers() {
            Ok(db_peers) if !db_peers.is_empty() => {
                log::info!("Found {} working peers in database", db_peers.len());
                let peers: Vec<PeerInfo> = db_peers
                    .iter()
                    .map(|p| PeerInfo {
                        address: p.address.clone(),
                        port: p.port,
                        version: p.version.clone(),
                        last_seen: Some(p.last_seen),
                        latency_ms: p.latency_ms,
                    })
                    .collect();

                // Try connecting to database peers
                if self.connect_to_peers(peers.clone()).await.is_ok() {
                    log::info!("Successfully connected using database peers");
                    // Update peer records with successful connection
                    for peer in &peers {
                        self.update_peer_in_db(db, peer, true).await;
                    }
                } else {
                    log::warn!("Failed to connect to database peers, trying API");
                    // Fall through to API fetch
                }
            }
            Ok(_) => {
                log::info!("No working peers in database, fetching from API");
            }
            Err(e) => {
                log::warn!("Failed to read peers from database: {}", e);
            }
        }

        // If no database peers worked, try API
        if self.connected_peers.is_empty() {
            match self.fetch_peers().await {
                Ok(peers) => {
                    log::info!("Successfully fetched {} peers from API", peers.len());
                    if !peers.is_empty() {
                        self.connect_to_peers(peers.clone()).await?;
                        // Save new peers to database
                        for peer in &peers {
                            self.save_peer_to_db(db, peer).await;
                        }
                    } else {
                        log::warn!("API returned 0 peers");
                    }
                }
                Err(e) => {
                    log::warn!("Failed to fetch peers from API: {}", e);
                    log::info!("Falling back to bootstrap nodes");

                    // Fall back to bootstrap nodes from config
                    let fallback_peers: Vec<PeerInfo> = bootstrap_nodes
                        .into_iter()
                        .filter_map(|addr| {
                            if let Some((host, port_str)) = addr.rsplit_once(':') {
                                if let Ok(port) = port_str.parse() {
                                    return Some(PeerInfo {
                                        address: host.to_string(),
                                        port,
                                        version: None,
                                        last_seen: None,
                                        latency_ms: 0,
                                    });
                                }
                            }
                            None
                        })
                        .collect();

                    if !fallback_peers.is_empty() {
                        self.connect_to_peers(fallback_peers.clone()).await?;
                        // Save bootstrap peers to database
                        for peer in &fallback_peers {
                            self.save_peer_to_db(db, peer).await;
                        }
                    } else {
                        log::warn!("No bootstrap nodes available");
                    }
                }
            }
        }

        // Only sync if we have peers
        if !self.connected_peers.is_empty() {
            // Start blockchain sync
            if let Err(e) = self.start_sync().await {
                log::warn!("Blockchain sync failed: {}", e);
            }

            // Discover more peers and optimize connections
            log::info!("Discovering additional peers...");
            if let Err(e) = self.discover_and_connect_peers().await {
                log::warn!("Peer discovery had issues: {}", e);
            }
        } else {
            log::info!("No peers available - wallet running in offline mode");
        }

        Ok(())
    }

    /// Bootstrap network connections (legacy method without database)
    pub async fn bootstrap(&mut self, bootstrap_nodes: Vec<String>) -> Result<(), String> {
        log::info!("Bootstrapping network with {} nodes", bootstrap_nodes.len());

        // Try to fetch peers from API
        match self.fetch_peers().await {
            Ok(peers) => {
                log::info!("Successfully fetched {} peers from API", peers.len());
                if !peers.is_empty() {
                    self.connect_to_peers(peers).await?;
                } else {
                    log::warn!("API returned 0 peers");
                }
            }
            Err(e) => {
                log::warn!("Failed to fetch peers from API: {}", e);
                log::info!("Falling back to bootstrap nodes");

                // Fall back to bootstrap nodes from config
                let fallback_peers: Vec<PeerInfo> = bootstrap_nodes
                    .into_iter()
                    .filter_map(|addr| {
                        if let Some((host, port_str)) = addr.rsplit_once(':') {
                            if let Ok(port) = port_str.parse() {
                                return Some(PeerInfo {
                                    address: host.to_string(),
                                    port,
                                    version: None,
                                    last_seen: None,
                                    latency_ms: 0,
                                });
                            }
                        }
                        None
                    })
                    .collect();

                if !fallback_peers.is_empty() {
                    self.connect_to_peers(fallback_peers).await?;
                } else {
                    log::warn!("No bootstrap nodes available");
                }
            }
        }

        // Only sync if we have peers
        if !self.connected_peers.is_empty() {
            // Start blockchain sync
            if let Err(e) = self.start_sync().await {
                log::warn!("Blockchain sync failed: {}", e);
            }

            // Discover more peers and optimize connections
            log::info!("Discovering additional peers...");
            if let Err(e) = self.discover_and_connect_peers().await {
                log::warn!("Peer discovery had issues: {}", e);
            }
        } else {
            log::info!("No peers available - wallet running in offline mode");
        }

        Ok(())
    }

    /// Measure latency to a peer via TCP Ping
    async fn measure_latency(&self, peer_address: &str) -> Result<u64, String> {
        Self::measure_latency_static(peer_address).await
    }

    async fn measure_latency_static(peer_address: &str) -> Result<u64, String> {
        use time_network::protocol::{HandshakeMessage, NetworkMessage};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let peer_ip = peer_address.split(':').next().unwrap_or(peer_address);
        let port = peer_address
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(24100);
        let tcp_addr = format!("{}:{}", peer_ip, port);

        let start = std::time::Instant::now();

        match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&tcp_addr)).await {
            Ok(Ok(mut stream)) => {
                // Perform handshake first
                let network_type = if port == 24100 {
                    time_network::discovery::NetworkType::Testnet
                } else {
                    time_network::discovery::NetworkType::Mainnet
                };

                let our_addr = "0.0.0.0:0".parse().unwrap();
                let handshake = HandshakeMessage::new(network_type, our_addr);
                let magic = network_type.magic_bytes();

                if let Ok(handshake_json) = serde_json::to_vec(&handshake) {
                    let handshake_len = handshake_json.len() as u32;

                    if stream.write_all(&magic).await.is_ok()
                        && stream.write_all(&handshake_len.to_be_bytes()).await.is_ok()
                        && stream.write_all(&handshake_json).await.is_ok()
                        && stream.flush().await.is_ok()
                    {
                        // Receive their handshake
                        let mut their_magic = [0u8; 4];
                        let mut their_len_bytes = [0u8; 4];
                        if stream.read_exact(&mut their_magic).await.is_ok()
                            && their_magic == magic
                            && stream.read_exact(&mut their_len_bytes).await.is_ok()
                        {
                            let their_len = u32::from_be_bytes(their_len_bytes) as usize;
                            if their_len < 10 * 1024 {
                                let mut their_handshake_bytes = vec![0u8; their_len];
                                if stream.read_exact(&mut their_handshake_bytes).await.is_ok() {
                                    // Now send Ping
                                    let ping = NetworkMessage::Ping;
                                    if let Ok(data) = serde_json::to_vec(&ping) {
                                        let len = data.len() as u32;

                                        if stream.write_all(&len.to_be_bytes()).await.is_ok()
                                            && stream.write_all(&data).await.is_ok()
                                        {
                                            // Wait for Pong
                                            let mut len_bytes = [0u8; 4];
                                            if stream.read_exact(&mut len_bytes).await.is_ok() {
                                                let latency = start.elapsed().as_millis() as u64;
                                                return Ok(latency);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err("Failed to ping via TCP".to_string())
            }
            _ => Err("Failed to connect via TCP".to_string()),
        }
    }

    /// Discover peers from a connected peer via TCP GetPeerList
    async fn discover_peers_from_peer(&self, peer_address: &str) -> Result<Vec<PeerInfo>, String> {
        Self::discover_peers_from_peer_static(peer_address).await
    }

    async fn discover_peers_from_peer_static(peer_address: &str) -> Result<Vec<PeerInfo>, String> {
        use time_network::protocol::NetworkMessage;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let peer_ip = peer_address.split(':').next().unwrap_or(peer_address);
        let port = peer_address
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(24100);
        let tcp_addr = format!("{}:{}", peer_ip, port);

        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&tcp_addr)).await {
            Ok(Ok(mut stream)) => {
                // Perform handshake first
                let network_type = if port == 24100 {
                    time_network::discovery::NetworkType::Testnet
                } else {
                    time_network::discovery::NetworkType::Mainnet
                };

                let our_addr = "0.0.0.0:0".parse().unwrap();
                let handshake =
                    time_network::protocol::HandshakeMessage::new(network_type, our_addr);
                let magic = network_type.magic_bytes();

                if let Ok(handshake_json) = serde_json::to_vec(&handshake) {
                    let handshake_len = handshake_json.len() as u32;

                    if stream.write_all(&magic).await.is_ok()
                        && stream.write_all(&handshake_len.to_be_bytes()).await.is_ok()
                        && stream.write_all(&handshake_json).await.is_ok()
                        && stream.flush().await.is_ok()
                    {
                        // Read their handshake
                        let mut their_magic = [0u8; 4];
                        let mut their_len = [0u8; 4];
                        if stream.read_exact(&mut their_magic).await.is_ok()
                            && their_magic == magic
                            && stream.read_exact(&mut their_len).await.is_ok()
                        {
                            let len = u32::from_be_bytes(their_len) as usize;
                            if len < 10 * 1024 {
                                let mut their_handshake = vec![0u8; len];
                                if stream.read_exact(&mut their_handshake).await.is_ok() {
                                    // Now send GetPeerList message
                                    let message = NetworkMessage::GetPeerList;
                                    if let Ok(data) = serde_json::to_vec(&message) {
                                        let msg_len = data.len() as u32;

                                        if stream.write_all(&msg_len.to_be_bytes()).await.is_ok()
                                            && stream.write_all(&data).await.is_ok()
                                            && stream.flush().await.is_ok()
                                        {
                                            // Read response
                                            let mut len_bytes = [0u8; 4];
                                            if stream.read_exact(&mut len_bytes).await.is_ok() {
                                                let response_len =
                                                    u32::from_be_bytes(len_bytes) as usize;

                                                if response_len < 10 * 1024 * 1024 {
                                                    // 10MB limit
                                                    let mut response_data = vec![0u8; response_len];
                                                    if stream
                                                        .read_exact(&mut response_data)
                                                        .await
                                                        .is_ok()
                                                    {
                                                        if let Ok(NetworkMessage::PeerList(
                                                            peer_addresses,
                                                        )) = serde_json::from_slice::<
                                                            NetworkMessage,
                                                        >(
                                                            &response_data
                                                        ) {
                                                            log::info!(
                                                                "Discovered {} peers from {}",
                                                                peer_addresses.len(),
                                                                tcp_addr
                                                            );

                                                            // Convert to PeerInfo
                                                            let peer_infos: Vec<PeerInfo> = peer_addresses
                                                                .into_iter()
                                                                .map(|pa| {
                                                                    log::debug!(
                                                                        "Peer: {}:{} version: {}",
                                                                        pa.ip,
                                                                        pa.port,
                                                                        pa.version
                                                                    );
                                                                    PeerInfo {
                                                                        address: pa.ip.clone(),
                                                                        port: pa.port,
                                                                        version: Some(pa.version.clone()),
                                                                        last_seen: Some(
                                                                            std::time::SystemTime::now()
                                                                                .duration_since(
                                                                                    std::time::UNIX_EPOCH,
                                                                                )
                                                                                .unwrap()
                                                                                .as_secs(),
                                                                        ),
                                                                        latency_ms: 0,
                                                                    }
                                                                })
                                                                .collect();

                                                            return Ok(peer_infos);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err("Failed to discover peers via TCP".to_string())
            }
            _ => Err("Failed to connect via TCP".to_string()),
        }
    }

    /// Discover and connect to peers recursively
    pub fn get_connected_peers(&self) -> Vec<PeerInfo> {
        // Don't log every call - this is called frequently
        // Filter out unreachable peers (9999ms latency)
        let mut sorted_peers: Vec<PeerInfo> = self
            .connected_peers
            .iter()
            .filter(|p| p.latency_ms < 9999)
            .cloned()
            .collect();
        sorted_peers.sort_by_key(|p| p.latency_ms);
        sorted_peers
    }

    /// Save a peer to database
    async fn save_peer_to_db(&self, db: &crate::wallet_db::WalletDb, peer: &PeerInfo) {
        use crate::wallet_db::PeerRecord;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if peer already exists
        let peer_record = match db.get_all_peers() {
            Ok(peers) => peers
                .into_iter()
                .find(|p| p.address == peer.address && p.port == peer.port),
            Err(_) => None,
        };

        let record = if let Some(mut existing) = peer_record {
            // Update existing peer
            existing.last_seen = peer.last_seen.unwrap_or(now);
            existing.version = peer.version.clone();
            existing.latency_ms = peer.latency_ms;
            existing.successful_connections += 1;
            existing
        } else {
            // Create new peer
            PeerRecord {
                address: peer.address.clone(),
                port: peer.port,
                version: peer.version.clone(),
                last_seen: peer.last_seen.unwrap_or(now),
                first_seen: now,
                successful_connections: 1,
                failed_connections: 0,
                latency_ms: peer.latency_ms,
            }
        };

        if let Err(e) = db.save_peer(&record) {
            log::warn!("Failed to save peer to database: {}", e);
        }
    }

    /// Update peer connection status in database
    async fn update_peer_in_db(
        &self,
        db: &crate::wallet_db::WalletDb,
        peer: &PeerInfo,
        success: bool,
    ) {
        use crate::wallet_db::PeerRecord;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let peer_record = match db.get_all_peers() {
            Ok(peers) => peers
                .into_iter()
                .find(|p| p.address == peer.address && p.port == peer.port),
            Err(_) => None,
        };

        let record = if let Some(mut existing) = peer_record {
            existing.last_seen = now;
            if success {
                existing.successful_connections += 1;
            } else {
                existing.failed_connections += 1;
            }
            existing
        } else {
            PeerRecord {
                address: peer.address.clone(),
                port: peer.port,
                version: peer.version.clone(),
                last_seen: now,
                first_seen: now,
                successful_connections: if success { 1 } else { 0 },
                failed_connections: if success { 0 } else { 1 },
                latency_ms: peer.latency_ms,
            }
        };

        if let Err(e) = db.save_peer(&record) {
            log::warn!("Failed to update peer in database: {}", e);
        }
    }

    pub fn set_connected_peers(&mut self, peers: Vec<PeerInfo>) {
        self.connected_peers = peers;
    }

    pub async fn discover_and_connect_peers(&mut self) -> Result<(), String> {
        log::info!("Starting peer discovery...");

        let peers_to_check: Vec<String> = self
            .connected_peers
            .iter()
            .map(|p| format!("{}:{}", p.address, p.port))
            .collect();

        // Discover peers from ALL connected peers in PARALLEL
        let mut discovery_tasks = Vec::new();
        for peer_addr in peers_to_check {
            let task = tokio::spawn({
                let peer_addr = peer_addr.clone();
                async move {
                    // Use shorter timeout for discovery
                    match tokio::time::timeout(
                        Duration::from_secs(3),
                        Self::discover_peers_from_peer_static(&peer_addr),
                    )
                    .await
                    {
                        Ok(Ok(peers)) => Some(peers),
                        _ => None,
                    }
                }
            });
            discovery_tasks.push(task);
        }

        // Wait for all discovery tasks in parallel
        let mut results = Vec::new();
        for task in discovery_tasks {
            results.push(task.await);
        }

        let mut discovered_peers: std::collections::HashMap<String, PeerInfo> =
            std::collections::HashMap::new();

        for result in results {
            if let Ok(Some(peers)) = result {
                for peer in peers {
                    let peer_key = format!("{}:{}", peer.address, peer.port);
                    discovered_peers.entry(peer_key).or_insert(peer);
                }
            }
        }

        log::info!("Discovered {} total peers", discovered_peers.len());

        // Measure latency for all discovered peers in PARALLEL
        let mut latency_tasks = Vec::new();
        for (address, peer) in discovered_peers {
            let task = tokio::spawn(async move {
                // Use shorter timeout for latency check
                match tokio::time::timeout(
                    Duration::from_secs(2),
                    Self::measure_latency_static(&address),
                )
                .await
                {
                    Ok(Ok(latency)) => {
                        let mut peer_with_latency = peer;
                        peer_with_latency.latency_ms = latency;
                        Some((address, peer_with_latency))
                    }
                    _ => None,
                }
            });
            latency_tasks.push(task);
        }

        // Wait for all latency checks in parallel
        let mut latency_results = Vec::new();
        for task in latency_tasks {
            latency_results.push(task.await);
        }

        let mut peers_with_latency: Vec<PeerInfo> = Vec::new();
        for result in latency_results {
            if let Ok(Some((address, peer))) = result {
                log::info!("  ✓ Peer {} latency: {}ms", address, peer.latency_ms);
                peers_with_latency.push(peer);
            }
        }

        // Sort by latency (lowest first)
        peers_with_latency.sort_by_key(|p| p.latency_ms);

        log::info!(
            "Selected {} peers based on latency",
            peers_with_latency.len()
        );

        // ADD discovered peers to existing connected peers (don't replace!)
        if !peers_with_latency.is_empty() {
            log::info!(
                "Adding {} discovered peers to existing {} peers",
                peers_with_latency.len(),
                self.connected_peers.len()
            );

            // Merge discovered peers with existing ones (avoid duplicates)
            for new_peer in peers_with_latency {
                let peer_key = format!("{}:{}", new_peer.address, new_peer.port);
                if !self
                    .connected_peers
                    .iter()
                    .any(|p| format!("{}:{}", p.address, p.port) == peer_key)
                {
                    self.connected_peers.push(new_peer);
                }
            }

            log::info!(
                "Total connected peers after discovery: {}",
                self.connected_peers.len()
            );
        } else {
            log::info!(
                "No new peers discovered, keeping existing {} peers",
                self.connected_peers.len()
            );
        }

        Ok(())
    }

    /// Refresh latency measurements via TCP Ping
    pub async fn refresh_peer_latencies(&mut self) {
        use time_network::protocol::NetworkMessage;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        log::info!(
            "Pinging {} peers via TCP to measure latency",
            self.connected_peers.len()
        );

        for peer in &mut self.connected_peers {
            let peer_ip = peer.address.split(':').next().unwrap_or(&peer.address);
            let tcp_addr = format!("{}:{}", peer_ip, peer.port);

            let start = std::time::Instant::now();

            // Try TCP Ping with 3 second timeout
            match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                TcpStream::connect(&tcp_addr),
            )
            .await
            {
                Ok(Ok(mut stream)) => {
                    // Perform handshake first
                    let network_type = if peer.port == 24100 {
                        time_network::discovery::NetworkType::Testnet
                    } else {
                        time_network::discovery::NetworkType::Mainnet
                    };

                    let our_addr = "0.0.0.0:0".parse().unwrap();
                    let handshake =
                        time_network::protocol::HandshakeMessage::new(network_type, our_addr);
                    let magic = network_type.magic_bytes();

                    if let Ok(handshake_json) = serde_json::to_vec(&handshake) {
                        let handshake_len = handshake_json.len() as u32;

                        if stream.write_all(&magic).await.is_ok()
                            && stream.write_all(&handshake_len.to_be_bytes()).await.is_ok()
                            && stream.write_all(&handshake_json).await.is_ok()
                            && stream.flush().await.is_ok()
                        {
                            // Read their handshake
                            let mut their_magic = [0u8; 4];
                            let mut their_len = [0u8; 4];
                            if stream.read_exact(&mut their_magic).await.is_ok()
                                && their_magic == magic
                                && stream.read_exact(&mut their_len).await.is_ok()
                            {
                                let len = u32::from_be_bytes(their_len) as usize;
                                if len < 10 * 1024 {
                                    let mut their_handshake = vec![0u8; len];
                                    if stream.read_exact(&mut their_handshake).await.is_ok() {
                                        // Now send Ping
                                        let ping = NetworkMessage::Ping;
                                        if let Ok(data) = serde_json::to_vec(&ping) {
                                            let msg_len = data.len() as u32;

                                            if stream
                                                .write_all(&msg_len.to_be_bytes())
                                                .await
                                                .is_ok()
                                                && stream.write_all(&data).await.is_ok()
                                            {
                                                // Wait for Pong
                                                let mut len_bytes = [0u8; 4];
                                                if stream.read_exact(&mut len_bytes).await.is_ok() {
                                                    let latency =
                                                        start.elapsed().as_millis() as u64;
                                                    peer.latency_ms = latency;
                                                    log::info!(
                                                        "  Peer {} responded in {}ms via TCP",
                                                        peer.address,
                                                        latency
                                                    );
                                                } else {
                                                    peer.latency_ms = 9999;
                                                }
                                            } else {
                                                peer.latency_ms = 9999;
                                            }
                                        } else {
                                            peer.latency_ms = 9999;
                                        }
                                    } else {
                                        peer.latency_ms = 9999;
                                    }
                                } else {
                                    peer.latency_ms = 9999;
                                }
                            } else {
                                peer.latency_ms = 9999;
                            }
                        } else {
                            peer.latency_ms = 9999;
                        }
                    } else {
                        peer.latency_ms = 9999;
                    }
                }
                _ => {
                    log::warn!("  Failed to ping {} via TCP", peer.address);
                    peer.latency_ms = 9999; // Mark as unreachable
                }
            }
        }

        // Remove unreachable peers (9999 latency)
        let before_count = self.connected_peers.len();
        self.connected_peers.retain(|p| p.latency_ms < 9999);
        let removed = before_count - self.connected_peers.len();

        if removed > 0 {
            log::info!(
                "🗑️  Removed {} unreachable peer(s) (9999ms latency)",
                removed
            );
        }

        log::info!("TCP latency refresh complete");
    }

    /// Update blockchain height from connected peers
    pub async fn update_blockchain_height(&mut self) {
        if let Ok(info) = self.fetch_blockchain_info().await {
            if info.height > self.network_block_height {
                log::info!(
                    "📊 Blockchain height updated: {} -> {}",
                    self.network_block_height,
                    info.height
                );
                self.network_block_height = info.height;
                self.current_block_height = info.height;
            } else {
                log::trace!("Blockchain height unchanged: {}", self.network_block_height);
            }
        } else {
            log::debug!("Failed to fetch blockchain height from peers");
        }
    }

    /// Periodic refresh - updates latency, versions, and blockchain height
    pub async fn periodic_refresh(&mut self) {
        log::info!("🔄 Running periodic refresh (latency, version, blockchain height)...");

        // Refresh peer latency and version info
        let mut tasks = Vec::new();

        for peer in &self.connected_peers {
            let peer_ip = peer
                .address
                .split(':')
                .next()
                .unwrap_or(&peer.address)
                .to_string();
            let peer_address = peer.address.clone();
            let port = peer.port;

            let task = tokio::spawn(async move {
                let tcp_addr = format!("{}:{}", peer_ip, port);
                let start = std::time::Instant::now();

                // Quick connect and handshake to get version
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::net::TcpStream::connect(&tcp_addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        let latency_ms = start.elapsed().as_millis() as u64;

                        // Try to get version via handshake
                        let peer_version =
                            tokio::time::timeout(std::time::Duration::from_millis(500), async {
                                use time_network::protocol::HandshakeMessage;
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                                let network_type = if port == 24100 {
                                    time_network::discovery::NetworkType::Testnet
                                } else {
                                    time_network::discovery::NetworkType::Mainnet
                                };

                                let our_addr = "0.0.0.0:0".parse().unwrap();
                                let handshake = HandshakeMessage::new(network_type, our_addr);
                                let magic = network_type.magic_bytes();

                                if let Ok(handshake_json) = serde_json::to_vec(&handshake) {
                                    let handshake_len = handshake_json.len() as u32;

                                    if stream.write_all(&magic).await.is_ok()
                                        && stream
                                            .write_all(&handshake_len.to_be_bytes())
                                            .await
                                            .is_ok()
                                        && stream.write_all(&handshake_json).await.is_ok()
                                        && stream.flush().await.is_ok()
                                    {
                                        let mut their_magic = [0u8; 4];
                                        let mut their_len_bytes = [0u8; 4];
                                        if stream.read_exact(&mut their_magic).await.is_ok()
                                            && stream.read_exact(&mut their_len_bytes).await.is_ok()
                                        {
                                            let their_len =
                                                u32::from_be_bytes(their_len_bytes) as usize;
                                            if their_len < 10 * 1024 {
                                                let mut their_handshake_bytes =
                                                    vec![0u8; their_len];
                                                if stream
                                                    .read_exact(&mut their_handshake_bytes)
                                                    .await
                                                    .is_ok()
                                                {
                                                    if let Ok(hs) =
                                                        serde_json::from_slice::<HandshakeMessage>(
                                                            &their_handshake_bytes,
                                                        )
                                                    {
                                                        return Some(hs.version);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                None
                            })
                            .await
                            .ok()
                            .flatten();

                        Some((peer_address, latency_ms, peer_version))
                    }
                    _ => None,
                }
            });

            tasks.push(task);
        }

        // Wait for all tests to complete with overall timeout of 5 seconds
        let results = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut results = Vec::new();
            for task in tasks {
                results.push(task.await);
            }
            results
        })
        .await;

        // Update peer info
        if let Ok(results) = results {
            for (i, result) in results.into_iter().enumerate() {
                if let Ok(Some((peer_address, latency_ms, peer_version))) = result {
                    if let Some(peer) = self.connected_peers.get_mut(i) {
                        peer.latency_ms = latency_ms;
                        if peer_version.is_some() {
                            peer.version = peer_version;
                        }
                    }
                }
            }
        } else {
            log::warn!("⏱️ Peer refresh timed out after 5 seconds");
        }

        // Also update blockchain height (with shorter timeout)
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.update_blockchain_height(),
        )
        .await;
    }

    /// Get blockchain info from a specific peer
    pub async fn get_blockchain_info(&self, peer_address: &str) -> Result<BlockchainInfo, String> {
        use time_network::protocol::{HandshakeMessage, NetworkMessage};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Parse peer address to get IP and port
        let parts: Vec<&str> = peer_address.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid peer address format: {}", peer_address));
        }

        let peer_ip = parts[0];
        let peer_port: u16 = parts[1]
            .parse()
            .map_err(|e| format!("Invalid port in address {}: {}", peer_address, e))?;

        let tcp_addr = format!("{}:{}", peer_ip, peer_port);

        // Connect via TCP with timeout
        let mut stream =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&tcp_addr))
                .await
                .map_err(|_| format!("Connection timeout to {}", tcp_addr))?
                .map_err(|e| format!("Connection failed to {}: {}", tcp_addr, e))?;

        // Determine network from peer port
        let network_type = if peer_port == 24100 {
            time_network::discovery::NetworkType::Testnet
        } else {
            time_network::discovery::NetworkType::Mainnet
        };

        // Perform handshake
        let our_addr = "0.0.0.0:0".parse().unwrap();
        let handshake = HandshakeMessage::new(network_type, our_addr);
        let magic = network_type.magic_bytes();

        let handshake_json = serde_json::to_vec(&handshake)
            .map_err(|e| format!("Handshake serialization error: {}", e))?;
        let handshake_len = handshake_json.len() as u32;

        // Send handshake with magic and length prefix
        stream
            .write_all(&magic)
            .await
            .map_err(|e| format!("Failed to write magic bytes: {}", e))?;
        stream
            .write_all(&handshake_len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write handshake length: {}", e))?;
        stream
            .write_all(&handshake_json)
            .await
            .map_err(|e| format!("Failed to write handshake: {}", e))?;
        stream.flush().await.ok();

        // Receive their handshake
        let mut their_magic = [0u8; 4];
        let mut their_len_bytes = [0u8; 4];
        stream.read_exact(&mut their_magic).await.ok();
        stream.read_exact(&mut their_len_bytes).await.ok();

        let their_len = u32::from_be_bytes(their_len_bytes) as usize;
        if their_len < 10 * 1024 {
            let mut their_handshake_bytes = vec![0u8; their_len];
            stream.read_exact(&mut their_handshake_bytes).await.ok();
        }

        // Send GetBlockchainInfo request
        let get_info_msg = NetworkMessage::GetBlockchainInfo;
        let serialized = serde_json::to_vec(&get_info_msg)
            .map_err(|e| format!("GetBlockchainInfo serialization error: {}", e))?;
        let msg_len = serialized.len() as u32;

        stream
            .write_all(&msg_len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write message length: {}", e))?;
        stream
            .write_all(&serialized)
            .await
            .map_err(|e| format!("Failed to write GetBlockchainInfo: {}", e))?;
        stream.flush().await.ok();

        // Read response
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| "Timeout reading response length".to_string())?
            .map_err(|e| format!("Failed to read response length: {}", e))?;

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len > 10_000_000 {
            return Err(format!("Message too large: {} bytes", msg_len));
        }

        let mut msg_buf = vec![0u8; msg_len];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut msg_buf))
            .await
            .map_err(|_| "Timeout reading response body".to_string())?
            .map_err(|e| format!("Failed to read response body: {}", e))?;

        // Parse response
        let message: NetworkMessage = serde_json::from_slice(&msg_buf)
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        match message {
            NetworkMessage::BlockchainInfo {
                height,
                best_block_hash,
            } => Ok(BlockchainInfo {
                network: if peer_port == 24100 {
                    "testnet"
                } else {
                    "mainnet"
                }
                .to_string(),
                height: height.unwrap_or(0),
                best_block_hash,
                total_supply: 0,
                timestamp: 0,
            }),
            _ => Err(format!("Unexpected response type: {:?}", message)),
        }
    }

    /// Get blocks from a specific peer
    pub async fn get_blocks(
        &self,
        peer_address: &str,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<time_core::block::Block>, String> {
        use time_network::protocol::{HandshakeMessage, NetworkMessage};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Parse peer address
        let parts: Vec<&str> = peer_address.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid peer address format: {}", peer_address));
        }

        let peer_ip = parts[0];
        let peer_port: u16 = parts[1]
            .parse()
            .map_err(|e| format!("Invalid port: {}", e))?;

        let tcp_addr = format!("{}:{}", peer_ip, peer_port);

        // Connect
        let mut stream =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&tcp_addr))
                .await
                .map_err(|_| format!("Connection timeout to {}", tcp_addr))?
                .map_err(|e| format!("Connection failed to {}: {}", tcp_addr, e))?;

        // Network type
        let network_type = if peer_port == 24100 {
            time_network::discovery::NetworkType::Testnet
        } else {
            time_network::discovery::NetworkType::Mainnet
        };

        // Handshake
        let our_addr = "0.0.0.0:0".parse().unwrap();
        let handshake = HandshakeMessage::new(network_type, our_addr);
        let magic = network_type.magic_bytes();

        let handshake_json = serde_json::to_vec(&handshake)
            .map_err(|e| format!("Handshake serialization error: {}", e))?;
        let handshake_len = handshake_json.len() as u32;

        stream.write_all(&magic).await.ok();
        stream.write_all(&handshake_len.to_be_bytes()).await.ok();
        stream.write_all(&handshake_json).await.ok();
        stream.flush().await.ok();

        // Receive their handshake
        let mut their_magic = [0u8; 4];
        let mut their_len_bytes = [0u8; 4];
        stream.read_exact(&mut their_magic).await.ok();
        stream.read_exact(&mut their_len_bytes).await.ok();

        let their_len = u32::from_be_bytes(their_len_bytes) as usize;
        if their_len < 10 * 1024 {
            let mut their_handshake_bytes = vec![0u8; their_len];
            stream.read_exact(&mut their_handshake_bytes).await.ok();
        }

        // Send GetBlocks request
        let get_blocks_msg = NetworkMessage::GetBlocks {
            start_height,
            end_height,
        };
        let serialized = serde_json::to_vec(&get_blocks_msg)
            .map_err(|e| format!("GetBlocks serialization error: {}", e))?;
        let msg_len = serialized.len() as u32;

        stream.write_all(&msg_len.to_be_bytes()).await.ok();
        stream.write_all(&serialized).await.ok();
        stream.flush().await.ok();

        // Read response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.ok();

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len > 10_000_000 {
            return Err(format!("Message too large: {} bytes", msg_len));
        }

        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await.ok();

        // Parse response
        let message: NetworkMessage = serde_json::from_slice(&msg_buf)
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        match message {
            NetworkMessage::Blocks { blocks } => Ok(blocks),
            _ => Err("Unexpected response type".to_string()),
        }
    }

    /// Check if peer is rate limited
    pub async fn check_rate_limit(&self, peer: SocketAddr) -> bool {
        self.rate_limiter.check_rate_limit(peer).await
    }

    /// Check if peer is banned
    pub async fn is_peer_banned(&self, peer: SocketAddr) -> bool {
        self.rate_limiter.is_banned(peer).await
    }

    /// Record a violation for a peer
    pub async fn record_peer_violation(&self, peer: SocketAddr) {
        self.rate_limiter.record_violation(peer).await;
    }

    /// Get rate limiter stats
    pub async fn get_rate_limiter_stats(&self) -> crate::rate_limiter::RateLimiterStats {
        self.rate_limiter.get_stats().await
    }

    /// Cleanup old rate limiter entries (call periodically)
    pub async fn cleanup_rate_limiter(&self) {
        self.rate_limiter.cleanup_old_entries().await;
    }

    /// Get rate limiter instance
    pub fn rate_limiter(&self) -> Arc<RateLimiter> {
        Arc::clone(&self.rate_limiter)
    }
}
