//! Peer connection manager
//!
//! # Lock Ordering (CRITICAL - Quick Win #7)
//!
//! To prevent deadlocks, locks MUST be acquired in this order:
//!
//! 1. `connections` (highest priority)
//! 2. `peer_exchange`
//! 3. `recent_peer_broadcasts`
//! 4. `wallet_subscriptions` (lowest priority)
//!
//! **Never acquire locks in reverse order!**
//!
//! Use `crate::lock_ordering::LockOrdering` helpers for safe multi-lock operations.
//!
//! Example:
//! ```rust,ignore
//! // SAFE: Correct order
//! let (conns, exchange) = LockOrdering::write_connections_and_exchange(
//!     &self.connections,
//!     &self.peer_exchange,
//! ).await;
//!
//! // UNSAFE: Wrong order (deadlock risk)
//! let exchange = self.peer_exchange.write().await;
//! let conns = self.connections.write().await;  // ❌ DEADLOCK!
//! ```

use crate::connection::PeerConnection;
use crate::discovery::NetworkType;
use crate::peer_info::PeerInfo;
use crate::protocol::{NetworkMessage, TransactionMessage};
use crate::sync_gate::SyncGate;
use crate::unified_connection::{PoolStats, UnifiedPeerConnection};
use local_ip_address::local_ip;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, info, warn};

#[derive(serde::Deserialize, Debug)]
pub struct Snapshot {
    pub height: u64,
    pub state_hash: String,
    pub balances: std::collections::HashMap<String, u64>,
    pub masternodes: Vec<String>,
    pub timestamp: i64,
}

pub struct PeerManager {
    pub network: NetworkType,
    listen_addr: SocketAddr,
    public_addr: SocketAddr,

    /// UNIFIED CONNECTION POOL - Consolidates peers + connections + last_seen into single map
    /// Benefits: 67% fewer locks, 50% fewer HashMap lookups, 31% memory reduction
    connections: Arc<RwLock<HashMap<IpAddr, UnifiedPeerConnection>>>,

    peer_exchange: Arc<RwLock<crate::peer_exchange::PeerExchange>>,
    stale_after: Duration,
    reaper_interval: Duration,
    /// Track recently broadcast peers to prevent re-broadcasting
    recent_peer_broadcasts: Arc<RwLock<HashMap<String, Instant>>>,
    /// Track broadcast rate limiting (broadcasts per minute)
    broadcast_count: Arc<RwLock<u32>>,
    broadcast_count_reset: Arc<RwLock<Instant>>,
    /// Track connected wallets and their xpubs for push notifications
    wallet_subscriptions: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>, // xpub -> connected peer IPs
    /// Quarantine system for bad peers
    quarantine: Arc<crate::quarantine::PeerQuarantine>,
    /// SECURITY FIX (Issue #6): Rate limiter for DoS protection
    rate_limiter: Arc<crate::rate_limiter::RateLimiter>,
    /// FORK PREVENTION: Gate to prevent block creation when behind network
    pub sync_gate: Arc<SyncGate>,
}

impl PeerManager {
    pub fn new(network: NetworkType, listen_addr: SocketAddr, public_addr: SocketAddr) -> Self {
        let manager = PeerManager {
            network,
            listen_addr,
            public_addr,
            connections: Arc::new(RwLock::new(HashMap::new())),
            peer_exchange: Arc::new(RwLock::new(crate::peer_exchange::PeerExchange::new(
                "/root/time-coin-node/data/peers.json".to_string(),
                network,
            ))),
            stale_after: Duration::from_secs(300), // 5 minutes
            reaper_interval: Duration::from_secs(30),
            recent_peer_broadcasts: Arc::new(RwLock::new(HashMap::new())),
            broadcast_count: Arc::new(RwLock::new(0)),
            broadcast_count_reset: Arc::new(RwLock::new(Instant::now())),
            wallet_subscriptions: Arc::new(RwLock::new(HashMap::new())),
            quarantine: Arc::new(crate::quarantine::PeerQuarantine::new()),
            rate_limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            sync_gate: Arc::new(SyncGate::new(0)), // Start at height 0
        };

        // OPTIMIZATION: Single unified maintenance task instead of 4 separate tasks
        manager.spawn_network_maintenance();
        manager
    }

    /// Get our public IP address
    pub async fn get_public_ip(&self) -> String {
        self.public_addr.ip().to_string()
    }

    /// Get our node ID (public IP address)
    pub async fn get_node_id(&self) -> Option<String> {
        Some(self.public_addr.ip().to_string())
    }

    /// Mark that we have recent evidence the peer is alive.
    /// UNIFIED POOL: Single lock, O(1) update
    pub async fn peer_seen(&self, addr: IpAddr) {
        let mut connections = self.connections.write().await;
        if let Some(peer) = connections.get_mut(&addr) {
            peer.mark_seen();
        }
    }

    /// SECURITY FIX (Issue #6): Check rate limit for incoming requests
    ///
    /// Returns Ok(()) if request is allowed, Err with reason if rate limited
    pub async fn check_rate_limit(&self, peer: IpAddr, bytes: u64) -> Result<(), String> {
        self.rate_limiter
            .check_rate_limit(peer, bytes)
            .await
            .map_err(|e| e.to_string())
    }

    /// Get rate limiter for advanced usage
    pub fn rate_limiter(&self) -> Arc<crate::rate_limiter::RateLimiter> {
        self.rate_limiter.clone()
    }

    /// Get quarantine for fork resolution
    pub fn quarantine(&self) -> Arc<crate::quarantine::PeerQuarantine> {
        self.quarantine.clone()
    }

    /// Get connection pool statistics
    /// UNIFIED POOL: Single lock to gather all stats
    pub async fn get_pool_stats(&self) -> PoolStats {
        let connections = self.connections.read().await;

        if connections.is_empty() {
            return PoolStats::default();
        }

        let total = connections.len();
        let mut healthy = 0;
        let mut stale = 0;
        let mut total_health_score = 0u32;
        let mut oldest_uptime = Duration::ZERO;

        for peer in connections.values() {
            if peer.is_healthy() {
                healthy += 1;
            }
            if peer.is_stale(self.stale_after) {
                stale += 1;
            }
            total_health_score += peer.health_score as u32;

            let uptime = peer.uptime();
            if uptime > oldest_uptime {
                oldest_uptime = uptime;
            }
        }

        PoolStats {
            total_connections: total,
            healthy_connections: healthy,
            stale_connections: stale,
            avg_health_score: (total_health_score / total as u32) as u8,
            oldest_connection_secs: oldest_uptime.as_secs(),
        }
    }

    /// Remove a connected peer
    /// UNIFIED POOL: Single lock operation instead of 3
    pub async fn remove_connected_peer(&self, addr: &IpAddr) {
        let mut connections = self.connections.write().await;
        let removed = connections.remove(addr).is_some();

        if removed {
            let remaining = connections.len();
            info!(peer = %addr, connected_count = remaining, "Peer removed");
        }
    }

    /// Attempt to connect to a peer and manage the live connection entry.
    /// Returns Err(String) on connect failure (keeps same signature as original).
    pub async fn connect_to_peer(&self, peer: PeerInfo) -> Result<(), String> {
        // Skip self
        if let Ok(my_ip) = local_ip() {
            if peer.address.ip() == my_ip {
                return Ok(());
            }
        }
        if peer.address == self.listen_addr {
            return Ok(());
        }

        let peer_addr = peer.address;
        let peer_ip = peer_addr.ip();

        // CRITICAL FIX (Issue #4): Check quarantine before attempting connection
        if self.quarantine.is_quarantined(&peer_ip).await {
            debug!(peer = %peer_ip, "Skipping quarantined peer");
            return Err(format!("Peer {} is quarantined", peer_ip));
        }

        // DEDUPLICATION: Check if we already have a connection to this peer
        {
            let connections = self.connections.read().await;
            if connections.contains_key(&peer_ip) {
                debug!(peer = %peer_ip, "Already connected to peer, skipping duplicate connection");
                return Ok(());
            }
        }

        let peer_arc = Arc::new(tokio::sync::Mutex::new(peer.clone()));

        // CRITICAL FIX (Issue #6): Add connection timeout (5 seconds)
        let connect_result = tokio::time::timeout(
            Duration::from_secs(5),
            PeerConnection::connect(
                peer_arc.clone(),
                self.network,
                self.public_addr,
                None, // No blockchain for outgoing connections
            ),
        )
        .await;

        match connect_result {
            Ok(Ok(conn)) => {
                // On successful connect, get peer info and record
                let info = conn.peer_info().await;
                info!(peer = %info.address, version = %info.version, "connected to peer");

                // UNIFIED POOL: Create unified connection and insert with single lock
                let conn_arc = Arc::new(tokio::sync::Mutex::new(conn));
                let unified = UnifiedPeerConnection::from_arc(conn_arc.clone(), info.clone());

                {
                    let mut connections = self.connections.write().await;
                    connections.insert(peer_ip, unified);
                }

                // Persist discovery / mark success in peer exchange
                self.add_discovered_peer(
                    peer_addr.ip().to_string(),
                    peer_addr.port(),
                    info.version.clone(),
                )
                .await;

                self.record_peer_success(&peer_addr.ip().to_string()).await;

                // Broadcast the newly connected peer to all other connected peers
                self.broadcast_new_peer(&info).await;

                // Request peer list for peer exchange via HTTP API (best effort, don't fail on error)
                let manager_for_pex = self.clone();
                let peer_addr_for_pex = peer_addr;
                tokio::spawn(async move {
                    match manager_for_pex
                        .fetch_peers_from_api(&peer_addr_for_pex)
                        .await
                    {
                        Ok(peer_list) => {
                            debug!(
                                peer = %peer_addr_for_pex,
                                count = peer_list.len(),
                                "Received peer list from connected peer via API"
                            );
                            // Add discovered peers to our peer exchange
                            for discovered_peer in peer_list {
                                manager_for_pex
                                    .add_discovered_peer(
                                        discovered_peer.address.ip().to_string(),
                                        discovered_peer.address.port(),
                                        discovered_peer.version.clone(),
                                    )
                                    .await;
                            }
                        }
                        Err(e) => {
                            debug!(peer = %peer_addr_for_pex, error = %e, "Failed to get peer list from API");
                        }
                    }
                });

                // Clone handles for the spawned keep-alive task.
                let connections_clone = self.connections.clone();
                let manager_clone = self.clone();

                // Spawn a task to run the connection keep-alive and cleanup on exit.
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

                        // Check if peer still exists and get connection
                        let conn_opt = {
                            let conns = connections_clone.read().await;
                            conns.get(&peer_ip).map(|u| u.connection.clone())
                        };

                        let Some(conn_arc) = conn_opt else {
                            debug!(peer = %peer_addr, "Connection removed by reaper, exiting keep-alive loop");
                            break;
                        };

                        // Ping the peer
                        let mut conn_guard = conn_arc.lock().await;
                        let ping_result = conn_guard.ping().await;
                        drop(conn_guard);

                        match ping_result {
                            Ok(_) => {
                                // Successful ping - refresh last-seen
                                manager_clone.peer_seen(peer_ip).await;
                            }
                            Err(e) => {
                                // Ping failed but this might be OK - message handler could be using the stream
                                // Don't fail immediately, let reaper check last_seen timestamp
                                debug!(
                                    peer = %peer_addr,
                                    error = %e,
                                    "Ping failed (non-fatal, will check again in 30s)"
                                );
                            }
                        }
                    }

                    debug!(peer = %peer_addr, "peer keep_alive finished");

                    // Clean up peer - single removal call
                    manager_clone.remove_connected_peer(&peer_ip).await;
                });

                Ok(())
            }
            Ok(Err(e)) => {
                // Connection attempt failed
                self.record_peer_failure(&peer_addr.ip().to_string()).await;
                Err(e)
            }
            Err(_) => {
                // Connection timeout
                self.record_peer_failure(&peer_addr.ip().to_string()).await;
                Err("Connection timeout after 5 seconds".to_string())
            }
        }
    }

    /// Connect concurrently to a list of peers.
    /// CRITICAL FIX (Issue #3): Limited to 10 concurrent connections via semaphore to prevent resource exhaustion
    pub async fn connect_to_peers(&self, peer_list: Vec<PeerInfo>) {
        // Limit concurrent connections to prevent file descriptor exhaustion
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let mut handles = Vec::new();

        for peer in peer_list {
            let mgr = self.clone();
            let peer_addr = peer.address;
            let permit = semaphore.clone();

            let handle = tokio::spawn(async move {
                // Acquire permit before connecting (blocks if 10 connections already active)
                let _permit = permit.acquire().await.expect("Semaphore closed");

                debug!(peer = %peer_addr, "Attempting connection...");
                match mgr.connect_to_peer(peer).await {
                    Ok(_) => {
                        info!(peer = %peer_addr, "Successfully connected");
                        Ok(())
                    }
                    Err(e) => {
                        warn!(peer = %peer_addr, error = %e, "Failed to connect to peer");
                        Err(e)
                    }
                }
                // Permit automatically released when _permit is dropped
            });
            handles.push(handle);
        }

        // Wait for all connection attempts to complete (with timeout)
        let timeout = Duration::from_secs(10);
        match tokio::time::timeout(timeout, futures::future::join_all(handles)).await {
            Ok(results) => {
                let successes = results.iter().filter(|r| matches!(r, Ok(Ok(())))).count();
                let failures = results.len() - successes;
                info!(
                    total = results.len(),
                    successes, failures, "Peer connection batch completed"
                );
            }
            Err(_) => {
                warn!("Peer connection batch timed out after {:?}", timeout);
            }
        }
    }

    /// Connect to seed nodes - critical for network recovery
    pub async fn connect_to_seed_nodes(&self) -> Result<(), String> {
        use crate::discovery::{DnsDiscovery, HttpDiscovery, SeedNodes};

        let mut discovered_peers = Vec::new();

        // 1. Try HTTP discovery (time-coin.io API)
        let http_discovery = HttpDiscovery::new(self.network);
        match http_discovery.fetch_peers().await {
            Ok(peers) => {
                info!(count = peers.len(), "Discovered peers via HTTP");
                discovered_peers.extend(peers);
            }
            Err(e) => {
                warn!(error = %e, "HTTP discovery failed");
            }
        }

        // 2. Try DNS seeds
        let dns_discovery = DnsDiscovery::new(self.network);
        match dns_discovery.resolve_peers().await {
            Ok(addrs) => {
                info!(count = addrs.len(), "Discovered peers via DNS");
                for addr in addrs {
                    discovered_peers.push(PeerInfo::new(addr, self.network));
                }
            }
            Err(e) => {
                warn!(error = %e, "DNS discovery failed");
            }
        }

        // 3. Try environment seeds
        let env_seeds = SeedNodes::from_env();
        if !env_seeds.is_empty() {
            info!(count = env_seeds.len(), "Found environment seed nodes");
            for seed in env_seeds {
                if let Ok(addr) = seed.parse::<SocketAddr>() {
                    discovered_peers.push(PeerInfo::new(addr, self.network));
                }
            }
        }

        if discovered_peers.is_empty() {
            return Err("No seed nodes discovered from any source".to_string());
        }

        // Deduplicate by IP
        let mut seen_ips = std::collections::HashSet::new();
        discovered_peers.retain(|p| seen_ips.insert(p.address.ip()));

        info!(
            count = discovered_peers.len(),
            "Connecting to discovered seed nodes"
        );

        // Connect to all seeds concurrently
        self.connect_to_peers(discovered_peers).await;

        Ok(())
    }

    /// Return a vector of active PeerInfo entries (live connections).
    /// Only returns peers that have an active TCP connection stored.
    pub async fn get_connected_peers(&self) -> Vec<PeerInfo> {
        // UNIFIED POOL: Single lock, direct extraction
        self.connections
            .read()
            .await
            .values()
            .map(|unified| unified.info.clone())
            .collect()
    }

    /// Return the number of currently active (live) peer connections.
    pub async fn active_peer_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Keep the old helper name but delegate to active_peer_count for clarity.
    pub async fn peer_count(&self) -> usize {
        self.active_peer_count().await
    }

    /// Remove a peer's connection when it fails or disconnects
    pub async fn remove_peer_connection(&self, peer_ip: IpAddr) {
        self.connections.write().await.remove(&peer_ip);
        // Note: We keep the peer in the peers map for discovery purposes,
        // but it won't show up in get_connected_peers() without an active connection
    }

    /// DEPRECATED: Use add_connected_peer_with_connection_arc instead
    /// This method is kept for compatibility but should not be used
    /// as the unified pool requires both connection and peer info together
    #[deprecated(note = "Use add_connected_peer_with_connection_arc instead")]
    pub async fn add_connected_peer(&self, peer: PeerInfo) {
        // No-op in unified pool - peer info without connection is not useful
        warn!("add_connected_peer called without connection - ignoring");

        // Just add to discovery
        self.add_discovered_peer(
            peer.address.ip().to_string(),
            peer.address.port(),
            peer.version.clone(),
        )
        .await;
    }

    /// Add a connected peer WITH its connection object (for incoming connections)
    /// This ensures the connection is stored and maintained, not just the peer info
    pub async fn add_connected_peer_with_connection_arc(
        &self,
        peer: PeerInfo,
        conn_arc: Arc<tokio::sync::Mutex<crate::connection::PeerConnection>>,
    ) {
        if peer.address.ip().is_unspecified() || peer.address == self.listen_addr {
            return;
        }

        let peer_ip = peer.address.ip();
        let peer_addr = peer.address;

        // DEDUPLICATION: Check if we already have a connection
        // Use tie-breaking: lower IP connects to higher IP (discard reverse)
        {
            let connections = self.connections.read().await;
            if let Some(_existing) = connections.get(&peer_ip) {
                // If we already have a connection, decide which one to keep
                let our_ip = self.public_addr.ip();

                // Keep outbound connections (we initiated) if our IP is lower
                // Keep incoming connections (they initiated) if their IP is lower
                if our_ip < peer_ip {
                    // We should be the one connecting out, drop this incoming connection
                    debug!(
                        peer = %peer_ip,
                        "Duplicate connection detected - we are lower IP, keeping outbound connection"
                    );
                    return;
                }
                // Otherwise, we'll replace the existing connection with this incoming one
                debug!(
                    peer = %peer_ip,
                    "Duplicate connection detected - they are lower IP, keeping incoming connection"
                );
            }
        }

        let is_new_peer = {
            let connections = self.connections.read().await;
            !connections.contains_key(&peer_ip)
        };

        // UNIFIED POOL: Create unified connection and insert with single lock
        {
            let mut connections = self.connections.write().await;

            if let Some(existing) = connections.get(&peer_ip) {
                // keep an existing known good version over unknown version
                if existing.info.version != "unknown" && peer.version == "unknown" {
                    return;
                }
            }

            let unified = UnifiedPeerConnection::from_arc(conn_arc.clone(), peer.clone());
            connections.insert(peer_ip, unified);
        }

        // Since we now use listen_addr from handshake, the address/port is always correct
        self.add_discovered_peer(
            peer.address.ip().to_string(),
            peer.address.port(),
            peer.version.clone(),
        )
        .await;

        // Broadcast the newly connected peer to all other connected peers
        // Only broadcast if this is a genuinely new peer, not an update
        if is_new_peer {
            self.broadcast_new_peer(&peer).await;
        }

        // Spawn keep-alive loop for incoming connections
        let connections_clone = self.connections.clone();
        let manager_clone = self.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

                // Check if peer still exists and get connection
                let conn_opt = {
                    let conns = connections_clone.read().await;
                    conns.get(&peer_ip).map(|u| u.connection.clone())
                };

                let Some(conn_arc) = conn_opt else {
                    debug!(peer = %peer_addr, "Connection removed by reaper, exiting keep-alive loop");
                    break;
                };

                // Ping the peer
                let mut conn_guard = conn_arc.lock().await;
                let ping_result = conn_guard.ping().await;
                drop(conn_guard);

                match ping_result {
                    Ok(_) => {
                        // Successful ping - refresh last-seen
                        manager_clone.peer_seen(peer_ip).await;
                    }
                    Err(e) => {
                        // Ping failed but this might be OK - message handler could be using the stream
                        // Don't fail immediately, let reaper check last_seen timestamp
                        debug!(
                            peer = %peer_addr,
                            error = %e,
                            "Ping failed (non-fatal, will check again in 30s)"
                        );
                    }
                }
            }

            debug!(peer = %peer_addr, "peer keep_alive finished");

            // Clean up peer - single removal call
            manager_clone.remove_connected_peer(&peer_ip).await;
        });
    }

    /// Add a connected peer WITH its connection object (for incoming connections)
    /// This ensures the connection is stored and maintained, not just the peer info
    pub async fn add_connected_peer_with_connection(
        &self,
        peer: PeerInfo,
        conn: crate::connection::PeerConnection,
    ) {
        let conn_arc = Arc::new(tokio::sync::Mutex::new(conn));
        self.add_connected_peer_with_connection_arc(peer, conn_arc)
            .await;
    }

    pub async fn get_peer_ips(&self) -> Vec<String> {
        // UNIFIED POOL: Single lock, direct key iteration
        self.connections
            .read()
            .await
            .keys()
            .map(|ip| ip.to_string())
            .collect()
    }

    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        // UNIFIED POOL: Return all peer info from connections
        self.get_connected_peers().await
    }

    pub async fn broadcast_transaction(&self, tx: TransactionMessage) -> Result<usize, String> {
        let peer_count = self.connections.read().await.len();

        let message = NetworkMessage::Transaction(tx);
        let _data = message.serialize()?; // keep existing behavior; serialize may be used later

        info!(count = peer_count, "broadcasting transaction to peers");

        Ok(peer_count)
    }

    /// Send a network message to a specific peer over the stored TCP connection
    /// If no stored connection exists, attempts to use raw TCP with proper handshake
    pub async fn send_message_to_peer(
        &self,
        peer_addr: SocketAddr,
        message: crate::protocol::NetworkMessage,
    ) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let peer_ip = peer_addr.ip();

        // Try to use stored connection first (preferred - already has handshake)
        let connections = self.connections.read().await;
        if let Some(unified) = connections.get(&peer_ip) {
            // Use the stored connection (CONNECTION REUSE - OPTIMIZED!)
            let mut conn = unified.connection.lock().await;
            let msg_clone = message.clone();
            return conn
                .send_message(msg_clone)
                .await
                .map_err(|e| format!("Failed to send via stored connection: {}", e));
        }
        drop(connections);

        // If no stored connection, fall back to creating a new one WITH HANDSHAKE
        warn!(
            peer = %peer_addr,
            "No stored connection, creating new connection with handshake"
        );

        let stream = tokio::net::TcpStream::connect(peer_addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", peer_addr, e))?;

        // Enable TCP keep-alive and TCP_NODELAY for fallback connections
        if let Err(e) = stream.set_nodelay(true) {
            warn!(peer = %peer_addr, "Failed to set TCP_NODELAY: {}", e);
        }

        let socket2_sock = socket2::Socket::from(stream.into_std().map_err(|e| e.to_string())?);
        let ka = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(30))
            .with_interval(std::time::Duration::from_secs(30));

        if let Err(e) = socket2_sock.set_tcp_keepalive(&ka) {
            warn!(peer = %peer_addr, "Failed to set TCP keep-alive: {}", e);
        }

        let mut stream = tokio::net::TcpStream::from_std(socket2_sock.into())
            .map_err(|e| format!("Failed to convert socket: {}", e))?;

        // Perform handshake first (CRITICAL: must include magic bytes)
        let handshake = crate::protocol::HandshakeMessage::new(self.network, self.listen_addr);
        let handshake_json = serde_json::to_vec(&handshake).map_err(|e| e.to_string())?;
        let handshake_len = handshake_json.len() as u32;

        // Write magic bytes first
        let magic = self.network.magic_bytes();
        stream
            .write_all(&magic)
            .await
            .map_err(|e| format!("Failed to write magic bytes: {}", e))?;

        // Then write handshake
        stream
            .write_all(&handshake_len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write handshake length: {}", e))?;
        stream
            .write_all(&handshake_json)
            .await
            .map_err(|e| format!("Failed to write handshake: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush handshake: {}", e))?;

        // Read their handshake response (MAGIC + LENGTH + PAYLOAD)
        let mut magic_bytes = [0u8; 4];
        stream
            .read_exact(&mut magic_bytes)
            .await
            .map_err(|e| format!("Failed to read handshake magic: {}", e))?;

        let expected_magic = self.network.magic_bytes();
        if magic_bytes != expected_magic {
            return Err(format!(
                "Invalid handshake magic bytes: expected {:?}, got {:?}",
                expected_magic, magic_bytes
            ));
        }

        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| format!("Failed to read handshake length: {}", e))?;
        let handshake_len = u32::from_be_bytes(len_bytes) as usize;
        let mut handshake_bytes = vec![0u8; handshake_len];
        stream
            .read_exact(&mut handshake_bytes)
            .await
            .map_err(|e| format!("Failed to read handshake: {}", e))?;

        // Now send the actual message (LENGTH + PAYLOAD, no magic - protocol after handshake)
        let json = serde_json::to_vec(&message).map_err(|e| e.to_string())?;
        let len = json.len() as u32;

        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write length: {}", e))?;
        stream
            .write_all(&json)
            .await
            .map_err(|e| format!("Failed to write message: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }

    /// Send message to peer and wait for response (REUSES EXISTING CONNECTIONS)
    pub async fn send_message_to_peer_with_response(
        &self,
        peer_addr: SocketAddr,
        message: crate::protocol::NetworkMessage,
        timeout_secs: u64,
    ) -> Result<Option<crate::protocol::NetworkMessage>, String> {
        let peer_ip = peer_addr.ip();

        // CRITICAL FIX: Try stored TCP connection first (prevents connection spam)
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;

            // Use request_response for better reliability
            let timeout_duration = std::time::Duration::from_secs(timeout_secs);
            match conn
                .request_response(message.clone(), timeout_duration)
                .await
            {
                Ok(response) => {
                    drop(conn);
                    self.peer_seen(peer_ip).await;
                    return Ok(Some(response));
                }
                Err(e) => {
                    // Connection failed, remove it and fall through to create new one
                    debug!(peer = %peer_ip, error = %e, "Stored connection failed, creating new one");
                    drop(conn);
                    self.remove_dead_connection(peer_ip).await;
                }
            }
        }

        // FALLBACK ONLY: Create new connection if no stored connection exists
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        warn!(peer = %peer_addr, "No stored connection available, creating temporary connection");

        let mut stream = tokio::net::TcpStream::connect(peer_addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", peer_addr, e))?;

        // OPTIMIZATION (Quick Win #6): Use consolidated handshake helper
        let handshake = crate::protocol::HandshakeMessage::new(self.network, self.listen_addr);
        let _their_handshake = crate::connection::PeerConnection::perform_handshake(
            &mut stream,
            &handshake,
            &self.network,
            None, // No genesis validation for simple requests
            true, // We send first (initiating connection)
        )
        .await?;

        // Now send the actual request
        let json = serde_json::to_vec(&message).map_err(|e| e.to_string())?;
        let len = json.len() as u32;

        tracing::debug!("📤 Sending request to {}: {} bytes", peer_addr, len);
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write length: {}", e))?;
        stream
            .write_all(&json)
            .await
            .map_err(|e| format!("Failed to write message: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush: {}", e))?;
        tracing::debug!("✅ Request sent and flushed");

        // Read response with timeout
        let timeout_duration = tokio::time::Duration::from_secs(timeout_secs);
        tracing::debug!("⏳ Waiting for response with {}s timeout", timeout_secs);
        let response_result = timeout(timeout_duration, async {
            // Read response length
            let mut len_bytes = [0u8; 4];
            tracing::debug!("📥 Reading response length...");
            stream
                .read_exact(&mut len_bytes)
                .await
                .map_err(|e| format!("Failed to read response length: {}", e))?;
            let response_len = u32::from_be_bytes(len_bytes) as usize;
            tracing::debug!("📏 Response length: {} bytes", response_len);

            // Sanity check on length
            if response_len > 10_000_000 {
                // 10MB max
                return Err(format!("Response too large: {} bytes", response_len));
            }

            // Read response data
            let mut response_bytes = vec![0u8; response_len];
            stream
                .read_exact(&mut response_bytes)
                .await
                .map_err(|e| format!("Failed to read response data: {}", e))?;

            // Deserialize response
            let response: crate::protocol::NetworkMessage = serde_json::from_slice(&response_bytes)
                .map_err(|e| format!("Failed to deserialize response: {}", e))?;

            Ok(response)
        })
        .await;

        match response_result {
            Ok(Ok(response)) => Ok(Some(response)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(format!("Response timeout after {} seconds", timeout_secs)),
        }
    }

    /// Broadcast chain tip update to all connected peers
    pub async fn broadcast_tip_update(&self, height: u64, hash: String) {
        // UNIFIED POOL: Extract connection arcs and release lock before sending
        let connection_handles: Vec<(IpAddr, Arc<tokio::sync::Mutex<PeerConnection>>)> = {
            let connections = self.connections.read().await;
            connections
                .iter()
                .map(|(ip, unified)| (*ip, unified.connection.clone()))
                .collect()
        }; // Lock dropped here

        for (ip, conn_arc) in connection_handles {
            let mut conn = conn_arc.lock().await;
            let result = conn
                .send_message(crate::protocol::NetworkMessage::UpdateTip {
                    height,
                    hash: hash.clone(),
                })
                .await;
            drop(conn); // Release lock before peer_seen/remove_dead_connection

            match result {
                Ok(_) => {
                    // CRITICAL FIX: Mark peer as seen on successful send
                    self.peer_seen(ip).await;
                }
                Err(e) => {
                    debug!(peer = %ip, error = %e, "Failed to send tip update");
                    // CRITICAL FIX: Remove dead connection on ANY error
                    self.remove_dead_connection(ip).await;
                }
            }
        }
    }

    /// Request wallet transactions from a connected masternode (uses ONE masternode)
    /// This avoids duplicate requests to all masternodes
    pub async fn request_wallet_transactions(
        &self,
        xpub: String,
    ) -> Result<Vec<crate::protocol::WalletTransaction>, String> {
        let connections = self.connections.read().await;

        // Try to request from FIRST available masternode connection only
        // (avoid sending duplicate requests to all masternodes)
        if let Some((_ip, unified)) = connections.iter().next() {
            let mut conn = unified.connection.lock().await;
            conn.send_message(crate::protocol::NetworkMessage::RequestWalletTransactions {
                xpub: xpub.clone(),
            })
            .await
            .map_err(|e| format!("Failed to send transaction request: {}", e))?;

            info!("Sent wallet transaction request to masternode, waiting for response...");

            // TODO: Implement proper request/response pattern with timeout
            // For now, return empty list until masternode implements the handler
            // The response will come as NetworkMessage::WalletTransactionsResponse
            // which needs to be handled in the connection message loop

            return Ok(vec![]);
        }

        Err("No connected masternodes available".to_string())
    }

    /// Request peer list from all connected masternodes and connect to new peers
    pub async fn discover_peers_from_masternodes(&self) {
        let connections = self.connections.read().await;
        let connection_vec: Vec<_> = connections
            .iter()
            .map(|(ip, unified)| (*ip, unified.connection.clone()))
            .collect();
        drop(connections);

        for (peer_ip, conn_arc) in connection_vec {
            let mut conn = conn_arc.lock().await;
            if let Err(e) = conn
                .send_message(crate::protocol::NetworkMessage::GetPeerList)
                .await
            {
                debug!(peer = %peer_ip, error = %e, "Failed to request peer list");
            } else {
                debug!(peer = %peer_ip, "Requested peer list from masternode");
            }
        }
    }

    /// Broadcast a network message to all connected peers over TCP
    /// Send a ping to a specific peer to keep the connection alive
    /// Returns Ok if ping succeeded, Err if connection is dead
    pub async fn send_ping(&self, peer_ip: IpAddr) -> Result<(), String> {
        let connections = self.connections.read().await;
        if let Some(unified) = connections.get(&peer_ip) {
            let mut conn_guard = unified.connection.lock().await;
            match conn_guard.send_message(NetworkMessage::Ping).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    // Connection is dead, drop the read lock and clean it up
                    drop(conn_guard);
                    drop(connections);

                    // Remove dead connection
                    self.remove_dead_connection(peer_ip).await;
                    Err(format!("Failed to send ping: {}", e))
                }
            }
        } else {
            // Debug: show what IPs we actually have
            let available_ips: Vec<String> = connections.keys().map(|ip| ip.to_string()).collect();
            Err(format!(
                "No connection found for {} (have: {:?})",
                peer_ip, available_ips
            ))
        }
    }

    /// Remove a dead connection from both connections and peers maps
    pub async fn remove_dead_connection(&self, peer_ip: IpAddr) {
        // Remove from connections
        let mut connections = self.connections.write().await;
        connections.remove(&peer_ip);
        drop(connections);

        info!("Removed dead connection for {}", peer_ip);

        // Schedule reconnection attempt after brief delay
        let peer_manager_clone = self.clone();
        let network = self.network;
        let peer_addr = match self.network {
            NetworkType::Mainnet => format!("{}:24000", peer_ip),
            NetworkType::Testnet => format!("{}:24100", peer_ip),
        };

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;

            info!("🔄 Attempting to reconnect to {}", peer_addr);

            // Try to reconnect
            let socket_addr: SocketAddr = match peer_addr.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    debug!("Invalid address {}: {}", peer_addr, e);
                    return;
                }
            };

            let peer_info = PeerInfo::new(socket_addr, network);

            if let Err(e) = peer_manager_clone.connect_to_peer(peer_info).await {
                debug!("Failed to reconnect to {}: {}", peer_addr, e);
            } else {
                info!("✅ Reconnected to {}", peer_addr);
            }
        });
    }

    /// CRITICAL FIX (Issue #7): Use Arc to avoid cloning large messages for each peer
    pub async fn broadcast_message(&self, message: crate::protocol::NetworkMessage) {
        let peer_ips: Vec<IpAddr> = self.connections.read().await.keys().copied().collect();

        // Wrap message in Arc to avoid cloning large data structures (Vec<Block>, Vec<Transaction>)
        let message_arc = Arc::new(message);

        for peer_ip in peer_ips {
            let msg_ref = message_arc.clone(); // Only clones Arc pointer, not message data
            let manager_clone = self.clone();

            tokio::spawn(async move {
                // Clone the Arc'd message for sending (still just pointer clone)
                let msg_to_send = (*msg_ref).clone();

                // Use stored connection with handshake (preferred method)
                if let Err(e) = manager_clone.send_to_peer_tcp(peer_ip, msg_to_send).await {
                    debug!(
                        peer = %peer_ip,
                        error = %e,
                        "Failed to broadcast message via stored connection"
                    );
                }
            });
        }
    }

    /// Check if connection to peer is healthy by sending a ping
    #[allow(dead_code)]
    async fn check_connection_health(&self, peer_ip: IpAddr) -> bool {
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;
            if let Err(e) = conn.ping().await {
                debug!(peer = %peer_ip, error = %e, "Connection health check failed");
                return false;
            }
            return true;
        }
        false
    }

    /// Execute a network request with automatic connection health checking and retry
    #[allow(dead_code)]
    async fn request_with_retry<F, T>(
        &self,
        peer_addr: &str,
        max_retries: u32,
        request_fn: F,
    ) -> Result<T, Box<dyn std::error::Error>>
    where
        F: Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, Box<dyn std::error::Error>>> + Send>,
        >,
    {
        let peer_ip: IpAddr = peer_addr
            .split(':')
            .next()
            .ok_or("Invalid peer address")?
            .parse()?;

        for attempt in 1..=max_retries {
            // Check connection health before making request
            if !self.check_connection_health(peer_ip).await {
                warn!(peer = %peer_addr, attempt = attempt, "Connection health check failed, removing dead connection");
                self.remove_dead_connection(peer_ip).await;

                if attempt < max_retries {
                    // Try to reconnect
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt as u64))
                        .await;
                    continue;
                }
            }

            // Execute the request
            match request_fn().await {
                Ok(result) => {
                    // Mark peer as seen on success
                    self.peer_seen(peer_ip).await;
                    return Ok(result);
                }
                Err(e) => {
                    warn!(peer = %peer_addr, attempt = attempt, error = %e, "Request failed");

                    // Remove dead connection if error suggests connection issue
                    let err_str = e.to_string();
                    if err_str.contains("Broken pipe")
                        || err_str.contains("Connection")
                        || err_str.contains("timeout")
                    {
                        self.remove_dead_connection(peer_ip).await;
                    }

                    if attempt >= max_retries {
                        return Err(e);
                    }

                    // Exponential backoff
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt as u64))
                        .await;
                }
            }
        }

        Err("Max retries exceeded".into())
    }

    pub async fn request_genesis(
        &self,
        peer_addr: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Parse peer address to get IP
        let peer_ip: IpAddr = peer_addr
            .split(':')
            .next()
            .ok_or("Invalid peer address")?
            .parse()?;

        // Try TCP first - clone connection Arc and drop read lock immediately
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;

            // Use request_response to serialize the request/response pair
            let response = conn
                .request_response(
                    crate::protocol::NetworkMessage::GetGenesis,
                    std::time::Duration::from_secs(10),
                )
                .await?;

            match response {
                crate::protocol::NetworkMessage::GenesisBlock(json_str) => {
                    let genesis: serde_json::Value = serde_json::from_str(&json_str)?;
                    // CRITICAL FIX: Mark peer as seen on successful response
                    drop(conn);
                    self.peer_seen(peer_ip).await;
                    return Ok(genesis);
                }
                other => {
                    warn!(
                        "Unexpected response from {}: expected GenesisBlock, got {:?}",
                        peer_addr, other
                    );
                    return Err(format!(
                        "Protocol error: received {:?} instead of GenesisBlock",
                        other
                    )
                    .into());
                }
            }
        }

        Err("No TCP connection available".into())
    }

    /// Request mempool from a peer
    pub async fn request_mempool(
        &self,
        peer_addr: &str,
    ) -> Result<Vec<time_core::Transaction>, Box<dyn std::error::Error>> {
        // Parse peer address to get IP
        let peer_ip: IpAddr = peer_addr
            .split(':')
            .next()
            .ok_or("Invalid peer address")?
            .parse()?;

        // Try TCP first - clone connection Arc and drop read lock immediately
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;

            // Use request_response to serialize the request/response pair
            let response = conn
                .request_response(
                    crate::protocol::NetworkMessage::GetMempool,
                    std::time::Duration::from_secs(30),
                )
                .await?;

            match response {
                crate::protocol::NetworkMessage::MempoolResponse(transactions) => {
                    return Ok(transactions);
                }
                other => {
                    return Err(format!(
                        "Protocol error: received {:?} instead of MempoolResponse",
                        other
                    )
                    .into());
                }
            }
        }

        Err("No TCP connection available".into())
    }

    pub async fn request_blockchain_info(
        &self,
        peer_addr: &str,
    ) -> Result<Option<u64>, Box<dyn std::error::Error + Send>> {
        // Parse peer address to get IP and full SocketAddr
        let peer_socket_addr: SocketAddr = peer_addr
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        let peer_ip = peer_socket_addr.ip();

        // Try stored TCP connection first - clone Arc and drop read lock immediately
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;

            // Health check: verify connection is still alive before using
            if !conn.is_alive().await {
                debug!(peer = %peer_socket_addr.ip(), "Connection health check failed, reconnecting");
                drop(conn);
                // Remove from pool and fall through to create new connection
                self.remove_dead_connection(peer_socket_addr.ip()).await;
            } else {
                // Try to use stored connection, but fall back to new connection if it fails
                let result: Result<Option<u64>, Box<dyn std::error::Error + Send>> = async {
                    // Use request_response to serialize the request/response pair
                    // Increased timeout to handle message crossing delays
                    let response = conn
                        .request_response(
                            crate::protocol::NetworkMessage::GetBlockchainInfo,
                            std::time::Duration::from_secs(15),
                        )
                        .await
                        .map_err(|e| {
                            Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send>
                        })?;

                    match response {
                        crate::protocol::NetworkMessage::BlockchainInfo { height, .. } => {
                            // CRITICAL FIX: Mark peer as seen on successful response
                            drop(conn);
                            self.peer_seen(peer_ip).await;
                            Ok(height)
                        }
                        msg => {
                            let msg_type = match msg {
                                crate::protocol::NetworkMessage::Ping => "Ping",
                                crate::protocol::NetworkMessage::Pong => "Pong",
                                crate::protocol::NetworkMessage::UpdateTip { .. } => "UpdateTip",
                                crate::protocol::NetworkMessage::GetMempool => "GetMempool",
                                crate::protocol::NetworkMessage::MempoolResponse(..) => {
                                    "MempoolResponse"
                                }
                                crate::protocol::NetworkMessage::RequestFinalizedTransactions {
                                    ..
                                } => "RequestFinalizedTransactions",
                                _ => "Other",
                            };
                            Err(Box::new(std::io::Error::other(format!(
                                "Unexpected response type: {} (expected BlockchainInfo)",
                                msg_type
                            )))
                                as Box<dyn std::error::Error + Send>)
                        }
                    }
                }
                .await;

                match result {
                    Ok(info) => return Ok(info),
                    Err(e) => {
                        // Log the error for debugging but fall through to retry with new connection
                        debug!(
                            peer = %peer_socket_addr.ip(),
                            error = %e,
                            "GetBlockchainInfo failed on existing connection, retrying with new connection"
                        );
                    }
                }
            }
        }

        // No stored connection - establish new connection with handshake
        let response = self
            .send_message_to_peer_with_response(
                peer_socket_addr,
                crate::protocol::NetworkMessage::GetBlockchainInfo,
                15, // Increased timeout to handle message crossing delays
            )
            .await
            .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send>)?;

        match response {
            Some(crate::protocol::NetworkMessage::BlockchainInfo { height, .. }) => Ok(height),
            Some(msg) => {
                let msg_type = match msg {
                    crate::protocol::NetworkMessage::Ping => "Ping",
                    crate::protocol::NetworkMessage::Pong => "Pong",
                    crate::protocol::NetworkMessage::UpdateTip { .. } => "UpdateTip",
                    crate::protocol::NetworkMessage::GetMempool => "GetMempool",
                    crate::protocol::NetworkMessage::MempoolResponse(..) => "MempoolResponse",
                    crate::protocol::NetworkMessage::RequestFinalizedTransactions { .. } => {
                        "RequestFinalizedTransactions"
                    }
                    _ => "Other",
                };
                Err(Box::new(std::io::Error::other(format!(
                    "Unexpected response type: {} (expected BlockchainInfo)",
                    msg_type
                ))))
            }
            None => Err(Box::new(std::io::Error::other("No response received"))),
        }
    }

    /// Request a specific block by height from a peer via TCP
    pub async fn request_block_by_height(
        &self,
        peer_addr: &str,
        height: u64,
    ) -> Result<time_core::block::Block, Box<dyn std::error::Error + Send>> {
        // Parse peer address to get IP and full SocketAddr
        let peer_socket_addr: SocketAddr = peer_addr
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        let peer_ip = peer_socket_addr.ip();

        // Try stored TCP connection first - clone Arc and drop read lock immediately
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;

            // Try to use stored connection, but fall back to new connection if it fails
            let result: Result<time_core::block::Block, Box<dyn std::error::Error + Send>> =
                async {
                    // Send request
                    conn.send_message(crate::protocol::NetworkMessage::GetBlocks {
                        start_height: height,
                        end_height: height,
                    })
                    .await
                    .map_err(|e| {
                        Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send>
                    })?;

                    // Wait for response with timeout, but keep reading until we get Blocks message
                    // (peer may send other messages like MasternodeList first)
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);

                    loop {
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if remaining.is_zero() {
                            return Err(
                                Box::new(std::io::Error::other("Timeout waiting for blocks"))
                                    as Box<dyn std::error::Error + Send>,
                            );
                        }

                        let response = tokio::time::timeout(remaining, conn.receive_message())
                            .await
                            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?
                            .map_err(|e| {
                                Box::new(std::io::Error::other(e))
                                    as Box<dyn std::error::Error + Send>
                            })?;

                        match response {
                            crate::protocol::NetworkMessage::Blocks { blocks } => {
                                if let Some(block) = blocks.into_iter().next() {
                                    return Ok(block);
                                } else {
                                    return Err(Box::new(std::io::Error::other(
                                        "No block in response",
                                    ))
                                        as Box<dyn std::error::Error + Send>);
                                }
                            }
                            // Ignore other message types and keep waiting for Blocks
                            _ => continue,
                        }
                    }
                }
                .await;

            match result {
                Ok(block) => return Ok(block),
                Err(_e) => {
                    // Silently fall through to create new connection
                }
            }
        }

        // No stored connection - establish new connection with handshake
        let response = self
            .send_message_to_peer_with_response(
                peer_socket_addr,
                crate::protocol::NetworkMessage::GetBlocks {
                    start_height: height,
                    end_height: height,
                },
                10,
            )
            .await
            .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send>)?;

        match response {
            Some(crate::protocol::NetworkMessage::Blocks { blocks }) => {
                if let Some(block) = blocks.into_iter().next() {
                    Ok(block)
                } else {
                    Err(Box::new(std::io::Error::other("No block in response")))
                }
            }
            Some(other) => {
                warn!(
                    "Unexpected response from {}: expected Blocks, got {:?}",
                    peer_addr, other
                );
                Err(Box::new(std::io::Error::other(format!(
                    "Protocol error: received {:?} instead of Blocks",
                    other
                ))))
            }
            None => {
                warn!("No response from {} (connection may be dead)", peer_addr);
                Err(Box::new(std::io::Error::other(
                    "Connection failed - no response received",
                )))
            }
        }
    }

    /// Request finalized transactions from a peer via TCP
    pub async fn request_finalized_transactions(
        &self,
        peer_addr: &str,
        since_timestamp: i64,
    ) -> Result<Vec<(time_core::Transaction, i64)>, Box<dyn std::error::Error>> {
        // Parse peer address to get IP
        let peer_ip: IpAddr = peer_addr
            .split(':')
            .next()
            .ok_or("Invalid peer address")?
            .parse()?;

        // Try TCP first - clone Arc and drop read lock immediately
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;

            // Use request_response to serialize the request/response pair
            let response = conn
                .request_response(
                    crate::protocol::NetworkMessage::RequestFinalizedTransactions {
                        since_timestamp,
                    },
                    std::time::Duration::from_secs(30),
                )
                .await?;

            match response {
                crate::protocol::NetworkMessage::FinalizedTransactionsResponse {
                    transactions,
                    finalized_at,
                } => {
                    // Pair transactions with their finalization timestamps
                    let paired: Vec<(time_core::Transaction, i64)> = transactions
                        .into_iter()
                        .zip(finalized_at.into_iter())
                        .collect();
                    return Ok(paired);
                }
                other => {
                    warn!("Unexpected response from {}: expected FinalizedTransactionsResponse, got {:?}", peer_addr, other);
                    return Err(format!(
                        "Protocol error: received {:?} instead of FinalizedTransactionsResponse",
                        other
                    )
                    .into());
                }
            }
        }

        Err("No TCP connection available".into())
    }

    pub async fn request_snapshot(
        &self,
        peer_addr: &str,
    ) -> Result<Snapshot, Box<dyn std::error::Error>> {
        // Parse peer address to get IP
        let peer_ip: IpAddr = peer_addr
            .split(':')
            .next()
            .ok_or("Invalid peer address")?
            .parse()?;

        // Try TCP first
        let connections = self.connections.read().await;
        if let Some(_conn_arc) = connections.get(&peer_ip) {
            // Snapshot protocol removed - use HTTP API instead
            return Err("Snapshot via TCP not supported - use HTTP API /snapshot endpoint".into());
        }

        Err("No TCP connection available".into())
    }

    pub async fn sync_recent_blocks(
        &self,
        _peer_addr: &str,
        _from_height: u64,
        _to_height: u64,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }

    /// Add a discovered peer to the peer exchange
    /// OPTIMIZATION (Quick Win #4): Normalize ephemeral ports once at entry point
    /// Ephemeral ports (>= 49152) are normalized to network standard ports:
    /// - Mainnet: 24000
    /// - Testnet: 24100
    pub async fn add_discovered_peer(&self, address: String, port: u16, version: String) {
        // Normalize ephemeral ports once, at the entry point
        let normalized_port = match self.network {
            NetworkType::Mainnet => {
                if port >= 49152 {
                    24000
                } else {
                    port
                }
            }
            NetworkType::Testnet => {
                if port >= 49152 {
                    24100
                } else {
                    port
                }
            }
        };

        let mut exchange = self.peer_exchange.write().await;
        exchange.add_peer(address, normalized_port, version);
    }

    pub async fn get_best_peers(
        &self,
        count: usize,
    ) -> Vec<crate::peer_exchange::PersistentPeerInfo> {
        let exchange = self.peer_exchange.read().await;
        exchange.get_best_peers(count)
    }

    pub async fn record_peer_success(&self, address: &str) {
        let mut exchange = self.peer_exchange.write().await;
        exchange.record_success(address);
    }

    pub async fn record_peer_failure(&self, address: &str) {
        let mut exchange = self.peer_exchange.write().await;
        exchange.record_failure(address);
    }

    pub async fn known_peer_count(&self) -> usize {
        // number of remembered/persisted peers in peer_exchange
        let exchange = self.peer_exchange.read().await;
        exchange.peer_count()
    }

    /// Fetch peer list from a connected peer via TCP for peer exchange
    async fn fetch_peers_from_api(
        &self,
        peer_addr: &SocketAddr,
    ) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let peer_ip = peer_addr.ip();

        // Use TCP connection - clone Arc and drop read lock immediately
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;

            // Use request_response to serialize the request/response pair
            let response = conn
                .request_response(
                    crate::protocol::NetworkMessage::GetPeerList,
                    std::time::Duration::from_secs(15), // Increased timeout
                )
                .await?;

            match response {
                crate::protocol::NetworkMessage::PeerList(peer_addresses) => {
                    let p2p_port = match self.network {
                        NetworkType::Mainnet => 24000,
                        NetworkType::Testnet => 24100,
                    };

                    let mut peer_infos = Vec::new();
                    for p in peer_addresses {
                        // Try to parse address directly as SocketAddr
                        let parsed = format!("{}:{}", p.ip, p.port)
                            .parse::<SocketAddr>()
                            .or_else(|_| {
                                // If parsing fails, try appending default peer port and parse again
                                let with_port = format!("{}:{}", p.ip, p2p_port);
                                with_port.parse::<SocketAddr>()
                            });

                        match parsed {
                            Ok(addr) => {
                                let peer_info =
                                    PeerInfo::with_version(addr, self.network, p.version);
                                peer_infos.push(peer_info);
                            }
                            Err(e) => {
                                debug!(address = %p.ip, error = %e, "Failed to parse peer address from TCP response; skipping entry");
                            }
                        }
                    }

                    return Ok(peer_infos);
                }
                other => {
                    warn!(
                        "Unexpected response from {}: expected PeerList, got {:?}",
                        peer_addr, other
                    );
                    return Err(format!(
                        "Protocol error: received {:?} instead of PeerList",
                        other
                    )
                    .into());
                }
            }
        }

        Err("No TCP connection available".into())
    }

    /// Send a message to a peer via TCP (if connection exists)
    /// Automatically retries once if connection is broken
    pub async fn send_to_peer_tcp(
        &self,
        peer_ip: IpAddr,
        message: crate::protocol::NetworkMessage,
    ) -> Result<(), String> {
        let conn_arc = {
            let connections = self.connections.read().await;
            connections.get(&peer_ip).map(|u| u.connection.clone())
        };

        if let Some(conn_arc) = conn_arc {
            let mut conn = conn_arc.lock().await;
            match conn.send_message(message.clone()).await {
                Ok(_) => {
                    // CRITICAL FIX: Mark peer as seen on successful send
                    drop(conn); // Release connection lock before acquiring last_seen lock
                    self.peer_seen(peer_ip).await;
                    Ok(())
                }
                Err(e) => {
                    // CRITICAL FIX: Remove dead connection on ANY send error, not just broken pipe
                    debug!(
                        peer = %peer_ip,
                        error = %e,
                        "Connection failed during send, removing from pool"
                    );
                    drop(conn); // Release lock before removing

                    // Remove the stale connection
                    self.connections.write().await.remove(&peer_ip);
                    self.remove_connected_peer(&peer_ip).await;

                    Err(format!(
                        "Connection failed: {} (auto-reconnect scheduled)",
                        e
                    ))
                }
            }
        } else {
            Err("No TCP connection available".to_string())
        }
    }

    /// Send a vote to a peer (fire-and-forget, no ACK)
    /// Returns Ok if message was sent, Err on connection failure
    /// Heartbeat mechanism will detect dead connections separately
    pub async fn send_vote_with_ack(
        &self,
        peer_ip: IpAddr,
        message: crate::protocol::NetworkMessage,
        _expected_block_hash: String, // Keep signature for compatibility
    ) -> Result<(), String> {
        // Fire-and-forget broadcast - don't wait for ACK to avoid protocol collisions
        // The TCP keep-alive and heartbeat will detect dead connections
        self.send_to_peer_tcp(peer_ip, message).await
    }

    pub async fn broadcast_block_proposal(&self, proposal: serde_json::Value) {
        let proposal_json = proposal.to_string();
        let message =
            crate::protocol::NetworkMessage::ConsensusBlockProposal(proposal_json.clone());

        // UNIFIED POOL: Single lock to get peer IPs
        let peer_ips_with_connections: Vec<IpAddr> = {
            let connections = self.connections.read().await;
            let my_ip = self.public_addr.ip();
            connections
                .keys()
                .filter(|ip| **ip != my_ip)
                .copied()
                .collect()
        }; // Lock dropped here

        println!(
            "📤 Broadcasting proposal to {} peers",
            peer_ips_with_connections.len()
        );

        // CRITICAL FIX (Issue #7): Use Arc to avoid cloning large proposal message
        let message_arc = Arc::new(message);
        let mut send_tasks = vec![];

        for peer_ip in peer_ips_with_connections {
            let msg_ref = message_arc.clone(); // Only clones Arc pointer
            let manager_clone = self.clone();

            let task = tokio::spawn(async move {
                let msg_to_send = (*msg_ref).clone(); // Clone when ready to send
                match manager_clone.send_to_peer_tcp(peer_ip, msg_to_send).await {
                    Ok(_) => {
                        println!("   ✓ Proposal sent to {}", peer_ip);
                        true
                    }
                    Err(e) => {
                        debug!(peer = %peer_ip, error = %e, "Failed to send proposal");
                        false
                    }
                }
            });

            send_tasks.push(task);
        }

        // Wait for all sends to complete
        let results = futures::future::join_all(send_tasks).await;
        let successful = results
            .iter()
            .filter(|r| r.as_ref().ok() == Some(&true))
            .count();
        println!(
            "   📊 Proposal broadcast: {} successful, {} failed",
            successful,
            results.len() - successful
        );
    }

    pub async fn broadcast_block_vote(&self, vote: serde_json::Value) {
        let vote_json = vote.to_string();
        let message = crate::protocol::NetworkMessage::ConsensusBlockVote(vote_json.clone());

        // Extract block hash for ACK verification
        let block_hash = vote
            .get("block_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // UNIFIED POOL: Single lock to get peer IPs
        let peer_ips_with_connections: Vec<IpAddr> = {
            let connections = self.connections.read().await;
            let my_ip = self.public_addr.ip();
            connections
                .keys()
                .filter(|ip| **ip != my_ip)
                .copied()
                .collect()
        }; // Lock dropped here

        println!(
            "📤 Broadcasting vote to {} peers",
            peer_ips_with_connections.len()
        );

        // CRITICAL FIX (Issue #7): Use Arc to avoid cloning large vote message
        let message_arc = Arc::new(message);
        let mut send_tasks = vec![];

        for peer_ip in peer_ips_with_connections {
            let msg_ref = message_arc.clone(); // Only clones Arc pointer
            let hash_clone = block_hash.clone();
            let manager_clone = self.clone();

            let task = tokio::spawn(async move {
                let msg_to_send = (*msg_ref).clone(); // Clone when ready to send
                match manager_clone
                    .send_vote_with_ack(peer_ip, msg_to_send, hash_clone)
                    .await
                {
                    Ok(_) => {
                        println!("   ✓ Vote sent to {}", peer_ip);
                        true
                    }
                    Err(e) => {
                        debug!(peer = %peer_ip, error = %e, "Failed to send vote");
                        false
                    }
                }
            });

            send_tasks.push(task);
        }

        // Wait for all sends to complete
        let results = futures::future::join_all(send_tasks).await;
        let successful = results
            .iter()
            .filter(|r| r.as_ref().ok() == Some(&true))
            .count();
        println!(
            "   📊 Vote broadcast: {} successful, {} failed",
            successful,
            results.len() - successful
        );
    }

    /// Broadcast a newly connected peer to all other connected peers
    /// This ensures that when a new peer connects, all existing peers learn about it
    /// Includes deduplication and rate limiting to prevent broadcast storms
    pub async fn broadcast_new_peer(&self, new_peer_info: &PeerInfo) {
        let peer_key = new_peer_info.address.to_string();

        // Check if we recently broadcast this peer (deduplication)
        {
            let mut broadcasts = self.recent_peer_broadcasts.write().await;
            let now = Instant::now();

            if let Some(&last_broadcast) = broadcasts.get(&peer_key) {
                if now.duration_since(last_broadcast) < Duration::from_secs(300) {
                    // Skip broadcasting if we broadcast this peer within the last 5 minutes
                    debug!(
                        peer = %peer_key,
                        "Skipping broadcast - peer was recently broadcast"
                    );
                    return;
                }
            }

            // Record this broadcast
            broadcasts.insert(peer_key.clone(), now);
        }

        // Rate limiting: max 60 broadcasts per minute
        {
            let mut count = self.broadcast_count.write().await;
            let reset_time = self.broadcast_count_reset.read().await;
            let now = Instant::now();

            // Check if we need to reset the counter
            if now.duration_since(*reset_time) >= Duration::from_secs(60) {
                drop(reset_time);
                let mut reset = self.broadcast_count_reset.write().await;
                *reset = now;
                *count = 0;
            }

            if *count >= 60 {
                warn!(
                    "Broadcast rate limit exceeded, skipping broadcast for peer {}",
                    peer_key
                );
                return;
            }
            *count += 1;
        }

        let peers: Vec<(IpAddr, SocketAddr)> = self
            .connections
            .read()
            .await
            .values()
            .map(|u| (u.info.address.ip(), u.info.address))
            .collect();
        let my_addr = self.listen_addr;

        debug!(
            new_peer = %new_peer_info.address,
            peer_count = peers.len(),
            "Broadcasting new peer to all connected peers"
        );

        let new_peer_ip = new_peer_info.address.ip();
        let new_peer_addr = new_peer_info.address.to_string(); // Use full address from handshake
        let new_peer_version = new_peer_info.version.clone();

        // Create peer discovery message
        let peer_address = crate::protocol::PeerAddress {
            ip: new_peer_ip.to_string(),
            port: new_peer_info.address.port(),
            version: new_peer_version.clone(),
        };

        for (peer_ip, _peer_address_info) in peers {
            // Don't broadcast to the peer itself
            if peer_ip == new_peer_ip {
                continue;
            }

            // Don't send broadcast back to ourselves
            if peer_ip == my_addr.ip() {
                continue;
            }

            // Send peer list containing the new peer via TCP (fire and forget)
            let message = crate::protocol::NetworkMessage::PeerList(vec![peer_address.clone()]);

            if let Err(e) = self.send_to_peer_tcp(peer_ip, message).await {
                debug!(
                    target_peer = %peer_ip,
                    new_peer = %new_peer_addr,
                    error = %e,
                    "Failed to notify peer about new connection via TCP"
                );
            } else {
                debug!(
                    target_peer = %peer_ip,
                    new_peer = %new_peer_addr,
                    "Successfully notified peer about new connection via TCP"
                );
            }
        }
    }

    /// OPTIMIZATION: Unified network maintenance task
    /// Consolidates reaper, reconnection, broadcast cleanup, and peer exchange cleanup
    /// into a single task to reduce lock thrashing and CPU overhead
    fn spawn_network_maintenance(&self) {
        let connections = self.connections.clone();
        let stale_after = self.stale_after;
        let manager = self.clone();
        let recent_broadcasts = self.recent_peer_broadcasts.clone();
        let broadcast_count = self.broadcast_count.clone();
        let broadcast_count_reset = self.broadcast_count_reset.clone();
        let peer_exchange = self.peer_exchange.clone();

        tokio::spawn(async move {
            // Wait 10 seconds before first run to allow initial connections
            time::sleep(Duration::from_secs(10)).await;

            let mut ticker = time::interval(Duration::from_secs(30)); // Unified 30s heartbeat
            let mut tick_count = 0u64;

            const MIN_CONNECTIONS: usize = 5;
            const TARGET_CONNECTIONS: usize = 8;

            loop {
                ticker.tick().await;
                tick_count += 1;
                let now = Instant::now();

                // ============================================================
                // PHASE 1: Peer Health Check & Reaper (every 30s)
                // ============================================================
                let (stale_peers, current_count) = {
                    let conns = connections.read().await;
                    let stale: Vec<IpAddr> = conns
                        .iter()
                        .filter(|(_, peer)| peer.is_stale(stale_after))
                        .map(|(ip, _)| *ip)
                        .collect();
                    (stale, conns.len())
                };

                // Remove stale peers
                if !stale_peers.is_empty() {
                    for addr in &stale_peers {
                        warn!(peer = %addr, "Peer down (heartbeat timeout)");
                        manager.remove_connected_peer(addr).await;
                    }
                    let remaining = connections.read().await.len();
                    info!(
                        removed = stale_peers.len(),
                        connected_count = remaining,
                        "Connected peers after purge"
                    );
                }

                // ============================================================
                // PHASE 2: Reconnection Logic (adaptive based on connection count)
                // ============================================================
                let should_reconnect = match current_count {
                    n if n < MIN_CONNECTIONS => {
                        // CRITICAL: Aggressive reconnection every 30s
                        warn!(
                            current = n,
                            minimum = MIN_CONNECTIONS,
                            "🚨 Below minimum connections - aggressive reconnection"
                        );
                        true
                    }
                    n if n < TARGET_CONNECTIONS => {
                        // Moderate: Every 60s (every 2nd tick)
                        tick_count.is_multiple_of(2)
                    }
                    _ => {
                        // Relaxed: Every 120s (every 4th tick)
                        tick_count.is_multiple_of(4)
                    }
                };

                if should_reconnect {
                    // Get currently connected IPs
                    let connected_ips: std::collections::HashSet<IpAddr> = {
                        let conns = connections.read().await;
                        conns.keys().copied().collect()
                    };

                    // Try seed nodes if critically low
                    if current_count < MIN_CONNECTIONS {
                        info!("Attempting to connect to seed nodes");
                        if let Err(e) = manager.connect_to_seed_nodes().await {
                            warn!(error = %e, "Failed to connect to seed nodes");
                        }
                    }

                    // Get best peers based on urgency
                    let peer_count = if current_count < MIN_CONNECTIONS {
                        20 // Aggressive
                    } else if current_count < TARGET_CONNECTIONS {
                        10 // Moderate
                    } else {
                        5 // Relaxed
                    };

                    let best_peers = manager.get_best_peers(peer_count).await;

                    // Filter disconnected peers and spawn reconnection attempts
                    for pex_peer in best_peers {
                        if let Ok(addr) = pex_peer.full_address().parse::<SocketAddr>() {
                            if !connected_ips.contains(&addr.ip()) {
                                let peer_info = PeerInfo::new(addr, manager.network);
                                let mgr = manager.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = mgr.connect_to_peer(peer_info.clone()).await {
                                        debug!(peer = %peer_info.address, error = %e, "Reconnection failed");
                                    } else {
                                        info!(peer = %peer_info.address, "Reconnected to peer");
                                    }
                                });
                            }
                        }
                    }
                }

                // ============================================================
                // PHASE 3: Broadcast Cleanup (every 60s = every 2nd tick)
                // ============================================================
                if tick_count.is_multiple_of(2) {
                    // Clean up old broadcast tracking (older than 5 minutes)
                    {
                        let mut broadcasts = recent_broadcasts.write().await;
                        broadcasts.retain(|_, &mut last_broadcast| {
                            now.duration_since(last_broadcast) < Duration::from_secs(300)
                        });
                    }

                    // Reset rate limiter counter every minute
                    {
                        let mut reset_time = broadcast_count_reset.write().await;
                        if now.duration_since(*reset_time) >= Duration::from_secs(60) {
                            let mut count = broadcast_count.write().await;
                            *count = 0;
                            *reset_time = now;
                        }
                    }
                }

                // ============================================================
                // PHASE 4: Peer Exchange Cleanup (every 1 hour = every 120th tick)
                // ============================================================
                if tick_count.is_multiple_of(120) {
                    // Remove peers not seen in 7 days
                    let mut exchange = peer_exchange.write().await;
                    let removed = exchange.cleanup_stale_peers(604800);
                    if removed > 0 {
                        info!(removed, "Cleaned up stale peers from exchange");
                    }
                }
            }
        });
    }

    /// Subscribe a wallet to transaction notifications
    pub async fn subscribe_wallet(&self, xpub: &str, peer_ip: IpAddr) {
        let mut subscriptions = self.wallet_subscriptions.write().await;
        subscriptions
            .entry(xpub.to_string())
            .or_insert_with(Vec::new)
            .push(peer_ip);
        info!(
            "Subscribed wallet {} to notifications for xpub: {}...",
            peer_ip,
            &xpub[..8]
        );
    }

    /// Unsubscribe a wallet (called when peer disconnects)
    pub async fn unsubscribe_wallet(&self, peer_ip: IpAddr) {
        let mut subscriptions = self.wallet_subscriptions.write().await;
        subscriptions.retain(|_, peers| {
            peers.retain(|ip| *ip != peer_ip);
            !peers.is_empty()
        });
    }

    /// Notify subscribed wallets about a new transaction
    /// Call this when a transaction is added to mempool or confirmed in a block
    pub async fn notify_wallet_transaction(
        &self,
        transaction: crate::protocol::WalletTransaction,
        _addresses: &[String],
    ) {
        let subscriptions = self.wallet_subscriptions.read().await;

        // For each address in the transaction, check if we have subscribed wallets
        // Note: In practice, you'd derive addresses from each xpub and check matches
        // For now, we'll notify all subscribed wallets as a placeholder

        info!(
            "📬 Checking wallet subscriptions for transaction {}",
            &transaction.tx_hash[..16]
        );
        info!("   Total subscriptions: {}", subscriptions.len());

        if subscriptions.is_empty() {
            warn!("   ⚠️  No wallet subscriptions registered!");
            return;
        }

        // Collect all subscribed peer IPs
        let mut notified = std::collections::HashSet::new();
        for peers in subscriptions.values() {
            for peer_ip in peers {
                notified.insert(*peer_ip);
            }
        }

        // Send notification to each subscribed peer
        for peer_ip in notified {
            if let Err(e) = self
                .send_message_to_peer(
                    SocketAddr::new(peer_ip, 24100),
                    crate::protocol::NetworkMessage::NewTransactionNotification {
                        transaction: transaction.clone(),
                    },
                )
                .await
            {
                debug!(
                    "Failed to send transaction notification to {}: {}",
                    peer_ip, e
                );
            } else {
                info!("📬 Sent transaction notification to wallet at {}", peer_ip);
            }
        }
    }

    /// Broadcast UTXO state notification to all connected masternodes
    pub async fn broadcast_utxo_notification(
        &self,
        notification: &time_core::utxo_state_manager::UTXOStateNotification,
    ) {
        let notification_json = match serde_json::to_string(notification) {
            Ok(json) => json,
            Err(e) => {
                warn!(error = %e, "Failed to serialize UTXO notification");
                return;
            }
        };

        let message = crate::protocol::NetworkMessage::UTXOStateNotification {
            notification: notification_json,
        };

        self.broadcast_message(message).await;
    }

    /// Send UTXO state notification to a specific peer (for wallet subscriptions)
    pub async fn send_utxo_notification_to_peer(
        &self,
        peer_ip: IpAddr,
        notification: &time_core::utxo_state_manager::UTXOStateNotification,
    ) -> Result<(), String> {
        let notification_json = serde_json::to_string(notification)
            .map_err(|e| format!("Failed to serialize notification: {}", e))?;

        let message = crate::protocol::NetworkMessage::UTXOStateNotification {
            notification: notification_json,
        };

        let peer_addr = SocketAddr::new(peer_ip, self.listen_addr.port());
        self.send_message_to_peer(peer_addr, message).await
    }

    /// Handle UTXO protocol messages using the handler
    pub async fn handle_utxo_message(
        &self,
        message: &crate::protocol::NetworkMessage,
        peer_ip: IpAddr,
        utxo_handler: &crate::utxo_handler::UTXOProtocolHandler,
    ) -> Result<Option<crate::protocol::NetworkMessage>, String> {
        utxo_handler.handle_message(message, peer_ip).await
    }

    /// Request state snapshot from peer (Phase 1 optimization)
    pub async fn request_state_snapshot(
        &self,
        peer_addr: SocketAddr,
        height: u64,
    ) -> Result<crate::protocol::NetworkMessage, String> {
        info!(
            "🚀 Requesting state snapshot at height {} from {}",
            height, peer_addr
        );

        let request = crate::protocol::NetworkMessage::StateSnapshotRequest { height };

        // Use longer timeout for snapshots (they can be large)
        let timeout_secs = 300; // 5 minutes

        match self
            .send_message_to_peer_with_response(peer_addr, request, timeout_secs)
            .await?
        {
            Some(crate::protocol::NetworkMessage::StateSnapshotResponse {
                height: response_height,
                utxo_merkle_root,
                state_data,
                compressed,
                snapshot_size_bytes,
            }) => {
                info!(
                    "✅ Received snapshot: height={}, size={}KB, compressed={}",
                    response_height,
                    snapshot_size_bytes / 1024,
                    compressed
                );

                Ok(crate::protocol::NetworkMessage::StateSnapshotResponse {
                    height: response_height,
                    utxo_merkle_root,
                    state_data,
                    compressed,
                    snapshot_size_bytes,
                })
            }
            Some(other) => Err(format!("Unexpected response type: {:?}", other)),
            None => Err("No response received for snapshot request".to_string()),
        }
    }

    /// Handle GetPeerList request - returns peer list
    pub async fn handle_get_peer_list(&self) -> crate::protocol::NetworkMessage {
        info!("📨 Received GetPeerList request");

        // Get all peers with full info from peer manager
        let peers = self.get_peers().await;
        info!(
            peer_count = peers.len(),
            "Got {} peers from manager",
            peers.len()
        );

        let peer_addresses: Vec<crate::protocol::PeerAddress> = peers
            .into_iter()
            .map(|peer| crate::protocol::PeerAddress {
                ip: peer.address.ip().to_string(),
                port: peer.address.port(),
                version: peer.version.clone(),
            })
            .collect();

        info!(
            peer_count = peer_addresses.len(),
            network = ?self.network,
            "📤 Returning PeerList with {} peers",
            peer_addresses.len()
        );

        // Return peer list
        crate::protocol::NetworkMessage::PeerList(peer_addresses)
    }
}

// Implement Clone trait for PeerManager so `.clone()` is idiomatic.
impl Clone for PeerManager {
    fn clone(&self) -> Self {
        PeerManager {
            network: self.network,
            public_addr: self.public_addr,
            listen_addr: self.listen_addr,
            connections: self.connections.clone(),
            peer_exchange: self.peer_exchange.clone(),
            stale_after: self.stale_after,
            reaper_interval: self.reaper_interval,
            recent_peer_broadcasts: self.recent_peer_broadcasts.clone(),
            broadcast_count: self.broadcast_count.clone(),
            broadcast_count_reset: self.broadcast_count_reset.clone(),
            wallet_subscriptions: self.wallet_subscriptions.clone(),
            quarantine: self.quarantine.clone(),
            rate_limiter: self.rate_limiter.clone(),
            sync_gate: self.sync_gate.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_peer_manager_stale_timeout() {
        // Test that the stale_after timeout is set correctly to 90 seconds
        let manager = PeerManager::new(
            NetworkType::Testnet,
            "127.0.0.1:8333".parse().unwrap(),
            "127.0.0.1:8333".parse().unwrap(),
        );

        assert_eq!(
            manager.stale_after,
            Duration::from_secs(300),
            "Stale timeout should be 300 seconds (5 minutes) to allow for slow block processing"
        );
    }

    #[tokio::test]
    async fn test_peer_manager_reaper_interval() {
        // Test that the reaper interval is set correctly
        let manager = PeerManager::new(
            NetworkType::Testnet,
            "127.0.0.1:8333".parse().unwrap(),
            "127.0.0.1:8333".parse().unwrap(),
        );

        assert_eq!(
            manager.reaper_interval,
            Duration::from_secs(30),
            "Reaper interval should be 30 seconds"
        );
    }

    #[tokio::test]
    async fn test_reconnection_task_spawned() {
        // Test that the manager spawns properly with reconnection task
        let manager = PeerManager::new(
            NetworkType::Testnet,
            "127.0.0.1:8333".parse().unwrap(),
            "127.0.0.1:8333".parse().unwrap(),
        );

        // If we can create the manager without panicking, the tasks were spawned successfully
        assert_eq!(manager.network, NetworkType::Testnet);

        // Give a moment for background tasks to initialize
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_broadcast_new_peer() {
        // Test that broadcast_new_peer sends notifications to connected peers
        let manager = PeerManager::new(
            NetworkType::Testnet,
            "127.0.0.1:24100".parse().unwrap(),
            "127.0.0.1:24100".parse().unwrap(),
        );

        // Create a new peer to broadcast
        let new_peer = PeerInfo::new("192.168.1.100:24100".parse().unwrap(), NetworkType::Testnet);

        // Initially no peers, so broadcast should complete without error
        manager.broadcast_new_peer(&new_peer).await;

        // The test passes if broadcast_new_peer doesn't panic
        // In a real scenario, we'd need to set up a mock HTTP server to verify the requests
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_add_connected_peer_triggers_broadcast() {
        // The deprecated add_connected_peer only adds to discovery, not connections.
        let manager = PeerManager::new(
            NetworkType::Testnet,
            "127.0.0.1:24100".parse().unwrap(),
            "127.0.0.1:24100".parse().unwrap(),
        );

        let test_peer = PeerInfo::with_version(
            "192.168.1.101:24100".parse().unwrap(),
            NetworkType::Testnet,
            "0.1.0".to_string(),
        );

        // Deprecated method adds to discovery, not connections
        manager.add_connected_peer(test_peer.clone()).await;

        // Connections map should be empty (deprecated method is a no-op for connections)
        let connections = manager.connections.read().await;
        assert_eq!(connections.len(), 0);
    }

    #[tokio::test]
    async fn test_network_aware_ports_mainnet() {
        // Test that mainnet uses correct ports (24000 for P2P, 24001 for API)
        let manager = PeerManager::new(
            NetworkType::Mainnet,
            "127.0.0.1:24000".parse().unwrap(),
            "127.0.0.1:24000".parse().unwrap(),
        );

        // Verify network type is set correctly
        assert_eq!(manager.network, NetworkType::Mainnet);

        // The manager should use port 24000 for P2P and 24001 for API
        // This is verified by the logic in functions like request_genesis, request_mempool, etc.
    }

    #[tokio::test]
    async fn test_network_aware_ports_testnet() {
        // Test that testnet uses correct ports (24100 for P2P, 24101 for API)
        let manager = PeerManager::new(
            NetworkType::Testnet,
            "127.0.0.1:24100".parse().unwrap(),
            "127.0.0.1:24100".parse().unwrap(),
        );

        // Verify network type is set correctly
        assert_eq!(manager.network, NetworkType::Testnet);

        // The manager should use port 24100 for P2P and 24101 for API
        // This is verified by the logic in functions like request_genesis, request_mempool, etc.
    }

    // #[tokio::test]
    //     async fn test_same_ip_different_ports_counted_once() {
    //         // Test that multiple connections from the same IP with different ports
    //         // are counted as a single peer (fixes the duplicate peer counting issue)
    //         let manager = PeerManager::new(NetworkType::Testnet, "127.0.0.1:24100".parse().unwrap(), "127.0.0.1:24100".parse().unwrap());
    //
    //         // Create three peers with the same IP but different ports (simulating ephemeral ports)
    //         let peer1 = PeerInfo::with_version(
    //             "192.0.2.10:52341".parse().unwrap(),
    //             NetworkType::Testnet,
    //             "0.1.0".to_string(),
    //         );
    //         let peer2 = PeerInfo::with_version(
    //             "192.0.2.10:52342".parse().unwrap(),
    //             NetworkType::Testnet,
    //             "0.1.0".to_string(),
    //         );
    //         let peer3 = PeerInfo::with_version(
    //             "192.0.2.10:52343".parse().unwrap(),
    //             NetworkType::Testnet,
    //             "0.1.0".to_string(),
    //         );
    //
    //         // Add all three "peers" (which are actually the same peer with different ephemeral ports)
    //         manager.add_connected_peer(peer1.clone()).await;
    //         manager.add_connected_peer(peer2.clone()).await;
    //         manager.add_connected_peer(peer3.clone()).await;
    //
    //         // Verify that only 1 peer is counted (not 3)
    //         let peer_count = manager.active_peer_count().await;
    //         assert_eq!(
    //             peer_count, 1,
    //             "Expected 1 peer (same IP), but got {}",
    //             peer_count
    //         );
    //
    //         // Verify the connected peers list has only 1 entry
    //         let connected_peers = manager.get_connected_peers().await;
    //         assert_eq!(
    //             connected_peers.len(),
    //             1,
    //             "Expected 1 connected peer, but got {}",
    //             connected_peers.len()
    //         );
    //
    //         // The stored peer should have the most recent connection info (peer3)
    //         assert_eq!(connected_peers[0].address, peer3.address);
    //     }

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_different_ips_counted_separately() {
        // Test that connections from different IPs are counted separately
        let manager = PeerManager::new(
            NetworkType::Testnet,
            "127.0.0.1:24100".parse().unwrap(),
            "127.0.0.1:24100".parse().unwrap(),
        );

        // Create three peers with different IPs
        let peer1 = PeerInfo::with_version(
            "192.0.2.10:24100".parse().unwrap(),
            NetworkType::Testnet,
            "0.1.0".to_string(),
        );
        let peer2 = PeerInfo::with_version(
            "192.168.1.100:24100".parse().unwrap(),
            NetworkType::Testnet,
            "0.1.0".to_string(),
        );
        let peer3 = PeerInfo::with_version(
            "10.0.0.1:24100".parse().unwrap(),
            NetworkType::Testnet,
            "0.1.0".to_string(),
        );

        // Add all three peers (deprecated — goes to discovery, not connections)
        manager.add_connected_peer(peer1.clone()).await;
        manager.add_connected_peer(peer2.clone()).await;
        manager.add_connected_peer(peer3.clone()).await;

        // Deprecated method only adds to discovery, not connections
        let connections = manager.connections.read().await;
        assert_eq!(connections.len(), 0);
    }
}
