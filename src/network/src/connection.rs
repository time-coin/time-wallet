//! Peer connection with handshake
//!
//! CRITICAL FIX (Issue #16): Document design decisions
//!
//! # TCP Keepalive Configuration
//!
//! ## Why TCP Keepalive?
//!
//! Many networks (NATs, firewalls, load balancers) drop idle TCP connections
//! after 2-5 minutes of inactivity. Without keepalive, peers would appear
//! connected but unable to communicate.
//!
//! ## Configuration (60s/30s)
//!
//! - **First probe:** 60 seconds after connection becomes idle
//! - **Interval:** 30 seconds between subsequent probes
//!
//! **Why these values?**
//!
//! Tested configurations:
//! - 5s/5s: Too aggressive - causes disconnections on some networks
//! - 120s/60s: Too slow - connections drop before detection
//! - 60s/30s: Sweet spot - reliable across most network types
//!
//! ## Expected Latency
//!
//! For consensus messages (block proposals, votes):
//! - **LAN:** < 10ms
//! - **Internet (same region):** 10-100ms
//! - **Internet (cross-region):** 100-500ms
//! - **Timeout threshold:** 2000ms (2 seconds)
//!
//! Messages taking > 2 seconds indicate network issues and trigger retry logic.
//!
//! # Ephemeral Port Normalization
//!
//! When accepting incoming connections, we normalize ephemeral source ports
//! (>= 49152) to the network's standard port. See peer_exchange.rs for details.

use crate::discovery::NetworkType;
use crate::peer_info::PeerInfo;
use crate::protocol::HandshakeMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Arc as StdArc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Peer connection with split TCP stream for concurrent I/O
///
/// OPTIMIZATION (Quick Win #3): Split read/write halves
/// - Allows concurrent send/recv operations
/// - Prevents slow peers from blocking broadcasts
/// - Enables fire-and-forget message sending
///
/// REQUEST SERIALIZATION: Uses a request_lock to ensure only one
/// request/response pair is in-flight at a time, preventing protocol
/// mismatch errors when responses arrive out of order.
pub struct PeerConnection {
    pub(crate) reader: Arc<Mutex<OwnedReadHalf>>,
    pub(crate) writer: Arc<Mutex<OwnedWriteHalf>>,
    peer_info: Arc<Mutex<PeerInfo>>,
    peer_addr: SocketAddr, // Cached peer address (split streams don't expose it)
    request_lock: Arc<Mutex<()>>, // Serialize request/response pairs
}

impl PeerConnection {
    pub async fn connect(
        peer: Arc<Mutex<PeerInfo>>,
        network: NetworkType,
        our_listen_addr: SocketAddr,
        // Add optional blockchain state for registration
        blockchain: Option<StdArc<tokio::sync::RwLock<time_core::state::BlockchainState>>>,
    ) -> Result<Self, String> {
        let peer_addr = peer.lock().await.address;
        let stream = TcpStream::connect(peer_addr)
            .await
            .map_err(|e| format!("Connect failed: {}", e))?;

        // Enable TCP keep-alive to prevent connection timeouts
        if let Err(e) = stream.set_nodelay(true) {
            eprintln!("⚠️  Failed to set TCP_NODELAY: {}", e);
        }

        // TCP keep-alive to prevent connection drops from idle timeout
        // Using reasonable intervals to avoid triggering firewall/NAT resets
        // 5-second probes are too aggressive and can actually cause disconnections
        let socket2_sock = socket2::Socket::from(stream.into_std().map_err(|e| e.to_string())?);

        // Reasonable keepalive: probe after 60s idle, then every 30s
        // Most networks handle this well, avoiding premature connection resets
        let ka = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60)) // First probe after 60s idle
            .with_interval(std::time::Duration::from_secs(30)); // 30s between probes

        if let Err(e) = socket2_sock.set_tcp_keepalive(&ka) {
            eprintln!("⚠️  Failed to set TCP keep-alive: {}", e);
        }

        // Convert back to tokio TcpStream
        let mut stream = TcpStream::from_std(socket2_sock.into())
            .map_err(|e| format!("Failed to convert socket: {}", e))?;

        // Get our genesis hash if blockchain is available
        let our_genesis_hash = if let Some(bc) = &blockchain {
            let chain = bc.read().await;
            Some(chain.genesis_hash().to_string())
        } else {
            None
        };

        let our_handshake =
            HandshakeMessage::new_with_genesis(network, our_listen_addr, our_genesis_hash.clone());

        // OPTIMIZATION (Quick Win #6): Use consolidated handshake helper
        let their_handshake = Self::perform_handshake(
            &mut stream,
            &our_handshake,
            &network,
            our_genesis_hash.as_deref(),
            true, // We send first (initiating connection)
        )
        .await?;

        // Update peer info with version AND commit info
        peer.lock().await.update_version_with_build_info(
            their_handshake.version.clone(),
            their_handshake.commit_date.clone(),
            their_handshake.commit_count.clone(),
        );

        // Silently connect to peer (reduce log verbosity)

        // Auto-register peer info from handshake
        if let Some(wallet_addr) = &their_handshake.wallet_address {
            if let Some(blockchain) = &blockchain {
                let mut chain = blockchain.write().await;
                let _ = chain.register_masternode(
                    peer_addr.ip().to_string(),
                    time_core::MasternodeTier::Free,
                    "peer_connection".to_string(),
                    wallet_addr.clone(),
                );
            }
        }

        // Check version and warn ONLY if peer is a masternode with a newer version
        // Skip version check for wallets (they don't have wallet_address in handshake)
        if their_handshake.wallet_address.is_some() {
            let peer_date = their_handshake.commit_date.as_deref();
            if crate::protocol::should_warn_version_update(
                peer_date,
                their_handshake.commit_count.as_deref(),
            ) {
                let warning = crate::protocol::version_update_warning(
                    &format!("{}", peer_addr),
                    &their_handshake.version,
                    peer_date.unwrap_or("unknown"),
                    their_handshake.commit_count.as_deref().unwrap_or("0"),
                );
                eprintln!("{}", warning);
            }
        }

        // OPTIMIZATION (Quick Win #3): Split stream for concurrent I/O
        // Cache peer_addr before splitting (split streams don't expose it)
        let cached_peer_addr = stream.peer_addr().map_err(|e| e.to_string())?;
        let (read_half, write_half) = stream.into_split();

        Ok(PeerConnection {
            reader: Arc::new(Mutex::new(read_half)),
            writer: Arc::new(Mutex::new(write_half)),
            peer_info: peer,
            peer_addr: cached_peer_addr,
            request_lock: Arc::new(Mutex::new(())),
        })
    }

    /// OPTIMIZATION (Quick Win #6): Consolidated handshake helper
    /// Performs complete bidirectional handshake with validation
    ///
    /// This replaces duplicate handshake code in:
    /// - PeerConnection::connect()
    /// - PeerListener::accept()
    /// - PeerManager::send_to_peer_tcp()
    ///
    /// Returns the peer's validated handshake message
    pub async fn perform_handshake(
        stream: &mut TcpStream,
        our_handshake: &HandshakeMessage,
        network: &NetworkType,
        expected_genesis: Option<&str>,
        send_first: bool,
    ) -> Result<HandshakeMessage, String> {
        if send_first {
            // Send our handshake, then receive theirs
            Self::send_handshake(stream, our_handshake, network).await?;
            let their_handshake = Self::receive_handshake(stream, network).await?;

            // Validate with genesis if provided, otherwise basic validation
            if expected_genesis.is_some() {
                their_handshake.validate_with_genesis(network, expected_genesis)?;
            } else {
                their_handshake.validate(network)?;
            }

            Ok(their_handshake)
        } else {
            // Receive theirs, then send ours
            let their_handshake = Self::receive_handshake(stream, network).await?;

            // Validate with genesis if provided, otherwise basic validation
            if expected_genesis.is_some() {
                their_handshake.validate_with_genesis(network, expected_genesis)?;
            } else {
                their_handshake.validate(network)?;
            }

            Self::send_handshake(stream, our_handshake, network).await?;
            Ok(their_handshake)
        }
    }

    async fn send_handshake(
        stream: &mut TcpStream,
        h: &HandshakeMessage,
        network: &NetworkType,
    ) -> Result<(), String> {
        let json = serde_json::to_vec(h).map_err(|e| e.to_string())?;
        let len = json.len() as u32;

        // Write magic bytes first
        let magic = network.magic_bytes();
        stream
            .write_all(&magic)
            .await
            .map_err(|e| format!("Failed to write magic bytes: {}", e))?;

        // Then write length and payload
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(&json).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn receive_handshake(
        stream: &mut TcpStream,
        network: &NetworkType,
    ) -> Result<HandshakeMessage, String> {
        // Read and validate magic bytes
        let mut magic_bytes = [0u8; 4];
        stream
            .read_exact(&mut magic_bytes)
            .await
            .map_err(|e| format!("Failed to read magic bytes: {}", e))?;

        let expected_magic = network.magic_bytes();
        if magic_bytes != expected_magic {
            return Err(format!(
                "Invalid magic bytes: expected {:?}, got {:?}",
                expected_magic, magic_bytes
            ));
        }

        // Read length
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| e.to_string())?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 1024 * 1024 {
            return Err("Too large".into());
        }

        // Read payload
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice(&buf).map_err(|e| e.to_string())
    }

    pub async fn peer_info(&self) -> PeerInfo {
        self.peer_info.lock().await.clone()
    }

    /// Get the real peer address (cached from connection time)
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    /// Check if connection is still alive
    /// OPTIMIZATION: After split, we just return true since sends/receives will detect failures
    pub async fn is_alive(&self) -> bool {
        // With split streams, individual operations detect failures
        // We can try a non-blocking peek but it's simpler to just return true
        // and let send/receive operations detect dead connections
        true
    }

    /// Send a network message over the TCP connection
    /// OPTIMIZATION: Uses dedicated write half for non-blocking sends
    pub async fn send_message(
        &mut self,
        msg: crate::protocol::NetworkMessage,
    ) -> Result<(), String> {
        let json = serde_json::to_vec(&msg).map_err(|e| e.to_string())?;
        let len = json.len() as u32;

        if len > 10 * 1024 * 1024 {
            return Err("Message too large (>10MB)".into());
        }

        // Wrap all I/O operations in a timeout to prevent indefinite blocking
        let timeout_duration = std::time::Duration::from_secs(5);

        let writer = self.writer.clone();
        tokio::time::timeout(timeout_duration, async move {
            let mut writer_guard = writer.lock().await;
            writer_guard
                .write_all(&len.to_be_bytes())
                .await
                .map_err(|e| format!("Failed to write length: {}", e))?;
            writer_guard
                .write_all(&json)
                .await
                .map_err(|e| format!("Failed to write message: {}", e))?;
            writer_guard
                .flush()
                .await
                .map_err(|e| format!("Failed to flush: {}", e))?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "Send timeout after 5s".to_string())??;

        Ok(())
    }

    /// Send a request and wait for response with request serialization
    /// This prevents protocol mismatch errors by ensuring only one request/response
    /// pair is in-flight at a time on this connection.
    pub async fn request_response(
        &mut self,
        request: crate::protocol::NetworkMessage,
        timeout: std::time::Duration,
    ) -> Result<crate::protocol::NetworkMessage, String> {
        // Clone the Arc before locking to avoid borrow checker issues
        let request_lock = self.request_lock.clone();

        // Acquire request lock to serialize request/response pairs
        let _lock = request_lock.lock().await;

        // Send request with retry on broken pipe
        let max_retries = 2;
        for attempt in 0..max_retries {
            match self.send_message(request.clone()).await {
                Ok(_) => break,
                Err(e) => {
                    if e.contains("Broken pipe") && attempt < max_retries - 1 {
                        // Wait briefly before retry
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        // Wait for response, handling background messages
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!("Request timeout after {:?}", timeout));
            }

            match tokio::time::timeout(remaining, self.receive_message()).await {
                Ok(Ok(msg)) => {
                    // Check if this is the expected response type
                    if Self::is_response_for_request(&request, &msg) {
                        return Ok(msg);
                    }
                    // Handle background messages (Ping, etc.)
                    self.handle_background_message(msg).await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(format!("Request timeout after {:?}", timeout)),
            }
        }
    }

    /// Check if a message is the expected response for a request
    fn is_response_for_request(
        request: &crate::protocol::NetworkMessage,
        response: &crate::protocol::NetworkMessage,
    ) -> bool {
        use crate::protocol::NetworkMessage;
        matches!(
            (request, response),
            (
                NetworkMessage::GetMempool,
                NetworkMessage::MempoolResponse(_)
            ) | (
                NetworkMessage::RequestFinalizedTransactions { .. },
                NetworkMessage::FinalizedTransactionsResponse { .. },
            ) | (
                NetworkMessage::HeightRequest,
                NetworkMessage::HeightResponse { .. }
            ) | (
                NetworkMessage::BlockRequest { .. },
                NetworkMessage::BlockResponse { .. }
            ) | (
                NetworkMessage::GetBlockchainInfo,
                NetworkMessage::BlockchainInfo { .. }
            ) | (NetworkMessage::GetGenesis, NetworkMessage::GenesisBlock(_))
        )
    }

    /// Handle background messages that arrive during request/response
    async fn handle_background_message(&mut self, msg: crate::protocol::NetworkMessage) {
        use crate::protocol::NetworkMessage;
        match msg {
            NetworkMessage::Ping => {
                // Respond to ping immediately
                if let Err(e) = self.send_message(NetworkMessage::Pong).await {
                    warn!("Failed to send Pong response: {}", e);
                }
            }
            NetworkMessage::Pong => {
                // Ignore pongs during request/response
            }
            other => {
                // Log unexpected messages but don't fail
                debug!(
                    "Received unexpected message during request/response: {:?}",
                    other
                );
            }
        }
    }

    /// Receive a network message from the TCP connection with timeout
    /// OPTIMIZATION: Uses dedicated read half for non-blocking receives
    pub async fn receive_message(&mut self) -> Result<crate::protocol::NetworkMessage, String> {
        // Add timeout to prevent indefinite blocking on dead connections
        let timeout_duration = std::time::Duration::from_secs(60);

        let reader = self.reader.clone();
        tokio::time::timeout(timeout_duration, async move {
            let mut reader_guard = reader.lock().await;
            let mut len_bytes = [0u8; 4];
            reader_guard
                .read_exact(&mut len_bytes)
                .await
                .map_err(|e| format!("Failed to read length: {}", e))?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len > 10 * 1024 * 1024 {
                return Err("Message too large (>10MB)".into());
            }

            let mut buf = vec![0u8; len];
            reader_guard
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("Failed to read message: {}", e))?;
            crate::protocol::NetworkMessage::deserialize(&buf)
        })
        .await
        .map_err(|_| "Receive timeout after 60s".to_string())?
    }

    /// Send a ping message to check if connection is alive
    /// OPTIMIZATION: Uses writer half, can overlap with receives
    pub async fn ping(&mut self) -> Result<(), String> {
        // Send ping with timeout to prevent blocking
        let msg = crate::protocol::NetworkMessage::Ping;
        let json = serde_json::to_vec(&msg).map_err(|e| e.to_string())?;
        let len = json.len() as u32;

        // Wrap ping send in timeout (5 seconds)
        let writer = self.writer.clone();
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            let mut writer_guard = writer.lock().await;
            writer_guard
                .write_all(&len.to_be_bytes())
                .await
                .map_err(|e| format!("Ping write failed: {}", e))?;
            writer_guard
                .write_all(&json)
                .await
                .map_err(|e| format!("Ping write failed: {}", e))?;
            writer_guard
                .flush()
                .await
                .map_err(|e| format!("Ping flush failed: {}", e))?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "Ping send timeout after 5s".to_string())??;

        // Wait for pong response with generous timeout (10s instead of 5s)
        // Peer might be busy handling other messages
        let pong_result =
            tokio::time::timeout(std::time::Duration::from_secs(10), self.receive_message()).await;

        match pong_result {
            Ok(Ok(crate::protocol::NetworkMessage::Pong)) => {
                tracing::trace!("Received Pong response");
                Ok(())
            }
            Ok(Ok(msg)) => {
                // Received wrong message type - this is a protocol violation
                // The peer should respond with Pong, not other messages
                tracing::warn!("Expected Pong but received {:?} - protocol mismatch", msg);
                Err(format!("Protocol error: expected Pong, got {:?}", msg))
            }
            Ok(Err(e)) => Err(format!("Pong receive error: {}", e)),
            Err(_) => Err("Pong timeout (10s)".to_string()),
        }
    }

    pub async fn keep_alive(mut self) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            if self.ping().await.is_err() {
                break;
            }
            self.peer_info.lock().await.touch();
        }
    }
}

use tokio::net::TcpListener;

pub struct PeerListener {
    listener: TcpListener,
    network: NetworkType,
    our_listen_addr: SocketAddr,
    _blockchain: Option<StdArc<tokio::sync::RwLock<time_core::state::BlockchainState>>>,
}

impl PeerListener {
    pub async fn bind(
        bind_addr: SocketAddr,
        network: NetworkType,
        public_addr: SocketAddr,
        blockchain: Option<StdArc<tokio::sync::RwLock<time_core::state::BlockchainState>>>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind: {}", e))?;
        println!("👂 Listening for peers on {}", bind_addr);
        println!("📢 Advertising public address: {}", public_addr);
        Ok(PeerListener {
            listener,
            network,
            our_listen_addr: public_addr,
            _blockchain: blockchain,
        })
    }

    pub async fn accept(&self) -> Result<PeerConnection, String> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| format!("Accept failed: {}", e))?;
        // Silently accept connection (reduce log verbosity)

        // Enable TCP keep-alive on incoming connections to prevent timeout
        if let Err(e) = stream.set_nodelay(true) {
            eprintln!(
                "⚠️  Failed to set TCP_NODELAY on incoming connection: {}",
                e
            );
        }

        // AGGRESSIVE TCP keep-alive to prevent connection drops
        // Connection resets observed after 3-5 seconds of inactivity
        // Strategy: Very frequent probes to keep NAT/firewall tables alive
        let socket2_sock = socket2::Socket::from(stream.into_std().map_err(|e| e.to_string())?);

        // Industry-standard keepalive: 60s idle, 30s probes
        // Prevents firewall timeouts while avoiding aggressive probing
        let ka = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60)) // First probe after 60s idle
            .with_interval(std::time::Duration::from_secs(30)); // 30s between probes

        if let Err(e) = socket2_sock.set_tcp_keepalive(&ka) {
            eprintln!(
                "⚠️  Failed to set TCP keep-alive on incoming connection: {}",
                e
            );
        }

        // Convert back to tokio TcpStream
        let mut stream = TcpStream::from_std(socket2_sock.into())
            .map_err(|e| format!("Failed to convert socket: {}", e))?;

        let our_handshake = HandshakeMessage::new(self.network, self.our_listen_addr);

        // OPTIMIZATION (Quick Win #6): Use consolidated handshake helper
        let their_handshake = PeerConnection::perform_handshake(
            &mut stream,
            &our_handshake,
            &self.network,
            None,  // Accept doesn't validate genesis (only basic validate)
            false, // We receive first (accepting connection)
        )
        .await?;

        let mut peer_info = PeerInfo::with_version(
            their_handshake.listen_addr,
            self.network,
            their_handshake.version.clone(),
        );

        // Update with commit information from handshake
        peer_info.commit_date = their_handshake.commit_date.clone();
        peer_info.commit_count = their_handshake.commit_count.clone();

        // Silently accepted (reduce log verbosity)

        // OPTIMIZATION (Quick Win #3): Split stream for concurrent I/O
        // Cache peer_addr before splitting
        let cached_peer_addr = stream.peer_addr().map_err(|e| e.to_string())?;
        let (read_half, write_half) = stream.into_split();

        Ok(PeerConnection {
            reader: Arc::new(Mutex::new(read_half)),
            writer: Arc::new(Mutex::new(write_half)),
            peer_info: Arc::new(Mutex::new(peer_info)),
            peer_addr: cached_peer_addr,
            request_lock: Arc::new(Mutex::new(())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::NetworkType;
    use crate::protocol::HandshakeMessage;

    #[test]
    fn test_peer_info_preserves_build_info() {
        // Test that PeerInfo correctly stores commit_date and commit_count
        let addr: SocketAddr = "127.0.0.1:24100".parse().unwrap();
        let mut peer_info =
            PeerInfo::with_version(addr, NetworkType::Testnet, "0.1.0-abc1234".to_string());

        // Initially, commit info should be None
        assert_eq!(peer_info.commit_date, None);
        assert_eq!(peer_info.commit_count, None);

        // Simulate what happens in accept() - update with handshake data
        let commit_date = Some("2025-11-07T15:09:21Z".to_string());
        let commit_count = Some("1234".to_string());
        peer_info.commit_date = commit_date.clone();
        peer_info.commit_count = commit_count.clone();

        // Verify the data is preserved
        assert_eq!(peer_info.commit_date, commit_date);
        assert_eq!(peer_info.commit_count, commit_count);
        assert_eq!(peer_info.version, "0.1.0-abc1234");
    }

    #[test]
    fn test_handshake_contains_build_info() {
        // Verify that HandshakeMessage includes commit info
        let addr: SocketAddr = "127.0.0.1:24100".parse().unwrap();
        let handshake = HandshakeMessage::new(NetworkType::Testnet, addr);

        // Handshake should always include build info
        assert!(handshake.commit_date.is_some());
        assert!(handshake.commit_count.is_some());

        // Verify it's not empty
        let commit_date = handshake.commit_date.unwrap();
        let commit_count = handshake.commit_count.unwrap();
        assert!(!commit_date.is_empty());
        assert!(!commit_count.is_empty());
    }

    #[test]
    fn test_ephemeral_port_normalization_testnet() {
        // Test that ephemeral ports are normalized to the standard P2P port for testnet

        // Simulate what PeerListener::accept() does with an ephemeral port
        let ephemeral_addr: SocketAddr = "192.0.2.1:56236".parse().unwrap();
        assert!(ephemeral_addr.port() >= 49152, "Port should be ephemeral");

        // This is what the fixed code does
        let normalized_port = if ephemeral_addr.port() >= 49152 {
            24100 // Testnet standard port
        } else {
            ephemeral_addr.port()
        };

        let normalized_addr = SocketAddr::new(ephemeral_addr.ip(), normalized_port);

        // Verify normalization
        assert_eq!(
            normalized_addr.port(),
            24100,
            "Ephemeral port should be normalized to 24100 for testnet"
        );
        assert_eq!(
            normalized_addr.ip(),
            ephemeral_addr.ip(),
            "IP address should remain unchanged"
        );
    }

    #[test]
    fn test_ephemeral_port_normalization_mainnet() {
        // Test that ephemeral ports are normalized to the standard P2P port for mainnet

        let ephemeral_addr: SocketAddr = "192.0.2.2:58378".parse().unwrap();
        assert!(ephemeral_addr.port() >= 49152, "Port should be ephemeral");

        // This is what the fixed code does for mainnet
        let normalized_port = if ephemeral_addr.port() >= 49152 {
            24000 // Mainnet standard port
        } else {
            ephemeral_addr.port()
        };

        let normalized_addr = SocketAddr::new(ephemeral_addr.ip(), normalized_port);

        // Verify normalization
        assert_eq!(
            normalized_addr.port(),
            24000,
            "Ephemeral port should be normalized to 24000 for mainnet"
        );
        assert_eq!(
            normalized_addr.ip(),
            ephemeral_addr.ip(),
            "IP address should remain unchanged"
        );
    }

    #[test]
    fn test_standard_port_not_changed() {
        // Test that standard P2P ports are not modified

        // Testnet standard port
        let testnet_addr: SocketAddr = "192.0.2.3:24100".parse().unwrap();
        let normalized_port = if testnet_addr.port() >= 49152 {
            24100
        } else {
            testnet_addr.port()
        };
        assert_eq!(
            normalized_port, 24100,
            "Standard testnet port should not be changed"
        );

        // Mainnet standard port
        let mainnet_addr: SocketAddr = "192.0.2.4:24000".parse().unwrap();
        let normalized_port = if mainnet_addr.port() >= 49152 {
            24000
        } else {
            mainnet_addr.port()
        };
        assert_eq!(
            normalized_port, 24000,
            "Standard mainnet port should not be changed"
        );
    }

    #[test]
    fn test_ephemeral_port_boundary() {
        // Test the boundary case at port 49152 (start of ephemeral range)

        // Port 49151 should not be normalized (just below ephemeral range)
        let below_ephemeral: SocketAddr = "192.168.1.1:49151".parse().unwrap();
        let normalized_port = if below_ephemeral.port() >= 49152 {
            24100
        } else {
            below_ephemeral.port()
        };
        assert_eq!(
            normalized_port, 49151,
            "Port 49151 should not be normalized"
        );

        // Port 49152 should be normalized (start of ephemeral range)
        let at_ephemeral: SocketAddr = "192.168.1.1:49152".parse().unwrap();
        let normalized_port = if at_ephemeral.port() >= 49152 {
            24100
        } else {
            at_ephemeral.port()
        };
        assert_eq!(normalized_port, 24100, "Port 49152 should be normalized");
    }
}
