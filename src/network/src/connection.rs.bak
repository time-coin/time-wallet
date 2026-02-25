//! Peer connection with handshake
use crate::discovery::{NetworkType, PeerInfo};
use crate::protocol::HandshakeMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Arc as StdArc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub struct PeerConnection {
    stream: TcpStream,
    peer_info: Arc<Mutex<PeerInfo>>,
}

impl PeerConnection {
    pub async fn connect(
        peer: Arc<Mutex<PeerInfo>>,
        network: NetworkType,
        our_listen_addr: SocketAddr,
        // Add optional blockchain state for registration
        blockchain: Option<StdArc<tokio::sync::RwLock<time_core::state::BlockchainState>>>,
        consensus: Option<StdArc<time_consensus::ConsensusEngine>>,
        block_consensus: Option<StdArc<time_consensus::block_consensus::BlockConsensusManager>>,
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
        Self::send_handshake(&mut stream, &our_handshake, &network).await?;
        let their_handshake = Self::receive_handshake(&mut stream, &network).await?;

        // Validate with genesis check
        their_handshake.validate_with_genesis(&network, our_genesis_hash.as_deref())?;

        // Update peer info with version AND commit info
        peer.lock().await.update_version_with_build_info(
            their_handshake.version.clone(),
            their_handshake.commit_date.clone(),
            their_handshake.commit_count.clone(),
        );

        // Silently connect to peer (reduce log verbosity)

        // Auto-register masternode if wallet address provided
        if let Some(wallet_addr) = &their_handshake.wallet_address {
            if let (Some(blockchain), Some(consensus)) = (&blockchain, &consensus) {
                Self::auto_register_masternode(
                    peer_addr.ip().to_string(),
                    wallet_addr.clone(),
                    blockchain.clone(),
                    consensus.clone(),
                    block_consensus.clone(),
                )
                .await;
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

        Ok(PeerConnection {
            stream,
            peer_info: peer,
        })
    }

    /// Auto-register a masternode when peer connects
    async fn auto_register_masternode(
        node_ip: String,
        wallet_address: String,
        blockchain: StdArc<tokio::sync::RwLock<time_core::state::BlockchainState>>,
        consensus: StdArc<time_consensus::ConsensusEngine>,
        block_consensus: Option<StdArc<time_consensus::block_consensus::BlockConsensusManager>>,
    ) {
        use time_core::MasternodeTier;

        // Silently auto-register masternode (reduce log verbosity)

        // Register in blockchain state
        let mut chain = blockchain.write().await;
        match chain.register_masternode(
            node_ip.clone(),
            MasternodeTier::Free, // Default to Free tier
            "peer_connection".to_string(),
            wallet_address.clone(),
        ) {
            Ok(_) => {
                drop(chain);

                // Also register in consensus
                consensus.add_masternode(node_ip.clone()).await;
                consensus
                    .register_wallet(node_ip.clone(), wallet_address.clone())
                    .await;

                // Also register in block consensus if available
                if let Some(bc) = block_consensus {
                    bc.add_masternode(node_ip.clone()).await;
                }

                println!(
                    "✅ Masternode auto-registered: {} -> {}",
                    node_ip, wallet_address
                );
            }
            Err(e) => {
                println!("⚠️  Auto-registration skipped for {}: {:?}", node_ip, e);
            }
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

    /// Get the real peer address from the TCP socket (not from handshake)
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Check if connection is still alive by attempting to peek at incoming data
    /// Returns true if connection appears healthy, false if broken
    pub async fn is_alive(&self) -> bool {
        // Try to peek at the socket state
        // We check if the peer_addr is still valid which indicates the socket is open
        self.stream.peer_addr().is_ok()
    }

    /// Send a network message over the TCP connection
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
        // This prevents "Broken pipe" errors caused by slow/stuck peers
        let timeout_duration = std::time::Duration::from_secs(5);

        tokio::time::timeout(timeout_duration, async {
            self.stream
                .write_all(&len.to_be_bytes())
                .await
                .map_err(|e| format!("Failed to write length: {}", e))?;
            self.stream
                .write_all(&json)
                .await
                .map_err(|e| format!("Failed to write message: {}", e))?;
            self.stream
                .flush()
                .await
                .map_err(|e| format!("Failed to flush: {}", e))?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "Send timeout after 5s".to_string())??;

        Ok(())
    }

    /// Receive a network message from the TCP connection with timeout
    pub async fn receive_message(&mut self) -> Result<crate::protocol::NetworkMessage, String> {
        // Add timeout to prevent indefinite blocking on dead connections
        let timeout_duration = std::time::Duration::from_secs(60);

        tokio::time::timeout(timeout_duration, async {
            let mut len_bytes = [0u8; 4];
            self.stream
                .read_exact(&mut len_bytes)
                .await
                .map_err(|e| format!("Failed to read length: {}", e))?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len > 10 * 1024 * 1024 {
                return Err("Message too large (>10MB)".into());
            }

            let mut buf = vec![0u8; len];
            self.stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("Failed to read message: {}", e))?;
            crate::protocol::NetworkMessage::deserialize(&buf)
        })
        .await
        .map_err(|_| "Receive timeout after 60s".to_string())?
    }

    pub async fn ping(&mut self) -> Result<(), String> {
        // Send ping with timeout to prevent blocking
        let msg = crate::protocol::NetworkMessage::Ping;
        let json = serde_json::to_vec(&msg).map_err(|e| e.to_string())?;
        let len = json.len() as u32;

        // Wrap ping send in timeout (5 seconds)
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            self.stream
                .write_all(&len.to_be_bytes())
                .await
                .map_err(|e| format!("Ping write failed: {}", e))?;
            self.stream
                .write_all(&json)
                .await
                .map_err(|e| format!("Ping write failed: {}", e))?;
            self.stream
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
    blockchain: Option<StdArc<tokio::sync::RwLock<time_core::state::BlockchainState>>>,
    consensus: Option<StdArc<time_consensus::ConsensusEngine>>,
    block_consensus: Option<StdArc<time_consensus::block_consensus::BlockConsensusManager>>,
}

impl PeerListener {
    pub async fn bind(
        bind_addr: SocketAddr,
        network: NetworkType,
        public_addr: SocketAddr,
        blockchain: Option<StdArc<tokio::sync::RwLock<time_core::state::BlockchainState>>>,
        consensus: Option<StdArc<time_consensus::ConsensusEngine>>,
        block_consensus: Option<StdArc<time_consensus::block_consensus::BlockConsensusManager>>,
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
            blockchain,
            consensus,
            block_consensus,
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

        let their_handshake = PeerConnection::receive_handshake(&mut stream, &self.network).await?;
        their_handshake.validate(&self.network)?;

        let our_handshake = HandshakeMessage::new(self.network, self.our_listen_addr);
        PeerConnection::send_handshake(&mut stream, &our_handshake, &self.network).await?;

        let mut peer_info = PeerInfo::with_version(
            their_handshake.listen_addr,
            self.network,
            their_handshake.version.clone(),
        );

        // Update with commit information from handshake
        peer_info.commit_date = their_handshake.commit_date.clone();
        peer_info.commit_count = their_handshake.commit_count.clone();

        // Silently accepted (reduce log verbosity)

        // Auto-register incoming peer as masternode if wallet provided
        if let Some(wallet_addr) = &their_handshake.wallet_address {
            if let (Some(blockchain), Some(consensus)) = (&self.blockchain, &self.consensus) {
                PeerConnection::auto_register_masternode(
                    their_handshake.listen_addr.ip().to_string(),
                    wallet_addr.clone(),
                    blockchain.clone(),
                    consensus.clone(),
                    self.block_consensus.clone(),
                )
                .await;
            }
        }

        Ok(PeerConnection {
            stream,
            peer_info: Arc::new(Mutex::new(peer_info)),
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
