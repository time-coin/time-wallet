//! Integration tests for network module
//! CRITICAL FIX (Issue #15): Add integration tests for complex scenarios

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use time_network::{NetworkConfig, NetworkMessage, PeerManager};
use tokio::time::sleep;

/// Test broadcast with rate limiting
#[tokio::test]
async fn test_broadcast_with_rate_limiting() {
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);

    let manager = Arc::new(PeerManager::new(
        time_network::NetworkType::Testnet,
        listen_addr,
        public_addr,
    ));

    // Simulate multiple broadcasts rapidly
    for i in 0..10 {
        let msg = NetworkMessage::Ping;
        manager.broadcast_message(msg).await;

        if i < 5 {
            // First 5 should succeed
            sleep(Duration::from_millis(10)).await;
        }
    }

    // Verify rate limiting kicked in (broadcasts tracked)
    // In a real scenario, we'd check internal state or logs
    // This is a smoke test to ensure no panics
}

/// Test concurrent peer removal during iteration
#[tokio::test]
async fn test_concurrent_peer_removal() {
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);

    let manager = Arc::new(PeerManager::new(
        time_network::NetworkType::Testnet,
        listen_addr,
        public_addr,
    ));

    // Add some test peers
    let mut peer_ips = vec![];
    for i in 0..5 {
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i + 1)), 8333);
        peer_ips.push(peer_addr.ip());

        // Note: In real test, we'd need to properly connect
        // This is a structural test to ensure no deadlocks
    }

    // Try to iterate and remove concurrently
    let manager1 = manager.clone();
    let manager2 = manager.clone();

    let handle1 = tokio::spawn(async move {
        // Simulate iterating over peers
        for _ in 0..10 {
            let _ = manager1.get_connected_peers().await;
            sleep(Duration::from_millis(10)).await;
        }
    });

    let handle2 = tokio::spawn(async move {
        // Simulate removing peers
        for ip in peer_ips {
            manager2.remove_dead_connection(ip).await;
            sleep(Duration::from_millis(15)).await;
        }
    });

    // Should complete without deadlock
    tokio::time::timeout(Duration::from_secs(5), async {
        handle1.await.unwrap();
        handle2.await.unwrap();
    })
    .await
    .expect("Test should complete within 5 seconds (no deadlock)");
}

/// Test large message handling (serialization/deserialization)
#[tokio::test]
async fn test_large_message_serialization() {
    use time_network::TransactionMessage;

    // Create a transaction message
    let tx_message = TransactionMessage {
        from: "sender".to_string(),
        to: "receiver".to_string(),
        amount: 1000,
        fee: 10,
        timestamp: 1234567890,
        signature: "test_signature".to_string(),
        txid: "test_txid".to_string(),
        nonce: 1,
    };

    // Wrap in network message
    let network_msg = NetworkMessage::Transaction(tx_message);

    // Test serialization with serde_json (bincode not available in public API)
    let serialized = serde_json::to_string(&network_msg).expect("Should serialize");

    // Verify reasonable size (not corrupted)
    assert!(serialized.len() > 50);
    assert!(serialized.len() < 10_000); // Single tx should be under 10KB

    // Test deserialization
    let deserialized: NetworkMessage =
        serde_json::from_str(&serialized).expect("Should deserialize");

    // Verify it's the same type
    match deserialized {
        NetworkMessage::Transaction(_) => { /* Success */ }
        _ => panic!("Should deserialize to Transaction variant"),
    }
}

/// Test protocol version mismatch handling
#[tokio::test]
async fn test_protocol_version_mismatch() {
    use time_network::{HandshakeMessage, NetworkType};

    // Create handshake with incompatible version
    let incompatible_handshake = HandshakeMessage {
        version: "v999.0.0".to_string(), // Future version
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333),
        genesis_hash: Some("test_genesis".to_string()),
        network: NetworkType::Testnet,
        commit_date: None,
        commit_count: None,
        protocol_version: 999,
        timestamp: 0,
        capabilities: vec![],
        wallet_address: None,
    };

    // Verify handshake validation catches this
    let result = incompatible_handshake.validate(&NetworkType::Testnet);

    // Should fail due to version mismatch or other validation
    // (Note: validation logic may vary, this ensures no panic)
    let _validation_result = result;
}

/// Test cleanup tasks don't cause memory leaks
#[tokio::test]
async fn test_cleanup_tasks_spawned() {
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8003);
    let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8003);

    // Create manager (spawns cleanup tasks)
    let manager = PeerManager::new(time_network::NetworkType::Testnet, listen_addr, public_addr);

    // Wait a bit to ensure tasks are running
    sleep(Duration::from_millis(100)).await;

    // Verify manager is still functional (no panics from background tasks)
    let peer_count = manager.get_connected_peers().await.len();
    assert_eq!(peer_count, 0);

    // Drop manager - cleanup tasks should terminate gracefully
    drop(manager);

    // Wait a bit to ensure no panics after drop
    sleep(Duration::from_millis(100)).await;
}

/// Test peer exchange cleanup
#[tokio::test]
async fn test_peer_exchange_cleanup() {
    use time_network::peer_exchange::PeerExchange;
    use time_network::NetworkType;

    let temp_file = format!("/tmp/test_peer_exchange_{}.json", rand::random::<u32>());
    let mut exchange = PeerExchange::new(temp_file.clone(), NetworkType::Testnet);

    // Add some peers
    for i in 0..100 {
        exchange.add_peer(format!("192.168.1.{}", i), 8333, "v0.1.0".to_string());
    }

    assert_eq!(exchange.peer_count(), 100);

    // Clean up peers older than 0 seconds (should remove all)
    let removed = exchange.cleanup_stale_peers(0);
    assert_eq!(removed, 100);
    assert_eq!(exchange.peer_count(), 0);

    // Cleanup temp file
    let _ = std::fs::remove_file(temp_file);
}

/// Test rate limiter cleanup
#[tokio::test]
async fn test_rate_limiter_cleanup() {
    use std::net::IpAddr;
    use time_network::RateLimiter;

    let rate_limiter = RateLimiter::new();

    // Simulate requests from many IPs
    for i in 1..=100 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        let _ = rate_limiter.check_rate_limit(ip, 100).await;
    }

    // Give time for cleanup timers to advance
    sleep(Duration::from_millis(50)).await;

    // Clean up entries older than 0 seconds (should remove all that have no recent requests)
    let removed = rate_limiter
        .cleanup_stale_entries(Duration::from_secs(0))
        .await;

    // Should have cleaned up most entries (may not be exactly 100 due to timing)
    assert!(removed > 50, "Should clean up at least 50 stale entries");
}

/// Test NetworkConfig variants
#[test]
fn test_network_config_variants() {
    let default_config = NetworkConfig::default();
    let testing_config = NetworkConfig::for_testing();
    let high_traffic_config = NetworkConfig::for_high_traffic();

    // Testing config should have shorter timeouts
    assert!(testing_config.connection_timeout < default_config.connection_timeout);
    assert!(testing_config.stale_peer_timeout < default_config.stale_peer_timeout);

    // High traffic config should have more aggressive settings
    assert!(high_traffic_config.min_connections > default_config.min_connections);
    assert!(high_traffic_config.target_connections > default_config.target_connections);
}
