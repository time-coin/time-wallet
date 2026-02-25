use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Network metrics tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub peer_count: usize,
    pub active_connections: usize,
    pub sync_progress: f64,
    pub current_height: u64,
    pub network_height: u64,
    pub tx_rate: f64,
    pub avg_latency_ms: u64,
    pub uptime_secs: u64,
}

/// Per-peer metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMetrics {
    pub peer_id: String,
    pub latency_ms: u64,
    pub success_rate: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_since: u64,
    pub last_seen: u64,
    pub failures: u32,
}

/// Network monitoring system
pub struct NetworkMonitor {
    start_time: Instant,
    metrics: Arc<RwLock<NetworkMetrics>>,
    peer_metrics: Arc<RwLock<HashMap<String, PeerMetrics>>>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            metrics: Arc::new(RwLock::new(NetworkMetrics {
                peer_count: 0,
                active_connections: 0,
                sync_progress: 0.0,
                current_height: 0,
                network_height: 0,
                tx_rate: 0.0,
                avg_latency_ms: 0,
                uptime_secs: 0,
            })),
            peer_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update network-wide metrics
    pub async fn update_network_metrics(
        &self,
        peer_count: usize,
        active_connections: usize,
        current_height: u64,
        network_height: u64,
    ) {
        let mut metrics = self.metrics.write().await;
        metrics.peer_count = peer_count;
        metrics.active_connections = active_connections;
        metrics.current_height = current_height;
        metrics.network_height = network_height;
        metrics.uptime_secs = self.start_time.elapsed().as_secs();

        if network_height > 0 {
            metrics.sync_progress = (current_height as f64 / network_height as f64) * 100.0;
        }
    }

    /// Update peer-specific metrics
    pub async fn update_peer_metrics(
        &self,
        peer_id: String,
        latency: Duration,
        success: bool,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        let mut peers = self.peer_metrics.write().await;

        let peer = peers.entry(peer_id.clone()).or_insert(PeerMetrics {
            peer_id: peer_id.clone(),
            latency_ms: 0,
            success_rate: 100.0,
            bytes_sent: 0,
            bytes_received: 0,
            connected_since: self.start_time.elapsed().as_secs(),
            last_seen: self.start_time.elapsed().as_secs(),
            failures: 0,
        });

        peer.latency_ms = latency.as_millis() as u64;
        peer.bytes_sent += bytes_sent;
        peer.bytes_received += bytes_received;
        peer.last_seen = self.start_time.elapsed().as_secs();

        if !success {
            peer.failures += 1;
            let total_attempts = peer.failures as f64 / (1.0 - peer.success_rate / 100.0).max(0.01);
            peer.success_rate = ((total_attempts - peer.failures as f64) / total_attempts) * 100.0;
        }
    }

    /// Get current network metrics
    pub async fn get_network_metrics(&self) -> NetworkMetrics {
        let mut metrics = self.metrics.read().await.clone();

        // Calculate average latency from all peers
        let peers = self.peer_metrics.read().await;
        if !peers.is_empty() {
            let total_latency: u64 = peers.values().map(|p| p.latency_ms).sum();
            metrics.avg_latency_ms = total_latency / peers.len() as u64;
        }

        metrics
    }

    /// Get peer-specific metrics
    pub async fn get_peer_metrics(&self, peer_id: &str) -> Option<PeerMetrics> {
        let peers = self.peer_metrics.read().await;
        peers.get(peer_id).cloned()
    }

    /// Get all peer metrics
    pub async fn get_all_peer_metrics(&self) -> Vec<PeerMetrics> {
        let peers = self.peer_metrics.read().await;
        peers.values().cloned().collect()
    }

    /// Remove peer metrics (when peer disconnects)
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peer_metrics.write().await;
        peers.remove(peer_id);
    }

    /// Generate debug report
    pub async fn generate_debug_report(&self) -> String {
        let metrics = self.get_network_metrics().await;
        let peers = self.get_all_peer_metrics().await;

        let mut report = String::new();
        report.push_str("=== TIME Coin Wallet Network Status ===\n\n");

        report.push_str(&format!("Uptime: {} seconds\n", metrics.uptime_secs));
        report.push_str(&format!(
            "Peers: {} connected ({} active)\n",
            metrics.peer_count, metrics.active_connections
        ));
        report.push_str(&format!(
            "Sync: {:.2}% ({}/{})\n",
            metrics.sync_progress, metrics.current_height, metrics.network_height
        ));
        report.push_str(&format!("Avg Latency: {} ms\n", metrics.avg_latency_ms));
        report.push_str(&format!("TX Rate: {:.2}/sec\n\n", metrics.tx_rate));

        report.push_str("=== Peer Details ===\n");
        for peer in peers {
            report.push_str(&format!("• {}\n", peer.peer_id));
            report.push_str(&format!("  Latency: {} ms\n", peer.latency_ms));
            report.push_str(&format!("  Success Rate: {:.2}%\n", peer.success_rate));
            report.push_str(&format!(
                "  Traffic: ↑{} ↓{} bytes\n",
                peer.bytes_sent, peer.bytes_received
            ));
            report.push_str(&format!("  Failures: {}\n\n", peer.failures));
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_metrics_update() {
        let monitor = NetworkMonitor::new();

        monitor.update_network_metrics(5, 3, 100, 200).await;

        let metrics = monitor.get_network_metrics().await;
        assert_eq!(metrics.peer_count, 5);
        assert_eq!(metrics.active_connections, 3);
        assert_eq!(metrics.current_height, 100);
        assert_eq!(metrics.network_height, 200);
        assert_eq!(metrics.sync_progress, 50.0);
    }

    #[tokio::test]
    async fn test_peer_metrics_update() {
        let monitor = NetworkMonitor::new();

        monitor
            .update_peer_metrics(
                "peer1".to_string(),
                Duration::from_millis(50),
                true,
                1000,
                2000,
            )
            .await;

        let peer = monitor.get_peer_metrics("peer1").await.unwrap();
        assert_eq!(peer.latency_ms, 50);
        assert_eq!(peer.bytes_sent, 1000);
        assert_eq!(peer.bytes_received, 2000);
    }
}
