//! Dynamic peer discovery via the TIME Coin website API.
//!
//! Discovery order:
//! 1. Manual peers from `config.toml` (`peers = [...]`)
//! 2. API peers from `https://time-coin.io/api/peers`
//! 3. Cached peers from `~/.timecoin/peers.dat` (fallback when API is down)
//!
//! After a successful API fetch, the peer list is cached to `peers.dat`
//! so the wallet can still connect if the website goes down.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Mainnet peer list URL.
const MAINNET_PEERS_URL: &str = "https://time-coin.io/api/peers";

/// Testnet peer list URL.
const TESTNET_PEERS_URL: &str = "https://www.time-coin.io/api/testnet/peers";

/// Mainnet RPC port.
const MAINNET_PORT: u16 = 24001;

/// Testnet RPC port.
const TESTNET_PORT: u16 = 24101;

/// Cached peer list stored in `peers.dat`.
#[derive(Debug, Serialize, Deserialize)]
struct PeerCache {
    network: String,
    peers: Vec<String>,
}

/// Fetch peers from the API, falling back to the local cache.
///
/// On success the peer list is saved to `~/.timecoin/peers.dat` for
/// future offline use.  Returns `http://{ip}:{port}` endpoint URLs.
pub async fn fetch_peers(is_testnet: bool) -> Result<Vec<String>, PeerDiscoveryError> {
    // Try API first
    match fetch_from_api(is_testnet).await {
        Ok(endpoints) => {
            save_cache(is_testnet, &endpoints);
            Ok(endpoints)
        }
        Err(api_err) => {
            log::warn!("⚠ API peer discovery failed: {}", api_err);
            // Fall back to cached peers
            match load_cache(is_testnet) {
                Some(cached) => {
                    log::info!("📦 Using {} cached peers from peers.dat", cached.len());
                    Ok(cached)
                }
                None => Err(api_err),
            }
        }
    }
}

/// Fetch the peer list directly from the website API.
async fn fetch_from_api(is_testnet: bool) -> Result<Vec<String>, PeerDiscoveryError> {
    let url = if is_testnet {
        TESTNET_PEERS_URL
    } else {
        MAINNET_PEERS_URL
    };

    let port = if is_testnet {
        TESTNET_PORT
    } else {
        MAINNET_PORT
    };

    log::info!("🔍 Fetching peers from {}", url);

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()?;

    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(PeerDiscoveryError::HttpStatus(response.status().as_u16()));
    }

    let ips: Vec<String> = response.json().await?;

    if ips.is_empty() {
        return Err(PeerDiscoveryError::NoPeers);
    }

    let endpoints: Vec<String> = ips
        .into_iter()
        .map(|ip| format!("http://{}:{}", ip, port))
        .collect();

    log::info!("✅ Discovered {} peers from API", endpoints.len());
    Ok(endpoints)
}

// ============================================================================
// Cache
// ============================================================================

fn cache_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".timecoin").join("peers.dat"))
}

fn save_cache(is_testnet: bool, endpoints: &[String]) {
    let Some(path) = cache_path() else { return };
    let cache = PeerCache {
        network: if is_testnet { "testnet" } else { "mainnet" }.to_string(),
        peers: endpoints.to_vec(),
    };
    match serde_json::to_string(&cache) {
        Ok(json) => {
            if let Err(e) = fs::write(&path, json) {
                log::warn!("⚠ Failed to write peers.dat: {}", e);
            } else {
                log::info!("💾 Cached {} peers to {}", endpoints.len(), path.display());
            }
        }
        Err(e) => log::warn!("⚠ Failed to serialize peer cache: {}", e),
    }
}

fn load_cache(is_testnet: bool) -> Option<Vec<String>> {
    let path = cache_path()?;
    let contents = fs::read_to_string(&path).ok()?;
    let cache: PeerCache = serde_json::from_str(&contents).ok()?;
    let expected_network = if is_testnet { "testnet" } else { "mainnet" };
    if cache.network != expected_network {
        log::warn!("⚠ Cached peers are for {}, need {} — ignoring", cache.network, expected_network);
        return None;
    }
    if cache.peers.is_empty() {
        return None;
    }
    Some(cache.peers)
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum PeerDiscoveryError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Peer API returned status {0}")]
    HttpStatus(u16),

    #[error("No peers returned by API")]
    NoPeers,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urls() {
        assert!(MAINNET_PEERS_URL.contains("time-coin.io"));
        assert!(TESTNET_PEERS_URL.contains("testnet"));
    }

    #[test]
    fn test_ports() {
        assert_eq!(MAINNET_PORT, 24001);
        assert_eq!(TESTNET_PORT, 24101);
    }

    #[test]
    fn test_cache_roundtrip() {
        let cache = PeerCache {
            network: "mainnet".to_string(),
            peers: vec!["http://1.2.3.4:24001".to_string()],
        };
        let json = serde_json::to_string(&cache).unwrap();
        let loaded: PeerCache = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.network, "mainnet");
        assert_eq!(loaded.peers.len(), 1);
    }

    #[test]
    fn test_cache_wrong_network() {
        let cache = PeerCache {
            network: "testnet".to_string(),
            peers: vec!["http://1.2.3.4:24101".to_string()],
        };
        let json = serde_json::to_string(&cache).unwrap();
        let loaded: PeerCache = serde_json::from_str(&json).unwrap();
        // Simulates load_cache rejecting wrong network
        assert_ne!(loaded.network, "mainnet");
    }
}
