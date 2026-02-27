//! Wallet configuration (simplified for thin client)
//!
//! In thin client mode, the wallet only needs to know:
//! - Which network (mainnet/testnet)
//! - Where to find the masternode
//! - Where to store local data

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network type ("mainnet" or "testnet")
    #[serde(default = "default_network")]
    pub network: String,

    /// Manually configured peer endpoints (e.g. ["64.91.241.10:24001"]).
    /// These are tried first, before peers discovered from the API.
    #[serde(default)]
    pub peers: Vec<String>,

    /// WebSocket endpoint for real-time notifications.
    /// Derived from the active peer if not set.
    #[serde(default)]
    pub ws_endpoint: Option<String>,

    /// Local data directory (for wallet storage)
    #[serde(skip)]
    pub data_dir: Option<PathBuf>,

    /// The currently active masternode endpoint (set at runtime, not serialized).
    #[serde(skip)]
    pub active_endpoint: Option<String>,
}

fn default_network() -> String {
    "mainnet".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: default_network(),
            peers: Vec::new(),
            ws_endpoint: None,
            data_dir: None,
            active_endpoint: None,
        }
    }
}

impl Config {
    /// Load configuration from disk
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            log::info!("📁 Loading config from: {}", config_path.display());
            let contents = fs::read_to_string(&config_path)?;
            let mut config: Config = toml::from_str(&contents)?;
            config.data_dir = Some(Self::data_dir()?);
            log::info!(
                "✅ Config loaded: network={}, {} manual peers",
                config.network,
                config.peers.len()
            );
            Ok(config)
        } else {
            log::info!("📝 Creating default config");
            let config = Config {
                data_dir: Some(Self::data_dir()?),
                ..Config::default()
            };
            config.save()?;
            Ok(config)
        }
    }

    /// Save configuration to disk
    pub fn save(&self) -> Result<(), ConfigError> {
        let config_path = Self::config_path()?;
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let contents = toml::to_string_pretty(self)?;
        fs::write(&config_path, contents)?;
        log::info!("💾 Config saved to: {}", config_path.display());
        Ok(())
    }

    /// Get the wallet directory for current network
    pub fn wallet_dir(&self) -> PathBuf {
        let mut path = self
            .data_dir
            .clone()
            .unwrap_or_else(|| Self::data_dir().unwrap_or_else(|_| PathBuf::from(".")));
        path.push("wallets");
        path.push(&self.network);
        path
    }

    /// Get config file path
    fn config_path() -> Result<PathBuf, ConfigError> {
        let mut path = Self::data_dir()?;
        path.push("config.toml");
        Ok(path)
    }

    /// Get base data directory
    pub fn data_dir() -> Result<PathBuf, ConfigError> {
        let home = dirs::home_dir().ok_or(ConfigError::NoHomeDir)?;
        let mut path = home;
        path.push(".timecoin");
        Ok(path)
    }

    /// Switch to mainnet
    pub fn use_mainnet(&mut self) {
        self.network = "mainnet".to_string();
    }

    /// Switch to testnet
    pub fn use_testnet(&mut self) {
        self.network = "testnet".to_string();
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.network != "mainnet" && self.network != "testnet" {
            return Err(ConfigError::InvalidNetwork(self.network.clone()));
        }

        // Validate manually configured peer addresses
        for peer in &self.peers {
            if peer.is_empty() {
                return Err(ConfigError::InvalidPeer("empty peer address".to_string()));
            }
        }

        Ok(())
    }

    /// Get the WebSocket URL, deriving from the active endpoint if not explicitly set.
    pub fn ws_url(&self) -> String {
        if let Some(ref ws) = self.ws_endpoint {
            return ws.clone();
        }
        if let Some(ref endpoint) = self.active_endpoint {
            return Self::derive_ws_url(endpoint);
        }
        // No endpoint yet — return a placeholder that will fail gracefully
        "ws://127.0.0.1:0/ws".to_string()
    }

    /// Derive a WebSocket URL from an RPC endpoint.
    ///
    /// The masternode WS server listens on RPC port + 1, so we bump the port
    /// and swap the scheme: `http://host:24101` → `ws://host:24102`.
    pub fn derive_ws_url(endpoint: &str) -> String {
        let base = endpoint
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        // Bump port: WS port = RPC port + 1
        if let Some(colon) = base.rfind(':') {
            if let Ok(rpc_port) = base[colon + 1..].parse::<u16>() {
                return format!("{}{}", &base[..colon + 1], rpc_port + 1);
            }
        }
        base
    }

    /// Get the RPC port for the current network.
    pub fn rpc_port(&self) -> u16 {
        if self.is_testnet() {
            24101
        } else {
            24001
        }
    }

    /// Build HTTP endpoint URLs from the manual peer list.
    /// Each entry can be `ip`, `ip:port`, or a full `http://...` URL.
    pub fn manual_endpoints(&self) -> Vec<String> {
        let port = self.rpc_port();
        self.peers
            .iter()
            .map(|p| {
                if p.starts_with("http://") || p.starts_with("https://") {
                    p.clone()
                } else if p.contains(':') {
                    format!("http://{}", p)
                } else {
                    format!("http://{}:{}", p, port)
                }
            })
            .collect()
    }

    /// Whether this is the testnet network.
    pub fn is_testnet(&self) -> bool {
        self.network == "testnet"
    }
}

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("Home directory not found")]
    NoHomeDir,

    #[error("Invalid network: {0} (must be 'mainnet' or 'testnet')")]
    InvalidNetwork(String),

    #[error("Invalid endpoint: {0} (must start with http:// or https://)")]
    InvalidEndpoint(String),

    #[error("Invalid peer: {0}")]
    InvalidPeer(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network, "mainnet");
        assert!(config.peers.is_empty());
    }

    #[test]
    fn test_network_switch() {
        let mut config = Config::default();

        config.use_mainnet();
        assert_eq!(config.network, "mainnet");

        config.use_testnet();
        assert_eq!(config.network, "testnet");
    }

    #[test]
    fn test_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.network = "invalid".to_string();
        assert!(config.validate().is_err());

        config.network = "mainnet".to_string();
        config.peers = vec!["".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_serialization() {
        let config = Config::default();
        let toml = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml).unwrap();
        assert_eq!(config.network, deserialized.network);
    }

    #[test]
    fn test_ws_url_derived() {
        let config = Config {
            active_endpoint: Some("https://example.com:24001".to_string()),
            ws_endpoint: None,
            ..Default::default()
        };
        assert_eq!(config.ws_url(), "wss://example.com:24002");

        let config2 = Config {
            active_endpoint: Some("http://127.0.0.1:24101".to_string()),
            ws_endpoint: None,
            ..Default::default()
        };
        assert_eq!(config2.ws_url(), "ws://127.0.0.1:24102");
    }

    #[test]
    fn test_ws_url_explicit() {
        let config = Config {
            ws_endpoint: Some("ws://custom:9999/ws".to_string()),
            ..Config::default()
        };
        assert_eq!(config.ws_url(), "ws://custom:9999/ws");
    }

    #[test]
    fn test_manual_endpoints() {
        let config = Config {
            peers: vec![
                "64.91.241.10".to_string(),
                "50.28.104.50:24001".to_string(),
                "http://custom.host:24001".to_string(),
            ],
            ..Config::default()
        };
        let endpoints = config.manual_endpoints();
        assert_eq!(endpoints[0], "http://64.91.241.10:24001");
        assert_eq!(endpoints[1], "http://50.28.104.50:24001");
        assert_eq!(endpoints[2], "http://custom.host:24001");
    }

    #[test]
    fn test_manual_endpoints_testnet() {
        let mut config = Config::default();
        config.use_testnet();
        config.peers = vec!["64.91.241.10".to_string()];
        let endpoints = config.manual_endpoints();
        assert_eq!(endpoints[0], "http://64.91.241.10:24101");
    }
}
