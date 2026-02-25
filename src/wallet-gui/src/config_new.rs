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

    /// Masternode endpoint URL
    #[serde(default = "default_masternode_endpoint")]
    pub masternode_endpoint: String,

    /// Local data directory (for wallet storage)
    #[serde(skip)]
    pub data_dir: Option<PathBuf>,
}

fn default_network() -> String {
    "testnet".to_string()
}

fn default_masternode_endpoint() -> String {
    // Default to testnet masternode
    "https://testnet-mn1.time-coin.io".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: default_network(),
            masternode_endpoint: default_masternode_endpoint(),
            data_dir: None,
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
            log::info!("✅ Config loaded: network={}, endpoint={}", config.network, config.masternode_endpoint);
            Ok(config)
        } else {
            log::info!("📝 Creating default config");
            let mut config = Config::default();
            config.data_dir = Some(Self::data_dir()?);
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
        let mut path = self.data_dir.clone().unwrap_or_else(|| {
            Self::data_dir().unwrap_or_else(|_| PathBuf::from("."))
        });
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
        self.masternode_endpoint = "https://mainnet-mn1.time-coin.io".to_string();
    }

    /// Switch to testnet
    pub fn use_testnet(&mut self) {
        self.network = "testnet".to_string();
        self.masternode_endpoint = "https://testnet-mn1.time-coin.io".to_string();
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Check network is valid
        if self.network != "mainnet" && self.network != "testnet" {
            return Err(ConfigError::InvalidNetwork(self.network.clone()));
        }

        // Check endpoint is valid URL
        if !self.masternode_endpoint.starts_with("http://") 
            && !self.masternode_endpoint.starts_with("https://") {
            return Err(ConfigError::InvalidEndpoint(self.masternode_endpoint.clone()));
        }

        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network, "testnet");
        assert!(config.masternode_endpoint.starts_with("https://"));
    }

    #[test]
    fn test_network_switch() {
        let mut config = Config::default();
        
        config.use_mainnet();
        assert_eq!(config.network, "mainnet");
        assert!(config.masternode_endpoint.contains("mainnet"));

        config.use_testnet();
        assert_eq!(config.network, "testnet");
        assert!(config.masternode_endpoint.contains("testnet"));
    }

    #[test]
    fn test_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.network = "invalid".to_string();
        assert!(config.validate().is_err());

        config.network = "testnet".to_string();
        config.masternode_endpoint = "not-a-url".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_serialization() {
        let config = Config::default();
        let toml = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml).unwrap();
        assert_eq!(config.network, deserialized.network);
    }
}
