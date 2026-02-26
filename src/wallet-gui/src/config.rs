use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_network")]
    pub network: String,

    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    #[serde(default = "default_rpc_port")]
    pub rpc_port: u16,

    #[serde(default = "default_rpc_user")]
    pub rpc_user: String,

    #[serde(default = "default_rpc_password")]
    pub rpc_password: String,

    #[serde(default = "default_bootstrap_nodes")]
    pub bootstrap_nodes: Vec<String>,

    #[serde(default = "default_api_endpoint")]
    pub api_endpoint: String,

    #[serde(default)]
    pub addnode: Vec<String>,
}

fn default_network() -> String {
    "testnet".to_string()
}

fn default_data_dir() -> PathBuf {
    // Use home directory with .timecoin for consistency with node data directory
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".timecoin")
}

fn default_rpc_port() -> u16 {
    24101
}

fn default_rpc_user() -> String {
    "rpcuser".to_string()
}

fn default_rpc_password() -> String {
    "rpcpassword".to_string()
}

fn default_bootstrap_nodes() -> Vec<String> {
    // Get bootstrap nodes from environment or use empty list
    // Use TIMECOIN_BOOTSTRAP_NODES="ip1:port1,ip2:port2"
    std::env::var("TIMECOIN_BOOTSTRAP_NODES")
        .ok()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

fn default_api_endpoint() -> String {
    "https://time-coin.io/api/peers".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            network: default_network(),
            data_dir: default_data_dir(),
            rpc_port: default_rpc_port(),
            rpc_user: default_rpc_user(),
            rpc_password: default_rpc_password(),
            bootstrap_nodes: default_bootstrap_nodes(),
            api_endpoint: default_api_endpoint(),
            addnode: Vec::new(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Self::config_path();

        if config_path.exists() {
            let contents = fs::read_to_string(&config_path)?;
            let config: Config = serde_json::from_str(&contents)?;
            Ok(config)
        } else {
            let config = Config::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::config_path();

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let contents = serde_json::to_string_pretty(self)?;
        fs::write(&config_path, contents)?;

        Ok(())
    }

    pub fn config_path() -> PathBuf {
        default_data_dir().join("config.json")
    }

    pub fn wallet_dir(&self) -> PathBuf {
        let network_dir = if self.network == "testnet" {
            "testnet"
        } else {
            "mainnet"
        };
        self.data_dir.join(network_dir)
    }

    /// Set network and save config
    pub fn set_network(&mut self, network: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.network = network.to_string();
        self.save()
    }

    /// Fetch masternode IPs from the peer discovery API and return the first
    /// reachable RPC endpoint (e.g. `http://1.2.3.4:24101`).
    pub fn fetch_masternode_endpoint(&self) -> Option<String> {
        let rpc_port = self.rpc_port;
        match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?
            .get(&self.api_endpoint)
            .send()
        {
            Ok(resp) => {
                if let Ok(peers) = resp.json::<Vec<String>>() {
                    if let Some(ip) = peers.first() {
                        let endpoint = format!("http://{}:{}", ip, rpc_port);
                        log::info!("📡 Discovered masternode from API: {}", endpoint);
                        return Some(endpoint);
                    }
                }
                None
            }
            Err(e) => {
                log::warn!("Failed to fetch peers from {}: {}", self.api_endpoint, e);
                None
            }
        }
    }
}
