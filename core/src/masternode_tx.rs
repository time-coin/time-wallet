//! Masternode transaction types
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeRegistration {
    pub public_key: String,
    pub ip_address: String,
    pub port: u16,
    pub collateral_tx: String,
    pub timestamp: i64,
    pub signature: String,
    pub version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeHeartbeat {
    pub public_key: String,
    pub timestamp: i64,
    pub current_block: u64,
    pub signature: String,
}
impl MasternodeRegistration {
    pub fn new(public_key: String, ip_address: String, port: u16, collateral_tx: String) -> Self {
        Self {
            public_key,
            ip_address,
            port,
            collateral_tx,
            timestamp: chrono::Utc::now().timestamp(),
            signature: String::new(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}
