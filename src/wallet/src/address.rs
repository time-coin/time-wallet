use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid address format")]
    InvalidAddress,

    #[error("Invalid address checksum")]
    InvalidChecksum,

    #[error("Invalid address version")]
    InvalidVersion,
}

/// Network type for addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
}

impl NetworkType {
    /// Get version byte for this network
    pub fn version_byte(&self) -> u8 {
        match self {
            NetworkType::Mainnet => 0x00,
            NetworkType::Testnet => 0x6F,
        }
    }

    /// Get address prefix for this network
    pub fn address_prefix(&self) -> &'static str {
        match self {
            NetworkType::Mainnet => "TIME1",
            NetworkType::Testnet => "TIME0",
        }
    }
}

/// TIME Coin address
/// Format: TIME1 (mainnet) or TIME0 (testnet) + base58(version + hash + checksum)
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    bytes: Vec<u8>, // version + hash160
}

impl Address {
    /// Create an address from a public key
    pub fn from_public_key(public_key: &[u8], network: NetworkType) -> Result<Self, AddressError> {
        if public_key.len() != 32 {
            return Err(AddressError::InvalidPublicKey);
        }

        // Version byte
        let version = network.version_byte();

        // Hash the public key: SHA256 then RIPEMD160
        let hash = Self::hash160_data(public_key);

        // Combine version + hash
        let mut bytes = Vec::with_capacity(21);
        bytes.push(version);
        bytes.extend_from_slice(&hash);

        Ok(Self { bytes })
    }

    /// Create an address from a string
    pub fn from_string(s: &str) -> Result<Self, AddressError> {
        // Accept either TIME1 (mainnet) or TIME0 (testnet) prefix
        let (prefix_len, expected_network) = if s.starts_with("TIME1") {
            (5, Some(NetworkType::Mainnet))
        } else if s.starts_with("TIME0") {
            (5, Some(NetworkType::Testnet))
        } else {
            return Err(AddressError::InvalidAddress);
        };

        let encoded = &s[prefix_len..];
        let decoded = bs58::decode(encoded)
            .into_vec()
            .map_err(|_| AddressError::InvalidAddress)?;

        if decoded.len() != 25 {
            // 1 version + 20 hash + 4 checksum
            return Err(AddressError::InvalidAddress);
        }

        // Verify checksum
        let (payload, checksum) = decoded.split_at(21);
        let expected_checksum = Self::checksum(payload);

        if checksum != expected_checksum {
            return Err(AddressError::InvalidChecksum);
        }

        // Verify version byte matches prefix
        if let Some(network) = expected_network {
            if payload[0] != network.version_byte() {
                return Err(AddressError::InvalidVersion);
            }
        }

        Ok(Self {
            bytes: payload.to_vec(),
        })
    }

    /// Convert address to string
    fn format_address(&self) -> String {
        // Add checksum
        let checksum = Self::checksum(&self.bytes);
        let mut full = self.bytes.clone();
        full.extend_from_slice(&checksum);

        // Base58 encode
        let encoded = bs58::encode(full).into_string();

        // Use appropriate prefix based on network
        let network = self.network();
        let prefix = network.address_prefix();
        format!("{}{}", prefix, encoded)
    }

    /// Get the version byte
    pub fn version(&self) -> u8 {
        self.bytes[0]
    }

    /// Get network type
    pub fn network(&self) -> NetworkType {
        if self.version() == NetworkType::Testnet.version_byte() {
            NetworkType::Testnet
        } else {
            NetworkType::Mainnet
        }
    }

    /// Check if this is a testnet address
    pub fn is_testnet(&self) -> bool {
        self.network() == NetworkType::Testnet
    }

    /// Get the hash160 portion
    pub fn hash160(&self) -> &[u8] {
        &self.bytes[1..]
    }

    /// Compute hash160 (SHA256 + RIPEMD160)
    fn hash160_data(data: &[u8]) -> [u8; 20] {
        let sha256_hash = Sha256::digest(data);
        let ripemd_hash = ripemd::Ripemd160::digest(sha256_hash);
        ripemd_hash.into()
    }

    /// Compute checksum (first 4 bytes of double SHA256)
    fn checksum(data: &[u8]) -> [u8; 4] {
        let hash1 = Sha256::digest(data);
        let hash2 = Sha256::digest(hash1);
        [hash2[0], hash2[1], hash2[2], hash2[3]]
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.format_address())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Address({})", self.format_address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key() -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = 0x12;
        pk[1] = 0x34;
        pk[31] = 0xFF;
        pk
    }

    #[test]
    fn test_address_creation_mainnet() {
        let public_key = test_public_key();
        let address = Address::from_public_key(&public_key, NetworkType::Mainnet).unwrap();

        assert_eq!(address.version(), NetworkType::Mainnet.version_byte());
        assert!(!address.is_testnet());
        assert_eq!(address.hash160().len(), 20);
    }

    #[test]
    fn test_address_creation_testnet() {
        let public_key = test_public_key();
        let address = Address::from_public_key(&public_key, NetworkType::Testnet).unwrap();

        assert_eq!(address.version(), NetworkType::Testnet.version_byte());
        assert!(address.is_testnet());
    }

    #[test]
    fn test_address_to_string() {
        let public_key = test_public_key();
        let address = Address::from_public_key(&public_key, NetworkType::Mainnet).unwrap();
        let addr_string = address.to_string();

        assert!(addr_string.starts_with("TIME1"));
        assert!(addr_string.len() > 10);
    }

    #[test]
    fn test_address_round_trip() {
        let public_key = test_public_key();
        let address1 = Address::from_public_key(&public_key, NetworkType::Mainnet).unwrap();
        let addr_string = address1.to_string();

        let address2 = Address::from_string(&addr_string).unwrap();

        assert_eq!(address1, address2);
        assert_eq!(address1.version(), address2.version());
        assert_eq!(address1.hash160(), address2.hash160());
    }

    #[test]
    fn test_invalid_address() {
        assert!(Address::from_string("INVALID").is_err());
        assert!(Address::from_string("TIME1invalid").is_err());
        assert!(Address::from_string("BTC1address").is_err());
    }

    #[test]
    fn test_network_detection() {
        let public_key = test_public_key();

        let mainnet = Address::from_public_key(&public_key, NetworkType::Mainnet).unwrap();
        assert!(!mainnet.is_testnet());
        assert_eq!(mainnet.network(), NetworkType::Mainnet);

        let testnet = Address::from_public_key(&public_key, NetworkType::Testnet).unwrap();
        assert!(testnet.is_testnet());
        assert_eq!(testnet.network(), NetworkType::Testnet);
    }
}
