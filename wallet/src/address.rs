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

    #[error("Invalid address length")]
    InvalidLength,

    #[error("Invalid address prefix")]
    InvalidPrefix,

    #[error("Invalid network digit")]
    InvalidNetwork,

    #[error("Invalid address checksum")]
    InvalidChecksum,

    #[error("Invalid address payload")]
    InvalidPayload,

    #[error("Invalid base58 character")]
    InvalidBase58,
}

/// Network type for addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
}

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// TIME Coin address
/// Format: TIME1 (mainnet) or TIME0 (testnet) + base58(payload[20] + checksum[4])
/// Matches the masternode's address format exactly.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    network: NetworkType,
    payload: [u8; 20],
}

impl Address {
    /// Create an address from an Ed25519 public key (32 bytes)
    pub fn from_public_key(public_key: &[u8], network: NetworkType) -> Result<Self, AddressError> {
        if public_key.len() != 32 {
            return Err(AddressError::InvalidPublicKey);
        }

        let payload = Self::hash_public_key(public_key);
        Ok(Self { network, payload })
    }

    /// Create an address from a string (TIME0... or TIME1...)
    pub fn from_string(s: &str) -> Result<Self, AddressError> {
        if s.len() < 35 || s.len() > 45 {
            return Err(AddressError::InvalidLength);
        }

        if !s.starts_with("TIME") {
            return Err(AddressError::InvalidPrefix);
        }

        let network = match s.chars().nth(4) {
            Some('0') => NetworkType::Testnet,
            Some('1') => NetworkType::Mainnet,
            _ => return Err(AddressError::InvalidNetwork),
        };

        let encoded = &s[5..];
        let decoded = Self::decode_base58(encoded)?;

        if decoded.len() != 24 {
            return Err(AddressError::InvalidPayload);
        }

        // Verify checksum
        let payload_bytes = &decoded[..20];
        let checksum = &decoded[20..24];
        let computed_checksum = Self::compute_checksum(payload_bytes);

        if checksum != &computed_checksum[..4] {
            return Err(AddressError::InvalidChecksum);
        }

        let mut payload = [0u8; 20];
        payload.copy_from_slice(payload_bytes);

        Ok(Self { network, payload })
    }

    /// Convert address to string (TIME0... or TIME1...)
    fn format_address(&self) -> String {
        let network_digit = match self.network {
            NetworkType::Testnet => '0',
            NetworkType::Mainnet => '1',
        };

        let checksum = Self::compute_checksum(&self.payload);
        let mut data = Vec::with_capacity(24);
        data.extend_from_slice(&self.payload);
        data.extend_from_slice(&checksum[..4]);

        let encoded = Self::encode_base58(&data);
        format!("TIME{}{}", network_digit, encoded)
    }

    /// Get network type
    pub fn network(&self) -> NetworkType {
        self.network
    }

    /// Check if this is a testnet address
    pub fn is_testnet(&self) -> bool {
        self.network == NetworkType::Testnet
    }

    /// Get the 20-byte payload hash
    pub fn payload(&self) -> &[u8; 20] {
        &self.payload
    }

    /// Hash public key: first 20 bytes of SHA256
    /// Matches the masternode's address derivation.
    fn hash_public_key(public_key: &[u8]) -> [u8; 20] {
        let sha_hash = Sha256::digest(public_key);
        let mut result = [0u8; 20];
        result.copy_from_slice(&sha_hash[..20]);
        result
    }

    /// Compute checksum (first 4 bytes of double SHA256)
    fn compute_checksum(data: &[u8]) -> [u8; 4] {
        let hash1 = Sha256::digest(data);
        let hash2 = Sha256::digest(hash1);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&hash2[..4]);
        checksum
    }

    fn encode_base58(data: &[u8]) -> String {
        let mut num = num_bigint::BigUint::from_bytes_be(data);
        let base = num_bigint::BigUint::from(58u32);
        let mut result = String::new();

        while num > num_bigint::BigUint::from(0u32) {
            let remainder = &num % &base;
            num /= &base;
            let digits = remainder.to_u32_digits();
            let idx = if digits.is_empty() { 0 } else { digits[0] } as usize;
            result.insert(0, BASE58_ALPHABET[idx] as char);
        }

        // Add leading '1's for leading zeros
        for &byte in data {
            if byte == 0 {
                result.insert(0, '1');
            } else {
                break;
            }
        }

        result
    }

    fn decode_base58(s: &str) -> Result<Vec<u8>, AddressError> {
        let mut num = num_bigint::BigUint::from(0u32);
        let base = num_bigint::BigUint::from(58u32);

        for ch in s.chars() {
            let idx = BASE58_ALPHABET
                .iter()
                .position(|&c| c == ch as u8)
                .ok_or(AddressError::InvalidBase58)?;
            num = num * &base + idx;
        }

        let mut bytes = num.to_bytes_be();

        // Add leading zeros
        let leading_ones = s.chars().take_while(|&c| c == '1').count();
        let mut result = vec![0u8; leading_ones];
        result.append(&mut bytes);

        Ok(result)
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

        assert!(!address.is_testnet());
        assert_eq!(address.payload().len(), 20);
    }

    #[test]
    fn test_address_creation_testnet() {
        let public_key = test_public_key();
        let address = Address::from_public_key(&public_key, NetworkType::Testnet).unwrap();

        assert!(address.is_testnet());
    }

    #[test]
    fn test_address_to_string() {
        let public_key = test_public_key();
        let address = Address::from_public_key(&public_key, NetworkType::Mainnet).unwrap();
        let addr_string = address.to_string();

        assert!(addr_string.starts_with("TIME1"));
        assert!(addr_string.len() >= 35 && addr_string.len() <= 45);
    }

    #[test]
    fn test_address_round_trip() {
        let public_key = test_public_key();
        let address1 = Address::from_public_key(&public_key, NetworkType::Mainnet).unwrap();
        let addr_string = address1.to_string();

        let address2 = Address::from_string(&addr_string).unwrap();

        assert_eq!(address1, address2);
        assert_eq!(address1.payload(), address2.payload());
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
