//! TIME Coin Cryptography

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
}

#[derive(Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_private_key(private_key_hex: &str) -> Result<Self, CryptoError> {
        let key_bytes = hex::decode(private_key_hex).map_err(|_| CryptoError::InvalidPrivateKey)?;

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPrivateKey)?;

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    pub fn verify(
        public_key_hex: &str,
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let pub_key_bytes =
            hex::decode(public_key_hex).map_err(|_| CryptoError::InvalidPublicKey)?;

        let pub_key_array: [u8; 32] = pub_key_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        let verifying_key =
            VerifyingKey::from_bytes(&pub_key_array).map_err(|_| CryptoError::InvalidPublicKey)?;

        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;

        let signature = Signature::from_bytes(&sig_array);

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

pub fn hash_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn public_key_to_address(public_key_hex: &str) -> String {
    format!("TIME1{}", &public_key_hex[..40])
}

/// Generate a masternode private key (Ed25519)
/// Returns a base58-encoded private key string suitable for masternode.conf
pub fn generate_masternode_key() -> String {
    let keypair = KeyPair::generate();
    // Use a custom encoding for masternode keys (similar to Dash's format)
    // For simplicity, we'll use hex encoding with a prefix
    format!("MN{}", keypair.private_key_hex())
}

/// Validate a masternode private key format
pub fn validate_masternode_key(key: &str) -> Result<(), CryptoError> {
    if !key.starts_with("MN") {
        return Err(CryptoError::InvalidPrivateKey);
    }

    let hex_part = &key[2..];
    if hex_part.len() != 64 {
        return Err(CryptoError::InvalidPrivateKey);
    }

    hex::decode(hex_part).map_err(|_| CryptoError::InvalidPrivateKey)?;
    Ok(())
}

/// Extract the raw private key from a masternode key
pub fn masternode_key_to_private_key(mn_key: &str) -> Result<String, CryptoError> {
    if !mn_key.starts_with("MN") {
        return Err(CryptoError::InvalidPrivateKey);
    }

    Ok(mn_key[2..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_masternode_key() {
        let key = generate_masternode_key();
        assert!(key.starts_with("MN"));
        assert_eq!(key.len(), 66); // "MN" + 64 hex chars
    }

    #[test]
    fn test_validate_masternode_key() {
        let key = generate_masternode_key();
        assert!(validate_masternode_key(&key).is_ok());

        assert!(validate_masternode_key("invalid").is_err());
        assert!(validate_masternode_key("MNinvalid").is_err());
    }

    #[test]
    fn test_masternode_key_to_private_key() {
        let key = generate_masternode_key();
        let private_key = masternode_key_to_private_key(&key).unwrap();
        assert_eq!(private_key.len(), 64);
    }
}
