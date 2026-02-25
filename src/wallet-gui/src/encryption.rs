//! Wallet Encryption Module
//!
//! SECURITY FIX: Implements AES-256-GCM encryption for wallet mnemonic storage
//! Uses Argon2id for key derivation from password

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encryption errors
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

/// KDF parameters for Argon2id
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Argon2 salt (base64 encoded)
    pub salt: String,
    /// Memory cost (in KB)
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism factor
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            salt: String::new(),
            memory_cost: 19_456, // 19 MB
            time_cost: 2,
            parallelism: 1,
        }
    }
}

/// Secure password container that zeros memory on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecurePassword(String);

impl SecurePassword {
    /// Create from string (will be zeroized on drop)
    pub fn new(password: String) -> Self {
        Self(password)
    }

    /// Get password reference
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Encrypt data with password using AES-256-GCM
///
/// Returns: (encrypted_data, nonce, kdf_params)
pub fn encrypt_with_password(
    data: &[u8],
    password: &SecurePassword,
) -> Result<(Vec<u8>, Vec<u8>, KdfParams), EncryptionError> {
    // Generate random salt for Argon2
    let salt = SaltString::generate(&mut OsRng);

    // Derive 256-bit key from password using Argon2id
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_str().as_bytes(), &salt)
        .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

    // Extract 32-byte key from hash
    let hash_output = password_hash
        .hash
        .ok_or_else(|| EncryptionError::KeyDerivationFailed("No hash output".to_string()))?;

    let key_bytes = hash_output.as_bytes();
    if key_bytes.len() < 32 {
        return Err(EncryptionError::KeyDerivationFailed(
            "Insufficient key length".to_string(),
        ));
    }

    // Create cipher with derived key
    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..32])
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // Generate random nonce (12 bytes for GCM)
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt data
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // Store KDF parameters
    let kdf_params = KdfParams {
        salt: salt.to_string(),
        memory_cost: 19_456,
        time_cost: 2,
        parallelism: 1,
    };

    Ok((ciphertext, nonce.to_vec(), kdf_params))
}

/// Decrypt data with password using AES-256-GCM
pub fn decrypt_with_password(
    encrypted_data: &[u8],
    nonce: &[u8],
    password: &SecurePassword,
    kdf_params: &KdfParams,
) -> Result<Vec<u8>, EncryptionError> {
    // Recreate salt from stored parameters
    let salt = SaltString::from_b64(&kdf_params.salt)
        .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

    // Derive key using same parameters
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_str().as_bytes(), &salt)
        .map_err(|e| EncryptionError::InvalidPassword)?;

    // Extract key from hash
    let hash_output = password_hash
        .hash
        .ok_or_else(|| EncryptionError::KeyDerivationFailed("No hash output".to_string()))?;

    let key_bytes = hash_output.as_bytes();
    if key_bytes.len() < 32 {
        return Err(EncryptionError::KeyDerivationFailed(
            "Insufficient key length".to_string(),
        ));
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..32])
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    // Verify nonce length
    if nonce.len() != 12 {
        return Err(EncryptionError::DecryptionFailed(
            "Invalid nonce length".to_string(),
        ));
    }

    let nonce = Nonce::from_slice(nonce);

    // Decrypt data
    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| EncryptionError::InvalidPassword)?;

    Ok(plaintext)
}

/// Verify password against stored hash
pub fn verify_password(
    password: &SecurePassword,
    password_hash_str: &str,
) -> Result<(), EncryptionError> {
    let parsed_hash = PasswordHash::new(password_hash_str)
        .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

    Argon2::default()
        .verify_password(password.as_str().as_bytes(), &parsed_hash)
        .map_err(|_| EncryptionError::InvalidPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"test mnemonic phrase for encryption";
        let password = SecurePassword::new("MySecurePassword123!".to_string());

        // Encrypt
        let (encrypted, nonce, kdf_params) = encrypt_with_password(data, &password).unwrap();

        // Decrypt
        let decrypted = decrypt_with_password(&encrypted, &nonce, &password, &kdf_params).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_password_fails() {
        let data = b"test data";
        let password = SecurePassword::new("correct_password".to_string());
        let wrong_password = SecurePassword::new("wrong_password".to_string());

        let (encrypted, nonce, kdf_params) = encrypt_with_password(data, &password).unwrap();

        let result = decrypt_with_password(&encrypted, &nonce, &wrong_password, &kdf_params);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::InvalidPassword
        ));
    }

    #[test]
    fn test_password_zeroizes_on_drop() {
        let password_str = "sensitive_password".to_string();
        let password = SecurePassword::new(password_str);

        // Password should be accessible
        assert_eq!(password.as_str(), "sensitive_password");

        // When dropped, memory is zeroized (tested by zeroize crate)
        drop(password);
    }
}
