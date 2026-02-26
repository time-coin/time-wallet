//! Wallet encryption and security module
//!
//! Provides password-based encryption for wallet data using industry-standard
//! cryptographic primitives.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::RngCore, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Encrypted wallet data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Argon2 password hash for verification
    pub password_hash: String,
    /// Salt used for key derivation
    pub salt: String,
    /// Encrypted wallet data
    pub ciphertext: Vec<u8>,
    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
    /// Version for future compatibility
    pub version: u32,
}

/// Secure password wrapper that zeros memory on drop
#[derive(ZeroizeOnDrop)]
pub struct SecurePassword(String);

impl SecurePassword {
    pub fn new(password: String) -> Self {
        Self(password)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Wallet encryption handler
pub struct WalletEncryption;

impl WalletEncryption {
    /// Encrypt wallet data with password
    pub fn encrypt(
        wallet_data: &[u8],
        password: &SecurePassword,
    ) -> Result<EncryptedWallet, EncryptionError> {
        // Generate random salt for key derivation
        let salt = SaltString::generate(&mut OsRng);

        // Derive encryption key using Argon2id
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| EncryptionError::KeyDerivationFailed)?
            .to_string();

        // Derive 256-bit key from password
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;

        // Create cipher
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| EncryptionError::EncryptionFailed)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt wallet data
        let ciphertext = cipher
            .encrypt(nonce, wallet_data)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        // Zero the key from memory
        key.zeroize();

        Ok(EncryptedWallet {
            password_hash,
            salt: salt.as_str().to_string(),
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            version: 1,
        })
    }

    /// Decrypt wallet data with password
    pub fn decrypt(
        encrypted: &EncryptedWallet,
        password: &SecurePassword,
    ) -> Result<Vec<u8>, EncryptionError> {
        // Verify password first
        let parsed_hash = PasswordHash::new(&encrypted.password_hash)
            .map_err(|_| EncryptionError::InvalidPassword)?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| EncryptionError::InvalidPassword)?;

        // Derive decryption key
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), encrypted.salt.as_bytes(), &mut key)
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;

        // Create cipher
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| EncryptionError::DecryptionFailed)?;

        // Decrypt
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        // Zero the key from memory
        key.zeroize();

        Ok(plaintext)
    }

    /// Verify password without decrypting
    pub fn verify_password(
        encrypted: &EncryptedWallet,
        password: &SecurePassword,
    ) -> Result<bool, EncryptionError> {
        let parsed_hash = PasswordHash::new(&encrypted.password_hash)
            .map_err(|_| EncryptionError::InvalidPassword)?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Change wallet password
    pub fn change_password(
        encrypted: &EncryptedWallet,
        old_password: &SecurePassword,
        new_password: &SecurePassword,
    ) -> Result<EncryptedWallet, EncryptionError> {
        // Decrypt with old password
        let plaintext = Self::decrypt(encrypted, old_password)?;

        // Re-encrypt with new password
        Self::encrypt(&plaintext, new_password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"sensitive wallet data";
        let password = SecurePassword::new("test_password_123".to_string());

        // Encrypt
        let encrypted = WalletEncryption::encrypt(data, &password).unwrap();

        // Decrypt
        let decrypted = WalletEncryption::decrypt(&encrypted, &password).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password() {
        let data = b"sensitive wallet data";
        let password = SecurePassword::new("correct_password".to_string());
        let wrong_password = SecurePassword::new("wrong_password".to_string());

        let encrypted = WalletEncryption::encrypt(data, &password).unwrap();

        // Should fail with wrong password
        assert!(WalletEncryption::decrypt(&encrypted, &wrong_password).is_err());
    }

    #[test]
    fn test_verify_password() {
        let data = b"test data";
        let password = SecurePassword::new("test_password".to_string());
        let wrong_password = SecurePassword::new("wrong_password".to_string());

        let encrypted = WalletEncryption::encrypt(data, &password).unwrap();

        assert!(WalletEncryption::verify_password(&encrypted, &password).unwrap());
        assert!(!WalletEncryption::verify_password(&encrypted, &wrong_password).unwrap());
    }

    #[test]
    fn test_change_password() {
        let data = b"wallet data";
        let old_password = SecurePassword::new("old_password".to_string());
        let new_password = SecurePassword::new("new_password".to_string());

        let encrypted = WalletEncryption::encrypt(data, &old_password).unwrap();

        // Change password
        let re_encrypted =
            WalletEncryption::change_password(&encrypted, &old_password, &new_password).unwrap();

        // Old password should not work
        assert!(WalletEncryption::decrypt(&re_encrypted, &old_password).is_err());

        // New password should work
        let decrypted = WalletEncryption::decrypt(&re_encrypted, &new_password).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_password_zeroization() {
        let password = SecurePassword::new("sensitive".to_string());
        // Password should be zeroized when dropped
        drop(password);
    }
}
