//! time-wallet.dat File Format
//!
//! SECURITY: Implements AES-256-GCM encryption for wallet storage
//! Uses Argon2id for key derivation from password

use crate::encryption::{self, KdfParams, SecurePassword};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use wallet::{Keypair, NetworkType};
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum WalletDatError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Wallet file not found")]
    WalletNotFound,

    #[error("Invalid wallet format")]
    InvalidFormat,

    #[error("Key generation error")]
    KeyGenerationError,

    #[error("Keypair error: {0}")]
    KeypairError(#[from] wallet::KeypairError),

    #[error("Wallet error: {0}")]
    WalletError(#[from] wallet::WalletError),

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] encryption::EncryptionError),

    #[error("Password required for encrypted wallet")]
    PasswordRequired,

    #[error("Wallet is not encrypted")]
    NotEncrypted,
}

/// time-wallet.dat file format
/// SECURITY: Stores encrypted mnemonic using AES-256-GCM
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletDat {
    /// Format version for future compatibility (VERSION 3 = encrypted)
    pub version: u32,
    /// Network type (mainnet/testnet)
    pub network: NetworkType,
    /// Wallet creation timestamp
    pub created_at: i64,
    /// Last modified timestamp
    pub modified_at: i64,
    /// Encryption nonce for AES-GCM (12 bytes)
    #[serde(default)]
    pub nonce: Option<Vec<u8>>,
    /// KDF parameters for Argon2id
    #[serde(default)]
    pub kdf_params: Option<KdfParams>,
    /// Is wallet encrypted with password
    #[serde(default)]
    pub is_encrypted: bool,
    /// Encrypted mnemonic (AES-256-GCM ciphertext)
    /// For v2 (legacy): base64-encoded plaintext
    /// For v3 (current): AES-256-GCM encrypted bytes
    #[serde(with = "serde_bytes")]
    pub encrypted_mnemonic: Vec<u8>,
    /// Master private key (for signing transactions)
    /// TODO: This should also be encrypted in future version
    pub master_key: [u8; 32],
}

impl WalletDat {
    /// Current time-wallet.dat format version (v3 = encrypted)
    pub const VERSION: u32 = 3;

    /// Create a new wallet from mnemonic (unencrypted - for backwards compatibility)
    /// For new wallets, use from_mnemonic_encrypted() instead
    pub fn from_mnemonic(mnemonic: &str, network: NetworkType) -> Result<Self, WalletDatError> {
        Self::from_mnemonic_with_password(mnemonic, network, None)
    }

    /// Create a new encrypted wallet from mnemonic with password protection
    pub fn from_mnemonic_encrypted(
        mnemonic: &str,
        network: NetworkType,
        password: &str,
    ) -> Result<Self, WalletDatError> {
        Self::from_mnemonic_with_password(mnemonic, network, Some(password))
    }

    /// Internal: Create wallet from mnemonic with optional encryption
    fn from_mnemonic_with_password(
        mnemonic: &str,
        network: NetworkType,
        password: Option<&str>,
    ) -> Result<Self, WalletDatError> {
        // Get master key using SLIP-0010 account-level derivation
        use wallet::mnemonic::mnemonic_to_keypair_hd;
        let keypair = mnemonic_to_keypair_hd(mnemonic, "", 0)
            .map_err(|e| WalletDatError::WalletError(wallet::WalletError::MnemonicError(e)))?;
        let master_key = keypair.secret_key_bytes();

        let now = chrono::Utc::now().timestamp();

        // Encrypt mnemonic if password provided
        let (encrypted_mnemonic, nonce, kdf_params, is_encrypted) = if let Some(pwd) = password {
            let secure_pwd = SecurePassword::new(pwd.to_string());
            let (ciphertext, nonce_bytes, kdf) =
                encryption::encrypt_with_password(mnemonic.as_bytes(), &secure_pwd)?;
            (ciphertext, Some(nonce_bytes), Some(kdf), true)
        } else {
            // Legacy format: base64 encoding (for backwards compatibility)
            use base64::{engine::general_purpose, Engine as _};
            let encoded = general_purpose::STANDARD.encode(mnemonic.as_bytes());
            (encoded.into_bytes(), None, None, false)
        };
        Ok(Self {
            version: Self::VERSION,
            network,
            created_at: now,
            modified_at: now,
            nonce,
            kdf_params,
            is_encrypted,
            encrypted_mnemonic,
            master_key,
        })
    }

    /// Decrypt mnemonic from wallet (with password if encrypted)
    fn decrypt_mnemonic(&self, password: Option<&str>) -> Result<String, WalletDatError> {
        if self.is_encrypted {
            // Wallet is encrypted - password required
            let password = password.ok_or(WalletDatError::PasswordRequired)?;
            let nonce = self.nonce.as_ref().ok_or(WalletDatError::InvalidFormat)?;
            let kdf_params = self
                .kdf_params
                .as_ref()
                .ok_or(WalletDatError::InvalidFormat)?;

            let secure_pwd = SecurePassword::new(password.to_string());
            let mnemonic_bytes = encryption::decrypt_with_password(
                &self.encrypted_mnemonic,
                nonce,
                &secure_pwd,
                kdf_params,
            )?;

            let mnemonic = String::from_utf8(mnemonic_bytes)
                .map_err(|e| WalletDatError::SerializationError(e.to_string()))?;

            // Return mnemonic (will be zeroized by caller)
            Ok(mnemonic)
        } else {
            // Legacy format: base64 decoding
            use base64::{engine::general_purpose, Engine as _};
            let mnemonic_bytes = general_purpose::STANDARD
                .decode(&self.encrypted_mnemonic)
                .map_err(|e| WalletDatError::SerializationError(e.to_string()))?;
            String::from_utf8(mnemonic_bytes)
                .map_err(|e| WalletDatError::SerializationError(e.to_string()))
        }
    }

    /// Derive a keypair at the given index
    /// Uses proper BIP-44 derivation: m/44'/0'/0'/0/index
    pub fn derive_keypair(&self, index: u32) -> Result<Keypair, WalletDatError> {
        self.derive_keypair_with_password(index, None)
    }

    /// Derive a keypair with password (for encrypted wallets)
    pub fn derive_keypair_with_password(
        &self,
        index: u32,
        password: Option<&str>,
    ) -> Result<Keypair, WalletDatError> {
        // Decrypt mnemonic
        let mut mnemonic = self.decrypt_mnemonic(password)?;

        // Derive keypair using BIP-44: m/44'/0'/0'/0/index
        use wallet::mnemonic::mnemonic_to_keypair_bip44;
        let keypair = mnemonic_to_keypair_bip44(&mnemonic, "", 0, 0, index)
            .map_err(|e| WalletDatError::WalletError(wallet::WalletError::MnemonicError(e)))?;

        // SECURITY: Zero mnemonic from memory
        mnemonic.zeroize();

        Ok(keypair)
    }

    /// Derive an address at the given index
    /// Uses SLIP-0010 derivation: m/44'/0'/0'/0'/index'
    pub fn derive_address(&self, index: u32) -> Result<String, WalletDatError> {
        // Decrypt mnemonic to derive the address via SLIP-0010
        let mut mnemonic = self.decrypt_mnemonic(None)?;

        use wallet::mnemonic_to_address;
        let address = mnemonic_to_address(&mnemonic, "", 0, 0, index, self.network)
            .map_err(|e| WalletDatError::SerializationError(e.to_string()))?;

        // SECURITY: Zero mnemonic from memory
        mnemonic.zeroize();

        Ok(address)
    }

    /// Derive an address with password (for encrypted wallets)
    pub fn derive_address_with_password(
        &self,
        index: u32,
        password: Option<&str>,
    ) -> Result<String, WalletDatError> {
        let mut mnemonic = self.decrypt_mnemonic(password)?;

        use wallet::mnemonic_to_address;
        let address = mnemonic_to_address(&mnemonic, "", 0, 0, index, self.network)
            .map_err(|e| WalletDatError::SerializationError(e.to_string()))?;

        mnemonic.zeroize();
        Ok(address)
    }

    /// Get the mnemonic (decrypted) - requires password if encrypted
    pub fn get_mnemonic(&self) -> Result<String, WalletDatError> {
        self.get_mnemonic_with_password(None)
    }

    /// Get the mnemonic with password (for encrypted wallets)
    pub fn get_mnemonic_with_password(
        &self,
        password: Option<&str>,
    ) -> Result<String, WalletDatError> {
        self.decrypt_mnemonic(password)
    }

    /// Check if wallet is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    /// Encrypt an existing unencrypted wallet with password
    pub fn encrypt_with_password(&mut self, password: &str) -> Result<(), WalletDatError> {
        if self.is_encrypted {
            return Err(WalletDatError::SerializationError(
                "Wallet is already encrypted".to_string(),
            ));
        }

        // Get current mnemonic (unencrypted)
        let mut mnemonic = self.decrypt_mnemonic(None)?;

        // Encrypt with password
        let secure_pwd = SecurePassword::new(password.to_string());
        let (ciphertext, nonce, kdf_params) =
            encryption::encrypt_with_password(mnemonic.as_bytes(), &secure_pwd)?;

        // Update wallet data
        self.encrypted_mnemonic = ciphertext;
        self.nonce = Some(nonce);
        self.kdf_params = Some(kdf_params);
        self.is_encrypted = true;
        self.version = Self::VERSION;
        self.modified_at = chrono::Utc::now().timestamp();

        // Zero mnemonic from memory
        mnemonic.zeroize();

        Ok(())
    }

    /// Save wallet to file (called only once during wallet creation)
    /// Uses atomic write for safety - wallet.dat should never change after creation
    pub fn save(&self) -> Result<(), WalletDatError> {
        let path = Self::default_path(self.network);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Wallet should only be saved once during creation
        // If it already exists, something is wrong
        if path.exists() {
            log::warn!(
                "Wallet file already exists at: {}. This should only happen during replacement.",
                path.display()
            );
        }

        // Serialize to bincode (unencrypted for now)
        let data = bincode::serialize(self)
            .map_err(|e| WalletDatError::SerializationError(e.to_string()))?;

        // Write to temporary file first for atomic operation
        let temp_path = path.with_extension("dat.tmp");
        fs::write(&temp_path, &data)?;

        // Atomic rename (overwrites destination on most platforms)
        fs::rename(&temp_path, &path)?;

        // On Unix, set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(&path, perms)?;
        }

        log::info!("Wallet saved successfully to: {}", path.display());
        Ok(())
    }

    /// Load wallet from file
    pub fn load(network: NetworkType) -> Result<Self, WalletDatError> {
        let path = Self::default_path(network);

        if !path.exists() {
            return Err(WalletDatError::WalletNotFound);
        }

        let data = fs::read(&path)?;

        // Try to deserialize the wallet
        match bincode::deserialize::<Self>(&data) {
            Ok(wallet) => Ok(wallet),
            Err(e) => Err(WalletDatError::SerializationError(format!(
                "Failed to deserialize wallet file: {}",
                e
            ))),
        }
    }

    /// Get the default wallet path for the given network.
    /// Mainnet: `~/.time-wallet/time-wallet.dat`
    /// Testnet: `~/.time-wallet/testnet/time-wallet.dat`
    pub fn default_path(network: NetworkType) -> PathBuf {
        let data_dir = Self::get_data_dir();
        match network {
            NetworkType::Mainnet => data_dir.join("time-wallet.dat"),
            NetworkType::Testnet => data_dir.join("testnet").join("time-wallet.dat"),
        }
    }

    /// Get the TIME Coin data directory
    pub fn get_data_dir() -> PathBuf {
        if let Some(dir) = dirs::home_dir() {
            dir.join(".time-wallet")
        } else {
            // Fallback to current directory
            PathBuf::from(".")
        }
    }

    /// Create data directory if it doesn't exist
    pub fn ensure_data_dir(network: NetworkType) -> Result<PathBuf, WalletDatError> {
        let wallet_path = Self::default_path(network);
        if let Some(parent) = wallet_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(wallet_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = WalletDat::from_mnemonic(mnemonic, NetworkType::Testnet).unwrap();
        assert_eq!(wallet.version, WalletDat::VERSION);
        assert_eq!(wallet.network, NetworkType::Testnet);
        assert!(!wallet.is_encrypted);
    }

    #[test]
    fn test_derive_address() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = WalletDat::from_mnemonic(mnemonic, NetworkType::Testnet).unwrap();

        let addr0 = wallet.derive_address(0).unwrap();
        let addr1 = wallet.derive_address(1).unwrap();

        // Addresses should be different
        assert_ne!(addr0, addr1);

        // Should be deterministic - derive again and get same result
        let addr0_again = wallet.derive_address(0).unwrap();
        assert_eq!(addr0, addr0_again);
    }

    #[test]
    fn test_save_and_load() {
        use std::env;

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = WalletDat::from_mnemonic(mnemonic, NetworkType::Testnet).unwrap();

        // Get the default path but create a test-specific path in temp directory
        let test_dir = env::temp_dir().join("time-coin-wallet-test");
        std::fs::create_dir_all(&test_dir).unwrap();
        let test_wallet_path = test_dir.join("time-wallet.dat");

        // Manually save to test path
        let data = bincode::serialize(&wallet).unwrap();
        std::fs::write(&test_wallet_path, data).unwrap();

        // Manually load from test path
        let data = std::fs::read(&test_wallet_path).unwrap();
        let loaded: WalletDat = bincode::deserialize(&data).unwrap();

        assert_eq!(loaded.version, wallet.version);
        assert_eq!(loaded.network, wallet.network);

        // Cleanup test file only (NOT production wallet)
        let _ = std::fs::remove_file(&test_wallet_path);
        let _ = std::fs::remove_dir(&test_dir);
    }
}
