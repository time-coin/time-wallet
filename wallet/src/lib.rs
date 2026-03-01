//! TIME Coin Wallet Module
//!
//! Improved implementation with:
//! - UTXO model for flexible transactions
//! - thiserror for clean error handling
//! - NetworkType enum for type safety
//! - Fee support in transactions
//! - Auto-incrementing nonce
//! - Convenience methods for key export/import
//! - BIP-39 mnemonic phrase support for deterministic key generation
//! - Password-based encryption with Argon2 + AES-GCM
//! - Auto-lock after inactivity for security
//! - PIN authentication for quick access
//! - Biometric authentication (Face ID, Touch ID, Fingerprint)

pub mod address;
pub mod auto_lock;
pub mod biometric;
pub mod encryption;
pub mod keypair;
pub mod metadata_db;
pub mod mnemonic;
pub mod pin;
pub mod transaction;
pub mod wallet;

pub use address::{Address, AddressError, NetworkType};
pub use auto_lock::{AutoLockConfig, AutoLockManager, LockState};
pub use biometric::{
    BiometricAuth, BiometricAuthenticator, BiometricCapability, BiometricConfig, BiometricError,
    BiometricType, MockBiometricAuth,
};
pub use encryption::{EncryptedWallet, EncryptionError, SecurePassword, WalletEncryption};
pub use keypair::{Keypair, KeypairError};
pub use metadata_db::{MetadataDb, MetadataDbError};
pub use mnemonic::{
    generate_mnemonic, is_valid_bip39_word, mnemonic_to_address, mnemonic_to_keypair,
    mnemonic_to_keypair_bip44, validate_mnemonic, MnemonicError, MnemonicPhrase,
};
pub use pin::{PinAuth, PinConfig, PinError, SecurePin, StoredPin};
pub use transaction::{OutPoint, Transaction, TransactionError, TxInput, TxOutput};
pub use wallet::{calculate_fee, FeeSchedule, FeeTier, Wallet, WalletError, UTXO};
