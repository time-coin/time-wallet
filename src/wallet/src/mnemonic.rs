//! BIP-39 Mnemonic implementation for TIME Coin wallet
//!
//! This module provides industry-standard mnemonic phrase support for
//! deterministic key generation and wallet recovery.

use crate::keypair::{Keypair, KeypairError};
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("Invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    #[error("Keypair generation error: {0}")]
    KeypairError(#[from] KeypairError),

    #[error("Invalid word count: {0} (must be 12, 15, 18, 21, or 24)")]
    InvalidWordCount(usize),

    #[error("Derivation error: {0}")]
    DerivationError(String),
}

/// Generate a new random mnemonic phrase with the specified number of words.
///
/// # Arguments
/// * `word_count` - Number of words in the mnemonic (12, 15, 18, 21, or 24)
///
/// # Returns
/// * `Result<String, MnemonicError>` - The mnemonic phrase as a space-separated string
///
/// # Example
/// ```
/// use wallet::mnemonic::generate_mnemonic;
///
/// let mnemonic = generate_mnemonic(12).unwrap();
/// assert_eq!(mnemonic.split_whitespace().count(), 12);
/// ```
pub fn generate_mnemonic(word_count: usize) -> Result<String, MnemonicError> {
    // Validate word count
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(MnemonicError::InvalidWordCount(word_count));
    }

    // Generate random mnemonic
    // Note: bip39 crate uses entropy bits: 12 words = 128 bits, 24 words = 256 bits
    let mnemonic = match word_count {
        12 => Mnemonic::generate(12).map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?,
        15 => Mnemonic::generate(15).map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?,
        18 => Mnemonic::generate(18).map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?,
        21 => Mnemonic::generate(21).map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?,
        24 => Mnemonic::generate(24).map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?,
        _ => unreachable!(),
    };

    Ok(mnemonic.to_string())
}

/// Validate a mnemonic phrase
///
/// # Arguments
/// * `phrase` - The mnemonic phrase to validate
///
/// # Returns
/// * `Result<(), MnemonicError>` - Ok if valid, error otherwise
pub fn validate_mnemonic(phrase: &str) -> Result<(), MnemonicError> {
    Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;
    Ok(())
}

/// Derive a keypair from a mnemonic phrase
///
/// # Arguments
/// * `phrase` - The mnemonic phrase (space-separated words)
/// * `passphrase` - Optional passphrase for additional security (use "" for none)
///
/// # Returns
/// * `Result<Keypair, MnemonicError>` - The derived keypair
///
/// # Example
/// ```
/// use wallet::mnemonic::{generate_mnemonic, mnemonic_to_keypair};
///
/// let mnemonic = generate_mnemonic(12).unwrap();
/// let keypair = mnemonic_to_keypair(&mnemonic, "").unwrap();
/// ```
pub fn mnemonic_to_keypair(phrase: &str, passphrase: &str) -> Result<Keypair, MnemonicError> {
    // Parse mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    // Convert to seed (512 bits / 64 bytes)
    let seed = mnemonic.to_seed(passphrase);

    // For Ed25519, we need 32 bytes for the private key
    // We'll use the first 32 bytes of the seed, or hash it if we want deterministic derivation
    // Using SHA-256 to derive a 32-byte key from the 64-byte seed
    let mut hasher = Sha256::new();
    hasher.update(&seed[..]);
    let key_bytes = hasher.finalize();

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes[..32]);

    Keypair::from_bytes(&key_array).map_err(MnemonicError::KeypairError)
}

/// Derive a keypair from a mnemonic phrase using BIP-32/BIP-44 derivation path
///
/// # Arguments
/// * `phrase` - The mnemonic phrase (space-separated words)
/// * `passphrase` - Optional passphrase for additional security (use "" for none)
/// * `account_index` - Account index for BIP-44 derivation (typically 0)
///
/// # Returns
/// * `Result<Keypair, MnemonicError>` - The derived keypair
///
/// # Example
/// ```
/// use wallet::mnemonic::{generate_mnemonic, mnemonic_to_keypair_hd};
///
/// let mnemonic = generate_mnemonic(12).unwrap();
/// let keypair = mnemonic_to_keypair_hd(&mnemonic, "", 0).unwrap();
/// ```
pub fn mnemonic_to_keypair_hd(
    phrase: &str,
    passphrase: &str,
    account_index: u32,
) -> Result<Keypair, MnemonicError> {
    // Parse mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    // Convert to seed (512 bits / 64 bytes)
    let seed = mnemonic.to_seed(passphrase);

    // Create extended private key from seed
    let xprv = XPrv::new(seed).map_err(|e| MnemonicError::DerivationError(e.to_string()))?;

    // BIP-44 path: m/44'/coin_type'/account'/change/address_index
    // For TIME Coin, we'll use coin_type = 0 (or register a specific one later)
    // For receiving addresses: change = 0, for change addresses: change = 1
    let path_str = format!("m/44'/0'/{}'", account_index);
    let path: DerivationPath = path_str
        .parse()
        .map_err(|e: bip32::Error| MnemonicError::DerivationError(e.to_string()))?;

    // Derive the key using iterator approach
    let mut current_key = xprv;
    for child_number in path.as_ref() {
        current_key = current_key
            .derive_child(*child_number)
            .map_err(|e| MnemonicError::DerivationError(e.to_string()))?;
    }

    // Get the private key bytes
    let private_key_bytes = current_key.private_key().to_bytes();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);

    Keypair::from_bytes(&key_array).map_err(MnemonicError::KeypairError)
}

/// Mnemonic wrapper for convenience
#[derive(Debug, Clone)]
pub struct MnemonicPhrase {
    phrase: String,
}

impl MnemonicPhrase {
    /// Generate a new random mnemonic
    pub fn generate(word_count: usize) -> Result<Self, MnemonicError> {
        let phrase = generate_mnemonic(word_count)?;
        Ok(Self { phrase })
    }

    /// Create from an existing phrase
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        validate_mnemonic(phrase)?;
        Ok(Self {
            phrase: phrase.to_string(),
        })
    }

    /// Get the phrase as a string
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Get word count
    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }

    /// Derive a keypair from this mnemonic
    pub fn to_keypair(&self, passphrase: &str) -> Result<Keypair, MnemonicError> {
        mnemonic_to_keypair(&self.phrase, passphrase)
    }
}

/// Get the Extended Public Key (xpub) from a mnemonic
///
/// This xpub can be used to derive all child addresses without exposing private keys
///
/// # Arguments
/// * `phrase` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (use "" for none)
/// * `account_index` - Account index (typically 0)
///
/// # Returns
/// * `Result<String, MnemonicError>` - The xpub as a base58-encoded string
pub fn mnemonic_to_xpub(
    phrase: &str,
    passphrase: &str,
    account_index: u32,
) -> Result<String, MnemonicError> {
    // Parse mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    // Convert to seed
    let seed = mnemonic.to_seed(passphrase);

    // Create extended private key from seed
    let xprv = XPrv::new(seed).map_err(|e| MnemonicError::DerivationError(e.to_string()))?;

    // BIP-44 path: m/44'/0'/account'
    let path_str = format!("m/44'/0'/{}'", account_index);
    let path: DerivationPath = path_str
        .parse()
        .map_err(|e: bip32::Error| MnemonicError::DerivationError(e.to_string()))?;

    // Derive to account level
    let mut current_key = xprv;
    for child_number in path.as_ref() {
        current_key = current_key
            .derive_child(*child_number)
            .map_err(|e| MnemonicError::DerivationError(e.to_string()))?;
    }

    // Get the extended public key
    let xpub = current_key.public_key();

    // Convert to string (requires Prefix parameter)
    Ok(xpub.to_string(bip32::Prefix::XPUB))
}

/// Derive an address from an xpub at a specific index
///
/// # Arguments
/// * `xpub_str` - The extended public key as a string
/// * `change` - 0 for receiving addresses, 1 for change addresses
/// * `index` - Address index
/// * `network` - Network type (mainnet/testnet)
///
/// # Returns
/// * `Result<String, MnemonicError>` - The derived address in TIME1 format
pub fn xpub_to_address(
    xpub_str: &str,
    change: u32,
    index: u32,
    network: crate::address::NetworkType,
) -> Result<String, MnemonicError> {
    use bip32::XPub;

    // Parse the xpub
    let xpub: XPub = xpub_str
        .parse()
        .map_err(|e: bip32::Error| MnemonicError::DerivationError(e.to_string()))?;

    // Derive change level (0 = receiving, 1 = change)
    let change_key = xpub
        .derive_child(bip32::ChildNumber::new(change, false).unwrap())
        .map_err(|e| MnemonicError::DerivationError(e.to_string()))?;

    // Derive address index
    let address_key = change_key
        .derive_child(bip32::ChildNumber::new(index, false).unwrap())
        .map_err(|e| MnemonicError::DerivationError(e.to_string()))?;

    // Get the actual public key bytes from the derived key
    // This must match what the GUI wallet does when deriving from mnemonic
    use bip32::PublicKey;
    let public_key_compressed = address_key.public_key().to_bytes();

    // BIP32 public keys are 33 bytes (compressed format with prefix byte)
    // but TIME addresses use 32-byte raw keys, so we strip the prefix
    let public_key_bytes = if public_key_compressed.len() == 33 {
        &public_key_compressed[1..] // Skip the compression prefix byte (0x02 or 0x03)
    } else {
        &public_key_compressed[..]
    };

    // Create a proper TIME address using the actual public key
    // This uses the same SHA256+RIPEMD160+Base58+checksum format as regular addresses
    let address = crate::address::Address::from_public_key(public_key_bytes, network)
        .map_err(|e| MnemonicError::DerivationError(format!("Address generation failed: {}", e)))?;

    Ok(address.to_string())
}

/// Derive keypair using full BIP-44 path: m/44'/0'/account'/change/index
///
/// This is the CORRECT way to derive addresses in HD wallets.
/// The GUI wallet should use this for proper BIP-44 compliance.
///
/// # Arguments
/// * `phrase` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (use "" for none)
/// * `account` - Account index (typically 0)
/// * `change` - Change index (0 = receiving, 1 = change addresses)
/// * `index` - Address index (0, 1, 2, ...)
///
/// # Returns
/// * `Result<Keypair, MnemonicError>` - The derived keypair at the full BIP-44 path
pub fn mnemonic_to_keypair_bip44(
    phrase: &str,
    passphrase: &str,
    account: u32,
    change: u32,
    index: u32,
) -> Result<Keypair, MnemonicError> {
    // Parse mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    // Convert to seed
    let seed = mnemonic.to_seed(passphrase);

    // Create extended private key from seed
    let xprv = XPrv::new(seed).map_err(|e| MnemonicError::DerivationError(e.to_string()))?;

    // Full BIP-44 path: m/44'/0'/account'/change/index
    let path_str = format!("m/44'/0'/{}'/{}/{}", account, change, index);
    let path: DerivationPath = path_str
        .parse()
        .map_err(|e: bip32::Error| MnemonicError::DerivationError(e.to_string()))?;

    // Derive the key
    let mut current_key = xprv;
    for child_number in path.as_ref() {
        current_key = current_key
            .derive_child(*child_number)
            .map_err(|e| MnemonicError::DerivationError(e.to_string()))?;
    }

    // Get the private key bytes
    let private_key_bytes = current_key.private_key().to_bytes();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);

    Keypair::from_bytes(&key_array).map_err(MnemonicError::KeypairError)
}

impl std::fmt::Display for MnemonicPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.phrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_12_words() {
        let mnemonic = generate_mnemonic(12).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic(24).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_invalid_word_count() {
        let result = generate_mnemonic(13);
        assert!(result.is_err());
        match result {
            Err(MnemonicError::InvalidWordCount(13)) => {}
            _ => panic!("Expected InvalidWordCount error"),
        }
    }

    #[test]
    fn test_validate_mnemonic() {
        let mnemonic = generate_mnemonic(12).unwrap();
        assert!(validate_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result =
            validate_mnemonic("invalid word word word word word word word word word word word");
        assert!(result.is_err());
    }

    #[test]
    fn test_mnemonic_to_keypair() {
        let mnemonic = generate_mnemonic(12).unwrap();
        let keypair = mnemonic_to_keypair(&mnemonic, "").unwrap();

        // Verify we can get public key
        let _public_key = keypair.public_key_bytes();
    }

    #[test]
    fn test_mnemonic_deterministic() {
        // Same mnemonic should produce same keypair
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let keypair1 = mnemonic_to_keypair(test_mnemonic, "").unwrap();
        let keypair2 = mnemonic_to_keypair(test_mnemonic, "").unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
        assert_eq!(keypair1.secret_key_bytes(), keypair2.secret_key_bytes());
    }

    #[test]
    fn test_mnemonic_with_passphrase() {
        let mnemonic = generate_mnemonic(12).unwrap();

        // Different passphrases should produce different keypairs
        let keypair1 = mnemonic_to_keypair(&mnemonic, "").unwrap();
        let keypair2 = mnemonic_to_keypair(&mnemonic, "password").unwrap();

        assert_ne!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_mnemonic_phrase_wrapper() {
        let phrase = MnemonicPhrase::generate(12).unwrap();
        assert_eq!(phrase.word_count(), 12);

        let keypair = phrase.to_keypair("").unwrap();
        let _public_key = keypair.public_key_bytes();
    }

    #[test]
    fn test_mnemonic_phrase_from_string() {
        let mnemonic_str = generate_mnemonic(12).unwrap();
        let phrase = MnemonicPhrase::from_phrase(&mnemonic_str).unwrap();
        assert_eq!(phrase.phrase(), mnemonic_str);
    }
}
