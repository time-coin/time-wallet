//! BIP-39 Mnemonic + SLIP-0010 HD key derivation for TIME Coin wallet
//!
//! Uses SLIP-0010 (Ed25519) for hierarchical deterministic key derivation.
//! All derivation levels are hardened (Ed25519 requirement).
//! BIP-44 path: m/44'/coin_type'/account'/change'/index'

use crate::keypair::{Keypair, KeypairError};
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

type HmacSha512 = Hmac<Sha512>;

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

// ── SLIP-0010 Ed25519 HD derivation ──────────────────────────────────

/// Derive the SLIP-0010 master key and chain code from a BIP-39 seed.
fn slip10_master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac =
        HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC can take key of any size");
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);
    (key, chain_code)
}

/// Derive a hardened child key using SLIP-0010.
/// Ed25519 only supports hardened derivation; the hardened bit is set automatically.
fn slip10_derive_child(key: &[u8; 32], chain_code: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let hardened = index | 0x80000000;
    let mut mac = HmacSha512::new_from_slice(chain_code).expect("HMAC can take key of any size");
    mac.update(&[0x00]);
    mac.update(key);
    mac.update(&hardened.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut child_key = [0u8; 32];
    let mut child_cc = [0u8; 32];
    child_key.copy_from_slice(&result[..32]);
    child_cc.copy_from_slice(&result[32..]);
    (child_key, child_cc)
}

/// Derive a keypair at the full SLIP-0010 / BIP-44 path.
/// Path: m/44'/coin_type'/account'/change'/index'  (all hardened)
fn slip10_derive_path(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let (mut key, mut cc) = slip10_master_key(seed);
    for &index in path {
        let (k, c) = slip10_derive_child(&key, &cc, index);
        key = k;
        cc = c;
    }
    key
}

// ── Public API ───────────────────────────────────────────────────────

/// Generate a new random mnemonic phrase with the specified number of words.
pub fn generate_mnemonic(word_count: usize) -> Result<String, MnemonicError> {
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(MnemonicError::InvalidWordCount(word_count));
    }

    let mnemonic = Mnemonic::generate(word_count)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    Ok(mnemonic.to_string())
}

/// Validate a mnemonic phrase
pub fn validate_mnemonic(phrase: &str) -> Result<(), MnemonicError> {
    Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;
    Ok(())
}

/// Check if a single word is in the BIP-39 English wordlist.
pub fn is_valid_bip39_word(word: &str) -> bool {
    Language::English.find_word(word).is_some()
}

/// Derive a keypair from a mnemonic phrase (simple SHA-256 derivation, no HD path).
pub fn mnemonic_to_keypair(phrase: &str, passphrase: &str) -> Result<Keypair, MnemonicError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    let seed = mnemonic.to_seed(passphrase);
    let key_bytes = Sha256::digest(&seed[..]);

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes[..32]);

    Keypair::from_bytes(&key_array).map_err(MnemonicError::KeypairError)
}

/// Derive a keypair at an account-level SLIP-0010 path: m/44'/0'/account'
///
/// Used for the master_key field in wallet_dat.
pub fn mnemonic_to_keypair_hd(
    phrase: &str,
    passphrase: &str,
    account_index: u32,
) -> Result<Keypair, MnemonicError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    let seed = mnemonic.to_seed(passphrase);
    let path = [44, 0, account_index];
    let key = slip10_derive_path(&seed, &path);

    Keypair::from_bytes(&key).map_err(MnemonicError::KeypairError)
}

/// Derive keypair using full BIP-44 / SLIP-0010 path: m/44'/0'/account'/change'/index'
///
/// All levels are hardened (Ed25519 SLIP-0010 requirement).
pub fn mnemonic_to_keypair_bip44(
    phrase: &str,
    passphrase: &str,
    account: u32,
    change: u32,
    index: u32,
) -> Result<Keypair, MnemonicError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

    let seed = mnemonic.to_seed(passphrase);
    let path = [44, 0, account, change, index];
    let key = slip10_derive_path(&seed, &path);

    Keypair::from_bytes(&key).map_err(MnemonicError::KeypairError)
}

/// Derive an address at the given SLIP-0010 / BIP-44 index from a mnemonic.
///
/// Path: m/44'/0'/account'/change'/index'
/// This replaces the old xpub_to_address which required secp256k1 xpub.
pub fn mnemonic_to_address(
    phrase: &str,
    passphrase: &str,
    account: u32,
    change: u32,
    index: u32,
    network: crate::address::NetworkType,
) -> Result<String, MnemonicError> {
    let keypair = mnemonic_to_keypair_bip44(phrase, passphrase, account, change, index)?;
    let pubkey = keypair.public_key_bytes();
    let address = crate::address::Address::from_public_key(&pubkey, network)
        .map_err(|e| MnemonicError::DerivationError(format!("Address generation failed: {}", e)))?;
    Ok(address.to_string())
}

/// Mnemonic wrapper for convenience
#[derive(Debug, Clone)]
pub struct MnemonicPhrase {
    phrase: String,
}

impl MnemonicPhrase {
    pub fn generate(word_count: usize) -> Result<Self, MnemonicError> {
        let phrase = generate_mnemonic(word_count)?;
        Ok(Self { phrase })
    }

    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        validate_mnemonic(phrase)?;
        Ok(Self {
            phrase: phrase.to_string(),
        })
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }

    pub fn to_keypair(&self, passphrase: &str) -> Result<Keypair, MnemonicError> {
        mnemonic_to_keypair(&self.phrase, passphrase)
    }
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
        let _public_key = keypair.public_key_bytes();
    }

    #[test]
    fn test_mnemonic_deterministic() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let keypair1 = mnemonic_to_keypair(test_mnemonic, "").unwrap();
        let keypair2 = mnemonic_to_keypair(test_mnemonic, "").unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
        assert_eq!(keypair1.secret_key_bytes(), keypair2.secret_key_bytes());
    }

    #[test]
    fn test_mnemonic_with_passphrase() {
        let mnemonic = generate_mnemonic(12).unwrap();

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

    #[test]
    fn test_slip10_derivation_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let network = crate::address::NetworkType::Testnet;

        // Same mnemonic + path → same address
        let addr1 = mnemonic_to_address(mnemonic, "", 0, 0, 0, network).unwrap();
        let addr2 = mnemonic_to_address(mnemonic, "", 0, 0, 0, network).unwrap();
        assert_eq!(addr1, addr2);

        // Different indices → different addresses
        let addr3 = mnemonic_to_address(mnemonic, "", 0, 0, 1, network).unwrap();
        assert_ne!(addr1, addr3);

        // Different accounts → different addresses
        let addr4 = mnemonic_to_address(mnemonic, "", 1, 0, 0, network).unwrap();
        assert_ne!(addr1, addr4);
    }

    #[test]
    fn test_slip10_keypair_matches_address() {
        let mnemonic = generate_mnemonic(12).unwrap();
        let network = crate::address::NetworkType::Testnet;

        // Derive via mnemonic_to_address
        let addr1 = mnemonic_to_address(&mnemonic, "", 0, 0, 0, network).unwrap();

        // Derive via keypair
        let keypair = mnemonic_to_keypair_bip44(&mnemonic, "", 0, 0, 0).unwrap();
        let pubkey = keypair.public_key_bytes();
        let addr2 = crate::address::Address::from_public_key(&pubkey, network)
            .unwrap()
            .to_string();

        assert_eq!(
            addr1, addr2,
            "mnemonic_to_address and keypair must produce the same address"
        );
    }
}
