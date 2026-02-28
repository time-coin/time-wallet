use crate::address::{Address, AddressError, NetworkType};
use crate::encryption::{EncryptedWallet, EncryptionError, SecurePassword, WalletEncryption};
use crate::keypair::{Keypair, KeypairError};
use crate::mnemonic::{mnemonic_to_keypair_bip44, MnemonicError};
use crate::transaction::{Transaction, TransactionError, TxInput, TxOutput};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Keypair error: {0}")]
    KeypairError(#[from] KeypairError),

    #[error("Address error: {0}")]
    AddressError(#[from] AddressError),

    #[error("Transaction error: {0}")]
    TransactionError(#[from] TransactionError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error")]
    SerializationError,

    #[error("Insufficient funds: have {have}, need {need}")]
    InsufficientFunds { have: u64, need: u64 },

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] MnemonicError),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),
}

const SATOSHIS_PER_TIME: u64 = 100_000_000;
const MIN_TX_FEE: u64 = 1_000_000; // 0.01 TIME

/// A single fee tier: transactions below `up_to` satoshis pay `rate_bps` basis points.
/// 100 bps = 1%.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeeTier {
    /// Upper bound in satoshis (exclusive). Use u64::MAX for the final tier.
    pub up_to: u64,
    /// Fee rate in basis points (1 bps = 0.01%).
    pub rate_bps: u64,
}

/// Governance-adjustable fee schedule.
///
/// Masternodes serve this via the `getfeeschedule` RPC so wallets always use
/// the latest parameters. Governance proposals can update these values without
/// requiring a software upgrade.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeeSchedule {
    /// Ordered list of tiers (smallest `up_to` first).
    pub tiers: Vec<FeeTier>,
    /// Absolute minimum fee in satoshis.
    pub min_fee: u64,
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            tiers: vec![
                FeeTier {
                    up_to: 100 * SATOSHIS_PER_TIME,
                    rate_bps: 100,
                }, // < 100 TIME  → 1%
                FeeTier {
                    up_to: 1_000 * SATOSHIS_PER_TIME,
                    rate_bps: 50,
                }, // < 1k TIME   → 0.5%
                FeeTier {
                    up_to: 10_000 * SATOSHIS_PER_TIME,
                    rate_bps: 25,
                }, // < 10k TIME  → 0.25%
                FeeTier {
                    up_to: u64::MAX,
                    rate_bps: 10,
                }, // >= 10k TIME → 0.1%
            ],
            min_fee: MIN_TX_FEE,
        }
    }
}

impl FeeSchedule {
    /// Calculate the fee for a given send amount.
    pub fn calculate_fee(&self, send_amount: u64) -> u64 {
        let rate_bps = self
            .tiers
            .iter()
            .find(|t| send_amount < t.up_to)
            .map(|t| t.rate_bps)
            .unwrap_or(10); // fallback 0.1%

        let proportional = send_amount * rate_bps / 10_000;
        proportional.max(self.min_fee)
    }
}

/// Calculate the transaction fee using the default fee schedule.
pub fn calculate_fee(send_amount: u64) -> u64 {
    FeeSchedule::default().calculate_fee(send_amount)
}

/// UTXO (Unspent Transaction Output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXO {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    pub amount: u64,
    pub address: String,
}

/// Statistics about UTXO consolidation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationStats {
    pub total_utxos: usize,
    pub dust_utxos: usize,
    pub small_utxos: usize,
    pub large_utxos: usize,
    pub total_value: u64,
    pub dust_value: u64,
    pub needs_consolidation: bool,
}

/// Wallet structure - represents active wallet state in memory
/// Physical storage is handled by:
/// - time-wallet.dat (via WalletDat) - cryptographic keys only
/// - wallet.db (via WalletDb) - metadata, contacts, transactions
#[derive(Serialize, Deserialize)]
pub struct Wallet {
    /// Master keypair for signing transactions
    keypair: Keypair,
    /// Primary address
    address: Address,
    /// Network type (mainnet/testnet)
    pub network: NetworkType,
    /// Current balance (synced from blockchain)
    balance: u64,
    /// Transaction nonce
    nonce: u64,
    /// Unspent transaction outputs
    utxos: Vec<UTXO>,
    /// HD wallet mnemonic phrase (optional, for recovery)
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic_phrase: Option<String>,
    /// Extended public key for transaction sync
    #[serde(skip_serializing_if = "Option::is_none")]
    xpub: Option<String>,
}

impl Wallet {
    /// Create a new wallet with a random keypair
    pub fn new(network: NetworkType) -> Result<Self, WalletError> {
        let keypair = Keypair::generate()?;
        let public_key = keypair.public_key_bytes();
        let address = Address::from_public_key(&public_key, network)?;

        Ok(Self {
            keypair,
            address,
            network,
            balance: 0,
            nonce: 0,
            utxos: Vec::new(),
            mnemonic_phrase: None,
            xpub: None,
        })
    }

    /// Create a wallet from an existing secret key
    pub fn from_secret_key(secret_key: &[u8], network: NetworkType) -> Result<Self, WalletError> {
        let keypair = Keypair::from_secret_key(secret_key)?;
        let public_key = keypair.public_key_bytes();
        let address = Address::from_public_key(&public_key, network)?;

        Ok(Self {
            keypair,
            address,
            network,
            balance: 0,
            nonce: 0,
            utxos: Vec::new(),
            mnemonic_phrase: None,
            xpub: None,
        })
    }

    /// Create a wallet from hex-encoded secret key
    pub fn from_private_key_hex(hex_key: &str, network: NetworkType) -> Result<Self, WalletError> {
        let keypair = Keypair::from_hex(hex_key)?;
        let public_key = keypair.public_key_bytes();
        let address = Address::from_public_key(&public_key, network)?;

        Ok(Self {
            keypair,
            address,
            network,
            balance: 0,
            nonce: 0,
            utxos: Vec::new(),
            mnemonic_phrase: None,
            xpub: None,
        })
    }

    /// Create a wallet from a BIP-39 mnemonic phrase
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase (space-separated words)
    /// * `passphrase` - Optional passphrase for additional security (use "" for none)
    /// * `network` - Network type (Mainnet or Testnet)
    ///
    /// # Returns
    /// * `Result<Self, WalletError>` - The created wallet
    ///
    /// # Example
    /// ```
    /// use wallet::{Wallet, NetworkType, generate_mnemonic};
    ///
    /// let mnemonic = generate_mnemonic(12).unwrap();
    /// let wallet = Wallet::from_mnemonic(&mnemonic, "", NetworkType::Mainnet).unwrap();
    /// ```
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: &str,
        network: NetworkType,
    ) -> Result<Self, WalletError> {
        // Use full BIP-44 path m/44'/0'/0'/0/0 for the default keypair
        let keypair = mnemonic_to_keypair_bip44(mnemonic, passphrase, 0, 0, 0)?;
        let public_key = keypair.public_key_bytes();
        let address = Address::from_public_key(&public_key, network)?;

        // Generate xpub for transaction sync
        use crate::mnemonic::mnemonic_to_xpub;
        let xpub = mnemonic_to_xpub(mnemonic, passphrase, 0).ok();

        Ok(Self {
            keypair,
            address,
            network,
            balance: 0,
            nonce: 0,
            utxos: Vec::new(),
            mnemonic_phrase: Some(mnemonic.to_string()),
            xpub,
        })
    }

    /// Get the wallet address
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the wallet address as a string
    pub fn address_string(&self) -> String {
        self.address.to_string()
    }

    /// Get the compressed public key (33 bytes)
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key_bytes()
    }

    /// Get the public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Get the secret key (be careful with this!)
    pub fn secret_key(&self) -> [u8; 32] {
        self.keypair.secret_key_bytes()
    }

    /// Export private key as hex string (⚠️ Keep secret!)
    pub fn export_private_key(&self) -> String {
        self.keypair.secret_key_hex()
    }

    /// Get current balance
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Set balance (called when syncing with blockchain)
    pub fn set_balance(&mut self, balance: u64) {
        self.balance = balance;
    }

    /// Get current nonce
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Set nonce (called when syncing with blockchain)
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    /// Increment nonce
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }

    /// Get network type
    pub fn network(&self) -> NetworkType {
        self.network
    }

    /// Add UTXO
    pub fn add_utxo(&mut self, utxo: UTXO) {
        let amount = utxo.amount;
        self.utxos.push(utxo);
        self.balance += amount;
    }

    /// Remove UTXO
    pub fn remove_utxo(&mut self, tx_hash: &[u8; 32], output_index: u32) {
        if let Some(pos) = self
            .utxos
            .iter()
            .position(|u| &u.tx_hash == tx_hash && u.output_index == output_index)
        {
            let utxo = self.utxos.remove(pos);
            self.balance = self.balance.saturating_sub(utxo.amount);
        }
    }

    /// Get all UTXOs
    pub fn utxos(&self) -> &[UTXO] {
        &self.utxos
    }

    /// Get UTXO count
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    /// Check if wallet needs consolidation (has many small UTXOs)
    pub fn needs_consolidation(&self) -> bool {
        // Recommend consolidation if:
        // - More than 50 UTXOs total, OR
        // - More than 20% of UTXOs are "dust" (< 1 TIME)
        if self.utxos.len() > 50 {
            return true;
        }

        let dust_threshold = 1_000_000_000; // 1 TIME in satoshis
        let dust_count = self
            .utxos
            .iter()
            .filter(|u| u.amount < dust_threshold)
            .count();
        dust_count > self.utxos.len() / 5 // > 20% dust
    }

    /// Create a UTXO consolidation transaction
    /// Combines multiple UTXOs into a single UTXO to improve transaction efficiency
    ///
    /// # Arguments
    /// * `max_utxos` - Maximum number of UTXOs to consolidate in one transaction (default: 100)
    /// * `fee` - Transaction fee
    ///
    /// Returns consolidated transaction or None if consolidation not beneficial
    pub fn create_consolidation_transaction(
        &mut self,
        max_utxos: Option<usize>,
        fee: u64,
    ) -> Result<Option<Transaction>, WalletError> {
        let max = max_utxos.unwrap_or(100);

        // Only consolidate if we have more than 10 UTXOs
        if self.utxos.len() <= 10 {
            return Ok(None);
        }

        // Select UTXOs to consolidate (up to max_utxos)
        let utxos_to_consolidate: Vec<UTXO> = self
            .utxos
            .iter()
            .take(max.min(self.utxos.len()))
            .cloned()
            .collect();

        if utxos_to_consolidate.is_empty() {
            return Ok(None);
        }

        // Calculate total amount
        let total_amount: u64 = utxos_to_consolidate.iter().map(|u| u.amount).sum();

        if total_amount <= fee {
            return Ok(None); // Not worth consolidating
        }

        // Create transaction
        let mut tx = Transaction::new();

        // Add all selected UTXOs as inputs
        for utxo in &utxos_to_consolidate {
            let input = TxInput::new(utxo.tx_hash, utxo.output_index);
            tx.add_input(input);
        }

        // Single output back to ourselves (minus fee)
        let output_amount = total_amount - fee;
        let output = TxOutput::new(output_amount, self.address.clone());
        tx.add_output(output)?;

        // Sign the transaction
        tx.sign_all(&self.keypair)?;

        // Remove spent UTXOs immediately
        for utxo in &utxos_to_consolidate {
            self.remove_utxo(&utxo.tx_hash, utxo.output_index);
        }

        // Update nonce
        self.increment_nonce();

        Ok(Some(tx))
    }

    /// Get consolidation statistics
    pub fn consolidation_stats(&self) -> ConsolidationStats {
        let dust_threshold = 1_000_000_000; // 1 TIME
        let small_threshold = 10_000_000_000; // 10 TIME

        let total_utxos = self.utxos.len();
        let dust_utxos = self
            .utxos
            .iter()
            .filter(|u| u.amount < dust_threshold)
            .count();
        let small_utxos = self
            .utxos
            .iter()
            .filter(|u| u.amount >= dust_threshold && u.amount < small_threshold)
            .count();
        let large_utxos = total_utxos - dust_utxos - small_utxos;

        let total_value: u64 = self.utxos.iter().map(|u| u.amount).sum();
        let dust_value: u64 = self
            .utxos
            .iter()
            .filter(|u| u.amount < dust_threshold)
            .map(|u| u.amount)
            .sum();

        ConsolidationStats {
            total_utxos,
            dust_utxos,
            small_utxos,
            large_utxos,
            total_value,
            dust_value,
            needs_consolidation: self.needs_consolidation(),
        }
    }

    /// Derive a keypair at the given address index (BIP-44: m/44'/0'/0'/0/index)
    pub fn derive_keypair(&self, index: u32) -> Result<Keypair, WalletError> {
        if let Some(ref mnemonic) = self.mnemonic_phrase {
            Ok(mnemonic_to_keypair_bip44(mnemonic, "", 0, 0, index)?)
        } else {
            Err(WalletError::MnemonicError(
                crate::mnemonic::MnemonicError::InvalidWordCount(0),
            ))
        }
    }

    /// Derive an address at the given index (for HD wallets)
    pub fn derive_address(&self, index: u32) -> Result<String, WalletError> {
        let keypair = self.derive_keypair(index)?;
        let public_key = keypair.public_key_bytes();
        let address = Address::from_public_key(&public_key, self.network)?;
        Ok(address.to_string())
    }

    /// Create a transaction with fee support
    ///
    /// **Instant Finality Behavior**: This method removes spent UTXOs immediately
    /// from the wallet's UTXO list. This ensures that the wallet balance reflects
    /// the transaction as soon as it's created and broadcast, consistent with the
    /// TIME Coin Protocol's instant finality design. The UTXOs are:
    /// 1. Removed immediately when transaction is created (this method)
    /// 2. Locked in the instant finality consensus system (<3 seconds)
    /// 3. Marked as spent when consensus achieved (instant finality)
    /// 4. Confirmed when included in a block (~24 hours later)
    ///
    /// This prevents the "ghost balance" issue where sent coins appear available
    /// for 24 hours until the block is created.
    pub fn create_transaction(
        &mut self,
        to_address: &str,
        amount: u64,
        _fee: u64,
    ) -> Result<Transaction, WalletError> {
        if amount == 0 {
            return Err(WalletError::TransactionError(
                TransactionError::InvalidAmount,
            ));
        }

        // Validate recipient address
        let recipient = Address::from_string(to_address)?;

        // Tiered fee: 1% under 100 TIME, 0.5% under 1k, 0.25% under 10k, 0.1% above
        // Minimum fee: 0.01 TIME (1_000_000 sats)
        let actual_fee = calculate_fee(amount);
        let total_needed = amount + actual_fee;

        if total_needed > self.balance {
            return Err(WalletError::InsufficientFunds {
                have: self.balance,
                need: total_needed,
            });
        }

        // Select UTXOs greedily
        let mut input_amount = 0u64;
        let mut selected_utxos = Vec::new();

        for utxo in &self.utxos {
            selected_utxos.push(utxo.clone());
            input_amount += utxo.amount;

            if input_amount >= total_needed {
                break;
            }
        }

        if input_amount < total_needed {
            return Err(WalletError::InsufficientFunds {
                have: input_amount,
                need: total_needed,
            });
        }

        // Create transaction
        let mut tx = Transaction::new();

        // Add inputs
        for utxo in &selected_utxos {
            let input = TxInput::new(utxo.tx_hash, utxo.output_index);
            tx.add_input(input);
        }

        // Add output to recipient
        let output = TxOutput::new(amount, recipient);
        tx.add_output(output)?;

        // Add change output if necessary
        let change = input_amount - total_needed;
        if change > 0 {
            let change_output = TxOutput::new(change, self.address.clone());
            tx.add_output(change_output)?;
        }

        // Sign the transaction
        tx.sign_all(&self.keypair)?;

        // Remove spent UTXOs immediately (instant finality)
        // These UTXOs are now locked in the instant finality system
        for utxo in &selected_utxos {
            self.remove_utxo(&utxo.tx_hash, utxo.output_index);
        }

        // Update wallet state (auto-increment nonce)
        self.increment_nonce();

        Ok(tx)
    }

    /// Sign an existing transaction
    pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<(), WalletError> {
        tx.sign_all(&self.keypair)?;
        Ok(())
    }

    /// Save wallet to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), WalletError> {
        let serialized =
            serde_json::to_string_pretty(self).map_err(|_| WalletError::SerializationError)?;
        fs::write(path, serialized)?;
        Ok(())
    }

    /// Load wallet from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let data = fs::read_to_string(path)?;
        let wallet: Self =
            serde_json::from_str(&data).map_err(|_| WalletError::SerializationError)?;
        Ok(wallet)
    }

    /// Save wallet to encrypted file with password protection
    ///
    /// # Arguments
    /// * `path` - File path to save encrypted wallet
    /// * `password` - Password for encryption (will be zeroized after use)
    ///
    /// # Security
    /// - Uses Argon2id for key derivation (memory-hard, resistant to GPU attacks)
    /// - Uses AES-256-GCM for encryption (authenticated encryption)
    /// - Random salt and nonce for each encryption
    ///
    /// # Example
    /// ```no_run
    /// use wallet::{Wallet, NetworkType, SecurePassword};
    ///
    /// let wallet = Wallet::new(NetworkType::Mainnet).unwrap();
    /// let password = SecurePassword::new("strong_password".to_string());
    /// wallet.save_encrypted("wallet.enc", &password).unwrap();
    /// ```
    pub fn save_encrypted<P: AsRef<Path>>(
        &self,
        path: P,
        password: &SecurePassword,
    ) -> Result<(), WalletError> {
        // Serialize wallet to JSON
        let wallet_json = serde_json::to_vec(self).map_err(|_| WalletError::SerializationError)?;

        // Encrypt
        let encrypted = WalletEncryption::encrypt(&wallet_json, password)?;

        // Save to file
        let encrypted_json = serde_json::to_string_pretty(&encrypted)
            .map_err(|_| WalletError::SerializationError)?;
        fs::write(path, encrypted_json)?;

        Ok(())
    }

    /// Load wallet from encrypted file with password
    ///
    /// # Arguments
    /// * `path` - Path to encrypted wallet file
    /// * `password` - Password for decryption
    ///
    /// # Errors
    /// - `InvalidPassword` if password is incorrect
    /// - `DecryptionFailed` if file is corrupted
    /// - `IoError` if file cannot be read
    ///
    /// # Example
    /// ```no_run
    /// use wallet::{Wallet, SecurePassword};
    ///
    /// let password = SecurePassword::new("strong_password".to_string());
    /// let wallet = Wallet::load_encrypted("wallet.enc", &password).unwrap();
    /// ```
    pub fn load_encrypted<P: AsRef<Path>>(
        path: P,
        password: &SecurePassword,
    ) -> Result<Self, WalletError> {
        // Read encrypted file
        let encrypted_json = fs::read_to_string(path)?;
        let encrypted: EncryptedWallet =
            serde_json::from_str(&encrypted_json).map_err(|_| WalletError::SerializationError)?;

        // Decrypt
        let wallet_json = WalletEncryption::decrypt(&encrypted, password)?;

        // Deserialize
        let wallet: Self =
            serde_json::from_slice(&wallet_json).map_err(|_| WalletError::SerializationError)?;

        Ok(wallet)
    }

    /// Verify password for encrypted wallet file without loading
    ///
    /// Useful for checking password before attempting full decryption
    pub fn verify_encrypted_password<P: AsRef<Path>>(
        path: P,
        password: &SecurePassword,
    ) -> Result<bool, WalletError> {
        let encrypted_json = fs::read_to_string(path)?;
        let encrypted: EncryptedWallet =
            serde_json::from_str(&encrypted_json).map_err(|_| WalletError::SerializationError)?;

        Ok(WalletEncryption::verify_password(&encrypted, password)?)
    }

    /// Change password for encrypted wallet file
    ///
    /// # Arguments
    /// * `path` - Path to encrypted wallet file
    /// * `old_password` - Current password
    /// * `new_password` - New password
    ///
    /// # Example
    /// ```no_run
    /// use wallet::{Wallet, SecurePassword};
    ///
    /// let old_pwd = SecurePassword::new("old_password".to_string());
    /// let new_pwd = SecurePassword::new("new_password".to_string());
    /// Wallet::change_encrypted_password("wallet.enc", &old_pwd, &new_pwd).unwrap();
    /// ```
    pub fn change_encrypted_password<P: AsRef<Path>>(
        path: P,
        old_password: &SecurePassword,
        new_password: &SecurePassword,
    ) -> Result<(), WalletError> {
        // Load current encrypted wallet
        let encrypted_json = fs::read_to_string(&path)?;
        let encrypted: EncryptedWallet =
            serde_json::from_str(&encrypted_json).map_err(|_| WalletError::SerializationError)?;

        // Change password
        let re_encrypted =
            WalletEncryption::change_password(&encrypted, old_password, new_password)?;

        // Save
        let new_encrypted_json = serde_json::to_string_pretty(&re_encrypted)
            .map_err(|_| WalletError::SerializationError)?;
        fs::write(path, new_encrypted_json)?;

        Ok(())
    }

    /// Check if testnet
    pub fn is_testnet(&self) -> bool {
        self.network == NetworkType::Testnet
    }

    /// Get the keypair (for advanced use)
    /// Generate QR code for the wallet address (as ASCII art for terminal display)
    pub fn address_qr_code(&self) -> Result<String, WalletError> {
        use qrcode::QrCode;
        let code = QrCode::new(self.address_string().as_bytes())
            .map_err(|_| WalletError::SerializationError)?;
        let string = code
            .render::<char>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .dark_color('█')
            .light_color(' ')
            .build();
        Ok(string)
    }

    /// Generate QR code as SVG string (for GUI applications)
    pub fn address_qr_code_svg(&self) -> Result<String, WalletError> {
        use qrcode::render::svg;
        use qrcode::QrCode;
        let code = QrCode::new(self.address_string().as_bytes())
            .map_err(|_| WalletError::SerializationError)?;
        let svg = code
            .render()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();
        Ok(svg)
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Get the xpub (extended public key) if available
    pub fn xpub(&self) -> Option<&str> {
        self.xpub.as_deref()
    }

    /// Set the xpub (extended public key)
    pub fn set_xpub(&mut self, xpub: String) {
        self.xpub = Some(xpub);
    }
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address.to_string())
            .field("network", &self.network)
            .field("balance", &self.balance)
            .field("nonce", &self.nonce)
            .field("utxos", &self.utxos.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new(NetworkType::Mainnet).unwrap();
        assert!(!wallet.is_testnet());
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.nonce(), 0);
    }

    #[test]
    fn test_wallet_from_secret_key() {
        let wallet1 = Wallet::new(NetworkType::Mainnet).unwrap();
        let secret_key = wallet1.secret_key();

        let wallet2 = Wallet::from_secret_key(&secret_key, NetworkType::Mainnet).unwrap();

        assert_eq!(wallet1.address_string(), wallet2.address_string());
        assert_eq!(wallet1.public_key(), wallet2.public_key());
    }

    #[test]
    fn test_wallet_from_hex() {
        let wallet1 = Wallet::new(NetworkType::Mainnet).unwrap();
        let hex_key = wallet1.export_private_key();

        let wallet2 = Wallet::from_private_key_hex(&hex_key, NetworkType::Mainnet).unwrap();

        assert_eq!(wallet1.address_string(), wallet2.address_string());
    }

    #[test]
    fn test_balance_management() {
        let mut wallet = Wallet::new(NetworkType::Mainnet).unwrap();

        let utxo = UTXO {
            tx_hash: [1u8; 32],
            output_index: 0,
            amount: 1000,
            address: wallet.address_string(),
        };

        wallet.add_utxo(utxo);
        assert_eq!(wallet.balance(), 1000);

        wallet.remove_utxo(&[1u8; 32], 0);
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn test_nonce_increment() {
        let mut wallet = Wallet::new(NetworkType::Mainnet).unwrap();
        assert_eq!(wallet.nonce(), 0);

        wallet.increment_nonce();
        assert_eq!(wallet.nonce(), 1);

        wallet.increment_nonce();
        assert_eq!(wallet.nonce(), 2);
    }

    #[test]
    fn test_create_transaction_with_fee() {
        let mut sender = Wallet::new(NetworkType::Mainnet).unwrap();
        let recipient = Wallet::new(NetworkType::Mainnet).unwrap();

        // Add UTXO to sender (10 TIME)
        let utxo = UTXO {
            tx_hash: [1u8; 32],
            output_index: 0,
            amount: 10 * 100_000_000, // 10 TIME
            address: sender.address_string(),
        };
        sender.add_utxo(utxo);

        // Create transaction: send 5 TIME
        let send_amount = 5 * 100_000_000; // 5 TIME
        let tx = sender
            .create_transaction(&recipient.address_string(), send_amount, 0)
            .unwrap();

        let fee = calculate_fee(send_amount); // 1% of 5 TIME = 0.05 TIME
        assert_eq!(tx.outputs.len(), 2); // recipient + change
        assert_eq!(tx.outputs[0].value, send_amount);
        assert_eq!(tx.outputs[1].value, 10 * 100_000_000 - send_amount - fee);
        assert_eq!(sender.nonce(), 1); // Auto-incremented
    }

    #[test]
    fn test_insufficient_funds() {
        let mut wallet = Wallet::new(NetworkType::Mainnet).unwrap();
        let recipient = Wallet::new(NetworkType::Mainnet).unwrap();

        // Add small UTXO (0.5 TIME)
        let utxo = UTXO {
            tx_hash: [1u8; 32],
            output_index: 0,
            amount: 50_000_000, // 0.5 TIME
            address: wallet.address_string(),
        };
        wallet.add_utxo(utxo);

        // Try to send 10 TIME — should fail
        let result = wallet.create_transaction(&recipient.address_string(), 10 * 100_000_000, 0);

        assert!(result.is_err());
        match result {
            Err(WalletError::InsufficientFunds { .. }) => {}
            _ => panic!("Expected InsufficientFunds error"),
        }
    }

    #[test]
    fn test_instant_finality_utxo_removal() {
        // Test that UTXOs are removed immediately when transaction is created
        // This is critical for instant finality - the wallet should show the
        // correct balance immediately, not 24 hours later when block is created

        let mut sender = Wallet::new(NetworkType::Mainnet).unwrap();
        let recipient = Wallet::new(NetworkType::Mainnet).unwrap();

        // Add UTXO to sender (10 TIME = 1,000,000,000 sats)
        let utxo = UTXO {
            tx_hash: [1u8; 32],
            output_index: 0,
            amount: 1_000_000_000,
            address: sender.address_string(),
        };
        sender.add_utxo(utxo);

        // Verify initial state
        assert_eq!(sender.balance(), 1_000_000_000);
        assert_eq!(sender.utxos().len(), 1);

        // Create transaction - this should IMMEDIATELY remove spent UTXOs
        // Send 1 TIME; fee = 1% of 1 TIME = 0.01 TIME (minimum)
        let _tx = sender
            .create_transaction(&recipient.address_string(), 100_000_000, 0)
            .unwrap();

        // CRITICAL TEST: Balance should be updated IMMEDIATELY (instant finality)
        // The spent UTXO (10 TIME) is removed
        // Change output will be added when transaction is finalized
        assert_eq!(
            sender.balance(),
            0,
            "Balance should reflect spent UTXOs immediately"
        );
        assert_eq!(
            sender.utxos().len(),
            0,
            "Spent UTXOs should be removed immediately"
        );

        // In a real scenario, when the transaction is finalized (within 3 seconds),
        // the change output would be added back to the wallet as a new UTXO
    }

    #[test]
    fn test_save_and_load() {
        let wallet1 = Wallet::new(NetworkType::Mainnet).unwrap();
        let temp_file = "/tmp/test_wallet_improved.json";

        wallet1.save_to_file(temp_file).unwrap();
        let wallet2 = Wallet::load_from_file(temp_file).unwrap();

        assert_eq!(wallet1.address_string(), wallet2.address_string());
        assert_eq!(wallet1.public_key(), wallet2.public_key());

        // Cleanup
        let _ = fs::remove_file(temp_file);
    }

    #[test]
    fn test_wallet_from_mnemonic() {
        use crate::mnemonic::generate_mnemonic;

        let mnemonic = generate_mnemonic(12).unwrap();
        let wallet = Wallet::from_mnemonic(&mnemonic, "", NetworkType::Mainnet).unwrap();

        assert!(!wallet.is_testnet());
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.nonce(), 0);
    }

    #[test]
    fn test_wallet_mnemonic_deterministic() {
        // Same mnemonic should produce same wallet
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let wallet1 = Wallet::from_mnemonic(test_mnemonic, "", NetworkType::Mainnet).unwrap();
        let wallet2 = Wallet::from_mnemonic(test_mnemonic, "", NetworkType::Mainnet).unwrap();

        assert_eq!(wallet1.address_string(), wallet2.address_string());
        assert_eq!(wallet1.public_key(), wallet2.public_key());
        assert_eq!(wallet1.secret_key(), wallet2.secret_key());
    }

    #[test]
    fn test_wallet_mnemonic_with_passphrase() {
        use crate::mnemonic::generate_mnemonic;

        let mnemonic = generate_mnemonic(12).unwrap();

        // Different passphrases should produce different wallets
        let wallet1 = Wallet::from_mnemonic(&mnemonic, "", NetworkType::Mainnet).unwrap();
        let wallet2 = Wallet::from_mnemonic(&mnemonic, "password", NetworkType::Mainnet).unwrap();

        assert_ne!(wallet1.address_string(), wallet2.address_string());
        assert_ne!(wallet1.public_key(), wallet2.public_key());
    }

    #[test]
    fn test_wallet_from_invalid_mnemonic() {
        let result = Wallet::from_mnemonic(
            "invalid word word word word word word word word word word word",
            "",
            NetworkType::Mainnet,
        );

        assert!(result.is_err());
    }
}
