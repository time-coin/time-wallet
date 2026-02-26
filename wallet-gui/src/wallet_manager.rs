//! Wallet Manager
//!
//! Manages time-wallet.dat file and provides high-level wallet operations
//! for the thin-client architecture.
//!
//! The wallet uses deterministic address derivation:
//! - time-wallet.dat stores ONLY: xpub, encrypted mnemonic, master key
//! - Addresses are derived on-demand from xpub
//! - All blockchain state is queried from masternodes via JSON-RPC

use crate::wallet_dat::{WalletDat, WalletDatError};
use std::fs;
use wallet::{Keypair, NetworkType, Transaction, Wallet, UTXO};

#[derive(Debug)]
pub struct WalletManager {
    wallet_dat: WalletDat,
    // Active wallet instance
    active_wallet: Wallet,
    // Next address index to derive
    next_address_index: u32,
}

impl WalletManager {
    /// Create a wallet from a BIP-39 mnemonic phrase (unencrypted)
    pub fn create_from_mnemonic(
        network: NetworkType,
        mnemonic: &str,
    ) -> Result<Self, WalletDatError> {
        // Check if wallet already exists
        let wallet_path = WalletDat::default_path(network);
        if wallet_path.exists() {
            log::warn!(
                "Wallet already exists at: {}. Loading existing wallet instead.",
                wallet_path.display()
            );
            return Self::load(network);
        }

        // Validate mnemonic first
        wallet::validate_mnemonic(mnemonic)
            .map_err(|e| WalletDatError::WalletError(wallet::WalletError::MnemonicError(e)))?;

        // Create wallet from mnemonic
        let wallet = Wallet::from_mnemonic(mnemonic, "", network)?;

        // Create wallet_dat from mnemonic (stores xpub, encrypted mnemonic, master key)
        let wallet_dat = WalletDat::from_mnemonic(mnemonic, network)?;

        log::info!("Created wallet with xpub: {}", wallet_dat.get_xpub());

        // Save immediately
        wallet_dat.save()?;

        Ok(Self {
            wallet_dat,
            active_wallet: wallet,
            next_address_index: 0,
        })
    }

    /// Create an encrypted wallet from a BIP-39 mnemonic phrase with password
    pub fn create_from_mnemonic_encrypted(
        network: NetworkType,
        mnemonic: &str,
        password: &str,
    ) -> Result<Self, WalletDatError> {
        // Check if wallet already exists
        let wallet_path = WalletDat::default_path(network);
        if wallet_path.exists() {
            log::warn!(
                "Wallet already exists at: {}. Loading existing wallet instead.",
                wallet_path.display()
            );
            return Self::load(network);
        }

        // Validate mnemonic first
        wallet::validate_mnemonic(mnemonic)
            .map_err(|e| WalletDatError::WalletError(wallet::WalletError::MnemonicError(e)))?;

        // Create wallet from mnemonic
        let wallet = Wallet::from_mnemonic(mnemonic, "", network)?;

        // Create encrypted wallet_dat from mnemonic with password
        let wallet_dat = WalletDat::from_mnemonic_encrypted(mnemonic, network, password)?;

        log::info!(
            "Created encrypted wallet with xpub: {}",
            wallet_dat.get_xpub()
        );

        // Save immediately
        wallet_dat.save()?;

        Ok(Self {
            wallet_dat,
            active_wallet: wallet,
            next_address_index: 0,
        })
    }

    /// Generate a new 12-word BIP-39 mnemonic phrase
    pub fn generate_mnemonic() -> Result<String, WalletDatError> {
        wallet::generate_mnemonic(12)
            .map_err(|e| WalletDatError::WalletError(wallet::WalletError::MnemonicError(e)))
    }

    /// Validate a BIP-39 mnemonic phrase
    pub fn validate_mnemonic(phrase: &str) -> Result<(), WalletDatError> {
        wallet::validate_mnemonic(phrase)
            .map_err(|e| WalletDatError::WalletError(wallet::WalletError::MnemonicError(e)))
    }

    /// Load existing wallet
    pub fn load(network: NetworkType) -> Result<Self, WalletDatError> {
        let wallet_dat = WalletDat::load(network)?;

        // Check if wallet is encrypted
        if wallet_dat.is_encrypted() {
            return Err(WalletDatError::PasswordRequired);
        }

        // Recreate wallet from mnemonic (unencrypted)
        let mnemonic = wallet_dat.get_mnemonic()?;
        let wallet = Wallet::from_mnemonic(&mnemonic, "", network)?;

        Ok(Self {
            wallet_dat,
            active_wallet: wallet,
            next_address_index: 0,
        })
    }

    /// Load existing encrypted wallet with password
    pub fn load_with_password(
        network: NetworkType,
        password: &str,
    ) -> Result<Self, WalletDatError> {
        let wallet_dat = WalletDat::load(network)?;

        // Decrypt and get mnemonic
        let mnemonic = wallet_dat.get_mnemonic_with_password(Some(password))?;
        let wallet = Wallet::from_mnemonic(&mnemonic, "", network)?;

        Ok(Self {
            wallet_dat,
            active_wallet: wallet,
            next_address_index: 0,
        })
    }

    /// Check if existing wallet is encrypted
    pub fn is_encrypted(network: NetworkType) -> Result<bool, WalletDatError> {
        let wallet_dat = WalletDat::load(network)?;
        Ok(wallet_dat.is_encrypted())
    }

    /// Update next_address_index based on existing addresses in the database
    /// Should be called after wallet.db is opened
    pub fn sync_address_index(&mut self, max_index: u32) {
        self.next_address_index = max_index + 1;
    }

    /// Check if wallet exists
    pub fn exists(network: NetworkType) -> bool {
        WalletDat::default_path(network).exists()
    }

    /// Replace existing wallet with a new one from mnemonic
    /// IMPORTANT: Creates backup before replacing. Old wallet saved as .dat.old
    pub fn replace_from_mnemonic(
        network: NetworkType,
        mnemonic: &str,
    ) -> Result<Self, WalletDatError> {
        // Validate mnemonic first
        wallet::validate_mnemonic(mnemonic)
            .map_err(|e| WalletDatError::WalletError(wallet::WalletError::MnemonicError(e)))?;

        // Create backup if wallet exists (save old wallet before replacing)
        let wallet_path = WalletDat::default_path(network);
        if wallet_path.exists() {
            let backup_path = wallet_path.with_extension("dat.old");
            fs::copy(&wallet_path, &backup_path)?;
            log::warn!("Old wallet backed up to: {}", backup_path.display());
        }

        // Create wallet from mnemonic
        let wallet = Wallet::from_mnemonic(mnemonic, "", network)?;

        // Create wallet_dat from mnemonic (stores xpub, encrypted mnemonic, master key)
        let wallet_dat = WalletDat::from_mnemonic(mnemonic, network)?;

        log::info!("Replaced wallet with new xpub: {}", wallet_dat.get_xpub());

        // Save (atomic write with temp file)
        wallet_dat.save()?;

        Ok(Self {
            wallet_dat,
            active_wallet: wallet,
            next_address_index: 0,
        })
    }

    /// Get the xpub for this wallet
    pub fn get_xpub(&self) -> &str {
        self.wallet_dat.get_xpub()
    }

    /// Derive an address at the given index
    pub fn derive_address(&self, index: u32) -> Result<String, WalletDatError> {
        self.wallet_dat.derive_address(index)
    }

    /// Derive a keypair at the given index
    pub fn derive_keypair(&self, index: u32) -> Result<Keypair, WalletDatError> {
        self.wallet_dat.derive_keypair(index)
    }

    /// Get the next available address (and increment counter)
    pub fn get_next_address(&mut self) -> Result<String, WalletDatError> {
        let address = self.derive_address(self.next_address_index)?;
        self.next_address_index += 1;
        Ok(address)
    }

    /// Generate a new address and get its index
    pub fn generate_new_address_with_index(&mut self) -> Result<(String, u32), WalletDatError> {
        let index = self.next_address_index;
        let address = self.derive_address(index)?;
        self.next_address_index += 1;
        Ok((address, index))
    }

    /// Get the current address count (next index)
    pub fn get_address_count(&self) -> u32 {
        self.next_address_index
    }

    /// Get network type
    pub fn network(&self) -> NetworkType {
        self.wallet_dat.network
    }

    /// Get wallet file path
    pub fn wallet_path(&self) -> std::path::PathBuf {
        WalletDat::default_path(self.wallet_dat.network)
    }

    /// Get the active wallet
    pub fn get_active_wallet(&self) -> &Wallet {
        &self.active_wallet
    }

    /// Get mutable active wallet
    pub fn get_active_wallet_mut(&mut self) -> &mut Wallet {
        &mut self.active_wallet
    }

    /// Get current balance from active wallet
    pub fn get_balance(&self) -> u64 {
        self.active_wallet.balance()
    }

    /// Get primary address (first derived address)
    pub fn get_primary_address(&self) -> Result<String, WalletDatError> {
        self.derive_address(0)
    }

    /// Add UTXO to active wallet
    pub fn add_utxo(&mut self, utxo: UTXO) {
        self.active_wallet.add_utxo(utxo);
    }

    /// Get all UTXOs from active wallet
    pub fn get_utxos(&self) -> Vec<UTXO> {
        self.active_wallet.utxos().to_vec()
    }

    /// Create and validate a transaction
    pub fn create_transaction(
        &mut self,
        to_address: &str,
        amount: u64,
        fee: u64,
    ) -> Result<Transaction, String> {
        // Create the transaction
        let tx = self
            .active_wallet
            .create_transaction(to_address, amount, fee)
            .map_err(|e| e.to_string())?;

        // Transaction will be validated by masternodes
        log::info!("Transaction created, will be validated by masternode network");
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Helper to get a test-specific wallet path
    fn test_wallet_path(test_name: &str) -> std::path::PathBuf {
        let temp_dir = env::temp_dir().join("time-coin-wallet-tests");
        std::fs::create_dir_all(&temp_dir).ok();
        temp_dir.join(format!("{}-test-wallet.dat", test_name))
    }

    /// Helper to cleanup test wallet
    fn cleanup_test_wallet(path: &std::path::PathBuf) {
        let _ = std::fs::remove_file(path);
        // Also remove backup files if they exist
        let _ = std::fs::remove_file(path.with_extension("dat.backup"));
        let _ = std::fs::remove_file(path.with_extension("dat.old"));
    }

    #[test]
    fn test_wallet_manager_creation_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Create wallet components WITHOUT saving to disk
        let wallet = Wallet::from_mnemonic(mnemonic, "", NetworkType::Testnet).unwrap();
        let wallet_dat = WalletDat::from_mnemonic(mnemonic, NetworkType::Testnet).unwrap();

        let manager = WalletManager {
            wallet_dat,
            active_wallet: wallet,
            next_address_index: 0,
        };

        assert!(!manager.get_xpub().is_empty());
        assert_eq!(manager.get_balance(), 0);

        // Can derive addresses
        let addr0 = manager.derive_address(0).unwrap();
        assert!(!addr0.is_empty());

        // NO cleanup needed - we never saved to disk!
    }

    #[test]
    fn test_balance_management() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Create wallet components WITHOUT saving to disk
        let wallet = Wallet::from_mnemonic(mnemonic, "", NetworkType::Testnet).unwrap();
        let wallet_dat = WalletDat::from_mnemonic(mnemonic, NetworkType::Testnet).unwrap();

        let mut manager = WalletManager {
            wallet_dat,
            active_wallet: wallet,
            next_address_index: 0,
        };

        assert_eq!(manager.get_balance(), 0);

        let address = manager.get_primary_address().unwrap();
        let utxo = UTXO {
            tx_hash: [1u8; 32],
            output_index: 0,
            amount: 1000,
            address: address.clone(),
        };

        manager.add_utxo(utxo);
        assert_eq!(manager.get_balance(), 1000);

        // NO cleanup needed - we never saved to disk!
    }
}
