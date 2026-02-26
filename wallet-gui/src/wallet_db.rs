//! Wallet database for storing metadata, contacts, and transaction history
//! Separate from wallet.dat which only stores keys

use serde::{Deserialize, Serialize};
use sled::Db;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletDbError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sled::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),

    #[error("Not found: {0}")]
    NotFound(String),
}

/// Contact information for an address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressContact {
    pub address: String,
    pub label: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub notes: Option<String>,
    pub is_default: bool,
    pub is_owned: bool, // true = my address (receive), false = external contact (send)
    #[serde(default)]
    pub derivation_index: Option<u32>, // For owned addresses derived from xpub
    pub created_at: i64,
    pub updated_at: i64,
}

/// Transaction record for history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub tx_hash: String,
    pub timestamp: i64,
    pub from_address: Option<String>,
    pub to_address: String,
    pub amount: u64,
    pub status: TransactionStatus,
    pub block_height: Option<u64>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Approved,
    Confirmed,
    Declined,
    Failed,
}

/// Wallet metadata database
#[derive(Clone, Debug)]
pub struct WalletDb {
    db: Db,
}

impl WalletDb {
    /// Open or create the wallet database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, WalletDbError> {
        let db = sled::open(path)?;
        Ok(WalletDb { db })
    }

    // ==================== Address Contacts ====================

    /// Save or update contact information for an address
    pub fn save_contact(&self, contact: &AddressContact) -> Result<(), WalletDbError> {
        let key = format!("contact:{}", contact.address);
        let value = bincode::serialize(contact)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get contact information for an address
    pub fn get_contact(&self, address: &str) -> Result<Option<AddressContact>, WalletDbError> {
        let key = format!("contact:{}", address);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    /// Get all contacts
    pub fn get_all_contacts(&self) -> Result<Vec<AddressContact>, WalletDbError> {
        let mut contacts = Vec::new();
        let prefix = b"contact:";

        for item in self.db.scan_prefix(prefix) {
            let (_, value) = item?;

            match bincode::deserialize::<AddressContact>(&value) {
                Ok(contact) => contacts.push(contact),
                Err(e) => {
                    // Skip corrupted entries
                    log::warn!("Failed to deserialize contact, skipping: {}", e);
                    continue;
                }
            }
        }

        self.db.flush()?;
        contacts.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(contacts)
    }

    /// Get only owned addresses (receive addresses)
    pub fn get_owned_addresses(&self) -> Result<Vec<AddressContact>, WalletDbError> {
        let all = self.get_all_contacts()?;
        Ok(all.into_iter().filter(|c| c.is_owned).collect())
    }

    /// Get only external contacts (send addresses)
    pub fn get_external_contacts(&self) -> Result<Vec<AddressContact>, WalletDbError> {
        let all = self.get_all_contacts()?;
        Ok(all.into_iter().filter(|c| !c.is_owned).collect())
    }

    /// Delete contact
    pub fn delete_contact(&self, address: &str) -> Result<(), WalletDbError> {
        let key = format!("contact:{}", address);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Set default address
    pub fn set_default_address(&self, address: &str) -> Result<(), WalletDbError> {
        // First, unset all defaults
        for contact in self.get_all_contacts()? {
            if contact.is_default {
                let mut updated = contact;
                updated.is_default = false;
                updated.updated_at = chrono::Utc::now().timestamp();
                self.save_contact(&updated)?;
            }
        }

        // Set the new default
        if let Some(mut contact) = self.get_contact(address)? {
            contact.is_default = true;
            contact.updated_at = chrono::Utc::now().timestamp();
            self.save_contact(&contact)?;
        }

        Ok(())
    }

    /// Get default address
    pub fn get_default_address(&self) -> Result<Option<AddressContact>, WalletDbError> {
        for contact in self.get_all_contacts()? {
            if contact.is_default {
                return Ok(Some(contact));
            }
        }
        Ok(None)
    }

    // ==================== Transaction History ====================

    /// Save transaction to history
    pub fn save_transaction(&self, tx: &TransactionRecord) -> Result<(), WalletDbError> {
        let key = format!("tx:{}", tx.tx_hash);
        let value = bincode::serialize(tx)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get transaction by hash
    pub fn get_transaction(
        &self,
        tx_hash: &str,
    ) -> Result<Option<TransactionRecord>, WalletDbError> {
        let key = format!("tx:{}", tx_hash);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    /// Get all transactions, sorted by timestamp (newest first)
    pub fn get_all_transactions(&self) -> Result<Vec<TransactionRecord>, WalletDbError> {
        let mut transactions = Vec::new();
        let prefix = b"tx:";

        for item in self.db.scan_prefix(prefix) {
            let (_key, value) = item?;
            let tx: TransactionRecord = bincode::deserialize(&value)?;
            transactions.push(tx);
        }

        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(transactions)
    }

    /// Get transactions for a specific address
    pub fn get_transactions_for_address(
        &self,
        address: &str,
    ) -> Result<Vec<TransactionRecord>, WalletDbError> {
        let all_txs = self.get_all_transactions()?;
        Ok(all_txs
            .into_iter()
            .filter(|tx| {
                tx.to_address == address
                    || tx.from_address.as_ref().is_some_and(|from| from == address)
            })
            .collect())
    }

    /// Update transaction status
    pub fn update_transaction_status(
        &self,
        tx_hash: &str,
        status: TransactionStatus,
        block_height: Option<u64>,
    ) -> Result<(), WalletDbError> {
        if let Some(mut tx) = self.get_transaction(tx_hash)? {
            tx.status = status;
            if let Some(height) = block_height {
                tx.block_height = Some(height);
            }
            self.save_transaction(&tx)?;
        }
        Ok(())
    }

    // ==================== Settings ====================

    /// Save a setting
    pub fn save_setting(&self, key: &str, value: &str) -> Result<(), WalletDbError> {
        let db_key = format!("setting:{}", key);
        self.db.insert(db_key.as_bytes(), value.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Get a setting
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, WalletDbError> {
        let db_key = format!("setting:{}", key);
        match self.db.get(db_key.as_bytes())? {
            Some(data) => Ok(Some(String::from_utf8_lossy(&data).to_string())),
            None => Ok(None),
        }
    }

    // ==================== UTXO Management ====================

    /// Save UTXO information
    pub fn save_utxo(&self, utxo: &UtxoRecord) -> Result<(), WalletDbError> {
        let key = format!("utxo:{}:{}", utxo.tx_hash, utxo.output_index);
        let value = bincode::serialize(utxo)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get UTXO by tx_hash and output_index
    pub fn get_utxo(
        &self,
        tx_hash: &str,
        output_index: u32,
    ) -> Result<Option<UtxoRecord>, WalletDbError> {
        let key = format!("utxo:{}:{}", tx_hash, output_index);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    /// Get all UTXOs
    pub fn get_all_utxos(&self) -> Result<Vec<UtxoRecord>, WalletDbError> {
        let mut utxos = Vec::new();
        let prefix = b"utxo:";

        for item in self.db.scan_prefix(prefix) {
            let (_key, value) = item?;
            let utxo: UtxoRecord = bincode::deserialize(&value)?;
            utxos.push(utxo);
        }

        Ok(utxos)
    }

    /// Get UTXOs for a specific address
    pub fn get_utxos_for_address(&self, address: &str) -> Result<Vec<UtxoRecord>, WalletDbError> {
        let all_utxos = self.get_all_utxos()?;
        Ok(all_utxos
            .into_iter()
            .filter(|utxo| utxo.address == address)
            .collect())
    }

    /// Delete UTXO (when spent)
    pub fn delete_utxo(&self, tx_hash: &str, output_index: u32) -> Result<(), WalletDbError> {
        let key = format!("utxo:{}:{}", tx_hash, output_index);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Get total balance from all UTXOs
    pub fn get_total_balance(&self) -> Result<u64, WalletDbError> {
        let utxos = self.get_all_utxos()?;
        Ok(utxos.iter().map(|utxo| utxo.amount).sum())
    }

    /// Clear all UTXOs (for re-sync)
    pub fn clear_all_utxos(&self) -> Result<(), WalletDbError> {
        let prefix = b"utxo:";
        let keys_to_remove: Vec<_> = self
            .db
            .scan_prefix(prefix)
            .filter_map(|item| item.ok().map(|(key, _)| key))
            .collect();

        for key in keys_to_remove {
            self.db.remove(key)?;
        }
        self.db.flush()?;
        Ok(())
    }

    // ==================== Peer Management ====================

    /// Save or update a peer
    pub fn save_peer(&self, peer: &PeerRecord) -> Result<(), WalletDbError> {
        let key = format!("peer:{}:{}", peer.address, peer.port);
        let value = bincode::serialize(peer)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get all known peers, sorted by last_seen (most recent first)
    pub fn get_all_peers(&self) -> Result<Vec<PeerRecord>, WalletDbError> {
        let mut peers = Vec::new();
        let prefix = b"peer:";

        for item in self.db.scan_prefix(prefix) {
            let (_key, value) = item?;
            match bincode::deserialize::<PeerRecord>(&value) {
                Ok(peer) => peers.push(peer),
                Err(e) => {
                    log::warn!("Failed to deserialize peer, skipping: {}", e);
                    continue;
                }
            }
        }

        peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        Ok(peers)
    }

    /// Get working peers (successfully connected in the last 24 hours)
    pub fn get_working_peers(&self) -> Result<Vec<PeerRecord>, WalletDbError> {
        let all_peers = self.get_all_peers()?;
        let cutoff_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (24 * 60 * 60); // 24 hours ago

        Ok(all_peers
            .into_iter()
            .filter(|p| p.last_seen >= cutoff_time && p.successful_connections > 0)
            .collect())
    }

    /// Delete a peer
    pub fn delete_peer(&self, address: &str, port: u16) -> Result<(), WalletDbError> {
        let key = format!("peer:{}:{}", address, port);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Clear all peers (for fresh bootstrap)
    pub fn clear_all_peers(&self) -> Result<(), WalletDbError> {
        let prefix = b"peer:";
        let keys_to_remove: Vec<_> = self
            .db
            .scan_prefix(prefix)
            .filter_map(|item| item.ok().map(|(key, _)| key))
            .collect();

        for key in keys_to_remove {
            self.db.remove(key)?;
        }
        self.db.flush()?;
        Ok(())
    }
}

/// UTXO record for wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoRecord {
    pub tx_hash: String,
    pub output_index: u32,
    pub amount: u64,
    pub address: String,
    pub block_height: u64,
    pub confirmations: u64,
}

/// Peer record for persistent peer management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub address: String,
    pub port: u16,
    pub version: Option<String>,
    pub last_seen: u64,
    pub first_seen: u64,
    pub successful_connections: u32,
    pub failed_connections: u32,
    pub latency_ms: u64,
}
