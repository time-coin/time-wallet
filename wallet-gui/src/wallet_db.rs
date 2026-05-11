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

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

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

    /// Save or update contact information for an address.
    /// Stored as JSON so future field additions stay backward-compatible.
    pub fn save_contact(&self, contact: &AddressContact) -> Result<(), WalletDbError> {
        let key = format!("contact:{}", contact.address);
        let value = serde_json::to_vec(contact)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get contact information for an address.
    /// Tries JSON first; migrates legacy bincode entries on first read.
    pub fn get_contact(&self, address: &str) -> Result<Option<AddressContact>, WalletDbError> {
        let key = format!("contact:{}", address);
        match self.db.get(key.as_bytes())? {
            None => Ok(None),
            Some(data) => {
                // Try JSON (current format)
                if let Ok(contact) = serde_json::from_slice::<AddressContact>(&data) {
                    return Ok(Some(contact));
                }
                // Fall back to bincode (legacy), migrate immediately
                if let Ok(contact) = bincode::deserialize::<AddressContact>(&data) {
                    log::info!("Migrating contact '{}' from bincode to JSON", address);
                    let _ = self.save_contact(&contact);
                    return Ok(Some(contact));
                }
                log::warn!(
                    "Could not deserialize contact for '{}' — entry may be corrupted",
                    address
                );
                Ok(None)
            }
        }
    }

    /// Get all contacts.
    /// Tries JSON first; migrates any legacy bincode entries on the fly.
    pub fn get_all_contacts(&self) -> Result<Vec<AddressContact>, WalletDbError> {
        let mut contacts = Vec::new();
        let mut to_migrate: Vec<AddressContact> = Vec::new();
        let prefix = b"contact:";

        for item in self.db.scan_prefix(prefix) {
            let (_key, value) = item?;
            // Try JSON (current format)
            if let Ok(contact) = serde_json::from_slice::<AddressContact>(&value) {
                contacts.push(contact);
                continue;
            }
            // Fall back to bincode (legacy format written before JSON migration)
            if let Ok(contact) = bincode::deserialize::<AddressContact>(&value) {
                log::info!(
                    "Migrating contact '{}' from bincode to JSON",
                    contact.address
                );
                to_migrate.push(contact.clone());
                contacts.push(contact);
                continue;
            }
            log::warn!("Skipping unreadable contact entry (unknown format)");
        }

        // Re-save migrated entries as JSON so future reads succeed
        for contact in to_migrate {
            let _ = self.save_contact(&contact);
        }

        contacts.sort_by_key(|c| std::cmp::Reverse(c.updated_at));
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

        transactions.sort_by_key(|t| std::cmp::Reverse(t.timestamp));
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

        peers.sort_by_key(|p| std::cmp::Reverse(p.last_seen));
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

    // ==================== Cached Data (for instant startup) ====================

    /// Save cached transactions (from RPC/WS) for instant startup
    pub fn save_cached_transactions(
        &self,
        txs: &[crate::masternode_client::TransactionRecord],
    ) -> Result<(), WalletDbError> {
        let value = bincode::serialize(txs)?;
        self.db.insert(b"cache:transactions", value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Load cached transactions for instant startup
    pub fn get_cached_transactions(
        &self,
    ) -> Result<Vec<crate::masternode_client::TransactionRecord>, WalletDbError> {
        match self.db.get(b"cache:transactions")? {
            Some(data) => Ok(bincode::deserialize(&data)?),
            None => Ok(Vec::new()),
        }
    }

    /// Save cached balance for instant startup
    pub fn save_cached_balance(
        &self,
        balance: &crate::masternode_client::Balance,
    ) -> Result<(), WalletDbError> {
        let value = bincode::serialize(balance)?;
        self.db.insert(b"cache:balance", value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Load cached balance for instant startup
    pub fn get_cached_balance(
        &self,
    ) -> Result<Option<crate::masternode_client::Balance>, WalletDbError> {
        match self.db.get(b"cache:balance")? {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    /// Save a locally-created send record (preserves correct send amount across restarts).
    /// Keyed by txid so it can be looked up when merging with RPC results.
    pub fn save_send_record(
        &self,
        tx: &crate::masternode_client::TransactionRecord,
    ) -> Result<(), WalletDbError> {
        let key = format!("send_record:{}", tx.txid);
        let value = bincode::serialize(tx)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Load all persisted send records (keyed by txid).
    pub fn get_send_records(
        &self,
    ) -> Result<
        std::collections::HashMap<String, crate::masternode_client::TransactionRecord>,
        WalletDbError,
    > {
        let mut map = std::collections::HashMap::new();
        for item in self.db.scan_prefix(b"send_record:") {
            let (key, value) = item?;
            let key_str = String::from_utf8_lossy(&key);
            let txid = key_str
                .strip_prefix("send_record:")
                .unwrap_or("")
                .to_string();
            if let Ok(tx) =
                bincode::deserialize::<crate::masternode_client::TransactionRecord>(&value)
            {
                map.insert(txid, tx);
            }
        }
        Ok(map)
    }

    // ==================== Masternode Entries ====================

    /// Save or update a masternode entry (stored as JSON).
    pub fn save_masternode_entry(&self, entry: &MasternodeEntry) -> Result<(), WalletDbError> {
        let key = format!("masternode:{}", entry.alias);
        let value = serde_json::to_vec(entry)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get all masternode entries.
    /// Tries JSON first; falls back to bincode for entries written by older versions
    /// and immediately re-saves them as JSON so future reads succeed.
    pub fn get_masternode_entries(&self) -> Result<Vec<MasternodeEntry>, WalletDbError> {
        let mut entries = Vec::new();
        let mut to_migrate: Vec<MasternodeEntry> = Vec::new();

        for item in self.db.scan_prefix(b"masternode:") {
            let (key, value) = item?;
            // Try JSON (current format)
            if let Ok(entry) = serde_json::from_slice::<MasternodeEntry>(&value) {
                entries.push(entry);
                continue;
            }
            // Fall back to bincode (legacy format — strip removed fields if possible)
            let key_str = String::from_utf8_lossy(&key);
            // Extract alias from key ("masternode:<alias>")
            let alias = key_str
                .strip_prefix("masternode:")
                .unwrap_or(&key_str)
                .to_string();
            // Try to parse as legacy bincode with old field layout via a migration struct
            #[derive(serde::Deserialize)]
            struct LegacyEntry {
                alias: String,
                ip: String,
                port: u16,
                masternode_key: String,
                collateral_txid: String,
                collateral_vout: u32,
                payout_address: Option<String>,
                #[serde(default)]
                collateral_amount: Option<u64>,
            }
            if let Ok(legacy) = bincode::deserialize::<LegacyEntry>(&value) {
                let entry = MasternodeEntry {
                    alias: legacy.alias,
                    collateral_txid: legacy.collateral_txid,
                    collateral_vout: legacy.collateral_vout,
                    payout_address: legacy.payout_address,
                    collateral_amount: legacy.collateral_amount,
                    reg_txid: None,
                    registered_ip: None,
                };
                log::info!(
                    "Migrating masternode entry '{}' from bincode to JSON",
                    entry.alias
                );
                to_migrate.push(entry.clone());
                entries.push(entry);
            } else {
                log::warn!(
                    "Skipping unreadable masternode entry '{}' (unknown format)",
                    alias
                );
            }
        }

        // Re-save migrated entries as JSON
        for entry in to_migrate {
            let _ = self.save_masternode_entry(&entry);
        }

        entries.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(entries)
    }

    /// Delete a masternode entry by alias.
    pub fn delete_masternode_entry(&self, alias: &str) -> Result<(), WalletDbError> {
        let key = format!("masternode:{}", alias);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    // ==================== Locked Collateral ====================

    /// Lock a collateral UTXO (mark it as in-use by a masternode).
    pub fn lock_collateral(&self, txid: &str, vout: u32, alias: &str) -> Result<(), WalletDbError> {
        let key = format!("locked_collateral:{}:{}", txid, vout);
        let value = alias.as_bytes();
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Unlock a collateral UTXO.
    pub fn unlock_collateral(&self, txid: &str, vout: u32) -> Result<(), WalletDbError> {
        let key = format!("locked_collateral:{}:{}", txid, vout);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Check if a specific UTXO is locked as collateral.
    pub fn is_collateral_locked(&self, txid: &str, vout: u32) -> bool {
        let key = format!("locked_collateral:{}:{}", txid, vout);
        self.db.contains_key(key.as_bytes()).unwrap_or(false)
    }

    /// Get all locked collateral outpoints as `(txid, vout, alias)`.
    pub fn get_locked_collaterals(&self) -> Result<Vec<(String, u32, String)>, WalletDbError> {
        let mut result = Vec::new();
        for item in self.db.scan_prefix(b"locked_collateral:") {
            let (key, value) = item?;
            let key_str = String::from_utf8_lossy(&key);
            // key format: "locked_collateral:txid:vout"
            let parts: Vec<&str> = key_str.splitn(3, ':').collect();
            if parts.len() == 3 {
                let txid = parts[1].to_string();
                let vout = parts[2].parse::<u32>().unwrap_or(0);
                let alias = String::from_utf8_lossy(&value).to_string();
                result.push((txid, vout, alias));
            }
        }
        Ok(result)
    }
}

/// Masternode configuration entry.
/// Stored as JSON in sled so future field additions remain backward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeEntry {
    pub alias: String,
    pub collateral_txid: String,
    pub collateral_vout: u32,
    #[serde(default)]
    pub payout_address: Option<String>,
    /// Cached collateral amount in satoshis — used for tier display when the
    /// UTXO is not yet in the wallet's fetched UTXO set.
    #[serde(default)]
    pub collateral_amount: Option<u64>,
    /// Txid of the on-chain MasternodeReg transaction, set after successful registration.
    #[serde(default)]
    pub reg_txid: Option<String>,
    /// IP address used during on-chain registration (needed to build CollateralUnlock).
    #[serde(default)]
    pub registered_ip: Option<String>,
}

impl MasternodeEntry {
    /// Parse a line from masternode.conf.
    /// New format:    `alias txid vout`
    /// Legacy format: `alias IP:port [key] txid vout`  (IP/key ignored)
    pub fn parse_conf_line(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let (txid_idx, vout_idx) = match parts.len() {
            3 => (1, 2), // alias txid vout
            4 => (2, 3), // alias IP:port txid vout
            5 => (3, 4), // alias IP:port key txid vout
            6 => (4, 5), // alias IP:port key cert txid vout
            _ => return None,
        };
        Some(MasternodeEntry {
            alias: parts[0].to_string(),
            collateral_txid: parts[txid_idx].to_string(),
            collateral_vout: parts[vout_idx].parse().ok()?,
            payout_address: None,
            collateral_amount: None,
            reg_txid: None,
            registered_ip: None,
        })
    }

    /// Format as a daemon conf line: `alias txid vout`
    /// Paste into ~/.timed/masternode.conf on the server, then restart timed.
    pub fn to_daemon_conf_line(&self) -> String {
        format!(
            "{} {} {}",
            self.alias, self.collateral_txid, self.collateral_vout
        )
    }
}

// Collateral thresholds in satoshis (1 TIME = 100_000_000 sat)
const GOLD_COLLATERAL_SATS: u64 = 100_000 * 100_000_000;
const SILVER_COLLATERAL_SATS: u64 = 10_000 * 100_000_000;
pub const BRONZE_COLLATERAL_SATS: u64 = 1_000 * 100_000_000;

/// Compute the masternode tier from a collateral UTXO amount (in satoshis).
///
/// Returns `Some("Gold")`, `Some("Silver")`, `Some("Bronze")`, or `None` if below threshold.
pub fn masternode_tier_from_satoshis(amount: u64) -> Option<&'static str> {
    if amount >= GOLD_COLLATERAL_SATS {
        Some("Gold")
    } else if amount >= SILVER_COLLATERAL_SATS {
        Some("Silver")
    } else if amount >= BRONZE_COLLATERAL_SATS {
        Some("Bronze")
    } else {
        None
    }
}

/// A payment request sent by this wallet to another wallet.
/// Stored in sled as JSON so future field additions stay backward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentPaymentRequest {
    pub id: String,
    /// The address being asked to pay (the payer).
    pub to_address: String,
    /// Our address that should receive the payment.
    pub from_address: String,
    pub amount: u64,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub memo: String,
    /// "pending" | "declined" | "cancelled" | "paid"
    pub status: String,
    pub created_at: i64,
    pub expires: i64,
    /// Transaction ID of the payment, populated when the payer responds with accepted=true.
    #[serde(default)]
    pub payment_txid: Option<String>,
}

/// A completed (paid or declined) incoming payment request, kept for history display.
/// Stored as JSON so future field additions stay backward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingPaymentHistory {
    pub id: String,
    /// The address that sent us the payment request (the requester).
    pub from_address: String,
    pub amount: u64,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub memo: String,
    /// "paid" | "declined"
    pub status: String,
    /// Transaction ID of the payment (only set when status == "paid").
    #[serde(default)]
    pub payment_txid: Option<String>,
    /// Unix timestamp of the original request.
    pub created_at: i64,
    /// Unix timestamp when we paid or declined.
    pub completed_at: i64,
}

impl WalletDb {
    // ==================== Sent Payment Requests ====================

    /// Save or update a sent payment request.
    pub fn save_sent_payment_request(&self, req: &SentPaymentRequest) -> Result<(), WalletDbError> {
        let key = format!("sent_pr:{}", req.id);
        let value = serde_json::to_vec(req)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get all sent payment requests, newest first.
    pub fn get_all_sent_payment_requests(&self) -> Result<Vec<SentPaymentRequest>, WalletDbError> {
        let mut reqs = Vec::new();
        for item in self.db.scan_prefix(b"sent_pr:") {
            let (_key, value) = item?;
            match serde_json::from_slice::<SentPaymentRequest>(&value) {
                Ok(req) => reqs.push(req),
                Err(e) => {
                    log::warn!(
                        "Failed to deserialize sent payment request, skipping: {}",
                        e
                    );
                }
            }
        }
        reqs.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        Ok(reqs)
    }

    /// Update the status of a sent payment request.
    pub fn update_sent_payment_request_status(
        &self,
        id: &str,
        status: &str,
        payment_txid: Option<&str>,
    ) -> Result<(), WalletDbError> {
        let key = format!("sent_pr:{}", id);
        if let Some(data) = self.db.get(key.as_bytes())? {
            let mut req: SentPaymentRequest = serde_json::from_slice(&data)?;
            req.status = status.to_string();
            if let Some(txid) = payment_txid {
                req.payment_txid = Some(txid.to_string());
            }
            let value = serde_json::to_vec(&req)?;
            self.db.insert(key.as_bytes(), value)?;
            self.db.flush()?;
        }
        Ok(())
    }

    /// Delete a sent payment request by id.
    pub fn delete_sent_payment_request(&self, id: &str) -> Result<(), WalletDbError> {
        let key = format!("sent_pr:{}", id);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    // ==================== Incoming Payment Requests ====================

    /// Save or update an incoming payment request.
    pub fn save_incoming_payment_request(
        &self,
        req: &crate::events::PaymentRequest,
    ) -> Result<(), WalletDbError> {
        let key = format!("incoming_pr:{}", req.id);
        let value = serde_json::to_vec(req)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get all saved incoming payment requests.
    pub fn get_all_incoming_payment_requests(
        &self,
    ) -> Result<Vec<crate::events::PaymentRequest>, WalletDbError> {
        let mut reqs = Vec::new();
        for item in self.db.scan_prefix(b"incoming_pr:") {
            let (_key, value) = item?;
            match serde_json::from_slice::<crate::events::PaymentRequest>(&value) {
                Ok(req) => reqs.push(req),
                Err(e) => {
                    log::warn!(
                        "Failed to deserialize incoming payment request, skipping: {}",
                        e
                    );
                }
            }
        }
        reqs.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
        Ok(reqs)
    }

    /// Get a single incoming payment request by id.
    pub fn get_incoming_payment_request(
        &self,
        id: &str,
    ) -> Result<Option<crate::events::PaymentRequest>, WalletDbError> {
        let key = format!("incoming_pr:{}", id);
        match self.db.get(key.as_bytes())? {
            Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
            None => Ok(None),
        }
    }

    /// Delete an incoming payment request by id (after paid, declined, or expired).
    pub fn delete_incoming_payment_request(&self, id: &str) -> Result<(), WalletDbError> {
        let key = format!("incoming_pr:{}", id);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    // ==================== Incoming Payment Request History ====================

    /// Persist a completed (paid or declined) incoming payment request for history display.
    pub fn save_incoming_payment_history(
        &self,
        entry: &IncomingPaymentHistory,
    ) -> Result<(), WalletDbError> {
        let key = format!("incoming_pr_history:{}", entry.id);
        let value = serde_json::to_vec(entry)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Load all incoming payment history entries, newest first.
    pub fn get_all_incoming_payment_history(
        &self,
    ) -> Result<Vec<IncomingPaymentHistory>, WalletDbError> {
        let mut entries = Vec::new();
        for item in self.db.scan_prefix(b"incoming_pr_history:") {
            let (_key, value) = item?;
            match serde_json::from_slice::<IncomingPaymentHistory>(&value) {
                Ok(e) => entries.push(e),
                Err(e) => log::warn!(
                    "Failed to deserialize incoming payment history entry, skipping: {}",
                    e
                ),
            }
        }
        entries.sort_by_key(|e| std::cmp::Reverse(e.completed_at));
        Ok(entries)
    }

    /// Delete a single history entry by id (user dismisses it).
    pub fn delete_incoming_payment_history(&self, id: &str) -> Result<(), WalletDbError> {
        let key = format!("incoming_pr_history:{}", id);
        self.db.remove(key.as_bytes())?;
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
