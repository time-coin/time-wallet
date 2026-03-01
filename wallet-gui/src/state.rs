//! Application state — plain data, no async, no Arc.
//!
//! `AppState` holds everything the UI needs to render. The service task sends
//! `ServiceEvent`s which are applied via `AppState::apply()`. The UI reads
//! fields directly — no locking, no channels.

use crate::events::{Screen, ServiceEvent};
use crate::masternode_client::{Balance, HealthStatus, TransactionRecord, TransactionStatus, Utxo};
use crate::ws_client::TxNotification;

/// Information about a discovered peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub endpoint: String,
    pub is_active: bool,
    pub is_healthy: bool,
    pub ws_available: bool,
    pub ping_ms: Option<u64>,
    pub block_height: Option<u64>,
    pub version: Option<String>,
}

/// Information about a wallet address with its user-assigned label.
#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub address: String,
    pub label: String,
}

/// External contact for the send address book.
#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub name: String,
    pub address: String,
}

/// All application state needed for rendering.
#[derive(Debug)]
pub struct AppState {
    // -- Navigation --
    pub screen: Screen,

    // -- Wallet --
    pub wallet_loaded: bool,
    pub addresses: Vec<AddressInfo>,
    pub selected_address: usize,
    pub is_testnet: bool,

    // -- Balances --
    pub balance: Balance,

    // -- Transactions --
    pub transactions: Vec<TransactionRecord>,
    pub selected_transaction: Option<usize>,

    // -- UTXOs --
    pub utxos: Vec<Utxo>,

    // -- Masternode --
    pub health: Option<HealthStatus>,
    pub ws_connected: bool,
    pub peers: Vec<PeerInfo>,

    // -- Notifications (real-time from WebSocket) --
    pub recent_notifications: Vec<TxNotification>,

    // -- UI transient state --
    pub wallet_exists: bool,
    pub send_address: String,
    pub send_amount: String,
    pub send_fee: String,
    pub contacts: Vec<ContactInfo>,
    pub new_contact_name: String,
    pub new_contact_address: String,
    pub show_add_contact: bool,
    pub contact_search: String,
    pub editing_contact_address: Option<String>,
    pub editing_contact_name: String,
    pub password_required: bool,
    pub password_input: String,
    pub show_password: bool,
    pub mnemonic_input: String,
    pub mnemonic_words: Vec<String>,
    pub mnemonic_use_24: bool,
    pub mnemonic_valid: Option<bool>,
    pub show_print_dialog: bool,
    pub new_wallet_password: String,
    pub backed_up_path: Option<String>,
    pub error: Option<String>,
    pub success: Option<String>,
    pub loading: bool,

    // -- Display preferences --
    pub decimal_places: usize,

    // -- Persisted send records (correct amounts from wallet, keyed by txid) --
    pub send_records: std::collections::HashMap<String, TransactionRecord>,

    // -- Tools state --
    pub resync_in_progress: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            screen: Screen::Welcome,
            wallet_loaded: false,
            addresses: Vec::new(),
            selected_address: 0,
            is_testnet: true,
            balance: Balance {
                confirmed: 0,
                pending: 0,
                total: 0,
            },
            transactions: Vec::new(),
            selected_transaction: None,
            utxos: Vec::new(),
            health: None,
            ws_connected: false,
            peers: Vec::new(),
            recent_notifications: Vec::new(),
            wallet_exists: false,
            send_address: String::new(),
            send_amount: String::new(),
            send_fee: String::new(),
            contacts: Vec::new(),
            new_contact_name: String::new(),
            new_contact_address: String::new(),
            show_add_contact: false,
            contact_search: String::new(),
            editing_contact_address: None,
            editing_contact_name: String::new(),
            password_required: false,
            password_input: String::new(),
            show_password: false,
            mnemonic_input: String::new(),
            mnemonic_words: vec![String::new(); 12],
            mnemonic_use_24: false,
            mnemonic_valid: None,
            show_print_dialog: false,
            new_wallet_password: String::new(),
            backed_up_path: None,
            error: None,
            success: None,
            loading: false,
            decimal_places: 2,
            send_records: std::collections::HashMap::new(),
            resync_in_progress: false,
        }
    }
}

impl AppState {
    /// Format a satoshi amount as TIME with the user's preferred decimal places.
    pub fn format_time(&self, sats: u64) -> String {
        let time = sats as f64 / 100_000_000.0;
        format!("{:.prec$} TIME", time, prec = self.decimal_places)
    }

    /// Format a satoshi amount with sign prefix (+ or -).
    pub fn format_time_signed(&self, sats: u64, is_negative: bool) -> String {
        let time = sats as f64 / 100_000_000.0;
        let sign = if is_negative { "-" } else { "+" };
        format!("{}{:.prec$} TIME", sign, time, prec = self.decimal_places)
    }

    /// Look up a display name for an address. Checks own wallet address labels
    /// first, then contacts. Returns None if not found.
    pub fn contact_name(&self, address: &str) -> Option<&str> {
        // Check own wallet addresses (e.g. "First Address")
        if let Some(info) = self.addresses.iter().find(|a| a.address == address) {
            return Some(&info.label);
        }
        // Check contacts
        self.contacts
            .iter()
            .find(|c| c.address == address)
            .map(|c| c.name.as_str())
    }

    /// Apply a service event to update state. Pure state-machine transition.
    pub fn apply(&mut self, event: ServiceEvent) {
        // Clear transient messages on any successful response
        match event {
            ServiceEvent::WalletLoaded {
                addresses,
                is_testnet,
            } => {
                self.wallet_loaded = true;
                self.addresses = addresses;
                self.selected_address = 0;
                self.is_testnet = is_testnet;
                self.screen = Screen::Overview;
                self.loading = false;
                self.error = None;
                self.password_required = false;
                self.password_input.clear();
            }

            ServiceEvent::WalletCreated { mnemonic: _ } => {
                // The mnemonic is shown on the confirmation screen.
                // We don't store it in state for security — the UI module
                // that triggered CreateWallet holds it locally.
                self.screen = Screen::MnemonicConfirm;
                self.loading = false;
            }

            ServiceEvent::BalanceUpdated(balance) => {
                // Use the masternode's UTXO-based balance as the source of truth
                self.balance = balance;
            }

            ServiceEvent::TransactionsUpdated(txs) => {
                // Preserve Approved status: if a tx was already Approved (via WS finality),
                // don't let a poll result downgrade it back to Pending
                let approved_txids: std::collections::HashSet<String> = self
                    .transactions
                    .iter()
                    .filter(|t| matches!(t.status, TransactionStatus::Approved))
                    .map(|t| t.txid.clone())
                    .collect();

                // Use persisted send records (survive restarts) as the source
                // of truth for send amounts. Also collect in-memory send records
                // (fee > 0 means locally-inserted, not from RPC).
                let mut local_sends = self.send_records.clone();
                for t in &self.transactions {
                    if t.is_send && !t.is_fee && t.fee > 0 {
                        local_sends.entry(t.txid.clone()).or_insert_with(|| t.clone());
                    }
                }

                // Keep fee line items (never come from RPC) and WS-injected
                // receive records not already covered by RPC results
                let rpc_keys: std::collections::HashSet<(String, bool, u32)> =
                    txs.iter().map(|t| (t.txid.clone(), t.is_send, t.vout)).collect();
                let ws_only: Vec<_> = self
                    .transactions
                    .iter()
                    .filter(|t| t.is_fee || !rpc_keys.contains(&(t.txid.clone(), t.is_send, t.vout)))
                    .cloned()
                    .collect();

                // Deduplicate the RPC results by (txid, is_send, vout).
                // Replace RPC "send" entries with persisted local versions.
                let mut seen = std::collections::HashSet::new();
                self.transactions = txs
                    .into_iter()
                    .filter(|t| seen.insert((t.txid.clone(), t.is_send, t.vout)))
                    .map(|t| {
                        if t.is_send && !t.is_fee {
                            if let Some(local) = local_sends.get(&t.txid) {
                                let mut merged = local.clone();
                                merged.status = t.status.clone();
                                return merged;
                            }
                        }
                        t
                    })
                    .collect();

                // Restore Approved status from WS finality
                for tx in &mut self.transactions {
                    if matches!(tx.status, TransactionStatus::Pending)
                        && approved_txids.contains(&tx.txid)
                    {
                        tx.status = TransactionStatus::Approved;
                    }
                }

                // Append locally-inserted send records if RPC had no send entry
                for (txid, local_tx) in &local_sends {
                    let has_send = self.transactions.iter().any(|t| t.txid == *txid && t.is_send && !t.is_fee);
                    if !has_send {
                        self.transactions.push(local_tx.clone());
                    }
                }

                // Append WS-only txs (dedup against existing entries)
                for tx in ws_only.into_iter().rev() {
                    let dup = self.transactions.iter().any(|t| {
                        t.txid == tx.txid && t.is_send == tx.is_send && t.is_fee == tx.is_fee && t.vout == tx.vout
                    });
                    if !dup {
                        self.transactions.insert(0, tx);
                    }
                }

                // Sort newest first
                self.transactions
                    .sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            }

            ServiceEvent::UtxosUpdated(utxos) => {
                self.utxos = utxos;
            }

            ServiceEvent::TransactionSent { txid } => {
                self.success = Some(format!("Transaction sent: {}", txid));
                self.send_address.clear();
                self.send_amount.clear();
                self.send_fee.clear();
                self.loading = false;
            }

            ServiceEvent::TransactionReceived(notification) => {
                self.recent_notifications.push(notification);
                // Keep only the last 50 notifications
                if self.recent_notifications.len() > 50 {
                    self.recent_notifications.remove(0);
                }
            }

            ServiceEvent::TransactionInserted(tx) => {
                // Track locally-inserted send records in memory
                if tx.is_send && !tx.is_fee && tx.fee > 0 {
                    self.send_records.entry(tx.txid.clone()).or_insert_with(|| tx.clone());
                }
                // Insert if not already present; dedup by (txid, is_send, is_fee, vout)
                let exists = self
                    .transactions
                    .iter()
                    .any(|t| t.txid == tx.txid && t.is_fee == tx.is_fee && t.is_send == tx.is_send && t.vout == tx.vout);
                if !exists {
                    self.transactions.push(tx);
                    self.transactions
                        .sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                }
            }

            ServiceEvent::TransactionFinalityUpdated { txid, finalized } => {
                // Update all entries with this txid (including fee line items)
                for tx in self.transactions.iter_mut().filter(|t| t.txid == txid) {
                    if finalized {
                        tx.status = TransactionStatus::Approved;
                    }
                }
            }

            ServiceEvent::HealthUpdated(health) => {
                self.health = Some(health);
            }

            ServiceEvent::ContactsUpdated(contacts) => {
                self.contacts = contacts;
            }

            ServiceEvent::WsConnected => {
                self.ws_connected = true;
            }

            ServiceEvent::WsDisconnected => {
                self.ws_connected = false;
            }

            ServiceEvent::PasswordRequired => {
                self.password_required = true;
                self.loading = false;
                self.error = None;
            }

            ServiceEvent::ReadyForMnemonic { backed_up_path } => {
                self.backed_up_path = backed_up_path;
                self.mnemonic_input.clear();
                self.mnemonic_words = vec![String::new(); if self.mnemonic_use_24 { 24 } else { 12 }];
                self.mnemonic_valid = None;
                self.new_wallet_password.clear();
                self.screen = Screen::MnemonicSetup;
                self.loading = false;
            }

            ServiceEvent::PeersDiscovered(peers) => {
                self.peers = peers;
            }

            ServiceEvent::AddressGenerated(info) => {
                self.addresses.push(info);
                self.selected_address = self.addresses.len() - 1;
            }

            ServiceEvent::Error(msg) => {
                self.error = Some(msg);
                self.loading = false;
                self.resync_in_progress = false;
            }

            ServiceEvent::ResyncComplete => {
                self.resync_in_progress = false;
                self.success = Some("Resync complete".to_string());
            }

            ServiceEvent::DecimalPlacesLoaded(dp) => {
                self.decimal_places = dp;
            }

            ServiceEvent::WalletExists(exists) => {
                self.wallet_exists = exists;
            }

            ServiceEvent::SendRecordsLoaded(records) => {
                self.send_records = records;
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_state() {
        let state = AppState::default();
        assert_eq!(state.screen, Screen::Welcome);
        assert!(!state.wallet_loaded);
        assert!(state.is_testnet);
        assert_eq!(state.balance.total, 0);
    }

    #[test]
    fn test_apply_wallet_loaded() {
        let mut state = AppState::default();
        state.apply(ServiceEvent::WalletLoaded {
            addresses: vec![AddressInfo {
                address: "TIME0abc".to_string(),
                label: "Address #0".to_string(),
            }],
            is_testnet: true,
        });
        assert!(state.wallet_loaded);
        assert_eq!(state.screen, Screen::Overview);
        assert_eq!(state.addresses.len(), 1);
        assert_eq!(state.addresses[0].address, "TIME0abc");
    }

    #[test]
    fn test_apply_balance_updated() {
        let mut state = AppState::default();
        state.apply(ServiceEvent::BalanceUpdated(Balance {
            confirmed: 1000,
            pending: 500,
            total: 1500,
        }));
        // Balance now uses masternode's UTXO-based balance directly
        assert_eq!(state.balance.confirmed, 1000);
        assert_eq!(state.balance.pending, 500);
        assert_eq!(state.balance.total, 1500);
    }

    #[test]
    fn test_apply_transaction_sent_clears_form() {
        let mut state = AppState {
            send_address: "TIME0xyz".to_string(),
            send_amount: "100".to_string(),
            loading: true,
            ..Default::default()
        };
        state.apply(ServiceEvent::TransactionSent {
            txid: "abc123".to_string(),
        });
        assert!(state.send_address.is_empty());
        assert!(state.send_amount.is_empty());
        assert!(!state.loading);
        assert!(state.success.is_some());
    }

    #[test]
    fn test_apply_error() {
        let mut state = AppState {
            loading: true,
            ..Default::default()
        };
        state.apply(ServiceEvent::Error("connection failed".to_string()));
        assert!(!state.loading);
        assert_eq!(state.error.as_deref(), Some("connection failed"));
    }

    #[test]
    fn test_apply_ws_connection() {
        let mut state = AppState::default();
        assert!(!state.ws_connected);
        state.apply(ServiceEvent::WsConnected);
        assert!(state.ws_connected);
        state.apply(ServiceEvent::WsDisconnected);
        assert!(!state.ws_connected);
    }

    #[test]
    fn test_notifications_capped_at_50() {
        let mut state = AppState::default();
        for i in 0..60 {
            state.apply(ServiceEvent::TransactionReceived(TxNotification {
                txid: format!("tx{}", i),
                address: "addr".to_string(),
                amount: serde_json::json!(1.0),
                output_index: 0,
                timestamp: 0,
                confirmations: 0,
            }));
        }
        assert_eq!(state.recent_notifications.len(), 50);
        // First notification should be tx10 (0-9 were evicted)
        assert_eq!(state.recent_notifications[0].txid, "tx10");
    }
}
