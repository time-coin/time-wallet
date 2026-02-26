//! Application state — plain data, no async, no Arc.
//!
//! `AppState` holds everything the UI needs to render. The service task sends
//! `ServiceEvent`s which are applied via `AppState::apply()`. The UI reads
//! fields directly — no locking, no channels.

use crate::events::{Screen, ServiceEvent};
use crate::masternode_client::{Balance, HealthStatus, TransactionRecord, Utxo};
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

/// All application state needed for rendering.
#[derive(Debug)]
pub struct AppState {
    // -- Navigation --
    pub screen: Screen,

    // -- Wallet --
    pub wallet_loaded: bool,
    pub addresses: Vec<String>,
    pub is_testnet: bool,

    // -- Balances --
    pub balance: Balance,

    // -- Transactions --
    pub transactions: Vec<TransactionRecord>,

    // -- UTXOs --
    pub utxos: Vec<Utxo>,

    // -- Masternode --
    pub health: Option<HealthStatus>,
    pub ws_connected: bool,
    pub peers: Vec<PeerInfo>,

    // -- Notifications (real-time from WebSocket) --
    pub recent_notifications: Vec<TxNotification>,

    // -- UI transient state --
    pub send_address: String,
    pub send_amount: String,
    pub send_fee: String,
    pub password_required: bool,
    pub password_input: String,
    pub show_password: bool,
    pub error: Option<String>,
    pub success: Option<String>,
    pub loading: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            screen: Screen::Welcome,
            wallet_loaded: false,
            addresses: Vec::new(),
            is_testnet: true,
            balance: Balance {
                confirmed: 0,
                pending: 0,
                total: 0,
            },
            transactions: Vec::new(),
            utxos: Vec::new(),
            health: None,
            ws_connected: false,
            peers: Vec::new(),
            recent_notifications: Vec::new(),
            send_address: String::new(),
            send_amount: String::new(),
            send_fee: String::new(),
            password_required: false,
            password_input: String::new(),
            show_password: false,
            error: None,
            success: None,
            loading: false,
        }
    }
}

impl AppState {
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
                self.balance = balance;
            }

            ServiceEvent::TransactionsUpdated(txs) => {
                self.transactions = txs;
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

            ServiceEvent::HealthUpdated(health) => {
                self.health = Some(health);
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

            ServiceEvent::PeersDiscovered(peers) => {
                self.peers = peers;
            }

            ServiceEvent::Error(msg) => {
                self.error = Some(msg);
                self.loading = false;
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
            addresses: vec!["TIME0abc".to_string()],
            is_testnet: true,
        });
        assert!(state.wallet_loaded);
        assert_eq!(state.screen, Screen::Overview);
        assert_eq!(state.addresses.len(), 1);
    }

    #[test]
    fn test_apply_balance_updated() {
        let mut state = AppState::default();
        state.apply(ServiceEvent::BalanceUpdated(Balance {
            confirmed: 1000,
            pending: 500,
            total: 1500,
        }));
        assert_eq!(state.balance.confirmed, 1000);
        assert_eq!(state.balance.pending, 500);
        assert_eq!(state.balance.total, 1500);
    }

    #[test]
    fn test_apply_transaction_sent_clears_form() {
        let mut state = AppState::default();
        state.send_address = "TIME0xyz".to_string();
        state.send_amount = "100".to_string();
        state.loading = true;
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
        let mut state = AppState::default();
        state.loading = true;
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
                amount: 1.0,
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
