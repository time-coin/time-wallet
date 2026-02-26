//! Event types for communication between UI and service task.
//!
//! These two enums are the *only* interface between the synchronous egui render
//! loop and the asynchronous service task. No shared state, no Arc, no Mutex.

use crate::masternode_client::{Balance, HealthStatus, TransactionRecord, Utxo};
use crate::ws_client::TxNotification;

// ============================================================================
// UI → Service
// ============================================================================

/// Commands sent from the UI thread to the background service task.
#[derive(Debug)]
pub enum UiEvent {
    /// Load an existing wallet (optionally with a password for encrypted wallets).
    LoadWallet { password: Option<String> },

    /// Create a new wallet from a mnemonic phrase.
    CreateWallet {
        mnemonic: String,
        password: Option<String>,
    },

    /// Request a balance refresh from the masternode.
    RefreshBalance,

    /// Request the full transaction history for all wallet addresses.
    RefreshTransactions,

    /// Request UTXOs for all wallet addresses.
    RefreshUtxos,

    /// Submit a signed transaction to the masternode.
    SendTransaction { to: String, amount: u64, fee: u64 },

    /// The user navigated to a new screen — the service may prefetch data.
    NavigatedTo(Screen),

    /// Request a masternode health check.
    CheckHealth,

    /// Switch network (mainnet / testnet). Requires wallet reload.
    SwitchNetwork { network: String },

    /// Clean shutdown.
    Shutdown,
}

/// Screens the wallet can display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Welcome,
    MnemonicSetup,
    MnemonicConfirm,
    Overview,
    Send,
    Receive,
    Transactions,
    Utxos,
    Settings,
}

// ============================================================================
// Service → UI
// ============================================================================

/// Events sent from the service task back to the UI thread.
#[derive(Debug)]
pub enum ServiceEvent {
    /// Wallet loaded successfully.
    WalletLoaded {
        addresses: Vec<String>,
        is_testnet: bool,
    },

    /// New wallet created — pass mnemonic back for confirmation screen.
    WalletCreated { mnemonic: String },

    /// Updated balance from masternode.
    BalanceUpdated(Balance),

    /// Updated transaction list.
    TransactionsUpdated(Vec<TransactionRecord>),

    /// Updated UTXO set.
    UtxosUpdated(Vec<Utxo>),

    /// Transaction broadcast succeeded.
    TransactionSent { txid: String },

    /// Real-time transaction notification from WebSocket.
    TransactionReceived(TxNotification),

    /// Masternode health status.
    HealthUpdated(HealthStatus),

    /// WebSocket connection state changed.
    WsConnected,
    WsDisconnected,

    /// The wallet is encrypted and a password is needed to unlock it.
    PasswordRequired,

    /// Non-fatal error to display in the UI.
    Error(String),
}
