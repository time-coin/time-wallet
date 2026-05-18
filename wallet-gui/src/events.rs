//! Event types for communication between UI and service task.
//!
//! These two enums are the *only* interface between the synchronous egui render
//! loop and the asynchronous service task. No shared state, no Arc, no Mutex.

use crate::masternode_client::{Balance, HealthStatus, TransactionRecord, Utxo};
use crate::state::AddressInfo;
use crate::ws_client::TxNotification;

/// A payment request displayed in the wallet UI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaymentRequest {
    pub id: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    /// Short label / subject for the request (e.g. "Invoice #42").
    pub label: String,
    pub memo: String,
    pub pubkey_hex: String,
    pub signature_hex: String,
    pub timestamp: i64,
    pub expires: i64,
}

// ============================================================================
// UI → Service
// ============================================================================

/// Commands sent from the UI thread to the background service task.
#[derive(Debug)]
pub enum UiEvent {
    /// Load an existing wallet (optionally with a password for encrypted wallets).
    LoadWallet {
        password: Option<String>,
    },

    /// Create a new wallet from a mnemonic phrase.
    CreateWallet {
        mnemonic: String,
        password: Option<String>,
    },

    /// Prepare for new wallet creation — backup existing wallet file if present.
    PrepareNewWallet,

    /// Request a balance refresh from the masternode.
    RefreshBalance,

    /// Request the full transaction history for all wallet addresses.
    RefreshTransactions,

    /// Request UTXOs for all wallet addresses.
    RefreshUtxos,

    /// Submit a signed transaction to the masternode.
    SendTransaction {
        to: String,
        amount: u64,
        fee: u64,
        memo: String,
        /// If set, only UTXOs belonging to this address are used as inputs.
        from_address: Option<String>,
        /// If this send is fulfilling a payment request, the request id to acknowledge after broadcast.
        payment_request_id: Option<String>,
    },

    /// The user navigated to a new screen — the service may prefetch data.
    NavigatedTo(Screen),

    /// Request a masternode health check.
    CheckHealth,

    /// Switch network (mainnet / testnet). Requires wallet reload.
    SwitchNetwork {
        network: String,
    },

    /// Select network on first run (before any wallet is created).
    SelectNetwork {
        network: String,
    },

    /// Update the label for a wallet address (persisted to local db).
    UpdateAddressLabel {
        index: usize,
        label: String,
    },

    /// Generate a new receive address from the HD wallet.
    GenerateAddress,

    /// Reload all wallet addresses from DB + HD keys without a full network switch.
    /// Use this to recover from sled read glitches or missing addresses.
    RefreshAddresses,

    /// Delete an owned receive address (must be unused — zero balance, no transactions).
    DeleteAddress {
        address: String,
    },

    /// Save an external contact (send address book).
    SaveContact {
        name: String,
        address: String,
    },

    /// Delete an external contact.
    DeleteContact {
        address: String,
    },

    /// Update the number of decimal places for amount display.
    UpdateDecimalPlaces(usize),

    /// Erase cached data and resync all transactions from masternodes.
    ResyncWallet,

    /// Repair the wallet database — backs up corrupt db, recreates, and resyncs.
    RepairDatabase,

    /// Open a config file in the system's default text editor.
    OpenConfigFile {
        path: std::path::PathBuf,
    },

    /// Clean shutdown.
    Shutdown,

    /// Encrypt an unencrypted wallet with the given password.
    EncryptWallet {
        password: String,
    },

    /// Set the external editor command (None = OS default).
    SetEditor {
        editor: Option<String>,
    },
    SetMaxConnections(usize),

    /// Save a masternode entry to the database.
    SaveMasternodeEntry(crate::wallet_db::MasternodeEntry),

    /// Delete a masternode entry by alias.
    DeleteMasternodeEntry {
        alias: String,
    },

    /// Import masternode entries from a masternode.conf file.
    ImportMasternodeConf {
        path: std::path::PathBuf,
    },

    /// Fetch the per-tier reward breakdown for a block reward transaction.
    FetchBlockRewardBreakdown {
        height: u64,
    },

    /// Consolidate many small UTXOs into fewer large ones.
    ConsolidateUtxos,

    /// Abort an in-progress UTXO consolidation.
    CancelConsolidation,

    /// Register a masternode on-chain via a special transaction.
    RegisterMasternode {
        alias: String,
        ip: String,
        port: u16,
        collateral_txid: String,
        collateral_vout: u32,
        payout_address: String,
    },

    /// Update a masternode's payout address on-chain.
    UpdateMasternodePayout {
        masternode_id: String,
        new_payout_address: String,
    },

    /// Deregister a masternode on-chain via a CollateralUnlock special transaction.
    DeregisterMasternode {
        alias: String,
        collateral_txid: String,
        collateral_vout: u32,
        masternode_ip: String,
    },

    /// Update a masternode entry in the DB, replacing the old alias key.
    UpdateMasternodeEntry {
        old_alias: String,
        new_entry: crate::wallet_db::MasternodeEntry,
    },

    /// Persist updated send records to the database.
    PersistSendRecords(Vec<TransactionRecord>),

    /// Manually switch the active masternode to a specific peer endpoint.
    SwitchPeer {
        endpoint: String,
    },

    /// Clear the manually-selected peer and return to automatic peer discovery.
    ClearPreferredPeer,

    /// Send a payment request to another wallet via the masternode P2P network.
    SendPaymentRequest {
        /// Our address the payer should send funds to.
        from_address: String,
        /// HD derivation index of `from_address` (used to sign the request).
        from_address_idx: usize,
        /// The payer's TIME address (who we are asking to pay us).
        to_address: String,
        amount: u64,
        label: String,
        memo: String,
    },

    /// Pay a received payment request (auto-fills and sends a transaction).
    PayRequest {
        request_id: String,
    },

    /// Decline a received payment request.
    DeclineRequest {
        request_id: String,
    },

    /// Cancel a sent payment request (withdraws it before the payer responds).
    CancelPaymentRequest {
        request_id: String,
    },

    /// Remove a sent payment request from the local list (any status).
    DeleteSentPaymentRequest {
        request_id: String,
    },

    /// Remove an entry from the incoming payment request history.
    DeleteIncomingPaymentHistory {
        id: String,
    },

    /// Clear all owned addresses from the DB and re-derive from index 0,
    /// scanning the blockchain for any funded addresses (gap-limit aware).
    /// Preserves existing labels where the address string matches.
    RebuildAddresses,
}

/// Screens the wallet can display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Welcome,
    NetworkSelect,
    MnemonicSetup,
    MnemonicConfirm,
    Overview,
    Send,
    Receive,
    PaymentRequests,
    Transactions,
    Utxos,
    Masternodes,
    Connections,
    Settings,
    Tools,
    Charts,
}

// ============================================================================
// Service → UI
// ============================================================================

/// Events sent from the service task back to the UI thread.
#[derive(Debug)]
pub enum ServiceEvent {
    /// Wallet loaded successfully.
    WalletLoaded {
        addresses: Vec<AddressInfo>,
        is_testnet: bool,
        is_encrypted: bool,
    },

    /// New wallet created — pass mnemonic back for confirmation screen.
    WalletCreated {
        mnemonic: String,
    },

    /// Updated balance from masternode.
    BalanceUpdated(Balance),

    /// Updated transaction list (full replace — used on first load and manual refresh).
    TransactionsUpdated(Vec<TransactionRecord>),

    /// New transactions from an incremental poll (merge into existing list).
    /// `chain_height` is the masternode's current tip so the wallet can update
    /// `last_synced_height` for the next incremental poll.
    TransactionsAppended {
        new_txs: Vec<TransactionRecord>,
        chain_height: u64,
    },

    /// Updated UTXO set.
    UtxosUpdated(Vec<Utxo>),

    /// Transaction broadcast succeeded.
    TransactionSent {
        txid: String,
    },

    /// Real-time transaction notification from WebSocket.
    TransactionReceived(TxNotification),

    /// A single transaction should be inserted (from WS notification or finality update).
    TransactionInserted(TransactionRecord),

    /// Transaction finality status updated.
    TransactionFinalityUpdated {
        txid: String,
        finalized: bool,
    },

    /// Masternode health status.
    HealthUpdated(HealthStatus),

    /// WebSocket connection state changed.
    WsConnected,
    WsDisconnected,
    /// Masternode WebSocket was at capacity — wallet should failover to another peer.
    WsCapacityFull(String),
    /// The set of active WebSocket URLs changed (used to show per-peer WS status).
    WsActiveUrlsChanged(Vec<String>),

    /// The wallet is encrypted and a password is needed to unlock it.
    PasswordRequired,

    /// Existing wallet was backed up (or none existed). Ready for mnemonic input.
    ReadyForMnemonic {
        backed_up_path: Option<String>,
    },

    /// Address list reloaded after a manual refresh (replaces current list).
    AddressesRefreshed(Vec<AddressInfo>),

    /// A new address was generated.
    AddressGenerated(AddressInfo),

    /// An owned address was deleted from the receive list.
    AddressDeleted(String),

    /// External contacts list updated.
    ContactsUpdated(Vec<crate::state::ContactInfo>),

    /// Peer discovery results with health/ping info.
    PeersDiscovered(Vec<crate::state::PeerInfo>),

    /// Lightweight per-peer block height update (endpoint → height).
    PeerHeightsUpdated(std::collections::HashMap<String, u64>),

    /// Non-fatal error to display in the UI.
    Error(String),

    /// Send failed because the transaction would be too large.
    /// Prompt the user to consolidate UTXOs first.
    SendTooLarge,

    /// Network selected on first run — config saved, service reinitialized.
    NetworkConfigured {
        is_testnet: bool,
    },

    /// Wallet was successfully encrypted with a password.
    WalletEncrypted,

    /// Resync completed — cache cleared, fresh data loaded.
    ResyncComplete,

    /// Database repair completed.
    DatabaseRepaired {
        message: String,
    },

    /// Initial network sync completed (first successful poll).
    SyncComplete,

    /// Decimal places preference loaded from database.
    DecimalPlacesLoaded(usize),

    /// Editor command loaded from config.
    EditorLoaded(Option<String>),

    /// Whether a wallet file exists on disk.
    WalletExists(bool),

    /// Persisted send records loaded from database.
    SendRecordsLoaded(std::collections::HashMap<String, TransactionRecord>),

    /// Masternode entries loaded from database.
    MasternodeEntriesLoaded(Vec<crate::wallet_db::MasternodeEntry>),

    /// Masternode registration transaction broadcast successfully.
    MasternodeRegistered {
        alias: String,
        txid: String,
    },

    /// Masternode deregistration transaction broadcast successfully.
    MasternodeDeregistered {
        alias: String,
    },

    /// Masternode payout update transaction broadcast successfully.
    MasternodePayoutUpdated {
        masternode_id: String,
        txid: String,
    },

    /// UTXO consolidation progress update.
    ConsolidationProgress {
        batch: usize,
        total_batches: usize,
        message: String,
    },

    /// UTXO consolidation completed.
    ConsolidationComplete {
        message: String,
    },

    /// Block reward tier breakdown loaded for the detail view.
    BlockRewardBreakdownLoaded(crate::masternode_client::BlockRewardBreakdown),

    /// Block height polled from active peer.
    BlockHeightUpdated(u64),

    /// Max connections setting updated.
    MaxConnectionsUpdated(usize),

    /// Payment requests received (from poll or WS).
    PaymentRequestsUpdated(Vec<PaymentRequest>),

    /// A single payment request arrived via WebSocket.
    PaymentRequestReceived(PaymentRequest),

    /// Payment request sent successfully.
    PaymentRequestSent {
        id: String,
    },

    /// Incoming payment requests loaded from the database on startup.
    IncomingPaymentRequestsLoaded(Vec<PaymentRequest>),

    /// Sent payment requests loaded from the database on startup.
    SentPaymentRequestsLoaded(Vec<crate::wallet_db::SentPaymentRequest>),

    /// Status of a sent payment request updated (payer responded or we cancelled).
    SentPaymentRequestStatusUpdated {
        id: String,
        /// "declined" | "cancelled" | "paid"
        status: String,
        /// Transaction ID of the payment (present when status == "paid").
        payment_txid: Option<String>,
    },

    /// A payment request send attempt failed; carry the human-readable reason.
    PaymentRequestFailed(String),

    /// Incoming payment request history loaded from the database on startup.
    IncomingPaymentHistoryLoaded(Vec<crate::wallet_db::IncomingPaymentHistory>),

    /// Address-recovery scan found previously-used addresses after DB reset.
    AddressesDiscovered {
        /// Number of addresses recovered.
        count: usize,
    },

    /// A newer wallet release is available.
    LatestVersionAvailable {
        /// Semver version string of the latest release (e.g. "0.7.0").
        version: String,
        /// GitHub release page URL.
        url: String,
    },
}
