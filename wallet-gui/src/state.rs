//! Application state — plain data, no async, no Arc.
//!
//! `AppState` holds everything the UI needs to render. The service task sends
//! `ServiceEvent`s which are applied via `AppState::apply()`. The UI reads
//! fields directly — no locking, no channels.

use crate::events::{Screen, ServiceEvent};
use crate::masternode_client::{Balance, HealthStatus, TransactionRecord, TransactionStatus, Utxo};
use crate::ws_client::TxNotification;

/// Group a formatted number string with spaces every 3 digits, both before
/// and after the decimal point.
///
/// Integer part groups from the right (e.g. "1234567" → "1 234 567").
/// Decimal part groups from the left (e.g. "89012345" → "890 123 45"),
/// which makes it easy to count satoshi positions.
fn format_with_spaces(s: &str) -> String {
    let (int_part, dec_part) = match s.find('.') {
        Some(pos) => (&s[..pos], Some(&s[pos + 1..])),
        None => (s, None),
    };
    let digits: Vec<u8> = int_part.bytes().collect();
    let mut result = String::with_capacity(s.len() + digits.len() / 3 + 1);
    for (i, &b) in digits.iter().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            result.push(' ');
        }
        result.push(b as char);
    }
    if let Some(dec) = dec_part {
        result.push('.');
        for (i, c) in dec.chars().enumerate() {
            if i > 0 && i.is_multiple_of(3) {
                result.push(' ');
            }
            result.push(c);
        }
    }
    result
}

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
    /// Masternode tier (e.g. "Gold", "Silver", "Bronze", "Free"), if known.
    pub tier: Option<String>,
    /// True when the masternode is still performing initial block download.
    pub is_syncing: bool,
    /// None = genesis not yet verified; Some(true) = genesis matches this network;
    /// Some(false) = incompatible genesis (different chain — never auto-select).
    pub genesis_ok: Option<bool>,
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

/// Income chart display mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChartMode {
    /// All addresses combined into a single total bar per month.
    Total,
    /// Each address shown as a separate colored bar per month.
    ByAddress,
    /// Only show income for one specific address.
    SingleAddress,
}

/// Which chart tab is active on the overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChartTab {
    /// Monthly income chart.
    Income,
    /// Transactions per second over time.
    Tps,
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
    /// Last balance reported by the masternode (for drift detection).
    pub masternode_balance: u64,
    /// Spendable balance reported by the masternode (excludes locked collateral).
    pub masternode_available: u64,
    /// Locked collateral balance reported by the masternode.
    pub masternode_locked: u64,
    /// Set when computed balance drifts from masternode — triggers auto-resync.
    pub needs_resync: bool,
    /// Consecutive polls where balance drift was detected (resets on match).
    pub drift_count: u8,
    /// When the last auto-resync was triggered (cooldown guard).
    pub last_resync_at: Option<std::time::Instant>,

    // -- Transactions --
    /// Chain tip height at the time of the last successful transaction poll.
    /// Passed as `from_height` on the next incremental poll so the masternode
    /// only scans newly-added blocks.  0 = not yet synced (full scan needed).
    pub last_synced_height: u64,
    pub transactions: Vec<TransactionRecord>,
    pub selected_transaction: Option<usize>,
    pub tx_search: String,
    pub tx_page: usize,
    /// Tracks which field was last copied and when, for "Copied!" feedback.
    pub copy_feedback: Option<(String, std::time::Instant)>,

    // -- UTXOs --
    pub utxos: Vec<Utxo>,
    /// Outpoints locked as masternode collateral (format: "txid:vout").
    pub locked_utxos: std::collections::HashSet<String>,

    // -- Masternode --
    pub health: Option<HealthStatus>,
    pub ws_connected: bool,
    /// WS URLs currently connected (one per active WS connection).
    pub ws_active_urls: Vec<String>,
    pub peers: Vec<PeerInfo>,

    // -- Notifications (real-time from WebSocket) --
    pub recent_notifications: Vec<TxNotification>,

    // -- UI transient state --
    pub wallet_exists: bool,
    pub send_address: String,
    pub send_recipient_name: String,
    pub send_amount: String,
    pub send_fee: String,
    pub send_memo: String,
    pub send_include_fee: bool,
    /// If set, only UTXOs from this address are used as inputs for the next send.
    pub send_from_address: Option<String>,
    pub qr_scanner: Option<crate::qr_scanner::QrScannerHandle>,
    pub qr_scan_error: Option<String>,
    pub pr_qr_scanner: Option<crate::qr_scanner::QrScannerHandle>,
    pub pr_qr_scan_error: Option<String>,
    pub block_reward_breakdown: Option<crate::masternode_client::BlockRewardBreakdown>,
    pub block_reward_breakdown_loading: bool,
    pub contacts: Vec<ContactInfo>,
    pub new_contact_name: String,
    pub new_contact_address: String,
    pub show_add_contact: bool,
    pub contact_search: String,
    pub receive_search: String,
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
    pub switching_network: bool,

    // -- Display preferences --
    pub decimal_places: usize,
    /// Editor command input for settings UI.
    pub editor_input: String,
    /// Max peer connections (mirrors config, editable in Settings).
    pub max_connections: usize,

    // -- Persisted send records (correct amounts from wallet, keyed by txid) --
    pub send_records: std::collections::HashMap<String, TransactionRecord>,

    // -- Security --
    pub wallet_encrypted: bool,
    pub encrypt_password_input: String,
    pub encrypt_password_confirm: String,
    pub show_encrypt_password: bool,
    pub show_encrypt_dialog: bool,

    // -- Tools state --
    pub resync_in_progress: bool,

    // -- Masternodes --
    pub masternode_entries: Vec<crate::wallet_db::MasternodeEntry>,
    pub mn_add_name: String,
    pub mn_add_txid: String,
    pub mn_add_vout: String,
    pub mn_show_add_form: bool,
    /// Alias of the masternode currently open in the inline edit form.
    pub mn_edit_alias: Option<String>,
    /// Edit form fields (name, TXID, vout).
    pub mn_edit_name: String,
    pub mn_edit_txid: String,
    pub mn_edit_vout: String,
    /// Alias of the masternode currently showing the on-chain register form.
    pub mn_reg_alias: Option<String>,
    /// On-chain registration form fields (IP, port, payout address).
    pub mn_reg_ip: String,
    pub mn_reg_port: String,
    pub mn_reg_payout: String,

    // -- Sync status --
    /// True while waiting for the first network poll after wallet load.
    pub syncing: bool,

    /// True while a database repair is in progress.
    pub repair_in_progress: bool,

    /// True while UTXO consolidation is in progress.
    pub consolidation_in_progress: bool,
    /// Status message from the last consolidation operation.
    pub consolidation_status: String,

    /// Set when a send fails because the tx would be too large.
    /// Prompts the user to consolidate UTXOs and retry.
    pub send_too_large: bool,

    /// Set on first UTXO sync when count exceeds the consolidation threshold.
    /// Dismissed by user; not re-shown until next startup.
    pub suggest_consolidation: bool,
    /// Set when the user dismisses the consolidation suggestion.
    /// Prevents suggest_consolidation from being re-raised until consolidation
    /// actually completes or the wallet is restarted.
    pub consolidation_dismissed: bool,

    // -- Pending DB writes --
    /// Send records whose status changed and need to be persisted.
    pub dirty_send_records: Vec<TransactionRecord>,

    // -- Payment Requests --
    /// Incoming payment requests from other wallets.
    pub payment_requests: Vec<crate::events::PaymentRequest>,
    /// History of completed (paid or declined) incoming payment requests.
    pub incoming_payment_history: Vec<crate::wallet_db::IncomingPaymentHistory>,
    /// Payment requests sent by this wallet to other wallets.
    pub sent_payment_requests: Vec<crate::wallet_db::SentPaymentRequest>,
    /// "Request Payment" form fields.
    pub pr_address: String,
    pub pr_amount: String,
    pub pr_label: String,
    pub pr_memo: String,
    /// Which of our own addresses to receive payment into (index into `addresses`).
    pub pr_from_address_idx: usize,
    /// Error message from the last failed payment request send attempt.
    pub pr_send_error: Option<String>,
    /// Whether the Request Payment inline form is expanded on the Receive screen.
    pub show_payment_request_form: bool,
    /// Per-request memo overrides: the payer can edit the memo before approving.
    /// Key = payment request id.
    pub pr_memo_overrides: std::collections::HashMap<String, String>,
    /// The incoming payment request id being fulfilled by the current Send, if any.
    pub pending_payment_request_id: Option<String>,

    // -- Charts --
    /// Which chart tab is active on the Charts page.
    pub chart_tab: ChartTab,
    /// Number of months of history to display (income chart).
    pub chart_months: usize,
    /// Income chart view mode.
    pub chart_mode: ChartMode,
    /// When mode is SingleAddress, which address to show.
    pub chart_address_idx: usize,
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
                locked: 0,
            },
            masternode_balance: 0,
            masternode_available: 0,
            masternode_locked: 0,
            needs_resync: false,
            drift_count: 0,
            last_resync_at: None,
            last_synced_height: 0,
            transactions: Vec::new(),
            selected_transaction: None,
            tx_search: String::new(),
            tx_page: 0,
            copy_feedback: None,
            utxos: Vec::new(),
            locked_utxos: std::collections::HashSet::new(),
            health: None,
            ws_connected: false,
            ws_active_urls: Vec::new(),
            peers: Vec::new(),
            recent_notifications: Vec::new(),
            wallet_exists: false,
            send_address: String::new(),
            send_recipient_name: String::new(),
            send_amount: String::new(),
            send_fee: String::new(),
            send_memo: String::new(),
            send_include_fee: false,
            send_from_address: None,
            qr_scanner: None,
            qr_scan_error: None,
            pr_qr_scanner: None,
            pr_qr_scan_error: None,
            block_reward_breakdown: None,
            block_reward_breakdown_loading: false,
            contacts: Vec::new(),
            new_contact_name: String::new(),
            new_contact_address: String::new(),
            show_add_contact: false,
            contact_search: String::new(),
            receive_search: String::new(),
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
            switching_network: false,
            decimal_places: 2,
            editor_input: String::new(),
            max_connections: 8,
            send_records: std::collections::HashMap::new(),
            wallet_encrypted: true, // assume safe until proven otherwise
            encrypt_password_input: String::new(),
            encrypt_password_confirm: String::new(),
            show_encrypt_password: false,
            show_encrypt_dialog: false,
            resync_in_progress: false,
            masternode_entries: Vec::new(),
            mn_add_name: String::new(),
            mn_add_txid: String::new(),
            mn_add_vout: "0".to_string(),
            mn_show_add_form: false,
            mn_edit_alias: None,
            mn_edit_name: String::new(),
            mn_edit_txid: String::new(),
            mn_edit_vout: "0".to_string(),
            mn_reg_alias: None,
            mn_reg_ip: String::new(),
            mn_reg_port: "24000".to_string(),
            mn_reg_payout: String::new(),
            syncing: false,
            repair_in_progress: false,
            consolidation_in_progress: false,
            consolidation_status: String::new(),
            send_too_large: false,
            suggest_consolidation: false,
            consolidation_dismissed: false,
            dirty_send_records: Vec::new(),
            payment_requests: Vec::new(),
            incoming_payment_history: Vec::new(),
            sent_payment_requests: Vec::new(),
            pr_address: String::new(),
            pr_amount: String::new(),
            pr_label: String::new(),
            pr_memo: String::new(),
            pr_from_address_idx: 0,
            pr_send_error: None,
            show_payment_request_form: true,
            pr_memo_overrides: std::collections::HashMap::new(),
            pending_payment_request_id: None,
            chart_tab: ChartTab::Income,
            chart_months: 12,
            chart_mode: ChartMode::Total,
            chart_address_idx: 0,
        }
    }
}

impl AppState {
    /// Compute total balance from the transaction list.
    /// This is the source of truth for display — updates instantly on send/receive.
    pub fn computed_balance(&self) -> u64 {
        let mut bal: i64 = 0;
        for tx in &self.transactions {
            if matches!(tx.status, TransactionStatus::Declined) {
                continue;
            }
            // Consolidation sends are self-sends: only the fee leaves the wallet.
            // Deduct just the fee so the balance decreases correctly after each
            // consolidation without double-counting the full sent amount.
            if tx.is_consolidation && tx.is_send {
                bal -= tx.fee as i64;
                continue;
            }
            // Consolidation receives (change back to own address) are already
            // accounted for by the fee deduction above — skip them too.
            if tx.is_consolidation {
                continue;
            }
            if tx.is_send || tx.is_fee {
                bal -= tx.amount as i64;
            } else {
                bal += tx.amount as i64;
            }
        }
        bal.max(0) as u64
    }

    /// Compute confirmed balance from finalized (Approved) transactions only.
    /// Updates immediately when a transaction is finalized via WS, not at block time.
    pub fn confirmed_balance(&self) -> u64 {
        let mut bal: i64 = 0;
        for tx in &self.transactions {
            if !matches!(tx.status, TransactionStatus::Approved) {
                continue;
            }
            if tx.is_consolidation {
                continue;
            }
            if tx.is_send || tx.is_fee {
                bal -= tx.amount as i64;
            } else {
                bal += tx.amount as i64;
            }
        }
        bal.max(0) as u64
    }

    /// Compute spendable balance for a single address from UTXOs.
    pub fn address_balance(&self, address: &str) -> u64 {
        self.utxos
            .iter()
            .filter(|u| u.address == address && u.spendable)
            .map(|u| u.amount)
            .sum()
    }

    /// Total balance from all UTXOs (spendable + locked).
    pub fn utxo_total(&self) -> u64 {
        self.utxos.iter().map(|u| u.amount).sum()
    }

    /// Balance locked as masternode collateral (not spendable).
    /// Only counts entries whose collateral UTXO is present in the live UTXO set.
    pub fn locked_balance(&self) -> u64 {
        self.masternode_entries
            .iter()
            .filter_map(|entry| {
                self.utxos
                    .iter()
                    .find(|u| u.txid == entry.collateral_txid && u.vout == entry.collateral_vout)
                    .map(|u| u.amount)
            })
            .sum()
    }

    /// Spendable balance (total minus locked collateral).
    pub fn available_balance(&self) -> u64 {
        self.utxo_total().saturating_sub(self.locked_balance())
    }

    /// Reconcile the transaction list against the UTXO set.
    ///
    /// When `computed_balance()` exceeds the UTXO total, there are phantom
    /// receive entries in the transaction list (e.g. from stale WebSocket
    /// notifications that were never backed by a real UTXO).
    ///
    /// This method finds unbacked, isolated receive entries whose removal
    /// exactly reconciles the two balances, and removes them.  Returns `true`
    /// if any entries were removed.
    pub fn reconcile_transactions_with_utxos(&mut self) -> bool {
        let utxo_total: u64 = self.utxos.iter().map(|u| u.amount).sum();
        let computed = self.computed_balance();

        if computed <= utxo_total || utxo_total == 0 {
            return false;
        }

        let excess = computed - utxo_total;

        // Build UTXO lookup by (txid, vout)
        let utxo_keys: std::collections::HashSet<(&str, u32)> = self
            .utxos
            .iter()
            .map(|u| (u.txid.as_str(), u.vout))
            .collect();

        // Count transaction entries per txid — isolated entries (count == 1)
        // are not part of a send/receive/fee group and are more likely phantom.
        let mut txid_counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for tx in &self.transactions {
            *txid_counts.entry(&tx.txid).or_insert(0) += 1;
        }

        // Collect candidate indices: unbacked, isolated, non-declined receives
        let mut candidates: Vec<usize> = Vec::new();
        for (i, tx) in self.transactions.iter().enumerate() {
            if tx.is_send || tx.is_fee {
                continue;
            }
            if matches!(tx.status, TransactionStatus::Declined) {
                continue;
            }
            if utxo_keys.contains(&(tx.txid.as_str(), tx.vout)) {
                continue; // backed by a real UTXO
            }
            let count = txid_counts.get(tx.txid.as_str()).copied().unwrap_or(0);
            if count > 1 {
                continue; // part of a send/receive group, likely legitimate
            }
            candidates.push(i);
        }

        // Greedily select candidates whose amounts sum to the excess
        let mut to_remove: Vec<usize> = Vec::new();
        let mut removed_total: u64 = 0;
        for &i in &candidates {
            let amt = self.transactions[i].amount;
            if removed_total + amt <= excess {
                to_remove.push(i);
                removed_total += amt;
            }
            if removed_total == excess {
                break;
            }
        }

        if removed_total != excess {
            log::warn!(
                "Balance drift of {} sats could not be exactly reconciled \
                 (found {} sats in {} phantom candidates)",
                excess,
                removed_total,
                candidates.len()
            );
            return false;
        }

        for &i in to_remove.iter().rev() {
            let tx = &self.transactions[i];
            log::info!(
                "🧹 Removing phantom receive: txid={}… amount={} sats",
                &tx.txid[..16.min(tx.txid.len())],
                tx.amount
            );
            self.transactions.remove(i);
        }
        true
    }

    /// Format a satoshi amount as TIME with the user's preferred decimal places.
    pub fn format_time(&self, sats: u64) -> String {
        let time = sats as f64 / 100_000_000.0;
        let raw = format!("{:.prec$}", time, prec = self.decimal_places);
        format!("{} TIME", format_with_spaces(&raw))
    }

    /// Format a satoshi amount with sign prefix (+ or -).
    pub fn format_time_signed(&self, sats: u64, is_negative: bool) -> String {
        let time = sats as f64 / 100_000_000.0;
        let sign = if is_negative { "-" } else { "+" };
        let raw = format!("{:.prec$}", time, prec = self.decimal_places);
        format!("{}{} TIME", sign, format_with_spaces(&raw))
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
                is_encrypted,
            } => {
                self.wallet_loaded = true;
                self.addresses = addresses;
                self.selected_address = 0;
                self.is_testnet = is_testnet;
                self.wallet_encrypted = is_encrypted;
                self.screen = Screen::Overview;
                self.loading = false;
                self.switching_network = false;
                self.syncing = true;
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
                self.loading = false;
                self.error = None;
                // During consolidation, freeze the displayed balance at its
                // pre-consolidation value. Intermediate RPC results are
                // unreliable (may temporarily double-count UTXOs). The
                // consolidation task sends a final BalanceUpdated after it
                // clears the active flag.
                if !self.consolidation_in_progress {
                    self.masternode_balance = balance.total;
                    self.masternode_available = balance.confirmed;
                    self.masternode_locked = balance.locked;
                }
                // Detect drift between computed and masternode balance
                let computed = self.computed_balance();
                if computed != balance.total
                    && !self.syncing
                    && !self.resync_in_progress
                    && !self.consolidation_in_progress
                    && !self.transactions.is_empty()
                {
                    self.drift_count = self.drift_count.saturating_add(1);
                    // Require 3 consecutive drifts and a 5-minute cooldown before resyncing
                    let cooldown_elapsed = self
                        .last_resync_at
                        .is_none_or(|t| t.elapsed().as_secs() >= 300);
                    if self.drift_count >= 3 && cooldown_elapsed {
                        log::warn!(
                            "Balance drift ({}× consecutive): computed={}, masternode={}. Triggering resync.",
                            self.drift_count,
                            computed,
                            balance.total
                        );
                        self.needs_resync = true;
                        self.drift_count = 0;
                        self.last_resync_at = Some(std::time::Instant::now());
                    }
                } else {
                    self.drift_count = 0;
                }
            }

            ServiceEvent::TransactionsUpdated(txs) => {
                // Collect Approved txids from both old state and new RPC results
                let approved_txids: std::collections::HashSet<String> = self
                    .transactions
                    .iter()
                    .chain(txs.iter())
                    .filter(|t| matches!(t.status, TransactionStatus::Approved))
                    .map(|t| t.txid.clone())
                    .collect();

                // Use persisted send records (survive restarts) as the source
                // of truth for send amounts. Also collect in-memory send records
                // (fee > 0 means locally-inserted, not from RPC).
                let mut local_sends = self.send_records.clone();
                for t in &self.transactions {
                    if t.is_send && !t.is_fee && t.fee > 0 {
                        local_sends
                            .entry(t.txid.clone())
                            .or_insert_with(|| t.clone());
                    }
                }

                // Keep fee line items (never come from RPC) and WS-injected
                // receive records not already covered by RPC results
                let rpc_keys: std::collections::HashSet<(String, bool, u32)> = txs
                    .iter()
                    .map(|t| (t.txid.clone(), t.is_send, t.vout))
                    .collect();
                let ws_only: Vec<_> = self
                    .transactions
                    .iter()
                    .filter(|t| {
                        t.is_fee || !rpc_keys.contains(&(t.txid.clone(), t.is_send, t.vout))
                    })
                    .cloned()
                    .collect();

                // Snapshot memos from the existing state so they can be
                // restored when an RPC update returns the same transaction
                // without a memo (common for block rewards / receives).
                let existing_memos: std::collections::HashMap<(String, bool, u32), String> = self
                    .transactions
                    .iter()
                    .filter_map(|t| {
                        t.memo
                            .as_ref()
                            .map(|m| ((t.txid.clone(), t.is_send, t.vout), m.clone()))
                    })
                    .collect();

                // Deduplicate the RPC results by (txid, is_send, vout).
                // When duplicates exist (e.g. a block reward appearing in both the
                // finalized pool as "receive" and in the confirmed block as "generate"),
                // prefer the entry that carries a memo so "Block Reward" isn't lost.
                // Replace RPC "send" entries with persisted local versions.
                // Restore memos on receive entries when the RPC omits them.
                //
                // Two-pass dedup: first pass builds the best entry per key (prefer
                // memo-bearing entries); second pass applies local-send / memo-restore
                // logic to preserve insertion order.
                let mut best: std::collections::HashMap<(String, bool, u32), usize> =
                    std::collections::HashMap::new();
                let mut ordered: Vec<crate::masternode_client::TransactionRecord> = Vec::new();
                for t in txs.into_iter() {
                    let key = (t.txid.clone(), t.is_send, t.vout);
                    if let Some(&idx) = best.get(&key) {
                        // Upgrade to this entry if it has a memo and the current best doesn't.
                        if ordered[idx].memo.is_none() && t.memo.is_some() {
                            ordered[idx] = t;
                        }
                    } else {
                        best.insert(key, ordered.len());
                        ordered.push(t);
                    }
                }
                self.transactions = ordered
                    .into_iter()
                    .map(|t| {
                        if t.is_send && !t.is_fee {
                            if let Some(local) = local_sends.get(&t.txid) {
                                let mut merged = local.clone();
                                merged.status = t.status.clone();
                                // Use the block timestamp from RPC so sent transactions
                                // show the same time basis as received transactions.
                                if t.timestamp > 0 {
                                    merged.timestamp = t.timestamp;
                                }
                                return merged;
                            }
                        }
                        // Preserve a previously-decrypted memo if the RPC entry
                        // doesn't carry one (e.g. block rewards on subsequent polls).
                        if t.memo.is_none() {
                            let key = (t.txid.clone(), t.is_send, t.vout);
                            if let Some(memo) = existing_memos.get(&key) {
                                let mut t = t;
                                t.memo = Some(memo.clone());
                                return t;
                            }
                        }
                        t
                    })
                    .collect();

                // Restore Approved status from WS finality (applied to RPC entries;
                // will be applied again after fee synthesis below)
                for tx in &mut self.transactions {
                    if matches!(tx.status, TransactionStatus::Pending)
                        && approved_txids.contains(&tx.txid)
                    {
                        tx.status = TransactionStatus::Approved;
                    }
                }

                // Append locally-inserted send records if RPC had no send entry
                // and synthesize fee line items from send records or RPC fee data.
                // If the RPC has no record of a send at all (no send or receive
                // entry), the masternode rejected it — mark as Declined.
                let rpc_txids: std::collections::HashSet<String> =
                    self.transactions.iter().map(|t| t.txid.clone()).collect();
                let mut declined_txids: Vec<String> = Vec::new();
                for (txid, local_tx) in &local_sends {
                    let rpc_knows = rpc_txids.contains(txid.as_str());
                    let has_send = self
                        .transactions
                        .iter()
                        .any(|t| t.txid == *txid && t.is_send && !t.is_fee);
                    if !has_send {
                        let mut record = local_tx.clone();
                        if !rpc_knows && matches!(record.status, TransactionStatus::Pending) {
                            record.status = TransactionStatus::Declined;
                            declined_txids.push(txid.clone());
                        }
                        self.transactions.push(record);
                    }
                    // Ensure a fee line item exists for this send
                    if local_tx.fee > 0 {
                        let has_fee = self
                            .transactions
                            .iter()
                            .any(|t| t.txid == *txid && t.is_fee);
                        if !has_fee {
                            let fee_status = if !rpc_knows
                                && matches!(local_tx.status, TransactionStatus::Pending)
                            {
                                TransactionStatus::Declined
                            } else {
                                local_tx.status.clone()
                            };
                            // Use the block timestamp from the merged send entry
                            let fee_timestamp = self
                                .transactions
                                .iter()
                                .find(|t| t.txid == *txid && t.is_send && !t.is_fee)
                                .map(|t| t.timestamp)
                                .unwrap_or(local_tx.timestamp);
                            self.transactions.push(TransactionRecord {
                                txid: txid.clone(),
                                vout: 0,
                                is_send: true,
                                address: "Network Fee".to_string(),
                                amount: local_tx.fee,
                                fee: 0,
                                timestamp: fee_timestamp,
                                status: fee_status,
                                is_fee: true,
                                is_change: false,
                                block_hash: String::new(),
                                block_height: 0,
                                confirmations: 0,
                                memo: local_tx.memo.clone(),
                                is_consolidation: false,
                            });
                        }
                    }
                }

                // Update persisted send records with Declined status
                for txid in &declined_txids {
                    if let Some(sr) = self.send_records.get_mut(txid) {
                        sr.status = TransactionStatus::Declined;
                        self.dirty_send_records.push(sr.clone());
                    }
                }

                // Synthesize fee line items from RPC fee data for sends
                // that have no local send record (e.g., after resync)
                let send_txids_with_fees: Vec<(String, u64, i64, TransactionStatus)> = self
                    .transactions
                    .iter()
                    .filter(|t| {
                        t.is_send && !t.is_fee && t.fee > 0 && !local_sends.contains_key(&t.txid)
                    })
                    .map(|t| (t.txid.clone(), t.fee, t.timestamp, t.status.clone()))
                    .collect();
                for (txid, fee, timestamp, status) in send_txids_with_fees {
                    let has_fee = self.transactions.iter().any(|t| t.txid == txid && t.is_fee);
                    if !has_fee {
                        // Copy memo from the corresponding send entry
                        let memo = self
                            .transactions
                            .iter()
                            .find(|t| t.txid == txid && t.is_send && !t.is_fee)
                            .and_then(|t| t.memo.clone());
                        self.transactions.push(TransactionRecord {
                            txid,
                            vout: 0,
                            is_send: true,
                            address: "Network Fee".to_string(),
                            amount: fee,
                            fee: 0,
                            timestamp,
                            status,
                            is_fee: true,
                            is_change: false,
                            block_hash: String::new(),
                            block_height: 0,
                            confirmations: 0,
                            memo,
                            is_consolidation: false,
                        });
                    }
                }

                // Mark change outputs: receive entries for txids we sent,
                // where the receive address is one of our own.
                // Exception: for send-to-self, keep one receive matching the send amount.
                let own_addrs: std::collections::HashSet<&str> =
                    self.addresses.iter().map(|a| a.address.as_str()).collect();
                let sent_txids: std::collections::HashSet<&str> =
                    local_sends.keys().map(|s| s.as_str()).collect();
                let mut kept_self_receive: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for tx in &mut self.transactions {
                    if !tx.is_send
                        && !tx.is_fee
                        && sent_txids.contains(tx.txid.as_str())
                        && own_addrs.contains(tx.address.as_str())
                    {
                        // Check if this is a send-to-self receive (amount matches send).
                        // Consolidation sends always produce change — never count as income.
                        let is_self_receive = local_sends
                            .get(&tx.txid)
                            .map(|send| {
                                !send.is_consolidation
                                    && own_addrs.contains(send.address.as_str())
                                    && tx.amount == send.amount
                            })
                            .unwrap_or(false);
                        if is_self_receive && !kept_self_receive.contains(&tx.txid) {
                            kept_self_receive.insert(tx.txid.clone());
                            // Copy memo from the local send record to the receive entry
                            if tx.memo.is_none() {
                                if let Some(send) = local_sends.get(&tx.txid) {
                                    tx.memo = send.memo.clone();
                                }
                            }
                        } else {
                            tx.is_change = true;
                        }
                    }
                }

                // Remove change outputs — they're internal and shouldn't be shown
                self.transactions.retain(|t| !t.is_change);

                // Synthesize missing receive entries for send-to-self transactions.
                // If the destination is one of our own addresses and the RPC
                // doesn't already include a receive entry, add one so the
                // transaction history shows the full picture.
                for (txid, send_tx) in &local_sends {
                    if !own_addrs.contains(send_tx.address.as_str()) {
                        continue; // not a self-send
                    }
                    let has_receive = self
                        .transactions
                        .iter()
                        .any(|t| t.txid == *txid && !t.is_send && !t.is_fee);
                    if !has_receive {
                        self.transactions.push(TransactionRecord {
                            txid: txid.clone(),
                            vout: 0,
                            is_send: false,
                            address: send_tx.address.clone(),
                            amount: send_tx.amount,
                            fee: 0,
                            timestamp: send_tx.timestamp,
                            status: send_tx.status.clone(),
                            is_fee: false,
                            is_change: false,
                            block_hash: String::new(),
                            block_height: 0,
                            confirmations: 0,
                            memo: send_tx.memo.clone(),
                            is_consolidation: false,
                        });
                    }
                }

                // Append WS-only txs (dedup against existing entries).
                // During resync, drop WS-only receives — the RPC is authoritative
                // and keeping stale WS entries can introduce phantom balances.
                for tx in ws_only.into_iter().rev() {
                    if self.resync_in_progress && !tx.is_send && !tx.is_fee {
                        continue;
                    }
                    let dup = self.transactions.iter().any(|t| {
                        t.txid == tx.txid
                            && t.is_send == tx.is_send
                            && t.is_fee == tx.is_fee
                            && t.vout == tx.vout
                    });
                    if !dup {
                        self.transactions.insert(0, tx);
                    }
                }

                // Restore Approved status again after fee synthesis and ws_only append,
                // so synthesized fee entries don't regress to Pending
                for tx in &mut self.transactions {
                    if matches!(tx.status, TransactionStatus::Pending)
                        && approved_txids.contains(&tx.txid)
                    {
                        tx.status = TransactionStatus::Approved;
                    }
                }

                // Sort newest first; within the same timestamp, show
                // receives before fees before sends (descending chronological).
                self.transactions.sort_by(|a, b| {
                    b.timestamp.cmp(&a.timestamp).then_with(|| {
                        fn order(t: &TransactionRecord) -> u8 {
                            if t.is_send && !t.is_fee {
                                2
                            } else if t.is_fee {
                                1
                            } else {
                                0
                            }
                        }
                        order(a).cmp(&order(b))
                    })
                });

                // Update incremental-sync height (0 = full scan happened but
                // chain height is unknown; keep 0 so next poll is also full).
                // The service will send a separate TransactionsAppended with the
                // authoritative chain_height once incremental polling is active.
                // For now just leave last_synced_height at whatever it was
                // (the service updates it directly after TransactionsUpdated).
            }

            ServiceEvent::TransactionsAppended {
                new_txs,
                chain_height,
            } => {
                // Incremental update: merge new_txs into the existing list.
                // Only add entries that are genuinely new (not already present).
                let existing_keys: std::collections::HashSet<(String, bool, u32)> = self
                    .transactions
                    .iter()
                    .map(|t| (t.txid.clone(), t.is_send, t.vout))
                    .collect();

                let approved_txids: std::collections::HashSet<String> = self
                    .transactions
                    .iter()
                    .filter(|t| matches!(t.status, TransactionStatus::Approved))
                    .map(|t| t.txid.clone())
                    .collect();

                let existing_memos: std::collections::HashMap<(String, bool, u32), String> = self
                    .transactions
                    .iter()
                    .filter_map(|t| {
                        t.memo
                            .as_ref()
                            .map(|m| ((t.txid.clone(), t.is_send, t.vout), m.clone()))
                    })
                    .collect();

                let mut added = false;
                for mut t in new_txs {
                    let key = (t.txid.clone(), t.is_send, t.vout);
                    if existing_keys.contains(&key) {
                        // Update status and memo on existing entry if they improved.
                        for existing in &mut self.transactions {
                            if existing.txid == t.txid
                                && existing.is_send == t.is_send
                                && existing.vout == t.vout
                            {
                                if matches!(t.status, TransactionStatus::Approved) {
                                    existing.status = TransactionStatus::Approved;
                                }
                                if t.timestamp > 0 {
                                    existing.timestamp = t.timestamp;
                                }
                                // Copy memo if the poll decrypted one the WS-inserted record lacks.
                                if existing.memo.is_none() && t.memo.is_some() {
                                    existing.memo = t.memo.clone();
                                }
                            }
                        }
                        continue;
                    }
                    // Restore memo from existing state when RPC omits it.
                    if t.memo.is_none() {
                        if let Some(m) = existing_memos.get(&key) {
                            t.memo = Some(m.clone());
                        }
                    }
                    // Synthesize fee entry for new sends.
                    if t.is_send && !t.is_fee && t.fee > 0 {
                        let fee_key = (t.txid.clone(), true, 0u32);
                        if !existing_keys.contains(&fee_key) {
                            self.transactions.push(TransactionRecord {
                                txid: t.txid.clone(),
                                vout: 0,
                                is_send: true,
                                address: "Network Fee".to_string(),
                                amount: t.fee,
                                fee: 0,
                                timestamp: t.timestamp,
                                status: t.status.clone(),
                                is_fee: true,
                                is_change: false,
                                block_hash: String::new(),
                                block_height: 0,
                                confirmations: 0,
                                memo: t.memo.clone(),
                                is_consolidation: false,
                            });
                        }
                    }
                    self.transactions.push(t);
                    added = true;
                }

                // Restore Approved status from existing finality records.
                for tx in &mut self.transactions {
                    if matches!(tx.status, TransactionStatus::Pending)
                        && approved_txids.contains(&tx.txid)
                    {
                        tx.status = TransactionStatus::Approved;
                    }
                }

                if added {
                    self.transactions.sort_by(|a, b| {
                        b.timestamp.cmp(&a.timestamp).then_with(|| {
                            fn order(t: &TransactionRecord) -> u8 {
                                if t.is_send && !t.is_fee {
                                    2
                                } else if t.is_fee {
                                    1
                                } else {
                                    0
                                }
                            }
                            order(a).cmp(&order(b))
                        })
                    });
                }

                // Advance the watermark regardless of whether new txs arrived.
                if chain_height > self.last_synced_height {
                    self.last_synced_height = chain_height;
                }
            }

            ServiceEvent::UtxosUpdated(utxos) => {
                // Suggest consolidation on first sync if there are many spendable UTXOs
                // and the user hasn't been prompted yet this session.
                const CONSOLIDATION_SUGGEST_THRESHOLD: usize = 1000;
                if !self.suggest_consolidation
                    && !self.consolidation_in_progress
                    && !self.consolidation_dismissed
                    && utxos.iter().filter(|u| u.spendable).count()
                        >= CONSOLIDATION_SUGGEST_THRESHOLD
                {
                    self.suggest_consolidation = true;
                }
                self.utxos = utxos;
                // Backfill collateral_amount on entries that don't have it yet
                for entry in &mut self.masternode_entries {
                    if entry.collateral_amount.is_none() {
                        if let Some(utxo) = self.utxos.iter().find(|u| {
                            u.txid == entry.collateral_txid && u.vout == entry.collateral_vout
                        }) {
                            entry.collateral_amount = Some(utxo.amount);
                        }
                    }
                }
                if self.reconcile_transactions_with_utxos() {
                    log::info!("✅ Reconciled transaction list with UTXOs");
                }
            }

            ServiceEvent::TransactionSent { txid } => {
                self.success = Some(format!("Transaction sent: {}", txid));
                self.send_address.clear();
                self.send_amount.clear();
                self.send_fee.clear();
                self.send_memo.clear();
                self.send_include_fee = false;
                self.send_recipient_name.clear();
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
                // Skip change outputs — they're internal
                if tx.is_change {
                    return;
                }
                // Track locally-inserted send records in memory
                if tx.is_send && !tx.is_fee && tx.fee > 0 {
                    self.send_records
                        .entry(tx.txid.clone())
                        .or_insert_with(|| tx.clone());
                }
                // Insert if not already present; dedup by (txid, is_send, is_fee, vout)
                let exists = self.transactions.iter().any(|t| {
                    t.txid == tx.txid
                        && t.is_fee == tx.is_fee
                        && t.is_send == tx.is_send
                        && t.vout == tx.vout
                });
                if !exists {
                    self.transactions.push(tx);
                    self.transactions.sort_by(|a, b| {
                        b.timestamp.cmp(&a.timestamp).then_with(|| {
                            fn order(t: &TransactionRecord) -> u8 {
                                if t.is_send && !t.is_fee {
                                    2
                                } else if t.is_fee {
                                    1
                                } else {
                                    0
                                }
                            }
                            order(a).cmp(&order(b))
                        })
                    });
                }
            }

            ServiceEvent::TransactionFinalityUpdated { txid, finalized } => {
                let new_status = if finalized {
                    TransactionStatus::Approved
                } else {
                    TransactionStatus::Declined
                };
                // Update all entries with this txid (including fee line items)
                for tx in self.transactions.iter_mut().filter(|t| t.txid == txid) {
                    tx.status = new_status.clone();
                }
                // Persist updated status to send record so it survives restarts
                if let Some(sr) = self.send_records.get_mut(&txid) {
                    sr.status = new_status;
                    self.dirty_send_records.push(sr.clone());
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

            ServiceEvent::WsCapacityFull(_url) => {
                // Service is already handling failover; just mark as disconnected
                self.ws_connected = false;
            }

            ServiceEvent::WsActiveUrlsChanged(urls) => {
                self.ws_active_urls = urls;
            }

            ServiceEvent::PasswordRequired => {
                self.password_required = true;
                self.loading = false;
                self.error = None;
            }

            ServiceEvent::ReadyForMnemonic { backed_up_path } => {
                self.backed_up_path = backed_up_path;
                self.mnemonic_input.clear();
                self.mnemonic_words =
                    vec![String::new(); if self.mnemonic_use_24 { 24 } else { 12 }];
                self.mnemonic_valid = None;
                self.new_wallet_password.clear();
                self.screen = Screen::MnemonicSetup;
                self.loading = false;
            }

            ServiceEvent::PeersDiscovered(peers) => {
                if !peers.is_empty() {
                    self.peers = peers;
                }
            }

            ServiceEvent::PeerHeightsUpdated(heights) => {
                for peer in &mut self.peers {
                    if let Some(&h) = heights.get(&peer.endpoint) {
                        peer.block_height = Some(h);
                    }
                }
            }

            ServiceEvent::AddressesRefreshed(addrs) => {
                self.addresses = addrs;
                if self.selected_address >= self.addresses.len() {
                    self.selected_address = 0;
                }
            }

            ServiceEvent::AddressGenerated(info) => {
                self.addresses.push(info);
                self.selected_address = self.addresses.len() - 1;
            }

            ServiceEvent::AddressDeleted(address) => {
                self.addresses.retain(|a| a.address != address);
                if self.selected_address >= self.addresses.len() && !self.addresses.is_empty() {
                    self.selected_address = self.addresses.len() - 1;
                }
            }

            ServiceEvent::AddressesDiscovered { count } => {
                // Keep selection at primary address after bulk recovery.
                self.selected_address = 0;
                self.success = Some(format!(
                    "Recovered {} address{} from chain history",
                    count,
                    if count == 1 { "" } else { "es" }
                ));
            }

            ServiceEvent::Error(msg) => {
                self.error = Some(msg);
                self.loading = false;
                self.resync_in_progress = false;
            }

            ServiceEvent::SendTooLarge => {
                self.send_too_large = true;
                self.loading = false;
            }

            ServiceEvent::ResyncComplete => {
                self.resync_in_progress = false;
                self.syncing = false;
                self.success = Some("Resync complete".to_string());
            }

            ServiceEvent::DatabaseRepaired { message } => {
                self.repair_in_progress = false;
                self.success = Some(message);
            }

            ServiceEvent::ConsolidationProgress { message, .. } => {
                self.consolidation_status = message;
            }

            ServiceEvent::ConsolidationComplete { message } => {
                self.consolidation_in_progress = false;
                self.consolidation_status.clear();
                // Consolidation ran — allow the suggestion to reappear if still needed.
                self.suggest_consolidation = false;
                self.consolidation_dismissed = false;
                self.success = Some(message);
            }

            ServiceEvent::SyncComplete => {
                self.syncing = false;
            }

            ServiceEvent::DecimalPlacesLoaded(dp) => {
                self.decimal_places = dp;
            }

            ServiceEvent::EditorLoaded(editor) => {
                self.editor_input = editor.unwrap_or_default();
            }

            ServiceEvent::BlockHeightUpdated(height) => {
                // Update health struct (shown in Settings)
                if let Some(ref mut h) = self.health {
                    h.block_height = height;
                } else {
                    self.health = Some(crate::masternode_client::HealthStatus {
                        status: "healthy".to_string(),
                        version: String::new(),
                        block_height: height,
                        peer_count: 0,
                        is_syncing: false,
                        sync_progress: 1.0,
                    });
                }
                // Update the active peer's block height in the connections list
                for peer in &mut self.peers {
                    if peer.is_active {
                        peer.block_height = Some(height);
                        break;
                    }
                }
            }

            ServiceEvent::MaxConnectionsUpdated(n) => {
                self.max_connections = n;
            }

            ServiceEvent::IncomingPaymentRequestsLoaded(requests) => {
                // Merge DB-loaded requests without overwriting any already in memory
                for req in requests {
                    if !self.payment_requests.iter().any(|r| r.id == req.id) {
                        self.payment_requests.push(req);
                    }
                }
            }

            ServiceEvent::PaymentRequestsUpdated(requests) => {
                self.payment_requests = requests;
            }

            ServiceEvent::PaymentRequestReceived(request) => {
                // Dedup by id
                if !self.payment_requests.iter().any(|r| r.id == request.id) {
                    self.payment_requests.push(request);
                }
            }

            ServiceEvent::PaymentRequestSent { id } => {
                self.pr_send_error = None;
                self.success = Some(format!(
                    "Payment request sent ({}...)",
                    &id[..16.min(id.len())]
                ));
                self.pr_address.clear();
                self.pr_amount.clear();
                self.pr_memo.clear();
            }

            ServiceEvent::PaymentRequestFailed(reason) => {
                self.pr_send_error = Some(reason);
            }

            ServiceEvent::SentPaymentRequestsLoaded(reqs) => {
                self.sent_payment_requests = reqs;
            }

            ServiceEvent::SentPaymentRequestStatusUpdated {
                id,
                status,
                payment_txid,
            } => {
                if let Some(req) = self.sent_payment_requests.iter_mut().find(|r| r.id == id) {
                    req.status = status;
                    if payment_txid.is_some() {
                        req.payment_txid = payment_txid;
                    }
                }
            }

            ServiceEvent::IncomingPaymentHistoryLoaded(entries) => {
                self.incoming_payment_history = entries;
            }

            ServiceEvent::WalletExists(exists) => {
                self.wallet_exists = exists;
                if !exists && self.switching_network {
                    self.switching_network = false;
                    self.screen = Screen::MnemonicSetup;
                }
            }

            ServiceEvent::SendRecordsLoaded(records) => {
                // Drop declined send records on reload — they represent
                // transactions that never happened and shouldn't influence
                // change detection or balance computation.
                self.send_records = records
                    .into_iter()
                    .filter(|(_, r)| !matches!(r.status, TransactionStatus::Declined))
                    .collect();
            }

            ServiceEvent::MasternodeEntriesLoaded(entries) => {
                // Rebuild locked UTXO set from the current entries
                self.locked_utxos = entries
                    .iter()
                    .map(|e| format!("{}:{}", e.collateral_txid, e.collateral_vout))
                    .collect();
                self.masternode_entries = entries;
            }

            ServiceEvent::MasternodeRegistered { alias, txid } => {
                self.success = Some(format!(
                    "Masternode '{}' registration broadcast (txid: {})",
                    alias,
                    &txid[..16]
                ));
            }

            ServiceEvent::MasternodeDeregistered { alias } => {
                self.success = Some(format!(
                    "Masternode '{}' deregistration broadcast.",
                    alias
                ));
            }

            ServiceEvent::MasternodePayoutUpdated {
                masternode_id,
                txid,
            } => {
                self.success = Some(format!(
                    "Payout update for '{}' broadcast (txid: {})",
                    masternode_id,
                    &txid[..16]
                ));
            }

            ServiceEvent::NetworkConfigured { is_testnet } => {
                self.is_testnet = is_testnet;
                // Clear ALL network-specific data from the previous network
                self.peers.clear();
                self.wallet_loaded = false;
                self.addresses.clear();
                self.balance = Balance {
                    confirmed: 0,
                    pending: 0,
                    total: 0,
                    locked: 0,
                };
                self.transactions.clear();
                self.utxos.clear();
                self.locked_utxos.clear();
                self.masternode_entries.clear();
                self.masternode_balance = 0;
                self.masternode_available = 0;
                self.masternode_locked = 0;
                self.send_records.clear();
                self.contacts.clear();
                self.recent_notifications.clear();
                self.health = None;
                self.ws_connected = false;
                self.ws_active_urls.clear();
                self.switching_network = true;
                // Only navigate to setup if not already switching from settings;
                // WalletLoaded will navigate to Overview if a wallet exists.
                if self.screen != Screen::Settings {
                    self.screen = Screen::MnemonicSetup;
                }
            }

            ServiceEvent::WalletEncrypted => {
                self.wallet_encrypted = true;
                self.show_encrypt_dialog = false;
                self.encrypt_password_input.clear();
                self.encrypt_password_confirm.clear();
                self.show_encrypt_password = false;
                self.success = Some("Wallet encrypted successfully".to_string());
            }

            ServiceEvent::BlockRewardBreakdownLoaded(breakdown) => {
                self.block_reward_breakdown = Some(breakdown);
                self.block_reward_breakdown_loading = false;
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
            is_encrypted: false,
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
            locked: 500,
        }));
        // Masternode balance stored for drift detection
        assert_eq!(state.masternode_balance, 1500);
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

    #[test]
    fn test_reconcile_removes_phantom_receive() {
        // Simulate: 10.00 received, 1.00 sent + 0.01 fee, 1.00 phantom receive
        let mut state = AppState {
            transactions: vec![
                TransactionRecord {
                    txid: "aaa".to_string(),
                    vout: 0,
                    is_send: false,
                    address: "TIME0addr".to_string(),
                    amount: 10_0000_0000,
                    fee: 0,
                    timestamp: 100,
                    status: TransactionStatus::Approved,
                    is_fee: false,
                    is_change: false,
                    block_hash: String::new(),
                    block_height: 0,
                    confirmations: 0,
                    memo: None,
                    is_consolidation: false,
                },
                TransactionRecord {
                    txid: "bbb".to_string(),
                    vout: 0,
                    is_send: true,
                    address: "TIME0other".to_string(),
                    amount: 1_0000_0000,
                    fee: 100_0000,
                    timestamp: 200,
                    status: TransactionStatus::Approved,
                    is_fee: false,
                    is_change: false,
                    block_hash: String::new(),
                    block_height: 0,
                    confirmations: 0,
                    memo: None,
                    is_consolidation: false,
                },
                TransactionRecord {
                    txid: "bbb".to_string(),
                    vout: 0,
                    is_send: true,
                    address: "Network Fee".to_string(),
                    amount: 100_0000,
                    fee: 0,
                    timestamp: 200,
                    status: TransactionStatus::Approved,
                    is_fee: true,
                    is_change: false,
                    block_hash: String::new(),
                    block_height: 0,
                    confirmations: 0,
                    memo: None,
                    is_consolidation: false,
                },
                // Phantom receive — no UTXO backs this
                TransactionRecord {
                    txid: "phantom123".to_string(),
                    vout: 0,
                    is_send: false,
                    address: "TIME0addr".to_string(),
                    amount: 1_0000_0000,
                    fee: 0,
                    timestamp: 300,
                    status: TransactionStatus::Approved,
                    is_fee: false,
                    is_change: false,
                    block_hash: String::new(),
                    block_height: 0,
                    confirmations: 0,
                    memo: None,
                    is_consolidation: false,
                },
            ],
            // UTXOs: only the change from the send (8.99 TIME)
            utxos: vec![Utxo {
                txid: "bbb".to_string(),
                vout: 1,
                amount: 8_9900_0000,
                address: "TIME0addr".to_string(),
                confirmations: 1,
                spendable: true,
            }],
            ..Default::default()
        };

        // computed_balance = 10 - 1 - 0.01 + 1 = 9.99
        assert_eq!(state.computed_balance(), 9_9900_0000);
        // UTXO total = 8.99
        let utxo_total: u64 = state.utxos.iter().map(|u| u.amount).sum();
        assert_eq!(utxo_total, 8_9900_0000);

        // Reconcile should remove the phantom
        assert!(state.reconcile_transactions_with_utxos());
        assert_eq!(state.computed_balance(), 8_9900_0000);
        assert_eq!(state.transactions.len(), 3);
        assert!(!state.transactions.iter().any(|t| t.txid == "phantom123"));
    }

    #[test]
    fn test_reconcile_keeps_legitimate_spent_receive() {
        // 10.00 received (UTXO spent), then 9.99 change UTXO remains
        // No phantom entries — should NOT remove the original receive
        let mut state = AppState {
            transactions: vec![
                TransactionRecord {
                    txid: "original_recv".to_string(),
                    vout: 0,
                    is_send: false,
                    address: "TIME0addr".to_string(),
                    amount: 10_0000_0000,
                    fee: 0,
                    timestamp: 100,
                    status: TransactionStatus::Approved,
                    is_fee: false,
                    is_change: false,
                    block_hash: String::new(),
                    block_height: 0,
                    confirmations: 0,
                    memo: None,
                    is_consolidation: false,
                },
                TransactionRecord {
                    txid: "spend_tx".to_string(),
                    vout: 0,
                    is_send: true,
                    address: "TIME0other".to_string(),
                    amount: 100_0000,
                    fee: 100_0000,
                    timestamp: 200,
                    status: TransactionStatus::Approved,
                    is_fee: false,
                    is_change: false,
                    block_hash: String::new(),
                    block_height: 0,
                    confirmations: 0,
                    memo: None,
                    is_consolidation: false,
                },
                TransactionRecord {
                    txid: "spend_tx".to_string(),
                    vout: 0,
                    is_send: true,
                    address: "Network Fee".to_string(),
                    amount: 100_0000,
                    fee: 0,
                    timestamp: 200,
                    status: TransactionStatus::Approved,
                    is_fee: true,
                    is_change: false,
                    block_hash: String::new(),
                    block_height: 0,
                    confirmations: 0,
                    memo: None,
                    is_consolidation: false,
                },
            ],
            utxos: vec![Utxo {
                txid: "spend_tx".to_string(),
                vout: 1,
                amount: 9_9800_0000,
                address: "TIME0addr".to_string(),
                confirmations: 1,
                spendable: true,
            }],
            ..Default::default()
        };

        // computed = 10 - 0.01 - 0.01 = 9.98 = UTXO total → no reconciliation needed
        assert_eq!(state.computed_balance(), 9_9800_0000);
        assert!(!state.reconcile_transactions_with_utxos());
        assert_eq!(state.transactions.len(), 3);
    }
}
