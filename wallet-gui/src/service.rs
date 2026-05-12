//! Background service task — single `select!` loop, no spawns, no sleeps.
//!
//! The service owns all async I/O. It receives [`UiEvent`]s from the UI thread,
//! calls the masternode JSON-RPC client, and sends [`ServiceEvent`]s back.
//! WebSocket events are forwarded as-is.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::config_new::Config;
use crate::events::{PaymentRequest, Screen, ServiceEvent, UiEvent};
use crate::masternode_client::{MasternodeClient, TransactionRecord, TransactionStatus};
use crate::peer_discovery;
use crate::state::{AddressInfo, PeerInfo};
use crate::wallet_dat;
use crate::wallet_db::{AddressContact, WalletDb};
use crate::wallet_manager::WalletManager;
use crate::ws_client::{WsClient, WsEvent};
use wallet::NetworkType;

type DiscoveryHandle = tokio::task::JoinHandle<Result<(String, Vec<PeerInfo>), ()>>;

/// Maximum number of blocks a peer may lag behind the best known height before
/// it is considered out of consensus and rejected as an active connection.
const CONSENSUS_LAG: u64 = 3;

/// Canonical genesis block hashes.  Any peer whose block-0 hash differs from
/// the expected value is on an incompatible chain and must never be used.
const MAINNET_GENESIS_HASH: &str =
    "45181d4c65a3a2bcc2215d037267bee4cc2248f21764466846d2b7218b601ce5";
const TESTNET_GENESIS_HASH: &str =
    "b9523431d4e59a1b41d757a8c0f01ed023c11123761b1455e4644ef9d5599ff6";

/// Run the service loop until the cancellation token fires.
///
/// This is the **only** `tokio::spawn`ed task in the application. It owns the
/// masternode client, wallet manager, and WebSocket connection.
pub async fn run(
    token: CancellationToken,
    mut ui_rx: mpsc::UnboundedReceiver<UiEvent>,
    svc_tx: mpsc::UnboundedSender<ServiceEvent>,
    mut config: Config,
) {
    let (ws_event_tx, mut ws_event_rx) = mpsc::unbounded_channel::<WsEvent>();

    let network_type = if config.is_testnet() {
        NetworkType::Testnet
    } else {
        NetworkType::Mainnet
    };

    // Open wallet metadata database
    let db_path = config.wallet_dir().join("wallet_db");
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let wallet_db = WalletDb::open(&db_path).ok();
    if wallet_db.is_some() {
        log::info!("📂 Wallet database opened at: {}", db_path.display());
    }

    // Load persisted display preferences
    if let Some(ref db) = wallet_db {
        if let Ok(Some(dp_str)) = db.get_setting("decimal_places") {
            if let Ok(dp) = dp_str.parse::<usize>() {
                let _ = svc_tx.send(ServiceEvent::DecimalPlacesLoaded(dp));
            }
        }
    }

    // Load editor preference from config
    let _ = svc_tx.send(ServiceEvent::EditorLoaded(config.editor.clone()));

    let mut state = ServiceState {
        svc_tx,
        client: None,
        wallet: None,
        wallet_db,
        addresses: Vec::new(),
        network_type,
        config: config.clone(),
        ws_event_tx,
        ws_conn_shutdown_senders: Vec::new(),
        ws_handles: Vec::new(),
        ws_connected_count: 0,
        ws_active_urls: std::collections::HashSet::new(),
        ws_seen: std::collections::HashMap::new(),
        last_peers: Vec::new(),
        // Restore manual peer selection from config (persisted via preferred_endpoint).
        manual_peer: config.preferred_endpoint.is_some(),
        consolidation_txids: Arc::new(Mutex::new(HashSet::new())),
        consolidation_active: Arc::new(AtomicBool::new(false)),
        signing_keys: Arc::new(Vec::new()),
        last_synced_height: Arc::new(AtomicU64::new(0)),
        pending_address_scan: false,
    };

    // Restore manually-selected peer so discovery doesn't override it on first result.
    if let Some(ref ep) = config.preferred_endpoint.clone() {
        state.client = Some(MasternodeClient::new(ep.clone(), config.rpc_credentials()));
        state.config.active_endpoint = Some(ep.clone());
        log::info!("📌 Restoring preferred peer from config: {}", ep);
    }

    // Auto-load wallet if it exists
    if WalletManager::exists(network_type) {
        if WalletManager::is_encrypted(network_type).unwrap_or(false) {
            let _ = state.svc_tx.send(ServiceEvent::PasswordRequired);
        } else {
            state.load_wallet(None);
        }
    }

    // Kick off peer discovery in the background (skip on first run — wait for network selection)
    let mut is_testnet = config.is_testnet();
    let mut manual_endpoints = config.manual_endpoints();
    let mut rpc_credentials = config.rpc_credentials();
    let mut discovery_handle: Option<DiscoveryHandle> = if config.is_first_run {
        None
    } else {
        let discovery_svc_tx = state.svc_tx.clone();
        let discovery_endpoints = manual_endpoints.clone();
        let discovery_creds = rpc_credentials.clone();
        let max_conn = config.max_connections;
        Some(tokio::spawn(async move {
            discover_peers(
                is_testnet,
                discovery_endpoints,
                discovery_creds,
                &discovery_svc_tx,
                max_conn,
            )
            .await
        }))
    };

    // Single 5-second poll: block height every tick, heavy data every 3rd tick (15s).
    // Delay::new fires immediately on the first tick so the first poll runs at T+0.
    let mut poll_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut poll_tick: u8 = 0;

    // Peer discovery refresh interval (separate from data poll)
    let mut peer_refresh_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    peer_refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Fast per-peer height poll — just getblockcount, no full probe
    let mut height_poll_interval = tokio::time::interval(std::time::Duration::from_secs(2));
    height_poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    log::info!("🚀 Service loop started ({})", state.config.network);

    let initial_sync_done = Arc::new(AtomicBool::new(false));
    // Generation counter: incremented on network switch so in-flight spawned
    // tasks from the old network silently discard their results.
    let poll_generation = Arc::new(AtomicU64::new(0));

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                log::info!("🛑 Service loop shutting down");
                for tx in state.ws_conn_shutdown_senders.drain(..) {
                    let _ = tx.send(true);
                }
                break;
            }

            // Unified poll: block height every 5s, heavy data every 15s
            _ = poll_interval.tick() => {
                poll_tick = poll_tick.wrapping_add(1);
                if let Some(ref client) = state.client {
                    // Fast: block height every tick (with timeout so it doesn't block)
                    let height_client = client.clone();
                    let height_tx = state.svc_tx.clone();
                    let height_gen = poll_generation.clone();
                    let cur_gen = poll_generation.load(Ordering::Relaxed);
                    tokio::spawn(async move {
                        if let Ok(Ok(height)) = tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            height_client.get_block_height(),
                        ).await {
                            if height_gen.load(Ordering::Relaxed) == cur_gen {
                                let _ = height_tx.send(ServiceEvent::BlockHeightUpdated(height));
                            }
                        }
                    });

                    // Heavy: balance / transactions / UTXOs every 3rd tick (15s),
                    // but always on the first tick for instant startup.
                    // Spawned so it doesn't block the select loop.
                    // Skipped during consolidation — the background task does its
                    // own final refresh; intermediate RPC results are unreliable.
                    if (poll_tick == 1 || poll_tick.is_multiple_of(3))
                        && !state.addresses.is_empty()
                        && !state.consolidation_active.load(Ordering::Relaxed)
                    {
                        let heavy_client = client.clone();
                        let heavy_tx = state.svc_tx.clone();
                        let heavy_addrs = state.addresses.clone();
                        let heavy_initial_sync_done = initial_sync_done.clone();
                        let heavy_db = state.wallet_db.clone();
                        let heavy_gen = poll_generation.clone();
                        let heavy_keys = Arc::clone(&state.signing_keys);
                        let heavy_last_synced = Arc::clone(&state.last_synced_height);
                        let cur_gen = poll_generation.load(Ordering::Relaxed);
                        tokio::spawn(async move {
                            // Bail if network switched while we were waiting to run
                            if heavy_gen.load(Ordering::Relaxed) != cur_gen { return; }

                            // Incremental polling: first sync scans from height 0 (full
                            // history); subsequent polls only scan new blocks.
                            let from_height = heavy_last_synced.load(Ordering::Relaxed);
                            let is_incremental = from_height > 0;

                            // Fire all three RPC calls in parallel.
                            let bal_client = heavy_client.clone();
                            let bal_addrs = heavy_addrs.clone();
                            let tx_client = heavy_client.clone();
                            let tx_addrs = heavy_addrs.clone();
                            let utxo_client = heavy_client;
                            let utxo_addrs = heavy_addrs;
                            let (bal_res, tx_res, utxo_res) = tokio::join!(
                                bal_client.get_balances(&bal_addrs),
                                tx_client.get_transactions_multi(&tx_addrs, 0, from_height),
                                async {
                                    // Fetch UTXOs for all addresses in parallel.
                                    let futs: Vec<_> = utxo_addrs.iter().map(|addr| {
                                        let c = utxo_client.clone();
                                        let a = addr.clone();
                                        async move { c.get_utxos(&a).await.ok() }
                                    }).collect();
                                    futures_util::future::join_all(futs).await
                                        .into_iter()
                                        .flatten()
                                        .flatten()
                                        .collect::<Vec<_>>()
                                },
                            );

                            if heavy_gen.load(Ordering::Relaxed) != cur_gen { return; }

                            if let Ok(bal) = bal_res {
                                if let Some(ref db) = heavy_db {
                                    let _ = db.save_cached_balance(&bal);
                                }
                                let _ = heavy_tx.send(ServiceEvent::BalanceUpdated(bal));
                            }

                            if let Ok(batch) = tx_res {
                                let chain_height = batch.chain_height;
                                let mut txs = batch.transactions;
                                decrypt_memos(&mut txs, &heavy_keys);

                                if is_incremental {
                                    // Incremental: merge only new transactions.
                                    let _ = heavy_tx.send(ServiceEvent::TransactionsAppended {
                                        new_txs: txs,
                                        chain_height,
                                    });
                                    // First incremental poll after loading from cache —
                                    // mark sync done so payment-request polling can start.
                                    if !heavy_initial_sync_done.load(Ordering::Relaxed) {
                                        heavy_initial_sync_done.store(true, Ordering::Relaxed);
                                    }
                                } else {
                                    // First load: full replace + cache.
                                    if let Some(ref db) = heavy_db {
                                        let _ = db.save_cached_transactions(&txs);
                                    }
                                    let _ = heavy_tx.send(ServiceEvent::TransactionsUpdated(txs));
                                    if !heavy_initial_sync_done.load(Ordering::Relaxed) {
                                        heavy_initial_sync_done.store(true, Ordering::Relaxed);
                                        let _ = heavy_tx.send(ServiceEvent::SyncComplete);
                                    }
                                }

                                // Advance the watermark so the next poll is incremental.
                                // Also persist it so a fresh start resumes from here
                                // instead of rescanning the full chain.
                                if chain_height > 0 {
                                    heavy_last_synced.store(chain_height, Ordering::Relaxed);
                                    if let Some(ref db) = heavy_db {
                                        let _ = db.save_setting(
                                            "last_synced_height",
                                            &chain_height.to_string(),
                                        );
                                    }
                                }
                            }

                            if !utxo_res.is_empty() {
                                let _ = heavy_tx.send(ServiceEvent::UtxosUpdated(utxo_res));
                            }
                        });
                    }

                    // Payment request poll every 30s (6th tick), but only after initial sync.
                    if poll_tick.is_multiple_of(6)
                        && !state.addresses.is_empty()
                        && initial_sync_done.load(Ordering::Relaxed)
                    {
                        let pr_client = client.clone();
                        let pr_addrs = state.addresses.clone();
                        let pr_tx = state.svc_tx.clone();
                        let pr_db = state.wallet_db.clone();
                        let pr_gen = poll_generation.clone();
                        let cur_gen = poll_generation.load(Ordering::Relaxed);
                        tokio::spawn(async move {
                            if pr_gen.load(Ordering::Relaxed) != cur_gen { return; }
                            match pr_client.get_payment_requests(&pr_addrs).await {
                                Ok(raw_requests) => {
                                    let requests: Vec<_> = raw_requests
                                        .iter()
                                        .filter_map(parse_payment_request_json)
                                        .collect();
                                    if let Some(ref db) = pr_db {
                                        for req in &requests {
                                            let _ = db.save_incoming_payment_request(req);
                                        }
                                    }
                                    let _ = pr_tx.send(ServiceEvent::PaymentRequestsUpdated(requests));
                                }
                                Err(e) => {
                                    log::debug!("Payment request poll failed: {}", e);
                                }
                            }
                        });
                    }
                }
            }

            // Periodic peer refresh
            _ = peer_refresh_interval.tick(), if discovery_handle.is_none() => {
                let tx = state.svc_tx.clone();
                let eps = manual_endpoints.clone();
                let creds = rpc_credentials.clone();
                let max_conn = state.config.max_connections;
                discovery_handle = Some(tokio::spawn(async move {
                    discover_peers(is_testnet, eps, creds, &tx, max_conn).await
                }));
            }

            // Fast block-height poll: query all known peers in parallel every 2s
            _ = height_poll_interval.tick() => {
                if !state.last_peers.is_empty() {
                    let peers_snapshot: Vec<_> = state.last_peers
                        .iter()
                        .map(|p| (p.endpoint.clone(), p.is_healthy))
                        .collect();
                    let creds = rpc_credentials.clone();
                    let tx = state.svc_tx.clone();
                    tokio::spawn(async move {
                        let mut heights = std::collections::HashMap::new();
                        let futs = peers_snapshot.into_iter().filter(|(_, h)| *h).map(|(ep, _)| {
                            let creds = creds.clone();
                            async move {
                                let client = MasternodeClient::new(ep.clone(), creds);
                                let h = tokio::time::timeout(
                                    std::time::Duration::from_secs(2),
                                    client.get_block_height(),
                                ).await.ok().and_then(|r| r.ok());
                                (ep, h)
                            }
                        });
                        let results = futures_util::future::join_all(futs).await;
                        for (ep, h) in results {
                            if let Some(height) = h {
                                heights.insert(ep, height);
                            }
                        }
                        if !heights.is_empty() {
                            let _ = tx.send(ServiceEvent::PeerHeightsUpdated(heights));
                        }
                    });
                }
            }

            // Peer discovery completes in the background
            Some(result) = async {
                if let Some(ref mut handle) = discovery_handle {
                    Some(handle.await)
                } else {
                    std::future::pending::<Option<Result<Result<(String, Vec<PeerInfo>), ()>, tokio::task::JoinError>>>().await
                }
            } => {
                discovery_handle = None;
                if let Ok(Ok((endpoint, mut peer_infos))) = result {
                    // Check before move: is the active peer still healthy?
                    let active_is_healthy = state.client.as_ref().map(|c| {
                        peer_infos.iter().any(|p| p.endpoint == c.endpoint() && p.is_healthy)
                    }).unwrap_or(false);

                    // Switch peer if we have none, or if the active one has become unhealthy.
                    // When the user manually selected a peer, keep it unless it goes unhealthy.
                    let should_switch = if state.client.is_none() {
                        true
                    } else if active_is_healthy {
                        // Active peer is fine — never auto-switch (manual or not)
                        false
                    } else {
                        // Active peer is unhealthy — clear manual override and failover
                        if state.manual_peer {
                            log::info!("📌 Manual peer is unhealthy, releasing override");
                            state.manual_peer = false;
                            state.config.preferred_endpoint = None;
                            config.preferred_endpoint = None;
                            if let Err(e) = state.config.save() {
                                log::error!("Failed to save config: {}", e);
                            }
                        }
                        true
                    };

                    if should_switch {
                        if let Some(ref old) = state.client {
                            log::warn!("🔄 Active peer {} is unhealthy, reconnecting to {}", old.endpoint(), endpoint);
                        } else {
                            log::info!("🔗 Using peer: {}", endpoint);
                        }
                        state.client = Some(MasternodeClient::new(endpoint.clone(), rpc_credentials.clone()));
                        state.config.active_endpoint = Some(endpoint.clone());
                        config.active_endpoint = Some(endpoint);

                        // If wallet is already loaded, restart WS and refresh data
                        if !state.addresses.is_empty() {
                            state.start_ws();
                            if let Some(ref client) = state.client {
                                if let Ok(bal) = client.get_balances(&state.addresses).await {
                                    let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                }
                            }
                            // Backfill any masternode entries that are still missing their
                            // collateral amount — resolves the UTXO directly from the node.
                            mn_backfill_via_gettxout(&state.client, &state.wallet_db, &state.svc_tx).await;
                            // Force a full heavy sync on the very next poll tick so transactions
                            // and UTXOs update immediately rather than waiting up to 10 s.
                            poll_tick = 0;
                        }
                    }

                    // Mark is_active based on the actual current client (post-switch),
                    // so the connections page always reflects which peer is truly active.
                    let current_ep = state.client.as_ref().map(|c| c.endpoint().to_string());
                    for p in &mut peer_infos {
                        p.is_active = current_ep.as_deref() == Some(p.endpoint.as_str());
                    }
                    state.last_peers = peer_infos.clone();
                    let _ = state.svc_tx.send(ServiceEvent::PeersDiscovered(peer_infos));
                }
            }

            Some(event) = ui_rx.recv() => {
                match event {
                    UiEvent::Shutdown => {
                        for tx in state.ws_conn_shutdown_senders.drain(..) {
                            let _ = tx.send(true);
                        }
                        break;
                    }

                    UiEvent::LoadWallet { password } => {
                        state.load_wallet(password);
                        // If a client is already connected (preferred endpoint configured),
                        // backfill missing masternode collateral amounts right away.
                        if !state.addresses.is_empty() {
                            mn_backfill_via_gettxout(&state.client, &state.wallet_db, &state.svc_tx).await;
                        }
                    }

                    UiEvent::CreateWallet { mnemonic, password } => {
                        state.create_wallet(&mnemonic, password);
                    }

                    UiEvent::PrepareNewWallet => {
                        let wallet_path = wallet_dat::WalletDat::default_path(state.network_type);
                        let backed_up = if wallet_path.exists() {
                            let date = chrono::Local::now().format("%Y-%m-%d_%H%M%S");
                            let backup_name = format!("time-wallet-{}.dat", date);
                            let backup_path = wallet_path.with_file_name(&backup_name);
                            match std::fs::rename(&wallet_path, &backup_path) {
                                Ok(_) => {
                                    log::info!("Backed up wallet to {}", backup_path.display());
                                    Some(backup_path.display().to_string())
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to backup wallet: {}", e),
                                    ));
                                    return;
                                }
                            }
                        } else {
                            None
                        };
                        let _ = state.svc_tx.send(ServiceEvent::ReadyForMnemonic {
                            backed_up_path: backed_up,
                        });
                    }

                    UiEvent::RefreshBalance => {
                        if let Some(ref client) = state.client {
                            if !state.addresses.is_empty() {
                                match client.get_balances(&state.addresses).await {
                                    Ok(balance) => { let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(balance)); }
                                    Err(e) => { let _ = state.svc_tx.send(ServiceEvent::Error(e.to_string())); }
                                }
                            }
                        }
                    }

                    UiEvent::RefreshTransactions => {
                        if let Some(ref client) = state.client {
                            if !state.addresses.is_empty() {
                                // Manual refresh: full scan from genesis.
                                state.last_synced_height.store(0, Ordering::Relaxed);
                                match client.get_transactions_multi(&state.addresses, 0, 0).await {
                                    Ok(batch) => {
                                        let chain_height = batch.chain_height;
                                        let mut txs = batch.transactions;
                                        decrypt_memos(&mut txs, &state.signing_keys);
                                        let _ = state.svc_tx.send(ServiceEvent::TransactionsUpdated(txs));
                                        if chain_height > 0 {
                                            state.last_synced_height.store(chain_height, Ordering::Relaxed);
                                        }
                                    }
                                    Err(e) => { let _ = state.svc_tx.send(ServiceEvent::Error(e.to_string())); }
                                }
                            }
                        }
                    }

                    UiEvent::RefreshUtxos => {
                        if let Some(ref client) = state.client {
                            let mut all_utxos = Vec::new();
                            for addr in &state.addresses {
                                match client.get_utxos(addr).await {
                                    Ok(utxos) => all_utxos.extend(utxos),
                                    Err(e) => {
                                        let _ = state.svc_tx.send(ServiceEvent::Error(e.to_string()));
                                        break;
                                    }
                                }
                            }
                            state.send_utxos_updated(all_utxos);
                        }
                    }

                    UiEvent::SendTransaction { to, amount, fee, memo, from_address, payment_request_id } => {
                        if let Some(ref client) = state.client {
                            if let Some(ref mut wm) = state.wallet {
                                // Retry loop: wait for locked UTXOs to finalize
                                let max_retries = 5;
                                let total_needed = amount + wallet::calculate_fee(amount);
                                let mut all_utxos = Vec::new();
                                let mut tx_result: Result<wallet::Transaction, String> =
                                    Err(String::new());

                                // Determine which addresses to fetch UTXOs from.
                                // If send_from is set, restrict to that address only.
                                let addrs_to_query: Vec<String> = match from_address.as_deref() {
                                    Some(fa) => vec![fa.to_string()],
                                    None => state.addresses.clone(),
                                };

                                for attempt in 0..max_retries {
                                    // Fetch UTXOs from masternode and sync into wallet
                                    all_utxos.clear();
                                    for addr in &addrs_to_query {
                                        match client.get_utxos(addr).await {
                                            Ok(utxos) => {
                                                all_utxos.extend(utxos);
                                            }
                                            Err(e) => {
                                                log::warn!("Failed to fetch UTXOs for {}: {}", addr, e);
                                            }
                                        }
                                    }
                                    log::debug!("UTXO sync (attempt {}): {} UTXOs fetched", attempt + 1, all_utxos.len());
                                    let wallet_inner = wm.get_active_wallet_mut();
                                    while !wallet_inner.utxos().is_empty() {
                                        let u = wallet_inner.utxos()[0].clone();
                                        wallet_inner.remove_utxo(&u.tx_hash, u.output_index);
                                    }
                                    let mut total_balance = 0u64;
                                    for utxo in &all_utxos {
                                        let mut tx_hash = [0u8; 32];
                                        let hex_chars: Vec<u8> = utxo.txid.bytes().collect();
                                        let mut valid = hex_chars.len() == 64;
                                        if valid {
                                            for i in 0..32 {
                                                let hi = match hex_chars[i * 2] {
                                                    b'0'..=b'9' => hex_chars[i * 2] - b'0',
                                                    b'a'..=b'f' => hex_chars[i * 2] - b'a' + 10,
                                                    b'A'..=b'F' => hex_chars[i * 2] - b'A' + 10,
                                                    _ => { valid = false; break; }
                                                };
                                                let lo = match hex_chars[i * 2 + 1] {
                                                    b'0'..=b'9' => hex_chars[i * 2 + 1] - b'0',
                                                    b'a'..=b'f' => hex_chars[i * 2 + 1] - b'a' + 10,
                                                    b'A'..=b'F' => hex_chars[i * 2 + 1] - b'A' + 10,
                                                    _ => { valid = false; break; }
                                                };
                                                tx_hash[i] = (hi << 4) | lo;
                                            }
                                        }
                                        if valid && utxo.spendable {
                                            wallet_inner.add_utxo(wallet::wallet::UTXO {
                                                tx_hash,
                                                output_index: utxo.vout,
                                                amount: utxo.amount,
                                                address: utxo.address.clone(),
                                            });
                                            total_balance += utxo.amount;
                                        }
                                    }
                                    wallet_inner.set_balance(total_balance);

                                    tx_result = wm.create_transaction(&to, amount, fee);
                                    if tx_result.is_ok() {
                                        break;
                                    }

                                    // Only retry on InsufficientFunds when masternode confirms we have enough
                                    if let Err(ref msg) = tx_result {
                                        if msg.contains("Insufficient funds") && attempt < max_retries - 1 {
                                            let mn_total = client.get_balances(&state.addresses).await
                                                .map(|b| b.total).unwrap_or(0);
                                            if mn_total >= total_needed {
                                                log::info!(
                                                    "UTXOs temporarily locked, waiting for finalization (attempt {}/{})",
                                                    attempt + 1, max_retries
                                                );
                                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                continue;
                                            }
                                        }
                                    }
                                    break;
                                }

                                match tx_result {
                                    Ok(mut tx) => {
                                        // Re-sign ALL inputs with correct BIP-44 HD keypairs.
                                        // create_transaction signs with Wallet.keypair which uses
                                        // m/44'/0'/0' (account-level), but addresses are derived at
                                        // m/44'/0'/0'/0/index (full BIP-44). We must re-sign every input.
                                        let addr_to_index: std::collections::HashMap<String, u32> =
                                            (0..wm.get_address_count())
                                                .filter_map(|i| wm.derive_address(i).ok().map(|a| (a, i)))
                                                .collect();

                                        let mut resignings: Vec<(usize, u32)> = Vec::new();
                                        for (input_idx, input) in tx.inputs.iter().enumerate() {
                                            let input_txid: String = input.previous_output.txid.iter().map(|b| format!("{:02x}", b)).collect();
                                            let input_vout = input.previous_output.vout;
                                            if let Some(utxo) = all_utxos.iter().find(|u| u.txid == input_txid && u.vout == input_vout) {
                                                if let Some(&hd_index) = addr_to_index.get(&utxo.address) {
                                                    resignings.push((input_idx, hd_index));
                                                }
                                            }
                                        }
                                        // Capture sender HD index before resignings is consumed.
                                        let sender_idx = resignings.first().map(|&(_, i)| i).unwrap_or(0);
                                        for (input_idx, hd_index) in resignings {
                                            if let Ok(kp) = wm.derive_keypair(hd_index) {
                                                log::info!("Signing input {} with HD key index {}", input_idx, hd_index);
                                                let _ = tx.sign(&kp, input_idx);
                                            }
                                        }

                                        // Encrypt memo if provided.
                                        // Use the HD key for the first spending input so the
                                        // recipient can identify the sender; fall back to index 0.
                                        if !memo.is_empty() {
                                            if let Ok(ref kp_sender) = wm.derive_keypair(sender_idx) {
                                                let sender_key = ed25519_dalek::SigningKey::from_bytes(&kp_sender.secret_key_bytes());
                                                match client.get_address_pubkey(&to).await {
                                                    Ok(Some(recipient_pub)) => {
                                                        match crate::memo::encrypt_memo(&sender_key, &recipient_pub, &memo) {
                                                            Ok(blob) => {
                                                                tx.encrypted_memo = Some(blob);
                                                                log::info!("🔒 Memo encrypted ({} bytes)", memo.len());
                                                            }
                                                            Err(e) => log::warn!("Memo encryption failed: {}", e),
                                                        }
                                                    }
                                                    Ok(None) => log::info!("ℹ️ Recipient pubkey unknown — memo skipped"),
                                                    Err(e) => log::warn!("Pubkey lookup failed: {} — memo skipped", e),
                                                }
                                            }
                                        }

                                        let actual_fee = wallet::calculate_fee(amount);
                                        // Serialize to bincode bytes then hex-encode for sendrawtransaction
                                        match tx.to_bytes() {
                                            Ok(bytes) => {
                                                let tx_hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                                                match client.broadcast_transaction(&tx_hex).await {
                                                    Ok(txid) => {
                                                        let _ = state.svc_tx.send(ServiceEvent::TransactionSent { txid: txid.clone() });
                                                        // If this send was fulfilling a payment request, respond now
                                                        if let Some(ref req_id) = payment_request_id {
                                                            let payer_addr = state.addresses.first().map(|s| s.as_str()).unwrap_or("");
                                                            let _ = client.respond_payment_request(req_id, payer_addr, true, Some(txid.as_str())).await;
                                                            if let Some(ref db) = state.wallet_db {
                                                                // Save to history before deleting
                                                                if let Ok(Some(orig)) = db.get_incoming_payment_request(req_id) {
                                                                    let completed_at = std::time::SystemTime::now()
                                                                        .duration_since(std::time::UNIX_EPOCH)
                                                                        .map(|d| d.as_secs() as i64)
                                                                        .unwrap_or(0);
                                                                    let hist = crate::wallet_db::IncomingPaymentHistory {
                                                                        id: orig.id.clone(),
                                                                        from_address: orig.from_address.clone(),
                                                                        amount: orig.amount,
                                                                        label: orig.label.clone(),
                                                                        memo: orig.memo.clone(),
                                                                        status: "paid".to_string(),
                                                                        payment_txid: Some(txid.clone()),
                                                                        created_at: orig.timestamp,
                                                                        completed_at,
                                                                    };
                                                                    let _ = db.save_incoming_payment_history(&hist);
                                                                }
                                                                let _ = db.delete_incoming_payment_request(req_id);
                                                                // Notify the UI to remove it from state.payment_requests
                                                                let remaining = db.get_all_incoming_payment_requests().unwrap_or_default();
                                                                let _ = state.svc_tx.send(ServiceEvent::IncomingPaymentRequestsLoaded(remaining));
                                                                let history = db.get_all_incoming_payment_history().unwrap_or_default();
                                                                let _ = state.svc_tx.send(ServiceEvent::IncomingPaymentHistoryLoaded(history));
                                                            }
                                                        }
                                                        let now = std::time::SystemTime::now()
                                                            .duration_since(std::time::UNIX_EPOCH)
                                                            .map(|d| d.as_secs() as i64)
                                                            .unwrap_or(0);
                                                        let sent_record = crate::masternode_client::TransactionRecord {
                                                            txid: txid.clone(),
                                                            vout: 0,
                                                            is_send: true,
                                                            address: to.clone(),
                                                            amount,
                                                            fee: actual_fee,
                                                            timestamp: now,
                                                            status: crate::masternode_client::TransactionStatus::Pending,
                                                            memo: if memo.is_empty() { None } else { Some(memo.clone()) },
                                                            ..Default::default()
                                                        };
                                                        let _ = state.svc_tx.send(ServiceEvent::TransactionInserted(sent_record.clone()));
                                                        // Persist send record so correct amount survives restarts
                                                        if let Some(ref db) = state.wallet_db {
                                                            let _ = db.save_send_record(&sent_record);
                                                        }
                                                        // Insert fee as a separate ledger entry
                                                        if actual_fee > 0 {
                                                            let fee_record = crate::masternode_client::TransactionRecord {
                                                                txid: txid.clone(),
                                                                vout: 0,
                                                                is_send: true,
                                                                address: "Network Fee".to_string(),
                                                                amount: actual_fee,
                                                                fee: 0,
                                                                timestamp: now,
                                                                status: crate::masternode_client::TransactionStatus::Pending,
                                                                is_fee: true,
                                                                ..Default::default()
                                                            };
                                                            let _ = state.svc_tx.send(ServiceEvent::TransactionInserted(fee_record));
                                                        }
                                                        // Self-send: also insert a pending receive entry immediately
                                                        let is_self_send = state.addresses.contains(&to);
                                                        if is_self_send {
                                                            let recv_record = crate::masternode_client::TransactionRecord {
                                                                txid: txid.clone(),
                                                                vout: 0,
                                                                is_send: false,
                                                                address: to.clone(),
                                                                amount,
                                                                fee: 0,
                                                                timestamp: now,
                                                                status: crate::masternode_client::TransactionStatus::Pending,
                                                                ..Default::default()
                                                            };
                                                            let _ = state.svc_tx.send(ServiceEvent::TransactionInserted(recv_record));
                                                        }
                                                        if !state.addresses.is_empty() {
                                                            if let Ok(balance) = client.get_balances(&state.addresses).await {
                                                                let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(balance));
                                                            }
                                                            // Refresh UTXOs so per-address balances reflect the spend immediately.
                                                            let mut refreshed_utxos = Vec::new();
                                                            for addr in &state.addresses {
                                                                if let Ok(utxos) = client.get_utxos(addr).await {
                                                                    refreshed_utxos.extend(utxos);
                                                                }
                                                            }
                                                            if !refreshed_utxos.is_empty() {
                                                                let _ = state.svc_tx.send(ServiceEvent::UtxosUpdated(refreshed_utxos));
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        let _ = state.svc_tx.send(ServiceEvent::Error(
                                                            format!("Broadcast failed: {}", e),
                                                        ));
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let _ = state.svc_tx.send(ServiceEvent::Error(
                                                    format!("Failed to serialize transaction: {}", e),
                                                ));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        if e.contains("too large") || e.contains("TxTooLarge") {
                                            let _ = state.svc_tx.send(ServiceEvent::SendTooLarge);
                                        } else {
                                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                                format!("Failed to create transaction: {}", e),
                                            ));
                                        }
                                    }
                                }
                            } else {
                                let _ = state.svc_tx.send(ServiceEvent::Error("No wallet loaded".to_string()));
                            }
                        } else {
                            let _ = state.svc_tx.send(ServiceEvent::Error("Not connected to any peer".to_string()));
                        }
                    }

                    UiEvent::NavigatedTo(screen) => {
                        if let Some(ref client) = state.client {
                            if !state.addresses.is_empty() {
                                match screen {
                                    Screen::Overview => {
                                        if let Ok(bal) = client.get_balances(&state.addresses).await {
                                            let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                        }
                                    }
                                    Screen::Transactions => {
                                        if let Ok(batch) = client.get_transactions_multi(&state.addresses, 0, 0).await {
                                            let mut txs = batch.transactions;
                                            decrypt_memos(&mut txs, &state.signing_keys);
                                            let _ = state.svc_tx.send(ServiceEvent::TransactionsUpdated(txs));
                                        }
                                    }
                                    Screen::Utxos => {
                                        let mut all = Vec::new();
                                        for addr in &state.addresses {
                                            if let Ok(utxos) = client.get_utxos(addr).await {
                                                all.extend(utxos);
                                            }
                                        }
                                        state.send_utxos_updated(all);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    UiEvent::CheckHealth => {
                        if let Some(ref client) = state.client {
                            match client.health_check().await {
                                Ok(health) => { let _ = state.svc_tx.send(ServiceEvent::HealthUpdated(health)); }
                                Err(e) => { let _ = state.svc_tx.send(ServiceEvent::Error(e.to_string())); }
                            }
                        }
                    }

                    UiEvent::SwitchNetwork { network: _ } => {
                        let _ = state.svc_tx.send(ServiceEvent::Error(
                            "Network switch requires restart".to_string(),
                        ));
                    }

                    UiEvent::SelectNetwork { network } => {
                        let selected_testnet = network == "testnet";
                        state.config.network = network;
                        state.network_type = if selected_testnet {
                            NetworkType::Testnet
                        } else {
                            NetworkType::Mainnet
                        };
                        // Clear any manually-pinned peer from the old network so discovery
                        // starts fresh on the new network.
                        state.manual_peer = false;
                        state.config.preferred_endpoint = None;
                        config.preferred_endpoint = None;
                        // Save config now that user has chosen
                        if let Err(e) = state.config.save() {
                            log::error!("Failed to save config: {}", e);
                        }
                        // Reopen wallet_db at the correct path
                        let db_path = state.config.wallet_dir().join("wallet_db");
                        if let Some(parent) = db_path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        state.wallet_db = WalletDb::open(&db_path).ok();
                        if state.wallet_db.is_some() {
                            log::info!("📂 Wallet database reopened at: {}", db_path.display());
                        }
                        // Always update UI network state first (clears stale data, sets badge)
                        let _ = state.svc_tx.send(ServiceEvent::NetworkConfigured { is_testnet: selected_testnet });

                        // Invalidate any in-flight poll tasks from the old network
                        poll_generation.fetch_add(1, Ordering::Relaxed);
                        initial_sync_done.store(false, Ordering::Relaxed);
                        // Force a full transaction rescan on the new network.
                        state.last_synced_height.store(0, Ordering::Relaxed);

                        // Check if a wallet already exists for this network
                        let exists = WalletManager::exists(state.network_type);
                        let _ = state.svc_tx.send(ServiceEvent::WalletExists(exists));
                        if exists {
                            // Wallet already exists — load it directly
                            state.load_wallet(None);
                        }

                        // Stop the old WebSocket before switching networks (graceful close)
                        for tx in state.ws_conn_shutdown_senders.drain(..) {
                            let _ = tx.send(true);
                        }
                        for h in state.ws_handles.drain(..) {
                            h.abort();
                        }
                        state.ws_connected_count = 0;
                        let _ = state.svc_tx.send(ServiceEvent::WsDisconnected);

                        // Re-trigger peer discovery with the correct network
                        is_testnet = selected_testnet;
                        manual_endpoints = state.config.manual_endpoints();
                        rpc_credentials = state.config.rpc_credentials();
                        state.client = None;
                        state.last_peers.clear();
                        let tx = state.svc_tx.clone();
                        let eps = manual_endpoints.clone();
                        let tn = is_testnet;
                        let creds = rpc_credentials.clone();
                        let max_conn = state.config.max_connections;
                        discovery_handle = Some(tokio::spawn(async move {
                            discover_peers(tn, eps, creds, &tx, max_conn).await
                        }));
                    }

                    UiEvent::UpdateAddressLabel { index, label } => {
                        if let Some(addr) = state.addresses.get(index) {
                            if let Some(ref db) = state.wallet_db {
                                let now = chrono::Utc::now().timestamp();
                                let mut contact = db
                                    .get_contact(addr)
                                    .ok()
                                    .flatten()
                                    .unwrap_or_else(|| AddressContact {
                                        address: addr.clone(),
                                        label: String::new(),
                                        name: None,
                                        email: None,
                                        phone: None,
                                        notes: None,
                                        is_default: index == 0,
                                        is_owned: true,
                                        derivation_index: Some(index as u32),
                                        created_at: now,
                                        updated_at: now,
                                    });
                                contact.label = label;
                                contact.updated_at = now;
                                if let Err(e) = db.save_contact(&contact) {
                                    log::warn!("Failed to save address label: {}", e);
                                }
                            }
                        }
                    }

                    UiEvent::RefreshAddresses => {
                        if let Some(ref wm) = state.wallet {
                            let owned_from_db: Vec<crate::wallet_db::AddressContact> = state
                                .wallet_db
                                .as_ref()
                                .and_then(|db| db.get_owned_addresses().ok())
                                .unwrap_or_default();
                            let mut db_indices: Vec<u32> = owned_from_db
                                .iter()
                                .filter_map(|c| c.derivation_index)
                                .collect();
                            db_indices.sort_unstable();
                            db_indices.dedup();

                            let mut mn_updated = false;

                            if let Some(ref client) = state.client {
                                // ── Step 1: gettxout backfill ────────────────────────────────
                                // For each masternode entry missing its collateral amount, call
                                // gettxout(txid, vout) to resolve the amount and the owning
                                // address directly from the blockchain — no address needed.
                                let entries = state
                                    .wallet_db
                                    .as_ref()
                                    .and_then(|db| db.get_masternode_entries().ok())
                                    .unwrap_or_default();
                                for mut entry in entries {
                                    if entry.collateral_amount.is_some()
                                        || entry.collateral_txid.is_empty()
                                    {
                                        continue;
                                    }
                                    match client
                                        .get_tx_out(&entry.collateral_txid, entry.collateral_vout)
                                        .await
                                    {
                                        Ok(Some((sats, utxo_addr))) => {
                                            entry.collateral_amount = Some(sats);
                                            if let Some(ref db) = state.wallet_db {
                                                let _ = db.save_masternode_entry(&entry);
                                            }
                                            log::info!(
                                                "💾 gettxout backfilled {} sats for '{}' (addr: {})",
                                                sats, entry.alias, utxo_addr
                                            );
                                            mn_updated = true;

                                            // If the collateral address is not yet tracked,
                                            // scan HD indices 0..max+50 to find its index.
                                            // Scanning from 0 catches deleted/gap addresses.
                                            let known_indices: std::collections::HashSet<u32> =
                                                db_indices.iter().copied().collect();
                                            if !utxo_addr.is_empty() {
                                                let search_max =
                                                    db_indices.last().copied().unwrap_or(0) + 50;
                                                for probe in 0..=search_max {
                                                    if known_indices.contains(&probe) {
                                                        continue;
                                                    }
                                                    if let Ok(candidate) = wm.derive_address(probe) {
                                                        if candidate == utxo_addr {
                                                            if let Some(ref db) = state.wallet_db {
                                                                let now = chrono::Utc::now().timestamp();
                                                                let label = format!("Address #{}", probe);
                                                                let _ = db.save_contact(
                                                                    &crate::wallet_db::AddressContact {
                                                                        address: candidate.clone(),
                                                                        label,
                                                                        name: None,
                                                                        email: None,
                                                                        phone: None,
                                                                        notes: None,
                                                                        is_default: false,
                                                                        is_owned: true,
                                                                        derivation_index: Some(probe),
                                                                        created_at: now,
                                                                        updated_at: now,
                                                                    },
                                                                );
                                                                log::info!(
                                                                    "🔍 Recovered collateral address at index {} for '{}' via gettxout",
                                                                    probe, entry.alias
                                                                );
                                                            }
                                                            db_indices.push(probe);
                                                            db_indices.sort_unstable();
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Ok(None) => {
                                            log::warn!(
                                                "gettxout returned null for '{}' ({}:{})",
                                                entry.alias,
                                                entry.collateral_txid,
                                                entry.collateral_vout
                                            );
                                        }
                                        Err(e) => {
                                            log::warn!("gettxout failed for '{}': {}", entry.alias, e);
                                        }
                                    }
                                }

                                // ── Step 2: scan-ahead ───────────────────────────────────────
                                // Probe the next 20 HD indices beyond the highest now known to
                                // discover any other funded addresses not tied to masternodes.
                                let scan_ahead = 20u32;
                                let max_known = db_indices.last().copied().unwrap_or(0);
                                let known_set: std::collections::HashSet<u32> =
                                    db_indices.iter().copied().collect();
                                for probe_idx in (max_known + 1)..=(max_known + scan_ahead) {
                                    if known_set.contains(&probe_idx) {
                                        continue;
                                    }
                                    if let Ok(probe_addr) = wm.derive_address(probe_idx) {
                                        match client.get_utxos(&probe_addr).await {
                                            Ok(utxos) if !utxos.is_empty() => {
                                                if let Some(ref db) = state.wallet_db {
                                                    let now = chrono::Utc::now().timestamp();
                                                    let label = format!("Address #{}", probe_idx);
                                                    let _ = db.save_contact(
                                                        &crate::wallet_db::AddressContact {
                                                            address: probe_addr.clone(),
                                                            label,
                                                            name: None,
                                                            email: None,
                                                            phone: None,
                                                            notes: None,
                                                            is_default: false,
                                                            is_owned: true,
                                                            derivation_index: Some(probe_idx),
                                                            created_at: now,
                                                            updated_at: now,
                                                        },
                                                    );
                                                    log::info!(
                                                        "🔍 scan-ahead discovered address at index {} ({} UTXOs)",
                                                        probe_idx,
                                                        utxos.len()
                                                    );
                                                }
                                                db_indices.push(probe_idx);
                                                db_indices.sort_unstable();
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }

                            // ── Step 3: build final address list ────────────────────────────
                            // Re-read DB so labels from both steps are included.
                            let owned_from_db: Vec<crate::wallet_db::AddressContact> = state
                                .wallet_db
                                .as_ref()
                                .and_then(|db| db.get_owned_addresses().ok())
                                .unwrap_or_default();
                            let contact_map: std::collections::HashMap<
                                String,
                                &crate::wallet_db::AddressContact,
                            > = owned_from_db.iter().map(|c| (c.address.clone(), c)).collect();

                            let raw_addrs: Vec<String> = db_indices
                                .iter()
                                .filter_map(|&i| wm.derive_address(i).ok())
                                .collect();
                            let address_infos: Vec<AddressInfo> = raw_addrs
                                .iter()
                                .enumerate()
                                .map(|(i, addr)| {
                                    let label = contact_map
                                        .get(addr)
                                        .map(|c| c.label.clone())
                                        .unwrap_or_else(|| format!("Address #{}", i));
                                    AddressInfo { address: addr.clone(), label }
                                })
                                .collect();
                            state.addresses = raw_addrs;

                            // Send updated masternode entries if any amounts were backfilled.
                            if mn_updated {
                                if let Some(ref db) = state.wallet_db {
                                    if let Ok(mut updated_entries) = db.get_masternode_entries() {
                                        updated_entries.sort_by(|a, b| a.alias.cmp(&b.alias));
                                        let _ = state.svc_tx.send(
                                            ServiceEvent::MasternodeEntriesLoaded(updated_entries),
                                        );
                                    }
                                }
                            }
                            let _ = state
                                .svc_tx
                                .send(ServiceEvent::AddressesRefreshed(address_infos));
                        }
                    }

                    UiEvent::RebuildAddresses => {
                        if let Some(ref mut wm) = state.wallet {
                            // Preserve existing labels so they survive the rebuild.
                            let existing_labels: std::collections::HashMap<String, String> = state
                                .wallet_db
                                .as_ref()
                                .and_then(|db| db.get_owned_addresses().ok())
                                .unwrap_or_default()
                                .into_iter()
                                .filter_map(|c| {
                                    c.derivation_index.map(|_| (c.address.clone(), c.label))
                                })
                                .collect();

                            // NOTE: Do NOT delete owned addresses here.
                            // Deleting before the scan completes causes addresses to
                            // disappear if the node is slow or the scan is interrupted.
                            // Instead, we overwrite found addresses below and prune
                            // stale ones after the scan finishes.

                            // Scan HD indices from 0 upward.  Stop after GAP_LIMIT consecutive
                            // indices with no on-chain activity (standard BIP44 gap limit).
                            // Index 0 is always included even if empty (primary address).
                            const GAP_LIMIT: u32 = 10;
                            let mut found_indices: Vec<u32> = Vec::new();
                            let mut consecutive_empty = 0u32;
                            let mut idx = 0u32;

                            // Also collect collateral addresses from masternode entries (via
                            // gettxout) so those addresses are always included even if they
                            // have no remaining spendable UTXOs.
                            let collateral_addrs: std::collections::HashSet<String> =
                                if let (Some(client), Some(db)) = (&state.client, &state.wallet_db) {
                                    let mut set = std::collections::HashSet::new();
                                    if let Ok(entries) = db.get_masternode_entries() {
                                        for entry in entries {
                                            if entry.collateral_txid.is_empty() {
                                                continue;
                                            }
                                            if let Ok(Some((_sats, addr))) = client
                                                .get_tx_out(
                                                    &entry.collateral_txid,
                                                    entry.collateral_vout,
                                                )
                                                .await
                                            {
                                                if !addr.is_empty() {
                                                    set.insert(addr);
                                                }
                                            }
                                        }
                                    }
                                    set
                                } else {
                                    std::collections::HashSet::new()
                                };

                            while let Ok(addr) = wm.derive_address(idx) {
                                // Index 0 and collateral addresses are always included.
                                // For all others, check on-chain activity.
                                let has_activity = idx == 0
                                    || collateral_addrs.contains(&addr)
                                    || if let Some(ref client) = state.client {
                                        matches!(
                                            client.get_utxos(&addr).await,
                                            Ok(ref u) if !u.is_empty()
                                        )
                                    } else {
                                        false
                                    };

                                if has_activity {
                                    found_indices.push(idx);
                                    consecutive_empty = 0;
                                } else {
                                    consecutive_empty += 1;
                                    if consecutive_empty >= GAP_LIMIT {
                                        break;
                                    }
                                }
                                idx += 1;
                            }

                            // Advance the wallet counter past the highest found index.
                            if let Some(&max_idx) = found_indices.last() {
                                wm.sync_address_index(max_idx);
                            }

                            // Re-save contacts for all found indices, restoring labels.
                            let now = chrono::Utc::now().timestamp();
                            let raw_addrs: Vec<String> = found_indices
                                .iter()
                                .filter_map(|&i| wm.derive_address(i).ok())
                                .collect();

                            let address_infos: Vec<AddressInfo> = raw_addrs
                                .iter()
                                .zip(found_indices.iter())
                                .map(|(addr, &i)| {
                                    let label = existing_labels
                                        .get(addr)
                                        .cloned()
                                        .unwrap_or_else(|| format!("Address #{}", i));
                                    if let Some(ref db) = state.wallet_db {
                                        let _ = db.save_contact(&crate::wallet_db::AddressContact {
                                            address: addr.clone(),
                                            label: label.clone(),
                                            name: None,
                                            email: None,
                                            phone: None,
                                            notes: None,
                                            is_default: i == 0,
                                            is_owned: true,
                                            derivation_index: Some(i),
                                            created_at: now,
                                            updated_at: now,
                                        });
                                    }
                                    AddressInfo { address: addr.clone(), label }
                                })
                                .collect();

                            // Prune derived addresses that are no longer in the found set.
                            // Done AFTER the scan so the list is never temporarily empty.
                            if let Some(ref db) = state.wallet_db {
                                if let Ok(owned) = db.get_owned_addresses() {
                                    let found_set: std::collections::HashSet<String> =
                                        raw_addrs.iter().cloned().collect();
                                    for contact in owned {
                                        // Only remove contacts that were HD-derived (have a
                                        // derivation_index) and are no longer in the found set.
                                        // Manually-added owned addresses (no index) are kept.
                                        if contact.derivation_index.is_some()
                                            && !found_set.contains(&contact.address)
                                        {
                                            let _ = db.delete_contact(&contact.address);
                                        }
                                    }
                                }
                            }

                            state.addresses = raw_addrs;
                            log::info!(
                                "🔄 Rebuilt address list: {} addresses found (scanned 0..{})",
                                state.addresses.len(),
                                idx
                            );
                            let _ = state
                                .svc_tx
                                .send(ServiceEvent::AddressesRefreshed(address_infos));

                            // Run masternode backfill now that addresses are rebuilt.
                            mn_backfill_via_gettxout(
                                &state.client,
                                &state.wallet_db,
                                &state.svc_tx,
                            )
                            .await;
                        }
                    }

                    UiEvent::GenerateAddress => {
                        if let Some(ref mut wm) = state.wallet {
                            match wm.get_next_address() {
                                Ok(addr) => {
                                    let index = state.addresses.len();
                                    state.addresses.push(addr.clone());
                                    let label = format!("Address #{}", index);
                                    if let Some(ref db) = state.wallet_db {
                                        let now = chrono::Utc::now().timestamp();
                                        let contact = AddressContact {
                                            address: addr.clone(),
                                            label: label.clone(),
                                            name: None,
                                            email: None,
                                            phone: None,
                                            notes: None,
                                            is_default: false,
                                            is_owned: true,
                                            derivation_index: Some(index as u32),
                                            created_at: now,
                                            updated_at: now,
                                        };
                                        let _ = db.save_contact(&contact);
                                    }
                                    let _ = state.svc_tx.send(ServiceEvent::AddressGenerated(
                                        AddressInfo { address: addr, label },
                                    ));
                                    // Re-subscribe WS with updated address list
                                    if state.config.active_endpoint.is_some() {
                                        state.start_ws();
                                    }
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to generate address: {}", e),
                                    ));
                                }
                            }
                        } else {
                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                "No wallet loaded".to_string(),
                            ));
                        }
                    }

                    UiEvent::DeleteAddress { address } => {
                        // Find the index — index 0 (primary address) cannot be deleted.
                        let idx = state.addresses.iter().position(|a| a == &address);
                        match idx {
                            Some(0) => {
                                let _ = state.svc_tx.send(ServiceEvent::Error(
                                    "Cannot delete the primary address.".to_string(),
                                ));
                            }
                            Some(_) => {
                                if let Some(ref db) = state.wallet_db {
                                    if let Err(e) = db.delete_contact(&address) {
                                        log::warn!("Failed to delete address from DB: {}", e);
                                    }
                                }
                                state.addresses.retain(|a| a != &address);
                                let _ = state.svc_tx.send(ServiceEvent::AddressDeleted(address));
                            }
                            None => {}
                        }
                    }

                    UiEvent::SaveContact { name, address } => {
                        if let Some(ref db) = state.wallet_db {
                            let contact = crate::wallet_db::AddressContact {
                                address: address.clone(),
                                label: name.clone(),
                                name: Some(name),
                                email: None,
                                phone: None,
                                notes: None,
                                is_default: false,
                                is_owned: false,
                                derivation_index: None,
                                created_at: chrono::Utc::now().timestamp(),
                                updated_at: chrono::Utc::now().timestamp(),
                            };
                            if let Err(e) = db.save_contact(&contact) {
                                log::warn!("Failed to save contact: {}", e);
                            }
                            // Reload contacts list
                            if let Ok(contacts) = db.get_external_contacts() {
                                let infos: Vec<crate::state::ContactInfo> = contacts
                                    .into_iter()
                                    .map(|c| crate::state::ContactInfo {
                                        name: c.name.unwrap_or(c.label),
                                        address: c.address,
                                    })
                                    .collect();
                                let _ = state.svc_tx.send(ServiceEvent::ContactsUpdated(infos));
                            }
                        }
                    }

                    UiEvent::DeleteContact { address } => {
                        if let Some(ref db) = state.wallet_db {
                            if let Err(e) = db.delete_contact(&address) {
                                log::warn!("Failed to delete contact: {}", e);
                            }
                            if let Ok(contacts) = db.get_external_contacts() {
                                let infos: Vec<crate::state::ContactInfo> = contacts
                                    .into_iter()
                                    .map(|c| crate::state::ContactInfo {
                                        name: c.name.unwrap_or(c.label),
                                        address: c.address,
                                    })
                                    .collect();
                                let _ = state.svc_tx.send(ServiceEvent::ContactsUpdated(infos));
                            }
                        }
                    }

                    UiEvent::UpdateDecimalPlaces(dp) => {
                        if let Some(ref db) = state.wallet_db {
                            if let Err(e) = db.save_setting("decimal_places", &dp.to_string()) {
                                log::warn!("Failed to save decimal_places: {}", e);
                            }
                        }
                        let _ = state.svc_tx.send(ServiceEvent::DecimalPlacesLoaded(dp));
                    }

                    UiEvent::ResyncWallet => {
                        log::info!("🔄 Resync requested — clearing cached data");
                        if let Some(ref db) = state.wallet_db {
                            if let Err(e) = db.clear_all_utxos() {
                                log::warn!("Failed to clear UTXOs: {}", e);
                            }
                            let _ = db.save_cached_transactions(&[]);
                            let _ = db.save_cached_balance(&crate::masternode_client::Balance {
                                confirmed: 0,
                                pending: 0,
                                total: 0,
                                locked: 0,
                            });
                        }

                        // Re-fetch everything from masternode before updating UI
                        if let Some(ref client) = state.client {
                            if !state.addresses.is_empty() {
                                match client.get_transactions_multi(&state.addresses, 0, 0).await {
                                    Ok(batch) => {
                                        let mut txs = batch.transactions;
                                        decrypt_memos(&mut txs, &state.signing_keys);
                                        if let Some(ref db) = state.wallet_db {
                                            let _ = db.save_cached_transactions(&txs);
                                        }
                                        let _ = state
                                            .svc_tx
                                            .send(ServiceEvent::TransactionsUpdated(txs));
                                    }
                                    Err(e) => {
                                        log::error!("Resync fetch failed: {}", e);
                                        let _ = state.svc_tx.send(ServiceEvent::Error(
                                            format!("Resync failed: {}", e),
                                        ));
                                    }
                                }
                                match client.get_balances(&state.addresses).await {
                                    Ok(bal) => {
                                        if let Some(ref db) = state.wallet_db {
                                            let _ = db.save_cached_balance(&bal);
                                        }
                                        let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                    }
                                    Err(e) => log::warn!("Resync balance fetch failed: {}", e),
                                }
                                let mut all_utxos = Vec::new();
                                for addr in &state.addresses {
                                    if let Ok(utxos) = client.get_utxos(addr).await {
                                        all_utxos.extend(utxos);
                                    }
                                }
                                state.send_utxos_updated(all_utxos);
                            }
                        }
                        let _ = state.svc_tx.send(ServiceEvent::ResyncComplete);
                    }

                    UiEvent::RepairDatabase => {
                        log::info!("🔧 Database repair requested");
                        let db_path = state.config.wallet_dir().join("wallet_db");
                        let backup_path = state.config.wallet_dir().join(format!(
                            "wallet_db_backup_{}",
                            chrono::Local::now().format("%Y%m%d_%H%M%S")
                        ));

                        // Drop the current database handle
                        state.wallet_db = None;

                        // Back up the existing database directory
                        let mut backed_up = false;
                        if db_path.exists() {
                            match std::fs::rename(&db_path, &backup_path) {
                                Ok(()) => {
                                    log::info!("📦 Backed up corrupt database to {}", backup_path.display());
                                    backed_up = true;
                                }
                                Err(e) => {
                                    log::error!("Failed to back up database: {}", e);
                                    // Try removing instead
                                    if let Err(e2) = std::fs::remove_dir_all(&db_path) {
                                        log::error!("Failed to remove database: {}", e2);
                                        let _ = state.svc_tx.send(ServiceEvent::Error(
                                            format!("Failed to repair database: backup failed ({}), removal failed ({})", e, e2),
                                        ));
                                        let _ = state.svc_tx.send(ServiceEvent::DatabaseRepaired {
                                            message: "Repair failed — could not move or delete database".to_string(),
                                        });
                                        continue;
                                    }
                                }
                            }
                        }

                        // Reopen a fresh database
                        if let Some(parent) = db_path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        state.wallet_db = WalletDb::open(&db_path).ok();

                        if state.wallet_db.is_none() {
                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                "Failed to create new database after repair".to_string(),
                            ));
                            let _ = state.svc_tx.send(ServiceEvent::DatabaseRepaired {
                                message: "Repair failed — could not create new database".to_string(),
                            });
                            continue;
                        }

                        log::info!("✅ Fresh database created");

                        // Re-persist owned addresses
                        if let Some(ref db) = state.wallet_db {
                            if state.wallet.is_some() {
                                for (i, addr) in state.addresses.iter().enumerate() {
                                    let contact = AddressContact {
                                        address: addr.clone(),
                                        label: format!("Address {}", i + 1),
                                        name: None,
                                        email: None,
                                        phone: None,
                                        notes: None,
                                        is_default: i == 0,
                                        is_owned: true,
                                        derivation_index: Some(i as u32),
                                        created_at: chrono::Utc::now().timestamp(),
                                        updated_at: chrono::Utc::now().timestamp(),
                                    };
                                    let _ = db.save_contact(&contact);
                                }
                            }
                        }

                        // Re-fetch all data from masternodes
                        if let Some(ref client) = state.client {
                            if !state.addresses.is_empty() {
                                match client.get_transactions_multi(&state.addresses, 0, 0).await {
                                    Ok(batch) => {
                                        let mut txs = batch.transactions;
                                        decrypt_memos(&mut txs, &state.signing_keys);
                                        if let Some(ref db) = state.wallet_db {
                                            let _ = db.save_cached_transactions(&txs);
                                        }
                                        let _ = state.svc_tx.send(ServiceEvent::TransactionsUpdated(txs));
                                    }
                                    Err(e) => log::warn!("Repair: failed to fetch transactions: {}", e),
                                }
                                match client.get_balances(&state.addresses).await {
                                    Ok(bal) => {
                                        if let Some(ref db) = state.wallet_db {
                                            let _ = db.save_cached_balance(&bal);
                                        }
                                        let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                    }
                                    Err(e) => log::warn!("Repair: failed to fetch balance: {}", e),
                                }
                                let mut all_utxos = Vec::new();
                                for addr in &state.addresses {
                                    if let Ok(utxos) = client.get_utxos(addr).await {
                                        all_utxos.extend(utxos);
                                    }
                                }
                                state.send_utxos_updated(all_utxos);
                            }
                        }

                        let msg = if backed_up {
                            format!("Database repaired. Backup saved to {}", backup_path.display())
                        } else {
                            "Database repaired. Fresh database created.".to_string()
                        };
                        let _ = state.svc_tx.send(ServiceEvent::DatabaseRepaired { message: msg });
                    }

                    UiEvent::ConsolidateUtxos => {
                        log::info!("🔄 UTXO consolidation requested");
                        if let (Some(ref client), Some(ref wm)) = (&state.client, &state.wallet) {
                            // Pre-extract everything the background task needs so we don't
                            // block the service loop during consolidation.
                            let addr_count = wm.get_address_count();
                            let addr_to_keypair: std::collections::HashMap<String, wallet::Keypair> =
                                (0..addr_count)
                                    .filter_map(|i| {
                                        let addr = wm.derive_address(i).ok()?;
                                        let kp = wm.derive_keypair(i).ok()?;
                                        Some((addr, kp))
                                    })
                                    .collect();
                            let client_clone = client.clone();
                            let svc_tx_clone = state.svc_tx.clone();
                            let addresses = state.addresses.clone();
                            let db_clone = state.wallet_db.clone();
                            // Clear previous consolidation txids and share with background task
                            state.consolidation_txids.lock().unwrap().clear();
                            let txids = Arc::clone(&state.consolidation_txids);
                            state.consolidation_active.store(true, Ordering::Relaxed);
                            let active_flag = Arc::clone(&state.consolidation_active);

                            tokio::spawn(async move {
                                consolidate_utxos_background(
                                    client_clone,
                                    svc_tx_clone,
                                    addresses,
                                    addr_to_keypair,
                                    db_clone,
                                    txids,
                                    active_flag,
                                )
                                .await;
                            });
                        } else {
                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                "Cannot consolidate: no masternode connection or wallet.".to_string(),
                            ));
                        }
                    }

                    UiEvent::FetchBlockRewardBreakdown { height } => {
                        if let Some(ref client) = state.client {
                            let client = client.clone();
                            let svc_tx = state.svc_tx.clone();
                            tokio::spawn(async move {
                                match client.get_block_reward_breakdown(height).await {
                                    Ok(breakdown) => {
                                        let _ = svc_tx.send(
                                            ServiceEvent::BlockRewardBreakdownLoaded(breakdown),
                                        );
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "Failed to fetch block reward breakdown for height {}: {}",
                                            height, e
                                        );
                                    }
                                }
                            });
                        }
                    }

                    UiEvent::CancelConsolidation => {
                        log::info!("🛑 UTXO consolidation cancel requested");
                        state.consolidation_active.store(false, Ordering::Relaxed);
                    }

                    UiEvent::OpenConfigFile { path } => {
                        log::info!("Opening config file: {}", path.display());
                        // Create file with template if it doesn't exist
                        if !path.exists() {
                            if let Some(parent) = path.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            let template = config_file_template(&path);
                            if let Err(e) = std::fs::write(&path, template) {
                                log::error!("Failed to create {}: {}", path.display(), e);
                                let _ = state.svc_tx.send(ServiceEvent::Error(
                                    format!("Failed to create {}: {}", path.display(), e),
                                ));
                                continue;
                            }
                            log::info!("Created {}", path.display());
                        }
                        let editor = state.config.editor.clone();
                        let svc_tx = state.svc_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let result = if let Some(ref ed) = editor {
                                std::process::Command::new(ed).arg(&path).spawn().map(|_| ())
                            } else {
                                open::that(&path)
                            };
                            if let Err(e) = result {
                                log::error!("Failed to open editor: {}", e);
                                let _ = svc_tx.send(ServiceEvent::Error(
                                    format!("Failed to open editor: {}", e),
                                ));
                            }
                        });
                    }

                    UiEvent::EncryptWallet { password } => {
                        if let Some(ref mut wm) = state.wallet {
                            match wm.encrypt_wallet(&password) {
                                Ok(()) => {
                                    log::info!("✅ Wallet encrypted successfully");
                                    let _ = state.svc_tx.send(ServiceEvent::WalletEncrypted);
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to encrypt wallet: {}", e),
                                    ));
                                }
                            }
                        } else {
                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                "No wallet loaded".to_string(),
                            ));
                        }
                    }

                    UiEvent::SetEditor { editor } => {
                        state.config.editor = editor;
                        if let Err(e) = state.config.save() {
                            log::error!("Failed to save config: {}", e);
                        }
                    }

                    UiEvent::SetMaxConnections(n) => {
                        state.config.max_connections = n;
                        if let Err(e) = state.config.save() {
                            log::error!("Failed to save config: {}", e);
                        }
                        let _ = state.svc_tx.send(ServiceEvent::MaxConnectionsUpdated(n));
                    }

                    UiEvent::PersistSendRecords(records) => {
                        if let Some(ref db) = state.wallet_db {
                            for record in &records {
                                let _ = db.save_send_record(record);
                            }
                        }
                    }

                    UiEvent::SwitchPeer { endpoint } => {
                        log::info!("📌 User manually switching to peer: {}", endpoint);

                        // Use cached discovery data when the peer is already known —
                        // avoids opening new TLS connections just for the safety checks.
                        let cached = state.last_peers.iter().find(|p| p.endpoint == endpoint).cloned();

                        // Genesis guard: use cached result; only probe if unknown.
                        {
                            let expected = if state.network_type == NetworkType::Testnet {
                                TESTNET_GENESIS_HASH
                            } else {
                                MAINNET_GENESIS_HASH
                            };
                            let cached_genesis = cached.as_ref().and_then(|p| p.genesis_ok);
                            match cached_genesis {
                                Some(true) => {
                                    // Already verified by discovery — skip the RPC.
                                }
                                Some(false) => {
                                    log::warn!(
                                        "⚠ Refusing switch to {}: cached discovery shows incompatible genesis",
                                        endpoint
                                    );
                                    let _ = state.svc_tx.send(ServiceEvent::Error(format!(
                                        "Peer {} is on a different chain (genesis mismatch). Choose a compatible peer.",
                                        endpoint
                                    )));
                                    continue;
                                }
                                None => {
                                    // Unknown peer (not in discovery list) — probe directly.
                                    let probe = MasternodeClient::new(endpoint.clone(), rpc_credentials.clone());
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(5),
                                        probe.get_genesis_hash(),
                                    )
                                    .await
                                    {
                                        Ok(Ok(hash)) if hash != expected => {
                                            log::warn!(
                                                "⚠ Refusing switch to {}: incompatible genesis {}…",
                                                endpoint,
                                                &hash[..16.min(hash.len())],
                                            );
                                            let _ = state.svc_tx.send(ServiceEvent::Error(format!(
                                                "Peer {} is on a different chain (genesis mismatch). Choose a compatible peer.",
                                                endpoint
                                            )));
                                            continue;
                                        }
                                        Ok(Err(e)) => {
                                            log::warn!("⚠ Cannot check genesis for {}: {}", endpoint, e);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Consensus guard: use cached block height when available.
                        let best_known = state
                            .last_peers
                            .iter()
                            .filter(|p| p.genesis_ok != Some(false))
                            .filter_map(|p| p.block_height)
                            .max()
                            .unwrap_or(0);

                        if best_known > 0 {
                            let cached_height = cached.as_ref().and_then(|p| p.block_height);
                            let peer_height = if let Some(h) = cached_height {
                                // Use the height we already know from discovery.
                                Some(h)
                            } else {
                                // Unknown peer — must probe.
                                let probe = MasternodeClient::new(endpoint.clone(), rpc_credentials.clone());
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    probe.get_block_height(),
                                )
                                .await
                                {
                                    Ok(Ok(h)) => Some(h),
                                    Ok(Err(e)) => {
                                        log::warn!("⚠ Cannot reach peer {} for consensus check: {}", endpoint, e);
                                        let _ = state.svc_tx.send(ServiceEvent::Error(format!(
                                            "Cannot reach peer {}: {}. Choose a different peer.",
                                            endpoint, e
                                        )));
                                        continue;
                                    }
                                    Err(_) => None, // timeout — give benefit of the doubt
                                }
                            };

                            if let Some(height) = peer_height {
                                if best_known.saturating_sub(height) > CONSENSUS_LAG {
                                    let lag = best_known - height;
                                    log::warn!(
                                        "⚠ Refusing switch to {}: height {} is {} blocks behind consensus ({})",
                                        endpoint, height, lag, best_known
                                    );
                                    let _ = state.svc_tx.send(ServiceEvent::Error(format!(
                                        "Peer {} is out of consensus: {} blocks behind (at {}, network is at {}). Choose a different peer.",
                                        endpoint, lag, height, best_known
                                    )));
                                    continue;
                                }
                            }
                        }

                        state.manual_peer = true;
                        state.client = Some(MasternodeClient::new(endpoint.clone(), rpc_credentials.clone()));
                        state.config.active_endpoint = Some(endpoint.clone());
                        state.config.preferred_endpoint = Some(endpoint.clone());
                        config.active_endpoint = Some(endpoint.clone());
                        config.preferred_endpoint = Some(endpoint);
                        // Persist so the choice survives a restart.
                        if let Err(e) = state.config.save() {
                            log::error!("Failed to save config after peer switch: {}", e);
                        }

                        // Mark the newly selected peer as active in the peer list
                        for peer in &mut state.last_peers {
                            peer.is_active = peer.endpoint == state.config.active_endpoint.as_deref().unwrap_or("");
                        }
                        let _ = state.svc_tx.send(ServiceEvent::PeersDiscovered(state.last_peers.clone()));

                        // Restart WS and refresh data if wallet is loaded
                        if !state.addresses.is_empty() {
                            state.start_ws();
                            if let Some(ref client) = state.client {
                                if let Ok(bal) = client.get_balances(&state.addresses).await {
                                    let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                }
                            }
                        }
                    }

                    UiEvent::ClearPreferredPeer => {
                        log::info!("📌 Clearing preferred peer — returning to auto-discovery");
                        state.manual_peer = false;
                        state.config.preferred_endpoint = None;
                        config.preferred_endpoint = None;
                        if let Err(e) = state.config.save() {
                            log::error!("Failed to save config after clearing preferred peer: {}", e);
                        }
                        // Unmark all peers; next discovery cycle will pick the fastest
                        for peer in &mut state.last_peers {
                            peer.is_active = false;
                        }
                        let _ = state.svc_tx.send(ServiceEvent::PeersDiscovered(state.last_peers.clone()));
                    }

                    UiEvent::SendPaymentRequest { from_address, from_address_idx, to_address, amount, label, memo } => {
                        if let Some(ref client) = state.client {
                            if let Some(ref wm) = state.wallet {
                                match wm.derive_keypair(from_address_idx as u32) {
                                    Ok(kp) => {

                                        let secret_bytes = kp.secret_key_bytes();
                                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
                                        let pubkey_bytes = signing_key.verifying_key().to_bytes();
                                        let pubkey_hex = hex::encode(pubkey_bytes);

                                        let timestamp = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs() as i64;

                                        use sha2::{Digest, Sha256};
                                        let mut hasher = Sha256::new();
                                        hasher.update(from_address.as_bytes());
                                        hasher.update(to_address.as_bytes());
                                        hasher.update(amount.to_le_bytes());
                                        hasher.update(timestamp.to_le_bytes());
                                        let id = hex::encode(hasher.finalize());

                                        let mut sign_data = Vec::new();
                                        sign_data.extend_from_slice(id.as_bytes());
                                        sign_data.extend_from_slice(from_address.as_bytes());
                                        sign_data.extend_from_slice(to_address.as_bytes());
                                        sign_data.extend_from_slice(&amount.to_le_bytes());
                                        sign_data.extend_from_slice(memo.as_bytes());
                                        sign_data.extend_from_slice(&timestamp.to_le_bytes());

                                        use ed25519_dalek::Signer;
                                        let signature = signing_key.sign(&sign_data);
                                        let signature_hex = hex::encode(signature.to_bytes());

                                        // Save locally first so it appears in the UI immediately
                                        let sent_req = crate::wallet_db::SentPaymentRequest {
                                            id: id.clone(),
                                            to_address: to_address.clone(),
                                            from_address: from_address.clone(),
                                            amount,
                                            label: label.clone(),
                                            memo: memo.clone(),
                                            status: "pending".to_string(),
                                            created_at: timestamp,
                                            expires: timestamp + 86400, // 24 hours, matching masternode TTL
                                            payment_txid: None,
                                        };
                                        if let Some(ref db) = state.wallet_db {
                                            let _ = db.save_sent_payment_request(&sent_req);
                                        }
                                        let _ = state.svc_tx.send(ServiceEvent::SentPaymentRequestsLoaded(
                                            state.wallet_db.as_ref()
                                                .and_then(|db| db.get_all_sent_payment_requests().ok())
                                                .unwrap_or_default(),
                                        ));

                                        match client.send_payment_request(
                                            &id,
                                            &from_address,
                                            &to_address,
                                            amount,
                                            &label,
                                            &memo,
                                            &pubkey_hex,
                                            &signature_hex,
                                            timestamp,
                                        ).await {
                                            Ok(result) => {
                                                let req_id = result.get("id")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or(&id)
                                                    .to_string();
                                                let _ = state.svc_tx.send(ServiceEvent::PaymentRequestSent { id: req_id });
                                            }
                                            Err(e) => {
                                                let reason = format!("{}", e);
                                                log::error!("sendpaymentrequest failed: {}", reason);
                                                // Mark as failed in DB so the user can see it didn't go through
                                                if let Some(ref db) = state.wallet_db {
                                                    let _ = db.update_sent_payment_request_status(&id, "failed", None);
                                                }
                                                let _ = state.svc_tx.send(ServiceEvent::SentPaymentRequestsLoaded(
                                                    state.wallet_db.as_ref()
                                                        .and_then(|db| db.get_all_sent_payment_requests().ok())
                                                        .unwrap_or_default(),
                                                ));
                                                let _ = state.svc_tx.send(ServiceEvent::PaymentRequestFailed(reason));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = state.svc_tx.send(ServiceEvent::Error(
                                            format!("Failed to derive keypair: {}", e),
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    UiEvent::PayRequest { .. } => {
                        // Acknowledge is deferred until the transaction is actually broadcast.
                        // Nothing to do here.
                    }

                    UiEvent::DeclineRequest { request_id } => {
                        if let Some(ref client) = state.client {
                            let payer_addr = state.addresses.first().map(|s| s.as_str()).unwrap_or("");
                            let _ = client.respond_payment_request(&request_id, payer_addr, false, None).await;
                        }
                        if let Some(ref db) = state.wallet_db {
                            // Save to history before deleting
                            if let Ok(Some(orig)) = db.get_incoming_payment_request(&request_id) {
                                let completed_at = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or(0);
                                let hist = crate::wallet_db::IncomingPaymentHistory {
                                    id: orig.id.clone(),
                                    from_address: orig.from_address.clone(),
                                    amount: orig.amount,
                                    label: orig.label.clone(),
                                    memo: orig.memo.clone(),
                                    status: "declined".to_string(),
                                    payment_txid: None,
                                    created_at: orig.timestamp,
                                    completed_at,
                                };
                                let _ = db.save_incoming_payment_history(&hist);
                            }
                            let _ = db.delete_incoming_payment_request(&request_id);
                            let history = db.get_all_incoming_payment_history().unwrap_or_default();
                            let _ = state.svc_tx.send(ServiceEvent::IncomingPaymentHistoryLoaded(history));
                        }
                    }

                    UiEvent::CancelPaymentRequest { request_id } => {
                        if let Some(ref client) = state.client {
                            let requester_addr = state.addresses.first().map(|s| s.as_str()).unwrap_or("");
                            let _ = client.cancel_payment_request(&request_id, requester_addr).await;
                        }
                        if let Some(ref db) = state.wallet_db {
                            let _ = db.update_sent_payment_request_status(&request_id, "cancelled", None);
                        }
                        let _ = state.svc_tx.send(ServiceEvent::SentPaymentRequestStatusUpdated {
                            id: request_id,
                            status: "cancelled".to_string(),
                            payment_txid: None,
                        });
                    }

                    UiEvent::DeleteSentPaymentRequest { request_id } => {
                        if let Some(ref db) = state.wallet_db {
                            let _ = db.delete_sent_payment_request(&request_id);
                        }
                        let _ = state.svc_tx.send(ServiceEvent::SentPaymentRequestsLoaded(
                            state.wallet_db.as_ref()
                                .and_then(|db| db.get_all_sent_payment_requests().ok())
                                .unwrap_or_default(),
                        ));
                    }

                    UiEvent::DeleteIncomingPaymentHistory { id } => {
                        if let Some(ref db) = state.wallet_db {
                            let _ = db.delete_incoming_payment_history(&id);
                        }
                    }

                    UiEvent::SaveMasternodeEntry(entry) => {
                        if let Some(ref db) = state.wallet_db {
                            match db.save_masternode_entry(&entry) {
                                Ok(()) => {
                                    log::info!("💾 Saved masternode entry '{}'", entry.alias);
                                    if let Ok(entries) = db.get_masternode_entries() {
                                        let _ = state.svc_tx.send(ServiceEvent::MasternodeEntriesLoaded(entries));
                                    }
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to save masternode '{}': {}", entry.alias, e),
                                    ));
                                }
                            }
                        } else {
                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                "Cannot save masternode: wallet database not available".to_string(),
                            ));
                        }
                    }

                    UiEvent::DeleteMasternodeEntry { alias } => {
                        if let Some(ref db) = state.wallet_db {
                            // Unlock the collateral UTXO before removing the entry.
                            if let Ok(entries) = db.get_masternode_entries() {
                                if let Some(entry) = entries.iter().find(|e| e.alias == alias) {
                                    let _ = db.unlock_collateral(&entry.collateral_txid, entry.collateral_vout);
                                }
                            }
                            let _ = db.delete_masternode_entry(&alias);
                            if let Ok(entries) = db.get_masternode_entries() {
                                let _ = state.svc_tx.send(ServiceEvent::MasternodeEntriesLoaded(entries));
                            }
                        }
                    }

                    UiEvent::UpdateMasternodeEntry { old_alias, new_entry } => {
                        if let Some(ref db) = state.wallet_db {
                            // Preserve registration state when editing
                            let (old_reg_txid, old_registered_ip) = db
                                .get_masternode_entries()
                                .ok()
                                .and_then(|es| es.into_iter().find(|e| e.alias == old_alias))
                                .map(|e| (e.reg_txid, e.registered_ip))
                                .unwrap_or((None, None));
                            let mut entry = new_entry.clone();
                            entry.reg_txid = old_reg_txid;
                            entry.registered_ip = old_registered_ip;
                            let _ = db.delete_masternode_entry(&old_alias);
                            match db.save_masternode_entry(&entry) {
                                Ok(()) => {
                                    log::info!("Updated masternode '{}' -> '{}'", old_alias, entry.alias);
                                    if let Ok(entries) = db.get_masternode_entries() {
                                        let _ = state.svc_tx.send(ServiceEvent::MasternodeEntriesLoaded(entries));
                                    }
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to update masternode '{}': {}", old_alias, e),
                                    ));
                                }
                            }
                        }
                    }

                    UiEvent::ImportMasternodeConf { path } => {
                        if let Some(ref db) = state.wallet_db {
                            match std::fs::read_to_string(&path) {
                                Ok(contents) => {
                                    let mut count = 0;
                                    for line in contents.lines() {
                                        if let Some(entry) = crate::wallet_db::MasternodeEntry::parse_conf_line(line) {
                                            let _ = db.save_masternode_entry(&entry);
                                            count += 1;
                                        }
                                    }
                                    log::info!("Imported {} masternode entries from {}", count, path.display());
                                    if let Ok(entries) = db.get_masternode_entries() {
                                        let _ = state.svc_tx.send(ServiceEvent::MasternodeEntriesLoaded(entries));
                                    }
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to read {}: {}", path.display(), e),
                                    ));
                                }
                            }
                        }
                    }

                    UiEvent::RegisterMasternode {
                        alias,
                        ip,
                        port,
                        collateral_txid,
                        collateral_vout,
                        payout_address,
                    } => {
                        if let (Some(ref client), Some(ref mut wm)) =
                            (&state.client, &mut state.wallet)
                        {
                            match build_masternode_reg_tx(
                                wm,
                                client,
                                &state.addresses,
                                &collateral_txid,
                                collateral_vout,
                                &ip,
                                port,
                                &payout_address,
                            )
                            .await
                            {
                                Ok((tx_hex, txid)) => {
                                    match client.broadcast_transaction(&tx_hex).await {
                                        Ok(broadcast_txid) => {
                                            let final_txid = if broadcast_txid.is_empty() {
                                                txid
                                            } else {
                                                broadcast_txid
                                            };
                                            // Lock the collateral UTXO and persist reg_txid/registered_ip
                                            if let Some(ref db) = state.wallet_db {
                                                let _ = db.lock_collateral(
                                                    &collateral_txid,
                                                    collateral_vout,
                                                    &alias,
                                                );
                                                // Update the entry with registration info
                                                if let Ok(mut entries) = db.get_masternode_entries() {
                                                    if let Some(entry) = entries.iter_mut().find(|e| e.alias == alias) {
                                                        entry.reg_txid = Some(final_txid.clone());
                                                        entry.registered_ip = Some(ip.clone());
                                                        let _ = db.save_masternode_entry(entry);
                                                    }
                                                    if let Ok(updated) = db.get_masternode_entries() {
                                                        let _ = state.svc_tx.send(ServiceEvent::MasternodeEntriesLoaded(updated));
                                                    }
                                                }
                                            }
                                            let _ = state.svc_tx.send(
                                                ServiceEvent::MasternodeRegistered {
                                                    alias,
                                                    txid: final_txid,
                                                },
                                            );
                                            // Immediately refresh UTXOs and balance so the
                                            // locked/available amounts reflect the new state
                                            // without waiting for the next poll cycle.
                                            let refresh_addresses = state.addresses.clone();
                                            if !refresh_addresses.is_empty() {
                                                let mut fresh_utxos = Vec::new();
                                                for addr in &refresh_addresses {
                                                    if let Ok(utxos) =
                                                        client.get_utxos(addr).await
                                                    {
                                                        fresh_utxos.extend(utxos);
                                                    }
                                                }
                                                state.send_utxos_updated(fresh_utxos);
                                                if let Ok(bal) =
                                                    client.get_balances(&refresh_addresses).await
                                                {
                                                    let _ = state
                                                        .svc_tx
                                                        .send(ServiceEvent::BalanceUpdated(bal));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                                format!("Failed to broadcast MN registration: {}", e),
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to build MN registration tx: {}", e),
                                    ));
                                }
                            }
                        }
                    }

                    UiEvent::DeregisterMasternode {
                        alias,
                        collateral_txid,
                        collateral_vout,
                        masternode_ip,
                    } => {
                        if let (Some(ref client), Some(ref mut wm)) =
                            (&state.client, &mut state.wallet)
                        {
                            match build_collateral_unlock_tx(
                                wm,
                                &state.addresses,
                                &collateral_txid,
                                collateral_vout,
                                &masternode_ip,
                            )
                            .await
                            {
                                Ok(tx_hex) => {
                                    match client.broadcast_transaction(&tx_hex).await {
                                        Ok(_) => {
                                            // Clear reg_txid and registered_ip from DB entry
                                            if let Some(ref db) = state.wallet_db {
                                                if let Ok(mut entries) = db.get_masternode_entries() {
                                                    if let Some(entry) = entries.iter_mut().find(|e| e.alias == alias) {
                                                        entry.reg_txid = None;
                                                        entry.registered_ip = None;
                                                        let _ = db.save_masternode_entry(entry);
                                                    }
                                                    if let Ok(updated) = db.get_masternode_entries() {
                                                        let _ = state.svc_tx.send(ServiceEvent::MasternodeEntriesLoaded(updated));
                                                    }
                                                }
                                            }
                                            let _ = state.svc_tx.send(
                                                ServiceEvent::MasternodeDeregistered { alias },
                                            );
                                            // Immediately refresh UTXOs and balance so the
                                            // collateral shows as spendable again right away.
                                            let refresh_addresses = state.addresses.clone();
                                            if !refresh_addresses.is_empty() {
                                                let mut fresh_utxos = Vec::new();
                                                for addr in &refresh_addresses {
                                                    if let Ok(utxos) =
                                                        client.get_utxos(addr).await
                                                    {
                                                        fresh_utxos.extend(utxos);
                                                    }
                                                }
                                                state.send_utxos_updated(fresh_utxos);
                                                if let Ok(bal) =
                                                    client.get_balances(&refresh_addresses).await
                                                {
                                                    let _ = state
                                                        .svc_tx
                                                        .send(ServiceEvent::BalanceUpdated(bal));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                                format!("Failed to broadcast deregistration: {}", e),
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to build CollateralUnlock tx: {}", e),
                                    ));
                                }
                            }
                        }
                    }

                    UiEvent::UpdateMasternodePayout {
                        masternode_id,
                        new_payout_address,
                    } => {
                        if let (Some(ref client), Some(ref mut wm)) =
                            (&state.client, &mut state.wallet)
                        {
                            match build_masternode_update_tx(
                                wm,
                                client,
                                &state.addresses,
                                &masternode_id,
                                &new_payout_address,
                            )
                            .await
                            {
                                Ok((tx_hex, txid)) => {
                                    match client.broadcast_transaction(&tx_hex).await {
                                        Ok(broadcast_txid) => {
                                            let final_txid = if broadcast_txid.is_empty() {
                                                txid
                                            } else {
                                                broadcast_txid
                                            };
                                            let _ = state.svc_tx.send(
                                                ServiceEvent::MasternodePayoutUpdated {
                                                    masternode_id,
                                                    txid: final_txid,
                                                },
                                            );
                                        }
                                        Err(e) => {
                                            let _ = state.svc_tx.send(ServiceEvent::Error(
                                                format!(
                                                    "Failed to broadcast payout update: {}",
                                                    e
                                                ),
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = state.svc_tx.send(ServiceEvent::Error(
                                        format!("Failed to build payout update tx: {}", e),
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            Some(ws_event) = ws_event_rx.recv() => {
                match ws_event {
                    WsEvent::TransactionReceived(notification) => {
                        if ws_dedup(&mut state.ws_seen, format!("tx:{}", notification.txid)) {
                            log::debug!("Dedup: skipping duplicate tx:{}", notification.txid);
                        } else {
                        let amount_sats = crate::masternode_client::json_to_satoshis(&notification.amount);

                        // Determine if this is a change output vs a real receive
                        let send_record = state.wallet_db.as_ref()
                            .and_then(|db| db.get_send_records().ok())
                            .and_then(|recs| recs.get(&notification.txid).cloned());
                        let is_own_addr = state.addresses.contains(&notification.address);
                        let is_consolidation = state.consolidation_txids
                            .lock()
                            .unwrap()
                            .contains(&notification.txid);
                        let is_change = if is_consolidation {
                            true // consolidation output — always change
                        } else if let Some(ref sr) = send_record {
                            // It's from a txid we sent — change unless it's send-to-self receive
                            let is_self_send = state.addresses.contains(&sr.address);
                            if is_self_send && is_own_addr && amount_sats == sr.amount {
                                false // actual send-to-self receive, keep it
                            } else {
                                is_own_addr // other receives to own addr are change
                            }
                        } else {
                            false // not a txid we sent, it's a real receive
                        };

                        if !is_change {
                            let tx_record = TransactionRecord {
                                txid: notification.txid.clone(),
                                vout: 0,
                                is_send: false,
                                address: notification.address.clone(),
                                amount: amount_sats,
                                fee: 0,
                                timestamp: notification.timestamp,
                                status: TransactionStatus::Pending,
                                ..Default::default()
                            };
                            let _ = state.svc_tx.send(ServiceEvent::TransactionInserted(tx_record));
                            let _ = state.svc_tx.send(ServiceEvent::TransactionReceived(notification.clone()));
                        }

                        // Refresh balance and transactions immediately.
                        // Skip during consolidation — intermediate RPC results are
                        // unreliable; the consolidation task does a final refresh.
                        if !state.consolidation_active.load(Ordering::Relaxed) {
                            if let Some(ref client) = state.client {
                                if !state.addresses.is_empty() {
                                    match client.get_balances(&state.addresses).await {
                                        Ok(bal) => { let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal)); }
                                        Err(e) => log::warn!("Failed to refresh balance after receive: {}", e),
                                    }
                                    // Refresh transactions so instant-finality status is reflected immediately
                                    if let Ok(batch) = client.get_transactions_multi(&state.addresses, 0, 0).await {
                                        let mut txs = batch.transactions;
                                        decrypt_memos(&mut txs, &state.signing_keys);
                                        let _ = state.svc_tx.send(ServiceEvent::TransactionsUpdated(txs));
                                    }
                                }
                            }
                        }
                        } // end dedup else
                    }
                    WsEvent::UtxoFinalized(notif) => {
                        if ws_dedup(&mut state.ws_seen, format!("fin:{}:{}", notif.txid, notif.output_index)) {
                            log::debug!("Dedup: skipping duplicate fin:{}:{}", notif.txid, notif.output_index);
                        } else {
                        // UTXO finalized by masternode consensus — mark tx as Approved
                        let amount_sats = crate::masternode_client::json_to_satoshis(&notif.amount);
                        log::info!("✅ UTXO finalized: txid={}... vout={} amount={}", &notif.txid[..16.min(notif.txid.len())], notif.output_index, amount_sats);

                        // Determine if this is a change output
                        let send_record = state.wallet_db.as_ref()
                            .and_then(|db| db.get_send_records().ok())
                            .and_then(|recs| recs.get(&notif.txid).cloned());
                        let is_own_addr = state.addresses.contains(&notif.address);
                        let is_consolidation = state.consolidation_txids
                            .lock()
                            .unwrap()
                            .contains(&notif.txid);
                        let is_change = if is_consolidation {
                            true // consolidation output — always change
                        } else if let Some(ref sr) = send_record {
                            let is_self_send = state.addresses.contains(&sr.address);
                            if is_self_send && is_own_addr && amount_sats == sr.amount {
                                false // send-to-self receive
                            } else {
                                is_own_addr
                            }
                        } else {
                            false
                        };

                        if !is_change {
                            let tx_record = TransactionRecord {
                                txid: notif.txid.clone(),
                                vout: notif.output_index,
                                is_send: false,
                                address: notif.address.clone(),
                                amount: amount_sats,
                                fee: 0,
                                timestamp: chrono::Utc::now().timestamp(),
                                status: TransactionStatus::Approved,
                                ..Default::default()
                            };
                            let _ = state.svc_tx.send(ServiceEvent::TransactionInserted(tx_record));
                        }

                        let _ = state.svc_tx.send(ServiceEvent::TransactionFinalityUpdated {
                            txid: notif.txid,
                            finalized: true,
                        });

                        // Refresh balance, transactions, and UTXOs after finalization.
                        // Skip during consolidation — intermediate RPC results are
                        // unreliable; the consolidation task does a final refresh.
                        if !state.consolidation_active.load(Ordering::Relaxed) {
                            if let Some(ref client) = state.client {
                                if !state.addresses.is_empty() {
                                    match client.get_balances(&state.addresses).await {
                                        Ok(bal) => {
                                            log::info!("🔍 Post-finalization balance: total={} available={}", bal.total, bal.confirmed);
                                            let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                        }
                                        Err(e) => log::warn!("Failed to refresh balance after finalization: {}", e),
                                    }
                                    if let Ok(batch) = client.get_transactions_multi(&state.addresses, 0, 0).await {
                                        let mut txs = batch.transactions;
                                        decrypt_memos(&mut txs, &state.signing_keys);
                                        let _ = state.svc_tx.send(ServiceEvent::TransactionsUpdated(txs));
                                    }
                                    let mut all_utxos = Vec::new();
                                    for addr in &state.addresses {
                                        if let Ok(utxos) = client.get_utxos(addr).await {
                                            all_utxos.extend(utxos);
                                        }
                                    }
                                    let utxo_sum: u64 = all_utxos.iter().map(|u| u.amount).sum();
                                    log::info!("🔍 Post-finalization UTXOs: count={} total={}", all_utxos.len(), utxo_sum);
                                    state.send_utxos_updated(all_utxos);
                                }
                            }
                        }
                        } // end dedup else
                    }
                    WsEvent::Connected(url) => {
                        state.ws_connected_count = state.ws_connected_count.saturating_add(1);
                        state.ws_active_urls.insert(url.clone());
                        let active: Vec<String> = state.ws_active_urls.iter().cloned().collect();
                        let _ = state.svc_tx.send(ServiceEvent::WsActiveUrlsChanged(active));
                        log::info!("✅ WS connected: {} (total active: {})", url, state.ws_connected_count);
                        if state.ws_connected_count == 1 {
                            let _ = state.svc_tx.send(ServiceEvent::WsConnected);
                            // Poll for pending payment requests only on first connection
                            if let Some(ref client) = state.client {
                                if !state.addresses.is_empty() {
                                    match client.get_payment_requests(&state.addresses).await {
                                        Ok(raw_requests) => {
                                            let requests: Vec<_> = raw_requests
                                                .iter()
                                                .filter_map(parse_payment_request_json)
                                                .collect();
                                            log::info!("📬 Polled {} pending payment requests", requests.len());
                                            if let Some(ref db) = state.wallet_db {
                                                for req in &requests {
                                                    let _ = db.save_incoming_payment_request(req);
                                                }
                                            }
                                            let _ = state.svc_tx.send(ServiceEvent::PaymentRequestsUpdated(requests));
                                        }
                                        Err(e) => {
                                            log::warn!("Failed to poll payment requests: {}", e);
                                        }
                                    }
                                }
                            }

                            // On fresh DB start, scan for previously-used derived addresses
                            // so the balance is correct after the first sync.
                            if state.pending_address_scan {
                                state.pending_address_scan = false;
                                if let Some(ref client) = state.client {
                                    const GAP_LIMIT: usize = 20;
                                    const MAX_SCAN: u32 = 200;

                                    // Pre-derive candidates (sync, CPU-only, fast).
                                    let start_idx = state.addresses.len() as u32; // typically 1
                                    let candidates: Vec<(u32, String)> = state
                                        .wallet
                                        .as_ref()
                                        .map(|wm| {
                                            (start_idx..start_idx + MAX_SCAN)
                                                .filter_map(|i| {
                                                    wm.derive_address(i).ok().map(|a| (i, a))
                                                })
                                                .collect()
                                        })
                                        .unwrap_or_default();

                                    log::info!(
                                        "🔍 Scanning {} candidate addresses for recovery (gap limit {})",
                                        candidates.len(),
                                        GAP_LIMIT
                                    );

                                    let mut recovered: Vec<(u32, String)> = Vec::new();
                                    let mut consecutive_empty: usize = 0;

                                    'scan: for chunk in candidates.chunks(GAP_LIMIT) {
                                        let chunk_addrs: Vec<String> =
                                            chunk.iter().map(|(_, a)| a.clone()).collect();

                                        // Primary check: addresses with current UTXOs.
                                        let active_by_utxo = match client
                                            .get_active_addresses_by_utxo(&chunk_addrs)
                                            .await
                                        {
                                            Ok(set) => set,
                                            Err(e) => {
                                                log::warn!("Address scan UTXO check failed: {}", e);
                                                break 'scan;
                                            }
                                        };

                                        // Secondary check: addresses that spent all coins
                                        // (history exists but no UTXOs remaining).
                                        let need_tx_check: Vec<String> = chunk_addrs
                                            .iter()
                                            .filter(|a| !active_by_utxo.contains(*a))
                                            .cloned()
                                            .collect();
                                        let active_by_tx: std::collections::HashSet<String> =
                                            if !need_tx_check.is_empty() {
                                                match client
                                                    .get_transactions_multi(&need_tx_check, 1, 0)
                                                    .await
                                                {
                                                    Ok(batch) => batch
                                                        .transactions
                                                        .iter()
                                                        .filter(|tx| !tx.is_send)
                                                        .map(|tx| tx.address.clone())
                                                        .collect(),
                                                    Err(_) => {
                                                        std::collections::HashSet::new()
                                                    }
                                                }
                                            } else {
                                                std::collections::HashSet::new()
                                            };

                                        for (idx, addr) in chunk {
                                            if active_by_utxo.contains(addr)
                                                || active_by_tx.contains(addr)
                                            {
                                                recovered.push((*idx, addr.clone()));
                                                consecutive_empty = 0;
                                            } else {
                                                consecutive_empty += 1;
                                                if consecutive_empty >= GAP_LIMIT {
                                                    break 'scan;
                                                }
                                            }
                                        }
                                    }

                                    if !recovered.is_empty() {
                                        log::info!(
                                            "✅ Address recovery: found {} addresses",
                                            recovered.len()
                                        );
                                        let max_idx = recovered
                                            .iter()
                                            .map(|(i, _)| *i)
                                            .max()
                                            .unwrap_or(0);

                                        for (idx, addr) in &recovered {
                                            // Persist to DB.
                                            if let Some(ref db) = state.wallet_db {
                                                let now = chrono::Utc::now().timestamp();
                                                let _ = db.save_contact(&crate::wallet_db::AddressContact {
                                                    address: addr.clone(),
                                                    label: format!("Address #{}", idx),
                                                    name: None,
                                                    email: None,
                                                    phone: None,
                                                    notes: None,
                                                    is_default: false,
                                                    is_owned: true,
                                                    derivation_index: Some(*idx),
                                                    created_at: now,
                                                    updated_at: now,
                                                });
                                            }
                                            // Update service address list.
                                            state.addresses.push(addr.clone());
                                            // Notify UI.
                                            let _ = state.svc_tx.send(
                                                ServiceEvent::AddressGenerated(AddressInfo {
                                                    address: addr.clone(),
                                                    label: format!("Address #{}", idx),
                                                }),
                                            );
                                        }

                                        // Advance wallet counter past the highest recovered index.
                                        if let Some(ref mut wm) = state.wallet {
                                            wm.sync_address_index(max_idx);
                                        }

                                        // Re-subscribe WS with the expanded address list.
                                        if state.config.active_endpoint.is_some() {
                                            state.start_ws();
                                        }

                                        let count = recovered.len();
                                        let _ = state.svc_tx.send(
                                            ServiceEvent::AddressesDiscovered { count },
                                        );
                                    } else {
                                        log::info!("ℹ️ Address recovery: no additional addresses found");
                                    }
                                }
                            }
                        }
                    }
                    WsEvent::Disconnected(url) => {
                        state.ws_connected_count = state.ws_connected_count.saturating_sub(1);
                        state.ws_active_urls.remove(&url);
                        let active: Vec<String> = state.ws_active_urls.iter().cloned().collect();
                        let _ = state.svc_tx.send(ServiceEvent::WsActiveUrlsChanged(active));
                        log::info!("🔌 WS disconnected: {} (remaining active: {})", url, state.ws_connected_count);
                        if state.ws_connected_count == 0 {
                            let _ = state.svc_tx.send(ServiceEvent::WsDisconnected);
                        }
                    }
                    WsEvent::CapacityFull(url) => {
                        log::warn!("⚠️ Masternode at capacity: {}. Attempting failover…", url);
                        // CapacityFull means the WsClient task exited without sending Disconnected
                        state.ws_connected_count = state.ws_connected_count.saturating_sub(1);
                        let _ = state.svc_tx.send(ServiceEvent::WsCapacityFull(url.clone()));

                        if state.ws_connected_count == 0 {
                            // All connections gone — failover RPC client + restart WS on a different peer
                            let current_endpoint = state.config.active_endpoint.clone();
                            let failover_best_height = state
                                .last_peers
                                .iter()
                                .filter_map(|p| p.block_height)
                                .max()
                                .unwrap_or(0);
                            let next = state.last_peers.iter().find(|p| {
                                p.is_healthy
                                    && Some(&p.endpoint) != current_endpoint.as_ref()
                                    && failover_best_height.saturating_sub(p.block_height.unwrap_or(0)) <= CONSENSUS_LAG
                            }).cloned();
                            if let Some(peer) = next {
                                log::info!("🔀 Failing over to {}", peer.endpoint);
                                state.client = Some(MasternodeClient::new(peer.endpoint.clone(), rpc_credentials.clone()));
                                state.config.active_endpoint = Some(peer.endpoint.clone());
                                config.active_endpoint = Some(peer.endpoint);
                                if !state.addresses.is_empty() {
                                    state.start_ws();
                                }
                            } else {
                                log::warn!("⚠️ No healthy fallback peer available for WS failover");
                            }
                        }
                    }
                    WsEvent::TransactionRejected(notif) => {
                        if !ws_dedup(&mut state.ws_seen, format!("rej:{}", notif.txid)) {
                            log::warn!("❌ Transaction {} rejected: {}", &notif.txid[..16.min(notif.txid.len())], notif.reason);
                            let _ = state.svc_tx.send(ServiceEvent::TransactionFinalityUpdated {
                                txid: notif.txid,
                                finalized: false,
                            });
                        } else {
                            log::debug!("Dedup: skipping duplicate rej:{}", notif.txid);
                        }
                    }

                    WsEvent::PaymentRequestResponse(notif) => {
                        if !ws_dedup(&mut state.ws_seen, format!("pr_resp:{}", notif.request_id)) {
                            let new_status = if notif.accepted { "paid" } else { "declined" }.to_string();
                            log::info!(
                                "📬 Payment request {} {} by {} txid={:?}",
                                notif.request_id,
                                new_status,
                                notif.payer_address,
                                notif.txid,
                            );
                            if let Some(ref db) = state.wallet_db {
                                let _ = db.update_sent_payment_request_status(
                                    &notif.request_id,
                                    &new_status,
                                    notif.txid.as_deref(),
                                );
                            }
                            let _ = state.svc_tx.send(ServiceEvent::SentPaymentRequestStatusUpdated {
                                id: notif.request_id,
                                status: new_status,
                                payment_txid: notif.txid,
                            });
                        }
                    }

                    WsEvent::PaymentRequestReceived(notif) => {
                        if !ws_dedup(&mut state.ws_seen, format!("pr:{}", notif.id)) {
                            log::info!("💰 Payment request received from {}", notif.from_address);
                            let pr = PaymentRequest {
                                id: notif.id,
                                from_address: notif.from_address,
                                to_address: notif.to_address,
                                amount: (notif.amount * 100_000.0) as u64,
                                label: notif.label,
                                memo: notif.memo,
                                pubkey_hex: notif.pubkey,
                                signature_hex: String::new(),
                                timestamp: notif.timestamp,
                                expires: notif.expires,
                            };
                            if let Some(ref db) = state.wallet_db {
                                let _ = db.save_incoming_payment_request(&pr);
                            }
                            let _ = state.svc_tx.send(ServiceEvent::PaymentRequestReceived(pr));
                        } else {
                            log::debug!("Dedup: skipping duplicate pr:{}", notif.id);
                        }
                    }
                }
            }
        }
    }

    log::info!("👋 Service loop exited");
}

/// Returns true if this event is a duplicate (already seen within the dedup window).
fn ws_dedup(seen: &mut std::collections::HashMap<String, std::time::Instant>, key: String) -> bool {
    let now = std::time::Instant::now();
    // Purge stale entries (older than 60s) to prevent unbounded growth
    seen.retain(|_, t| now.duration_since(*t).as_secs() < 60);
    if seen.contains_key(&key) {
        return true; // duplicate
    }
    seen.insert(key, now);
    false
}

/// Discover and health-check peers in the background.
/// Returns the best endpoint and the full peer info list.
async fn discover_peers(
    is_testnet: bool,
    manual_endpoints: Vec<String>,
    rpc_credentials: Option<(String, String)>,
    svc_tx: &mpsc::UnboundedSender<ServiceEvent>,
    max_connections: usize,
) -> Result<(String, Vec<PeerInfo>), ()> {
    let rpc_port = if is_testnet { 24101 } else { 24001 };
    let mut endpoints = manual_endpoints;
    match peer_discovery::fetch_peers(is_testnet).await {
        Ok(api_peers) => {
            log::info!("🌐 API returned {} peers", api_peers.len());
            endpoints.extend(api_peers);
        }
        Err(e) => {
            log::warn!("⚠ Peer discovery failed: {}", e);
        }
    }

    endpoints.sort();
    endpoints.dedup();

    if endpoints.is_empty() {
        let _ = svc_tx.send(ServiceEvent::Error(
            "No peers available. Add peers to time.conf or check your internet connection."
                .to_string(),
        ));
        return Err(());
    }

    // Probe all peers in parallel with a short timeout
    let probe_timeout = std::time::Duration::from_secs(4);
    let mut handles = Vec::new();
    for endpoint in endpoints.clone() {
        let creds = rpc_credentials.clone();
        let expected_genesis = if is_testnet { TESTNET_GENESIS_HASH } else { MAINNET_GENESIS_HASH };
        handles.push(tokio::spawn(async move {
            // Always probe the https:// form first; plain-http form is the fallback.
            let https_ep = if endpoint.starts_with("http://") {
                endpoint.replacen("http://", "https://", 1)
            } else {
                endpoint.clone()
            };
            let http_ep = https_ep.replacen("https://", "http://", 1);

            // TCP connect for accurate network ping (strips scheme)
            let tcp_addr = https_ep
                .strip_prefix("https://")
                .unwrap_or(&https_ep)
                .trim_end_matches('/');
            let tcp_start = Instant::now();
            let tcp_ok = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::net::TcpStream::connect(tcp_addr),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            let ping_ms = if tcp_ok {
                Some(tcp_start.elapsed().as_millis() as u64)
            } else {
                None
            };

            // Health check — capture the working client so tier/genesis can reuse
            // the same TCP+TLS connection (avoids two extra handshakes per peer).
            let (is_healthy, is_syncing, block_height, version, working_ep, probe_client) =
                if tcp_ok {
                    let client = MasternodeClient::new(https_ep.clone(), creds.clone());
                    match tokio::time::timeout(probe_timeout, client.health_check()).await {
                        Ok(Ok(health)) => (
                            true,
                            health.is_syncing,
                            Some(health.block_height),
                            Some(health.version),
                            https_ep.clone(),
                            Some(client),
                        ),
                        _ => {
                            log::debug!("HTTPS failed for {}, retrying with HTTP", https_ep);
                            let http_client = MasternodeClient::new(http_ep.clone(), creds.clone());
                            match tokio::time::timeout(probe_timeout, http_client.health_check())
                                .await
                            {
                                Ok(Ok(health)) => {
                                    log::info!("✅ Peer {} reachable via HTTP (no TLS)", http_ep);
                                    (
                                        true,
                                        health.is_syncing,
                                        Some(health.block_height),
                                        Some(health.version),
                                        http_ep.clone(),
                                        Some(http_client),
                                    )
                                }
                                Ok(Err(e)) => {
                                    log::warn!("⚠ Peer {} unhealthy: {}", http_ep, e);
                                    (false, false, None, None, endpoint.clone(), None)
                                }
                                Err(_) => {
                                    log::warn!("⚠ Peer {} timed out", http_ep);
                                    (false, false, None, None, endpoint.clone(), None)
                                }
                            }
                        }
                    }
                } else {
                    (false, false, None, None, endpoint.clone(), None)
                };

            // WS probe + tier + genesis run in parallel — all independent of each other
            // and all reuse the same reqwest connection pool from probe_client (one
            // TLS handshake total instead of three).
            let (ws_available, tier, genesis_ok) = if let Some(client) = probe_client {
                let ws_url = crate::config_new::Config::derive_ws_url(&working_ep);
                let tier_client = client.clone();
                let genesis_client = client.clone();

                let (ws_res, tier_res, genesis_res) = tokio::join!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        tokio_tungstenite::connect_async_tls_with_config(
                            &ws_url,
                            None,
                            false,
                            Some(crate::ws_client::make_tls_connector()),
                        ),
                    ),
                    tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        tier_client.get_tier(),
                    ),
                    tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        async move { genesis_client.get_genesis_hash().await },
                    ),
                );

                let ws_available = ws_res.map(|r| r.is_ok()).unwrap_or(false);
                let tier = tier_res.ok().flatten();
                let genesis_ok = match genesis_res {
                    Ok(Ok(hash)) => {
                        let ok = hash == expected_genesis;
                        if !ok {
                            log::warn!(
                                "⚠ Peer {} has incompatible genesis: {} (expected {}…)",
                                working_ep,
                                &hash[..16.min(hash.len())],
                                &expected_genesis[..16],
                            );
                        }
                        Some(ok)
                    }
                    _ => None,
                };
                (ws_available, tier, genesis_ok)
            } else {
                (false, None, None)
            };

            PeerInfo {
                endpoint: working_ep,
                is_active: false,
                is_healthy,
                is_syncing,
                ws_available,
                ping_ms,
                block_height,
                version,
                tier,
                genesis_ok,
            }
        }));
    }

    let mut peer_infos = Vec::new();
    for handle in handles {
        if let Ok(info) = handle.await {
            peer_infos.push(info);
        }
    }

    // Deduplicate by host:port — manual (http://) and API (https://) endpoints
    // for the same IP both survive string-level dedup, so collapse them here,
    // preferring the entry that succeeded with HTTPS.
    {
        let mut seen = std::collections::HashSet::new();
        peer_infos.sort_by(|a, b| {
            // Prefer https:// entries so they win the dedup
            let a_https = a.endpoint.starts_with("https://") as u8;
            let b_https = b.endpoint.starts_with("https://") as u8;
            b_https.cmp(&a_https)
        });
        peer_infos.retain(|p| {
            let normalized = p
                .endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .to_string();
            seen.insert(normalized)
        });
    }

    // Sort: fully-synced first, then WS-capable, then healthy by fastest ping, syncing/unhealthy last
    peer_infos.sort_by(|a, b| {
        b.is_healthy
            .cmp(&a.is_healthy)
            .then(a.is_syncing.cmp(&b.is_syncing)) // false < true → synced before syncing
            .then(b.ws_available.cmp(&a.ws_available))
            .then(
                a.ping_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.ping_ms.unwrap_or(u64::MAX)),
            )
    });

    // Save wrong-chain peers before healthy-only filtering so the connections
    // screen can display them with a "Wrong chain" warning. They are excluded from
    // auto-selection and must never be used as the active endpoint.
    let wrong_chain_display: Vec<PeerInfo> = peer_infos
        .iter()
        .filter(|p| p.is_healthy && p.genesis_ok == Some(false))
        .cloned()
        .collect();
    for p in &wrong_chain_display {
        log::warn!(
            "⚠ Peer {} has incompatible genesis — excluded from active pool",
            p.endpoint
        );
    }

    // Keep only healthy peers on the correct chain.
    peer_infos.retain(|p| p.is_healthy && p.genesis_ok != Some(false));

    // Consensus filter: discard peers whose block height lags the best known
    // height by more than CONSENSUS_LAG blocks. A lagging node has a stale UTXO
    // set and would return wrong balances / reject valid transactions.
    let best_height = peer_infos
        .iter()
        .filter_map(|p| p.block_height)
        .max()
        .unwrap_or(0);
    if best_height > 0 {
        peer_infos.retain(|p| {
            let height = p.block_height.unwrap_or(0);
            let ok = best_height - height <= CONSENSUS_LAG;
            if !ok {
                log::warn!(
                    "⚠ Dropping peer {} from pool: height {} is {} blocks behind consensus ({})",
                    p.endpoint,
                    height,
                    best_height - height,
                    best_height,
                );
            }
            ok
        });
    }

    if peer_infos.len() > max_connections {
        peer_infos.truncate(max_connections);
    }

    let active_endpoint = peer_infos
        .iter()
        .find(|p| p.is_healthy)
        .map(|p| p.endpoint.clone())
        .unwrap_or_else(|| {
            log::warn!("⚠ No peers responded to health check, using first peer");
            endpoints[0].clone()
        });

    // Send a preliminary peer update immediately so the UI stops showing
    // "discovering peers" and shows the initial set while gossip runs.
    // Skip if empty — an empty send would flash "Discovering peers..." when
    // all probes are temporarily failing (e.g. during a re-discovery cycle).
    {
        let mut preliminary = peer_infos.clone();
        for p in &mut preliminary {
            p.is_active = p.is_healthy && p.endpoint == active_endpoint;
        }
        preliminary.extend(wrong_chain_display.iter().cloned());
        if !preliminary.is_empty() {
            let _ = svc_tx.send(ServiceEvent::PeersDiscovered(preliminary));
        }
    }

    // Gossip discovery: ask ALL healthy peers for their known masternodes.
    // Querying only one peer means a stale registry on that node hides others.
    // Normalise to "ip:rpc_port" for dedup — ignore http/https scheme differences.
    let known_hosts: std::collections::HashSet<String> = peer_infos
        .iter()
        .filter_map(|p| {
            p.endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .split(':')
                .next()
                .map(|ip| format!("{}:{}", ip, rpc_port))
        })
        .collect();

    let gossip_endpoints: Vec<String> = peer_infos
        .iter()
        .filter(|p| p.is_healthy)
        .map(|p| p.endpoint.clone())
        .collect();

    // Query all healthy peers for their neighbour lists in parallel.
    let gossip_handles: Vec<_> = gossip_endpoints
        .iter()
        .map(|ep| {
            let client = MasternodeClient::new(ep.clone(), rpc_credentials.clone());
            tokio::spawn(async move { client.get_peer_info().await })
        })
        .collect();
    let mut new_endpoints: std::collections::HashSet<String> = std::collections::HashSet::new();
    for handle in gossip_handles {
        if let Ok(Ok(gossip_peers)) = handle.await {
            for gp in &gossip_peers {
                let ip = gp.addr.split(':').next().unwrap_or(&gp.addr);
                let host_key = format!("{}:{}", ip, rpc_port);
                if !known_hosts.contains(&host_key) {
                    new_endpoints.insert(format!("https://{}:{}", ip, rpc_port));
                }
            }
        }
    }

    if !new_endpoints.is_empty() {
        log::info!(
            "🔗 Gossip discovery: found {} new peers",
            new_endpoints.len()
        );
        // Probe new peers in parallel
        let probe_timeout2 = std::time::Duration::from_secs(4);
        let mut gossip_handles = Vec::new();
        for ep in new_endpoints {
            let creds = rpc_credentials.clone();
            let expected_genesis = if is_testnet { TESTNET_GENESIS_HASH } else { MAINNET_GENESIS_HASH };
            gossip_handles.push(tokio::spawn(async move {
                // Gossip peers are built as https://; fall back to http:// like the initial probe.
                let http_ep = ep.replacen("https://", "http://", 1);

                // TCP connect for accurate network ping
                let tcp_addr = ep
                    .strip_prefix("https://")
                    .unwrap_or(&ep)
                    .trim_end_matches('/');
                let tcp_start = Instant::now();
                let tcp_ok = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    tokio::net::TcpStream::connect(tcp_addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
                let ping_ms = if tcp_ok {
                    Some(tcp_start.elapsed().as_millis() as u64)
                } else {
                    None
                };

                let (is_healthy, is_syncing, block_height, version, working_ep, probe_client) =
                    if tcp_ok {
                        let c = MasternodeClient::new(ep.clone(), creds.clone());
                        match tokio::time::timeout(probe_timeout2, c.health_check()).await {
                            Ok(Ok(health)) => (
                                true,
                                health.is_syncing,
                                Some(health.block_height),
                                Some(health.version),
                                ep.clone(),
                                Some(c),
                            ),
                            _ => {
                                log::debug!(
                                    "HTTPS failed for gossip peer {}, retrying with HTTP",
                                    ep
                                );
                                let hc = MasternodeClient::new(http_ep.clone(), creds.clone());
                                match tokio::time::timeout(probe_timeout2, hc.health_check()).await
                                {
                                    Ok(Ok(health)) => {
                                        log::info!(
                                            "✅ Gossip peer {} reachable via HTTP (no TLS)",
                                            http_ep
                                        );
                                        (
                                            true,
                                            health.is_syncing,
                                            Some(health.block_height),
                                            Some(health.version),
                                            http_ep.clone(),
                                            Some(hc),
                                        )
                                    }
                                    _ => (false, false, None, None, ep.clone(), None),
                                }
                            }
                        }
                    } else {
                        (false, false, None, None, ep.clone(), None)
                    };

                let (ws_available, tier, genesis_ok) = if let Some(client) = probe_client {
                    let ws_url = crate::config_new::Config::derive_ws_url(&working_ep);
                    let tier_client = client.clone();
                    let genesis_client = client.clone();

                    let (ws_res, tier_res, genesis_res) = tokio::join!(
                        tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            tokio_tungstenite::connect_async_tls_with_config(
                                &ws_url,
                                None,
                                false,
                                Some(crate::ws_client::make_tls_connector()),
                            ),
                        ),
                        tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            tier_client.get_tier(),
                        ),
                        tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            async move { genesis_client.get_genesis_hash().await },
                        ),
                    );

                    let ws_available = ws_res.map(|r| r.is_ok()).unwrap_or(false);
                    let tier = tier_res.ok().flatten();
                    let genesis_ok = match genesis_res {
                        Ok(Ok(hash)) => {
                            let ok = hash == expected_genesis;
                            if !ok {
                                log::warn!(
                                    "⚠ Gossip peer {} has incompatible genesis: {}…",
                                    working_ep,
                                    &hash[..16.min(hash.len())],
                                );
                            }
                            Some(ok)
                        }
                        _ => None,
                    };
                    (ws_available, tier, genesis_ok)
                } else {
                    (false, None, None)
                };
                PeerInfo {
                    endpoint: working_ep,
                    is_active: false,
                    is_healthy,
                    is_syncing,
                    ws_available,
                    ping_ms,
                    block_height,
                    version,
                    tier,
                    genesis_ok,
                }
            }));
        }
        for handle in gossip_handles {
            if let Ok(info) = handle.await {
                if !info.is_healthy {
                    continue; // Don't bother adding unhealthy gossip peers
                }
                if info.genesis_ok == Some(false) {
                    log::warn!(
                        "⚠ Gossip peer {} has incompatible genesis — skipping",
                        info.endpoint
                    );
                    continue;
                }
                log::info!(
                    "✅ Gossip peer {} is healthy ({}ms)",
                    info.endpoint,
                    info.ping_ms.unwrap_or(0)
                );
                // Add the new peer if we're below the connection cap.
                // Only replace the slowest when at the limit.
                if peer_infos.len() < max_connections {
                    peer_infos.push(info);
                } else {
                    let slowest_idx = peer_infos
                        .iter()
                        .enumerate()
                        .filter(|(_, p)| p.is_healthy)
                        .max_by_key(|(_, p)| p.ping_ms.unwrap_or(u64::MAX));
                    let new_ping = info.ping_ms.unwrap_or(u64::MAX);
                    if let Some((idx, slowest)) = slowest_idx {
                        if slowest.ping_ms.unwrap_or(u64::MAX) > new_ping {
                            log::info!(
                                "🔀 Replacing slow peer {} ({}ms) with {} ({}ms)",
                                peer_infos[idx].endpoint,
                                slowest.ping_ms.unwrap_or(0),
                                info.endpoint,
                                new_ping
                            );
                            peer_infos[idx] = info;
                        }
                    }
                }
            }
        }
        // Re-sort after integrating gossip peers
        peer_infos.sort_by(|a, b| {
            b.is_healthy
                .cmp(&a.is_healthy)
                .then(b.ws_available.cmp(&a.ws_available))
                .then(
                    a.ping_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.ping_ms.unwrap_or(u64::MAX)),
                )
        });
    }

    // Cache all discovered healthy peers for offline use
    let healthy_endpoints: Vec<String> = peer_infos
        .iter()
        .filter(|p| p.is_healthy)
        .map(|p| p.endpoint.clone())
        .collect();
    if !healthy_endpoints.is_empty() {
        peer_discovery::save_discovered_peers(is_testnet, &healthy_endpoints);
    }

    for p in &mut peer_infos {
        p.is_active = p.is_healthy && p.endpoint == active_endpoint;
    }

    // Append wrong-chain peers for UI display. They are excluded from the active
    // pool but visible in the connections screen with a "Wrong chain" indicator.
    peer_infos.extend(wrong_chain_display);

    Ok((active_endpoint, peer_infos))
}

/// Mutable state owned by the service loop.
struct ServiceState {
    svc_tx: mpsc::UnboundedSender<ServiceEvent>,
    client: Option<MasternodeClient>,
    wallet: Option<WalletManager>,
    wallet_db: Option<WalletDb>,
    addresses: Vec<String>,
    network_type: NetworkType,
    config: Config,
    ws_event_tx: mpsc::UnboundedSender<WsEvent>,
    /// Per-connection shutdown senders. Signalling `true` triggers a graceful
    /// Close frame so the server-side subscription is cleaned up immediately.
    ws_conn_shutdown_senders: Vec<tokio::sync::watch::Sender<bool>>,
    ws_handles: Vec<tokio::task::JoinHandle<()>>,
    ws_connected_count: usize,
    /// WS URLs currently connected (one per active connection). Sent to the UI
    /// so the connections page can mark which peers have active WS links.
    ws_active_urls: std::collections::HashSet<String>,
    /// Dedup cache: event fingerprint → time first seen. Prevents duplicate
    /// UI updates when the same event arrives from multiple WS connections.
    ws_seen: std::collections::HashMap<String, std::time::Instant>,
    /// Most recent peer list from discovery, for failover on capacity-full.
    last_peers: Vec<PeerInfo>,
    /// When true, the user manually selected a peer — auto-discovery will not
    /// override the choice unless the selected peer becomes unhealthy.
    manual_peer: bool,
    /// Txids broadcast by the consolidation background task. Shared with the
    /// spawned task so the WS handler can identify consolidation outputs as
    /// change instead of real receives (prevents transient balance inflation).
    consolidation_txids: Arc<Mutex<HashSet<String>>>,
    /// True while the consolidation background task is running. Shared with the
    /// spawned task. Suppresses periodic and WS-triggered balance/tx/UTXO
    /// refreshes so that transient masternode RPC values don't reach the UI.
    consolidation_active: Arc<AtomicBool>,
    /// Signing keys for all derived addresses. Used to decrypt encrypted memos
    /// returned by the masternode in transaction history responses.
    signing_keys: Arc<Vec<ed25519_dalek::SigningKey>>,
    /// Chain height at the time of the last successful transaction poll.
    /// Shared with spawned poll tasks so they can pass it as `from_height`
    /// to the masternode and update it from the response.
    last_synced_height: Arc<AtomicU64>,
    /// Set to `true` when the wallet DB was empty at load time (fresh start or
    /// DB deletion).  Triggers an on-chain address-recovery scan the first time
    /// the node RPC becomes available so all previously-used addresses are
    /// re-discovered and added back to the wallet.
    pending_address_scan: bool,
}

impl ServiceState {
    /// Load a wallet and start the WebSocket connection.
    fn load_wallet(&mut self, password: Option<String>) {
        let result = match password {
            Some(pw) => WalletManager::load_with_password(self.network_type, &pw),
            None => {
                // Check if encrypted first
                if WalletManager::is_encrypted(self.network_type).unwrap_or(false) {
                    let _ = self.svc_tx.send(ServiceEvent::PasswordRequired);
                    return;
                }
                WalletManager::load(self.network_type)
            }
        };
        self.finish_wallet_init(result);
    }

    /// Create a wallet from mnemonic and start the WebSocket connection.
    fn create_wallet(&mut self, mnemonic: &str, password: Option<String>) {
        let result = match password {
            Some(pw) => {
                WalletManager::create_from_mnemonic_encrypted(self.network_type, mnemonic, &pw)
            }
            None => WalletManager::create_from_mnemonic(self.network_type, mnemonic),
        };
        self.finish_wallet_init(result);
    }

    fn finish_wallet_init(&mut self, result: Result<WalletManager, wallet_dat::WalletDatError>) {
        match result {
            Ok(mut wm) => {
                // Load owned addresses from the DB. Derive only those specific indices
                // so that explicitly deleted addresses do not resurface after a reload.
                let owned_from_db: Vec<crate::wallet_db::AddressContact> = self
                    .wallet_db
                    .as_ref()
                    .and_then(|db| db.get_owned_addresses().ok())
                    .unwrap_or_default();

                // Collect derivation indices that are recorded in the DB, sorted ascending.
                let mut db_indices: Vec<u32> = owned_from_db
                    .iter()
                    .filter_map(|c| c.derivation_index)
                    .collect();
                db_indices.sort_unstable();
                db_indices.dedup();

                // Advance the counter past the highest known index so the next
                // generated address does not collide with any existing one.
                if let Some(&max_idx) = db_indices.last() {
                    wm.sync_address_index(max_idx);
                }

                // Build the active address set.
                // First run: no DB entries yet — create the primary address and persist it.
                let raw_addrs: Vec<String> = if db_indices.is_empty() {
                    // Flag that we should scan for more addresses once connected.
                    self.pending_address_scan = true;
                    match wm.get_next_address() {
                        Ok(addr) => {
                            if let Some(ref db) = self.wallet_db {
                                let now = chrono::Utc::now().timestamp();
                                let _ = db.save_contact(&crate::wallet_db::AddressContact {
                                    address: addr.clone(),
                                    label: "Address #0".to_string(),
                                    name: None,
                                    email: None,
                                    phone: None,
                                    notes: None,
                                    is_default: true,
                                    is_owned: true,
                                    derivation_index: Some(0),
                                    created_at: now,
                                    updated_at: now,
                                });
                            }
                            vec![addr]
                        }
                        Err(e) => {
                            log::error!("Failed to derive primary address: {}", e);
                            vec![]
                        }
                    }
                } else {
                    // Normal run — derive only the indices present in the DB.
                    db_indices
                        .iter()
                        .filter_map(|&i| wm.derive_address(i).ok())
                        .collect()
                };

                self.addresses = raw_addrs.clone();
                // Force a full transaction rescan whenever a wallet is (re)loaded.
                self.last_synced_height.store(0, Ordering::Relaxed);

                // Build signing keys only for the active address indices.
                let active_indices: Vec<u32> = if db_indices.is_empty() {
                    vec![0]
                } else {
                    db_indices.clone()
                };
                // Collect (address, pubkey) pairs for node pre-registration.
                // Must happen before `wm` is moved into self.wallet.
                let addr_pubkeys: Vec<(String, [u8; 32])> = active_indices
                    .iter()
                    .zip(raw_addrs.iter())
                    .filter_map(|(&i, addr)| {
                        let kp = wm.derive_keypair(i).ok()?;
                        let signing_key =
                            ed25519_dalek::SigningKey::from_bytes(&kp.secret_key_bytes());
                        Some((addr.clone(), signing_key.verifying_key().to_bytes()))
                    })
                    .collect();

                self.signing_keys = Arc::new(
                    active_indices
                        .iter()
                        .filter_map(|&i| wm.derive_keypair(i).ok())
                        .map(|kp| ed25519_dalek::SigningKey::from_bytes(&kp.secret_key_bytes()))
                        .collect(),
                );

                // Build AddressInfo from the DB contacts; labels are already persisted so
                // no re-save is needed (and re-saving would resurrect deleted addresses).
                let contact_map: std::collections::HashMap<
                    String,
                    &crate::wallet_db::AddressContact,
                > = owned_from_db
                    .iter()
                    .map(|c| (c.address.clone(), c))
                    .collect();
                let address_infos: Vec<AddressInfo> = raw_addrs
                    .iter()
                    .enumerate()
                    .map(|(i, addr)| {
                        let label = contact_map
                            .get(addr)
                            .map(|c| c.label.clone())
                            .unwrap_or_else(|| format!("Address #{}", i));
                        AddressInfo {
                            address: addr.clone(),
                            label,
                        }
                    })
                    .collect();
                let is_testnet = self.network_type == NetworkType::Testnet;
                let is_encrypted = wm.is_wallet_encrypted();
                let _ = self.svc_tx.send(ServiceEvent::WalletLoaded {
                    addresses: address_infos,
                    is_testnet,
                    is_encrypted,
                });

                // Load cached data from database for instant startup
                if let Some(ref db) = self.wallet_db {
                    // Load persisted send records FIRST so they're available for merge.
                    // Cross-reference with cached transactions: if a send record's
                    // txid isn't in the cache, the masternode rejected it.
                    let cached_txs = db.get_cached_transactions().unwrap_or_default();
                    let cached_txids: std::collections::HashSet<&str> =
                        cached_txs.iter().map(|t| t.txid.as_str()).collect();

                    if let Ok(mut send_records) = db.get_send_records() {
                        let mut updated = Vec::new();
                        for (txid, sr) in send_records.iter_mut() {
                            if matches!(
                                sr.status,
                                crate::masternode_client::TransactionStatus::Pending
                            ) && !cached_txids.contains(txid.as_str())
                            {
                                log::info!(
                                    "Marking send record {} as Declined (not in cached txs)",
                                    &txid[..16.min(txid.len())]
                                );
                                sr.status = crate::masternode_client::TransactionStatus::Declined;
                                updated.push(sr.clone());
                            }
                        }
                        // Persist the Declined status immediately
                        for sr in &updated {
                            let _ = db.save_send_record(sr);
                        }
                        if !send_records.is_empty() {
                            log::info!("Loaded {} persisted send records", send_records.len());
                            let _ = self
                                .svc_tx
                                .send(ServiceEvent::SendRecordsLoaded(send_records));
                        }
                    }
                    if let Ok(Some(bal)) = db.get_cached_balance() {
                        log::info!("Loaded cached balance from database");
                        let _ = self.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                    }
                    // Load masternode entries
                    if let Ok(entries) = db.get_masternode_entries() {
                        if entries.is_empty() {
                            // Auto-import masternode.conf if it exists and DB has no entries
                            let mn_conf_path = self.config.wallet_dir().join("masternode.conf");
                            if mn_conf_path.exists() {
                                if let Ok(contents) = std::fs::read_to_string(&mn_conf_path) {
                                    let mut count = 0;
                                    for line in contents.lines() {
                                        if let Some(entry) =
                                            crate::wallet_db::MasternodeEntry::parse_conf_line(line)
                                        {
                                            let _ = db.save_masternode_entry(&entry);
                                            count += 1;
                                        }
                                    }
                                    if count > 0 {
                                        log::info!(
                                            "📥 Auto-imported {} entries from {}",
                                            count,
                                            mn_conf_path.display()
                                        );
                                        if let Ok(imported) = db.get_masternode_entries() {
                                            let _ = self.svc_tx.send(
                                                ServiceEvent::MasternodeEntriesLoaded(imported),
                                            );
                                        }
                                    }
                                }
                            }
                        } else {
                            log::info!("Loaded {} masternode entries", entries.len());
                            // Ensure collateral UTXOs are locked for all known entries
                            for entry in &entries {
                                let _ = db.lock_collateral(
                                    &entry.collateral_txid,
                                    entry.collateral_vout,
                                    &entry.alias,
                                );
                            }
                            let _ = self
                                .svc_tx
                                .send(ServiceEvent::MasternodeEntriesLoaded(entries));
                        }
                    }
                    // Load persisted incoming payment requests
                    if let Ok(incoming_reqs) = db.get_all_incoming_payment_requests() {
                        if !incoming_reqs.is_empty() {
                            log::info!("Loaded {} incoming payment requests", incoming_reqs.len());
                            let _ = self
                                .svc_tx
                                .send(ServiceEvent::IncomingPaymentRequestsLoaded(incoming_reqs));
                        }
                    }
                    // Load persisted sent payment requests
                    if let Ok(sent_reqs) = db.get_all_sent_payment_requests() {
                        if !sent_reqs.is_empty() {
                            log::info!("Loaded {} sent payment requests", sent_reqs.len());
                            let _ = self
                                .svc_tx
                                .send(ServiceEvent::SentPaymentRequestsLoaded(sent_reqs));
                        }
                    }
                    // Load incoming payment request history
                    if let Ok(history) = db.get_all_incoming_payment_history() {
                        if !history.is_empty() {
                            log::info!("Loaded {} incoming payment history entries", history.len());
                            let _ = self
                                .svc_tx
                                .send(ServiceEvent::IncomingPaymentHistoryLoaded(history));
                        }
                    }

                    if !cached_txs.is_empty() {
                        log::info!(
                            "Loaded {} cached transactions from database",
                            cached_txs.len()
                        );
                        let _ = self
                            .svc_tx
                            .send(ServiceEvent::TransactionsUpdated(cached_txs));

                        // We have cached history — restore the last-synced block height
                        // so the first live poll is incremental (new blocks only) instead
                        // of a full chain rescan from height 0.
                        if let Ok(Some(h_str)) = db.get_setting("last_synced_height") {
                            if let Ok(h) = h_str.parse::<u64>() {
                                self.last_synced_height.store(h, Ordering::Relaxed);
                                log::info!("Resuming incremental sync from block {}", h);
                            }
                        }

                        // Hide the "Synchronizing" banner immediately — cached data is
                        // displayed, and the incremental live sync runs in the background.
                        let _ = self.svc_tx.send(ServiceEvent::SyncComplete);
                    }
                    // Load persisted UTXOs so balance displays correctly before sync
                    if let Ok(utxo_records) = db.get_all_utxos() {
                        if !utxo_records.is_empty() {
                            let utxos: Vec<crate::masternode_client::Utxo> = utxo_records
                                .iter()
                                .map(|r| crate::masternode_client::Utxo {
                                    txid: r.tx_hash.clone(),
                                    vout: r.output_index,
                                    amount: r.amount,
                                    address: r.address.clone(),
                                    confirmations: r.confirmations as u32,
                                    spendable: true,
                                })
                                .collect();
                            log::info!("Loaded {} cached UTXOs from database", utxos.len());
                            self.send_utxos_updated(utxos);
                        }
                    }
                    // Load external contacts for send address book
                    if let Ok(contacts) = db.get_external_contacts() {
                        let infos: Vec<crate::state::ContactInfo> = contacts
                            .into_iter()
                            .map(|c| crate::state::ContactInfo {
                                name: c.name.unwrap_or(c.label),
                                address: c.address,
                            })
                            .collect();
                        let _ = self.svc_tx.send(ServiceEvent::ContactsUpdated(infos));
                    }
                }

                self.wallet = Some(wm);
                // Only start WS if we already have a peer connection
                if self.config.active_endpoint.is_some() {
                    self.start_ws();
                }

                // Pre-register address pubkeys with the node so it can encrypt memos
                // to us before we have any on-chain history as a sender.
                if let Some(ref client) = self.client {
                    let reg_client = client.clone();
                    tokio::spawn(async move {
                        for (addr, pubkey) in addr_pubkeys {
                            match reg_client.register_address_pubkey(&addr, &pubkey).await {
                                Ok(()) => log::debug!("📬 Registered pubkey for {}", addr),
                                Err(e) => {
                                    log::warn!("Failed to register pubkey for {}: {}", addr, e)
                                }
                            }
                        }
                    });
                }
            }
            Err(e) => {
                let _ = self
                    .svc_tx
                    .send(ServiceEvent::Error(format!("Wallet error: {}", e)));
            }
        }
    }

    /// Send UtxosUpdated event and persist UTXOs to sled for instant startup.
    /// Also backfills collateral_amount on masternode entries that are missing it.
    fn send_utxos_updated(&self, utxos: Vec<crate::masternode_client::Utxo>) {
        // Deduplicate UTXOs by txid:vout. This prevents double-counting when a
        // duplicate address entry causes the same UTXO to be fetched twice.
        let mut seen_utxo_keys = std::collections::HashSet::new();
        let utxos: Vec<crate::masternode_client::Utxo> = utxos
            .into_iter()
            .filter(|u| seen_utxo_keys.insert(format!("{}:{}", u.txid, u.vout)))
            .collect();

        if let Some(ref db) = self.wallet_db {
            let _ = db.clear_all_utxos();
            for u in &utxos {
                let _ = db.save_utxo(&crate::wallet_db::UtxoRecord {
                    tx_hash: u.txid.clone(),
                    output_index: u.vout,
                    amount: u.amount,
                    address: u.address.clone(),
                    block_height: 0,
                    confirmations: u.confirmations as u64,
                });
            }
            // Backfill collateral_amount on masternode entries and auto-create
            // entries for any non-spendable UTXOs not yet tracked.
            if let Ok(mut entries) = db.get_masternode_entries() {
                // Backfill amounts on existing entries
                let mut backfilled = false;
                for entry in &mut entries {
                    if entry.collateral_amount.is_none() {
                        if let Some(u) = utxos.iter().find(|u| {
                            u.txid == entry.collateral_txid && u.vout == entry.collateral_vout
                        }) {
                            entry.collateral_amount = Some(u.amount);
                            let _ = db.save_masternode_entry(entry);
                            backfilled = true;
                            log::info!(
                                "💾 Backfilled collateral {} for '{}'",
                                u.amount,
                                entry.alias
                            );
                        }
                    }
                }

                // Send updated entries whenever amounts were backfilled.
                if backfilled {
                    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
                    let _ = self
                        .svc_tx
                        .send(ServiceEvent::MasternodeEntriesLoaded(entries));
                }
            }
        }
        let _ = self.svc_tx.send(ServiceEvent::UtxosUpdated(utxos));
    }

    /// Start (or restart) the WebSocket client for current addresses.
    ///
    /// Signals existing connections to close gracefully (sending a WebSocket
    /// Close frame so the server unsubscribes immediately) before spawning new ones.
    fn start_ws(&mut self) {
        // Signal old connections to send a graceful Close frame.
        // This causes the server to clean up subscriptions right away rather than
        // waiting for a TCP keepalive timeout (which was causing 60+ subscription accumulation).
        for tx in self.ws_conn_shutdown_senders.drain(..) {
            let _ = tx.send(true);
        }
        // Abort handles after signalling (belt-and-suspenders).
        for h in self.ws_handles.drain(..) {
            h.abort();
        }
        self.ws_connected_count = 0;
        self.ws_active_urls.clear();

        let addrs = self.addresses.clone();
        let event_tx = self.ws_event_tx.clone();

        // Primary connection — always the configured endpoint
        let primary_url = self.config.ws_url();
        let (sd_tx1, sd_rx1) = tokio::sync::watch::channel(false);
        self.ws_conn_shutdown_senders.push(sd_tx1);
        self.ws_handles.push(WsClient::start(
            primary_url,
            addrs.clone(),
            event_tx.clone(),
            sd_rx1,
        ));

        // Secondary connection — first healthy peer that differs from the primary endpoint
        let primary_ep = self.config.active_endpoint.clone().unwrap_or_default();
        if let Some(peer) = self
            .last_peers
            .iter()
            .find(|p| p.is_healthy && p.endpoint != primary_ep)
        {
            let secondary_url = crate::config_new::Config::derive_ws_url(&peer.endpoint);
            let (sd_tx2, sd_rx2) = tokio::sync::watch::channel(false);
            self.ws_conn_shutdown_senders.push(sd_tx2);
            self.ws_handles
                .push(WsClient::start(secondary_url, addrs, event_tx, sd_rx2));
        }
    }
}

/// Build a masternode registration transaction.
///
/// Returns `(hex_encoded_tx, txid)` on success.
/// The transaction:
/// - Uses a wallet UTXO for the fee (minimum fee, since no value is transferred)
/// - Contains `special_data` with the registration payload
/// - The registration payload is signed with the collateral owner's Ed25519 key
/// - The transaction input is signed with the fee UTXO owner's key
#[allow(clippy::too_many_arguments)]
async fn build_masternode_reg_tx(
    wm: &mut WalletManager,
    client: &MasternodeClient,
    addresses: &[String],
    collateral_txid: &str,
    collateral_vout: u32,
    masternode_ip: &str,
    masternode_port: u16,
    payout_address: &str,
) -> Result<(String, String), String> {
    use sha2::{Digest, Sha256};
    use wallet::Transaction;

    // 1. Find the collateral UTXO owner address and derive their HD keypair
    let mut collateral_owner_addr: Option<String> = None;
    for addr in addresses {
        match client.get_utxos(addr).await {
            Ok(utxos) => {
                for utxo in &utxos {
                    if utxo.txid == collateral_txid && utxo.vout == collateral_vout {
                        collateral_owner_addr = Some(addr.clone());
                        break;
                    }
                }
            }
            Err(_) => continue,
        }
        if collateral_owner_addr.is_some() {
            break;
        }
    }
    let collateral_addr =
        collateral_owner_addr.ok_or("Collateral UTXO not found in wallet".to_string())?;

    // Find HD index for collateral owner
    let addr_to_index: std::collections::HashMap<String, u32> = (0..wm.get_address_count())
        .filter_map(|i| wm.derive_address(i).ok().map(|a| (a, i)))
        .collect();
    let collateral_hd_index = addr_to_index
        .get(&collateral_addr)
        .copied()
        .ok_or("Collateral address not found in HD wallet".to_string())?;
    let collateral_kp = wm
        .derive_keypair(collateral_hd_index)
        .map_err(|e| format!("Failed to derive collateral keypair: {}", e))?;

    // 2. Sign the registration payload.
    //
    // The daemon enforces payout_address == collateral owner address
    // (masternode_registry::validate_masternode_reg checks this).  Using any
    // other address causes the transaction to be silently rejected during block
    // processing.  We always use `collateral_addr` here regardless of what the
    // caller passed — the collateral owner is the only valid reward recipient.
    let _ = payout_address; // caller-supplied value is not used; see above
    let effective_payout = collateral_addr.clone();
    let collateral_outpoint = format!("{}:{}", collateral_txid, collateral_vout);
    let signing_message = format!(
        "MN_REG:{}:{}:{}:{}",
        collateral_outpoint, masternode_ip, masternode_port, effective_payout
    );
    let msg_hash: [u8; 32] = Sha256::digest(signing_message.as_bytes()).into();
    let signature_bytes = collateral_kp.sign(&msg_hash);
    let signature_hex = hex::encode(&signature_bytes);
    let owner_pubkey_hex = hex::encode(collateral_kp.public_key_bytes());

    // 3. Fetch all UTXOs to find one for the fee
    let min_fee: u64 = 1_000_000; // 0.01 TIME
    let mut fee_utxo = None;
    let mut all_utxos = Vec::new();
    for addr in addresses {
        match client.get_utxos(addr).await {
            Ok(utxos) => {
                for utxo in &utxos {
                    // Don't use the collateral UTXO for fee payment
                    let is_collateral =
                        utxo.txid == collateral_txid && utxo.vout == collateral_vout;
                    if !is_collateral && utxo.amount >= min_fee && fee_utxo.is_none() {
                        fee_utxo = Some(utxo.clone());
                    }
                    all_utxos.push(utxo.clone());
                }
            }
            Err(_) => continue,
        }
    }
    let fee_utxo = fee_utxo.ok_or("No UTXO available to pay registration fee".to_string())?;

    // 4. Build the transaction
    let mut tx = Transaction::new();

    // Add fee input
    let mut tx_hash = [0u8; 32];
    hex::decode_to_slice(&fee_utxo.txid, &mut tx_hash)
        .map_err(|e| format!("Invalid fee UTXO txid: {}", e))?;
    let input = wallet::TxInput::new(tx_hash, fee_utxo.vout);
    tx.add_input(input);

    // Add change output (fee_utxo.amount - min_fee)
    let change = fee_utxo.amount.saturating_sub(min_fee);
    if change > 0 {
        let change_addr = wallet::Address::from_string(&fee_utxo.address)
            .map_err(|e| format!("Invalid change address: {}", e))?;
        let change_output = wallet::TxOutput::new(change, change_addr);
        tx.add_output(change_output)
            .map_err(|e| format!("Failed to add change output: {}", e))?;
    }

    // Set the special_data
    tx.special_data = Some(wallet::SpecialTransactionData::MasternodeReg {
        collateral_outpoint,
        masternode_ip: masternode_ip.to_string(),
        masternode_port,
        payout_address: effective_payout,
        owner_pubkey: owner_pubkey_hex,
        signature: signature_hex,
    });

    // 5. Sign the fee input with the fee UTXO owner's key
    let fee_hd_index = addr_to_index
        .get(&fee_utxo.address)
        .copied()
        .ok_or("Fee UTXO address not found in HD wallet".to_string())?;
    let fee_kp = wm
        .derive_keypair(fee_hd_index)
        .map_err(|e| format!("Failed to derive fee keypair: {}", e))?;
    tx.sign(&fee_kp, 0)
        .map_err(|e| format!("Failed to sign fee input: {}", e))?;

    // 6. Attach a self-memo so the tx shows "Masternode Registration Fee" in history
    {
        use ed25519_dalek::SigningKey;
        let sender_key = SigningKey::from_bytes(&fee_kp.secret_key_bytes());
        let own_pub = sender_key.verifying_key().to_bytes();
        match crate::memo::encrypt_memo(&sender_key, &own_pub, "Masternode Registration Fee") {
            Ok(blob) => tx.encrypted_memo = Some(blob),
            Err(e) => log::warn!("Registration memo encryption failed: {}", e),
        }
    }

    // 7. Serialize and return
    let txid = tx.txid();
    let bytes = tx
        .to_bytes()
        .map_err(|e| format!("Failed to serialize tx: {}", e))?;
    let tx_hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

    log::info!(
        "Built MN registration tx: txid={}, fee_utxo={}, collateral={}:{}",
        txid,
        fee_utxo.txid,
        collateral_txid,
        collateral_vout
    );

    Ok((tx_hex, txid))
}

/// Build a CollateralUnlock special transaction to deregister a masternode.
/// No fee is required — the transaction has no inputs or outputs, only the signed payload.
async fn build_collateral_unlock_tx(
    wm: &mut WalletManager,
    addresses: &[String],
    collateral_txid: &str,
    collateral_vout: u32,
    masternode_ip: &str,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use wallet::Transaction;

    // Build address→HD-index map for all known wallet addresses
    let addr_to_index: std::collections::HashMap<String, u32> = (0..wm.get_address_count())
        .filter_map(|i| wm.derive_address(i).ok().map(|a| (a, i)))
        .collect();

    // Find the first wallet-owned address from the provided list
    let collateral_hd_index = addresses
        .iter()
        .find_map(|addr| addr_to_index.get(addr).copied())
        .ok_or("No wallet address found to sign deregistration".to_string())?;

    let collateral_kp = wm
        .derive_keypair(collateral_hd_index)
        .map_err(|e| format!("Failed to derive keypair: {}", e))?;

    // Sign the unlock payload
    let collateral_outpoint = format!("{}:{}", collateral_txid, collateral_vout);
    let signing_message = format!("MN_UNLOCK:{}:{}", collateral_outpoint, masternode_ip);
    let msg_hash: [u8; 32] = Sha256::digest(signing_message.as_bytes()).into();
    let signature_bytes = collateral_kp.sign(&msg_hash);
    let signature_hex = hex::encode(&signature_bytes);
    let owner_pubkey_hex = hex::encode(collateral_kp.public_key_bytes());

    let mut tx = Transaction::new();
    tx.special_data = Some(wallet::SpecialTransactionData::CollateralUnlock {
        collateral_outpoint,
        masternode_address: masternode_ip.to_string(),
        owner_pubkey: owner_pubkey_hex,
        signature: signature_hex,
    });

    log::info!(
        "Built CollateralUnlock tx for collateral={}:{} ip={}",
        collateral_txid,
        collateral_vout,
        masternode_ip,
    );

    let bytes = tx
        .to_bytes()
        .map_err(|e| format!("Failed to serialize CollateralUnlock tx: {}", e))?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Build a masternode payout update transaction.
///
/// Returns `(hex_encoded_tx, txid)` on success.
async fn build_masternode_update_tx(
    wm: &mut WalletManager,
    client: &MasternodeClient,
    addresses: &[String],
    masternode_id: &str,
    new_payout_address: &str,
) -> Result<(String, String), String> {
    use sha2::{Digest, Sha256};
    use wallet::Transaction;

    // Use the first address's key as the owner key (the owner registered the MN)
    let addr_to_index: std::collections::HashMap<String, u32> = (0..wm.get_address_count())
        .filter_map(|i| wm.derive_address(i).ok().map(|a| (a, i)))
        .collect();

    // Find the first wallet address that has a UTXO for the fee
    let min_fee: u64 = 1_000_000; // 0.01 TIME
    let mut fee_utxo = None;
    for addr in addresses {
        match client.get_utxos(addr).await {
            Ok(utxos) => {
                for utxo in utxos {
                    if utxo.amount >= min_fee && fee_utxo.is_none() {
                        fee_utxo = Some(utxo);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    let fee_utxo = fee_utxo.ok_or("No UTXO available to pay update fee".to_string())?;

    // Sign the update payload with address #0 (the owner key)
    let owner_index = 0u32;
    let owner_kp = wm
        .derive_keypair(owner_index)
        .map_err(|e| format!("Failed to derive owner keypair: {}", e))?;

    let signing_message = format!("MN_UPDATE:{}:{}", masternode_id, new_payout_address);
    let msg_hash: [u8; 32] = Sha256::digest(signing_message.as_bytes()).into();
    let signature_bytes = owner_kp.sign(&msg_hash);
    let signature_hex = hex::encode(&signature_bytes);
    let owner_pubkey_hex = hex::encode(owner_kp.public_key_bytes());

    // Build the transaction
    let mut tx = Transaction::new();

    let mut tx_hash = [0u8; 32];
    hex::decode_to_slice(&fee_utxo.txid, &mut tx_hash)
        .map_err(|e| format!("Invalid fee UTXO txid: {}", e))?;
    let input = wallet::TxInput::new(tx_hash, fee_utxo.vout);
    tx.add_input(input);

    let change = fee_utxo.amount.saturating_sub(min_fee);
    if change > 0 {
        let change_addr = wallet::Address::from_string(&fee_utxo.address)
            .map_err(|e| format!("Invalid change address: {}", e))?;
        let change_output = wallet::TxOutput::new(change, change_addr);
        tx.add_output(change_output)
            .map_err(|e| format!("Failed to add change output: {}", e))?;
    }

    tx.special_data = Some(wallet::SpecialTransactionData::MasternodePayoutUpdate {
        masternode_id: masternode_id.to_string(),
        new_payout_address: new_payout_address.to_string(),
        owner_pubkey: owner_pubkey_hex,
        signature: signature_hex,
    });

    // Sign the fee input
    let fee_hd_index = addr_to_index
        .get(&fee_utxo.address)
        .copied()
        .ok_or("Fee UTXO address not found in HD wallet".to_string())?;
    let fee_kp = wm
        .derive_keypair(fee_hd_index)
        .map_err(|e| format!("Failed to derive fee keypair: {}", e))?;
    tx.sign(&fee_kp, 0)
        .map_err(|e| format!("Failed to sign fee input: {}", e))?;

    let txid = tx.txid();
    let bytes = tx
        .to_bytes()
        .map_err(|e| format!("Failed to serialize tx: {}", e))?;
    let tx_hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

    log::info!(
        "Built MN payout update tx: txid={}, masternode_id={}",
        txid,
        masternode_id
    );

    Ok((tx_hex, txid))
}

/// Return a default template for a config file based on its filename.
pub fn config_file_template(path: &std::path::Path) -> &'static str {
    match path.file_name().and_then(|n| n.to_str()) {
        Some("time.toml") => {
            "\
# TIME Coin Wallet — startup preference
# Set to \"mainnet\" or \"testnet\"
network = \"mainnet\"
"
        }
        Some("time.conf") => {
            "\
# TIME Coin Wallet Configuration
# Lines starting with # are comments.
# Network is set in time.toml, not here.

# Masternode peers (IP, IP:port, or http://IP:port). Repeat for multiple.
#addnode=64.91.241.10:24001
#addnode=50.28.104.50:24001

# RPC credentials (from the masternode's time.conf)
#rpcuser=timecoinrpc
#rpcpassword=

# Maximum peer connections (0 = unlimited)
maxconnections=0
"
        }
        _ => "",
    }
}

/// Decrypt encrypted memos on a list of transactions in-place.
///
/// The masternode returns `encrypted_memo` bytes as a hex string in the `memo`
/// field of `listtransactionsmulti`. For each transaction that has a memo, try
/// to hex-decode it and decrypt with each of the wallet's signing keys. If
/// decryption succeeds the plaintext replaces the raw hex; otherwise the field
/// is cleared (we won't show garbled ciphertext to the user).
fn decrypt_memos(
    txs: &mut [crate::masternode_client::TransactionRecord],
    keys: &[ed25519_dalek::SigningKey],
) {
    if keys.is_empty() {
        return;
    }
    for tx in txs.iter_mut() {
        let raw = match tx.memo.take() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        // Try hex-decode → decrypt.
        let plaintext = hex::decode(&raw).ok().and_then(|blob| {
            keys.iter()
                .find_map(|key| crate::memo::decrypt_memo(&blob, key))
        });
        // If decryption failed, raw might already be plain text (e.g. locally
        // inserted send records store the unencrypted string).  Keep it if it
        // is valid UTF-8 that doesn't look like a hex blob (odd length or
        // non-hex chars).
        tx.memo = plaintext.or_else(|| {
            if hex::decode(&raw).is_ok() {
                None // hex but undecryptable — discard
            } else {
                Some(raw) // plain text memo, keep as-is
            }
        });
    }
}

/// Backfill missing `collateral_amount` on masternode entries by calling `gettxout`
/// for each entry whose amount is not yet known.  Sends `MasternodeEntriesLoaded`
/// if any amounts were resolved.
///
/// Designed to be called on startup and whenever a new client connection is
/// established, so users never need to press Refresh just to see their tier badge.
async fn mn_backfill_via_gettxout(
    client: &Option<crate::masternode_client::MasternodeClient>,
    wallet_db: &Option<crate::wallet_db::WalletDb>,
    svc_tx: &tokio::sync::mpsc::UnboundedSender<ServiceEvent>,
) {
    let (Some(client), Some(db)) = (client, wallet_db) else {
        return;
    };
    let entries = match db.get_masternode_entries() {
        Ok(e) => e,
        Err(_) => return,
    };
    let missing: Vec<_> = entries
        .into_iter()
        .filter(|e| e.collateral_amount.is_none() && !e.collateral_txid.is_empty())
        .collect();
    if missing.is_empty() {
        return;
    }
    let mut updated = false;
    for mut entry in missing {
        match client
            .get_tx_out(&entry.collateral_txid, entry.collateral_vout)
            .await
        {
            Ok(Some((sats, _addr))) => {
                entry.collateral_amount = Some(sats);
                let _ = db.save_masternode_entry(&entry);
                log::info!("💾 startup: backfilled {} sats for '{}'", sats, entry.alias);
                updated = true;
            }
            Ok(None) => {
                log::warn!(
                    "gettxout null for '{}' ({}:{})",
                    entry.alias,
                    entry.collateral_txid,
                    entry.collateral_vout
                );
            }
            Err(e) => {
                log::warn!("gettxout error for '{}': {}", entry.alias, e);
            }
        }
    }
    if updated {
        if let Ok(mut all) = db.get_masternode_entries() {
            all.sort_by(|a, b| a.alias.cmp(&b.alias));
            let _ = svc_tx.send(ServiceEvent::MasternodeEntriesLoaded(all));
        }
    }
}

/// Run UTXO consolidation in a background task.
///
/// This function owns all the data it needs (no references to ServiceState),
/// so it can run concurrently without blocking the service select! loop.
#[allow(clippy::too_many_arguments)]
async fn consolidate_utxos_background(
    client: MasternodeClient,
    svc_tx: mpsc::UnboundedSender<ServiceEvent>,
    addresses: Vec<String>,
    addr_to_keypair: std::collections::HashMap<String, wallet::Keypair>,
    wallet_db: Option<WalletDb>,
    consolidation_txids: Arc<Mutex<HashSet<String>>>,
    consolidation_active: Arc<AtomicBool>,
) {
    // Fetch spendable UTXOs per address and keep them grouped so that each
    // batch is sent back to the same address the inputs came from.
    let mut utxos_by_addr: std::collections::BTreeMap<String, Vec<crate::masternode_client::Utxo>> =
        std::collections::BTreeMap::new();
    for addr in &addresses {
        if let Ok(mut utxos) = client.get_utxos(addr).await {
            utxos.retain(|u| u.spendable);
            // Sort smallest-first so dust is consolidated first.
            utxos.sort_by_key(|u| u.amount);
            if utxos.len() > 1 {
                utxos_by_addr.insert(addr.clone(), utxos);
            }
        }
    }

    let total_utxos: usize = utxos_by_addr.values().map(|v| v.len()).sum();
    if total_utxos == 0 {
        consolidation_active.store(false, Ordering::Relaxed);
        let _ = svc_tx.send(ServiceEvent::ConsolidationComplete {
            message: "Nothing to consolidate — already 1 UTXO or fewer per address.".to_string(),
        });
        return;
    }

    let batch_size = 50;
    // Count total batches across all addresses.
    let total_batches: usize = utxos_by_addr
        .values()
        .map(|utxos| utxos.len().div_ceil(batch_size))
        .sum();

    let mut consolidated = 0usize;
    let mut failed = 0usize;
    let mut batch_idx = 0usize;

    for (dest_addr, addr_utxos) in &utxos_by_addr {
        // Validate the destination address (same as source) once per address.
        let dest_address = match wallet::Address::from_string(dest_addr) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Consolidation: invalid address {} — {}", dest_addr, e);
                failed += addr_utxos.len().div_ceil(batch_size);
                batch_idx += addr_utxos.len().div_ceil(batch_size);
                continue;
            }
        };

        for chunk in addr_utxos.chunks(batch_size) {
            if !consolidation_active.load(Ordering::Relaxed) {
                let msg = format!("Consolidation cancelled after {} batch(es).", consolidated);
                let _ = svc_tx.send(ServiceEvent::ConsolidationComplete { message: msg });
                consolidation_txids.lock().unwrap().clear();
                return;
            }

            batch_idx += 1;
            if chunk.len() <= 1 {
                continue;
            }

            let _ = svc_tx.send(ServiceEvent::ConsolidationProgress {
                batch: batch_idx,
                total_batches,
                message: format!(
                    "Consolidating batch {}/{} ({} UTXOs → {})…",
                    batch_idx,
                    total_batches,
                    chunk.len(),
                    &dest_addr[..dest_addr.len().min(16)],
                ),
            });

            // Build transaction directly — bypass create_transaction to avoid
            // double-fee calculation and temp-wallet address mismatch.
            let mut tx = wallet::Transaction::new();
            let mut valid_utxos: Vec<&crate::masternode_client::Utxo> = Vec::new();

            for utxo in chunk {
                let mut tx_hash = [0u8; 32];
                match hex::decode(&utxo.txid) {
                    Ok(bytes) if bytes.len() == 32 => {
                        tx_hash.copy_from_slice(&bytes);
                        tx.add_input(wallet::TxInput::new(tx_hash, utxo.vout));
                        valid_utxos.push(utxo);
                    }
                    _ => {
                        log::warn!(
                            "Consolidation batch {}: skipping UTXO with invalid txid '{}'",
                            batch_idx,
                            utxo.txid
                        );
                    }
                }
            }

            if valid_utxos.is_empty() {
                failed += 1;
                continue;
            }

            let batch_total: u64 = valid_utxos.iter().map(|u| u.amount).sum();
            // Calculate fee on the send_amount (output), not batch_total (input),
            // because the masternode validates fee against the send amount.
            // Iterate to converge since fee depends on send_amount which depends on fee.
            let mut fee = wallet::calculate_fee(batch_total);
            let mut send_amount = batch_total.saturating_sub(fee);
            for _ in 0..5 {
                let required = wallet::calculate_fee(send_amount);
                if required <= fee {
                    break;
                }
                fee = required;
                send_amount = batch_total.saturating_sub(fee);
            }

            if send_amount == 0 {
                log::info!(
                    "Consolidation batch {}: skipped — batch value {} <= min fee {}",
                    batch_idx,
                    batch_total,
                    fee
                );
                continue;
            }

            if tx
                .add_output(wallet::TxOutput::new(send_amount, dest_address.clone()))
                .is_err()
            {
                log::warn!("Consolidation batch {}: failed to add output", batch_idx);
                failed += 1;
                continue;
            }

            // Encrypt "UTXO Consolidation" self-memo using this address's keypair.
            if let Some(kp) = addr_to_keypair.get(dest_addr) {
                let sender_key = ed25519_dalek::SigningKey::from_bytes(&kp.secret_key_bytes());
                let own_pub = sender_key.verifying_key().to_bytes();
                match crate::memo::encrypt_memo(&sender_key, &own_pub, "UTXO Consolidation") {
                    Ok(blob) => tx.encrypted_memo = Some(blob),
                    Err(e) => log::warn!("Consolidation memo encryption failed: {}", e),
                }
            }

            // Sign each input with its address's keypair.
            let mut unsigned_inputs = 0usize;
            for (input_idx, utxo) in valid_utxos.iter().enumerate() {
                match addr_to_keypair.get(&utxo.address) {
                    Some(kp) => {
                        if let Err(e) = tx.sign(kp, input_idx) {
                            log::warn!(
                                "Consolidation batch {}: sign input {} failed: {}",
                                batch_idx,
                                input_idx,
                                e
                            );
                        }
                    }
                    None => {
                        log::warn!(
                            "Consolidation batch {}: no keypair for address {} (input {})",
                            batch_idx,
                            utxo.address,
                            input_idx
                        );
                        unsigned_inputs += 1;
                    }
                }
            }
            if unsigned_inputs > 0 {
                log::warn!(
                    "Consolidation batch {}: {} unsigned inputs — skipping broadcast",
                    batch_idx,
                    unsigned_inputs
                );
                failed += 1;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }

            match tx.to_bytes() {
                Ok(bytes) => {
                    let tx_hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    match client.broadcast_transaction(&tx_hex).await {
                        Ok(txid) => {
                            log::info!(
                                "✅ Consolidation batch {}/{} ({}): {}",
                                batch_idx,
                                total_batches,
                                dest_addr,
                                txid
                            );
                            consolidation_txids.lock().unwrap().insert(txid.clone());
                            consolidated += 1;

                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            let sent_record = crate::masternode_client::TransactionRecord {
                                txid: txid.clone(),
                                vout: 0,
                                is_send: true,
                                address: dest_addr.clone(),
                                amount: send_amount,
                                fee,
                                timestamp: now,
                                status: crate::masternode_client::TransactionStatus::Pending,
                                memo: Some("UTXO Consolidation".to_string()),
                                is_consolidation: true,
                                ..Default::default()
                            };
                            let _ =
                                svc_tx.send(ServiceEvent::TransactionInserted(sent_record.clone()));
                            if let Some(ref db) = wallet_db {
                                let _ = db.save_send_record(&sent_record);
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "❌ Consolidation batch {} broadcast failed: {}",
                                batch_idx,
                                e
                            );
                            failed += 1;
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "❌ Consolidation batch {} serialize failed: {}",
                        batch_idx,
                        e
                    );
                    failed += 1;
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        } // end chunk loop
    } // end per-address loop

    let msg = if failed == 0 {
        format!("Consolidation complete: {} batch(es) sent.", consolidated)
    } else {
        format!(
            "Consolidation finished: {} succeeded, {} failed.",
            consolidated, failed
        )
    };
    let _ = svc_tx.send(ServiceEvent::ConsolidationComplete { message: msg });

    // Refresh UTXOs and balance after consolidation.
    let mut refreshed = Vec::new();
    for addr in &addresses {
        if let Ok(utxos) = client.get_utxos(addr).await {
            refreshed.extend(utxos);
        }
    }
    let _ = svc_tx.send(ServiceEvent::UtxosUpdated(refreshed));
    if let Ok(bal) = client.get_balances(&addresses).await {
        let _ = svc_tx.send(ServiceEvent::BalanceUpdated(bal));
    }
    // Refresh transactions so consolidation txs appear as pending/approved.
    if let Ok(batch) = client.get_transactions_multi(&addresses, 0, 0).await {
        let mut txs = batch.transactions;
        let keys: Vec<ed25519_dalek::SigningKey> = addr_to_keypair
            .values()
            .map(|kp| ed25519_dalek::SigningKey::from_bytes(&kp.secret_key_bytes()))
            .collect();
        decrypt_memos(&mut txs, &keys);
        let _ = svc_tx.send(ServiceEvent::TransactionsUpdated(txs));
    }
    // Clear consolidation txids — the final refresh has correct data now.
    consolidation_txids.lock().unwrap().clear();
    // Re-enable normal polling and WS-triggered refreshes.
    consolidation_active.store(false, Ordering::Relaxed);
}

/// Parse a JSON value from the `getpaymentrequests` RPC into a `PaymentRequest`.
fn parse_payment_request_json(val: &serde_json::Value) -> Option<PaymentRequest> {
    Some(PaymentRequest {
        id: val.get("id")?.as_str()?.to_string(),
        from_address: val.get("from_address")?.as_str()?.to_string(),
        to_address: val.get("to_address")?.as_str()?.to_string(),
        // Masternode returns amount as u64 satoshis; accept float as fallback.
        amount: val.get("amount").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_f64().map(|f| (f * 100_000.0).round() as u64))
        })?,
        // masternode returns "requester_name" for what the wallet calls "label"
        label: val
            .get("requester_name")
            .or_else(|| val.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        memo: val
            .get("memo")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        // masternode returns "pubkey" not "pubkey_hex"
        pubkey_hex: val
            .get("pubkey")
            .or_else(|| val.get("pubkey_hex"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        signature_hex: val
            .get("signature_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        timestamp: val.get("timestamp")?.as_i64()?,
        expires: val.get("expires")?.as_i64()?,
    })
}
