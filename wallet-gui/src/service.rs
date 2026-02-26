//! Background service task — single `select!` loop, no spawns, no sleeps.
//!
//! The service owns all async I/O. It receives [`UiEvent`]s from the UI thread,
//! calls the masternode JSON-RPC client, and sends [`ServiceEvent`]s back.
//! WebSocket events are forwarded as-is.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use std::time::Instant;

use crate::config_new::Config;
use crate::events::{Screen, ServiceEvent, UiEvent};
use crate::masternode_client::MasternodeClient;
use crate::peer_discovery;
use crate::state::{AddressInfo, PeerInfo};
use crate::wallet_dat;
use crate::wallet_db::{AddressContact, WalletDb};
use crate::wallet_manager::WalletManager;
use crate::ws_client::{WsClient, WsEvent};
use wallet::NetworkType;

type DiscoveryHandle = tokio::task::JoinHandle<Result<(String, Vec<PeerInfo>), ()>>;

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
    let (ws_shutdown_tx, ws_shutdown_rx) = tokio::sync::watch::channel(false);

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

    let mut state = ServiceState {
        svc_tx,
        client: None,
        wallet: None,
        wallet_db,
        addresses: Vec::new(),
        network_type,
        config: config.clone(),
        ws_event_tx,
        ws_shutdown_rx,
        ws_handle: None,
    };

    // Kick off peer discovery in the background
    let is_testnet = config.is_testnet();
    let manual_endpoints = config.manual_endpoints();
    let discovery_svc_tx = state.svc_tx.clone();
    let discovery_endpoints = manual_endpoints.clone();
    let mut discovery_handle: Option<DiscoveryHandle> = Some(tokio::spawn(async move {
        discover_peers(is_testnet, discovery_endpoints, &discovery_svc_tx).await
    }));

    // Periodic refresh every 5 seconds
    let mut refresh_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the first immediate tick — the initial discovery is already in flight
    refresh_interval.tick().await;

    log::info!("🚀 Service loop started ({})", state.config.network);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                log::info!("🛑 Service loop shutting down");
                let _ = ws_shutdown_tx.send(true);
                break;
            }

            // Periodic peer refresh
            _ = refresh_interval.tick(), if discovery_handle.is_none() => {
                let tx = state.svc_tx.clone();
                let eps = manual_endpoints.clone();
                discovery_handle = Some(tokio::spawn(async move {
                    discover_peers(is_testnet, eps, &tx).await
                }));
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
                if let Ok(Ok((endpoint, peer_infos))) = result {
                    let _ = state.svc_tx.send(ServiceEvent::PeersDiscovered(peer_infos));

                    // Only switch active peer if we don't have one yet
                    if state.client.is_none() {
                        log::info!("🔗 Using peer: {}", endpoint);
                        state.client = Some(MasternodeClient::new(endpoint.clone()));
                        state.config.active_endpoint = Some(endpoint.clone());
                        config.active_endpoint = Some(endpoint);

                        // If wallet is already loaded, start WS and fetch data
                        if !state.addresses.is_empty() {
                            state.start_ws();
                            if let Some(ref client) = state.client {
                                if let Ok(bal) = client.get_balances(&state.addresses).await {
                                    let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                }
                            }
                        }
                    }
                }
            }

            Some(event) = ui_rx.recv() => {
                match event {
                    UiEvent::Shutdown => {
                        let _ = ws_shutdown_tx.send(true);
                        break;
                    }

                    UiEvent::LoadWallet { password } => {
                        state.load_wallet(password);
                    }

                    UiEvent::CreateWallet { mnemonic, password } => {
                        state.create_wallet(&mnemonic, password);
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
                                match client.get_transactions_multi(&state.addresses, 100).await {
                                    Ok(txs) => { let _ = state.svc_tx.send(ServiceEvent::TransactionsUpdated(txs)); }
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
                            let _ = state.svc_tx.send(ServiceEvent::UtxosUpdated(all_utxos));
                        }
                    }

                    UiEvent::SendTransaction { to, amount, fee } => {
                        if let Some(ref client) = state.client {
                            if let Some(ref mut wm) = state.wallet {
                                match wm.create_transaction(&to, amount, fee) {
                                    Ok(tx) => {
                                        let tx_hex = serde_json::to_string(&tx).unwrap_or_default();
                                        match client.broadcast_transaction(&tx_hex).await {
                                            Ok(txid) => {
                                                let _ = state.svc_tx.send(ServiceEvent::TransactionSent { txid });
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
                                            format!("Failed to create transaction: {}", e),
                                        ));
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
                                        if let Ok(txs) = client.get_transactions_multi(&state.addresses, 100).await {
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
                                        let _ = state.svc_tx.send(ServiceEvent::UtxosUpdated(all));
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
                }
            }

            Some(ws_event) = ws_event_rx.recv() => {
                match ws_event {
                    WsEvent::TransactionReceived(notification) => {
                        let _ = state.svc_tx.send(ServiceEvent::TransactionReceived(notification));
                        if let Some(ref client) = state.client {
                            if !state.addresses.is_empty() {
                                if let Ok(bal) = client.get_balances(&state.addresses).await {
                                    let _ = state.svc_tx.send(ServiceEvent::BalanceUpdated(bal));
                                }
                            }
                        }
                    }
                    WsEvent::Connected(_) => {
                        let _ = state.svc_tx.send(ServiceEvent::WsConnected);
                    }
                    WsEvent::Disconnected(_) => {
                        let _ = state.svc_tx.send(ServiceEvent::WsDisconnected);
                    }
                }
            }
        }
    }

    log::info!("👋 Service loop exited");
}

/// Discover and health-check peers in the background.
/// Returns the best endpoint and the full peer info list.
async fn discover_peers(
    is_testnet: bool,
    manual_endpoints: Vec<String>,
    svc_tx: &mpsc::UnboundedSender<ServiceEvent>,
) -> Result<(String, Vec<PeerInfo>), ()> {
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
            "No peers available. Add peers to config.toml or check your internet connection."
                .to_string(),
        ));
        return Err(());
    }

    // Probe all peers in parallel with a short timeout
    let probe_timeout = std::time::Duration::from_secs(8);
    let mut handles = Vec::new();
    for endpoint in endpoints.clone() {
        handles.push(tokio::spawn(async move {
            let client = MasternodeClient::new(endpoint.clone());
            let start = Instant::now();
            let (is_healthy, ping_ms, block_height, version) =
                match tokio::time::timeout(probe_timeout, client.health_check()).await {
                    Ok(Ok(health)) => {
                        let ms = start.elapsed().as_millis() as u64;
                        (
                            true,
                            Some(ms),
                            Some(health.block_height),
                            Some(health.version),
                        )
                    }
                    Ok(Err(e)) => {
                        log::warn!("⚠ Peer {} unhealthy: {}", endpoint, e);
                        (false, None, None, None)
                    }
                    Err(_) => {
                        log::warn!("⚠ Peer {} timed out", endpoint);
                        (false, None, None, None)
                    }
                };

            // Probe WebSocket connectivity (WS port = RPC port + 1)
            let ws_available = if is_healthy {
                let ws_url = crate::config_new::Config::derive_ws_url(&endpoint);
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    tokio_tungstenite::connect_async(&ws_url),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false)
            } else {
                false
            };

            PeerInfo {
                endpoint,
                is_active: false,
                is_healthy,
                ws_available,
                ping_ms,
                block_height,
                version,
            }
        }));
    }

    let mut peer_infos = Vec::new();
    for handle in handles {
        if let Ok(info) = handle.await {
            peer_infos.push(info);
        }
    }

    // Sort: WS-capable first, then healthy by fastest ping, unhealthy last
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

    let active_endpoint = peer_infos
        .iter()
        .find(|p| p.is_healthy)
        .map(|p| p.endpoint.clone())
        .unwrap_or_else(|| {
            log::warn!("⚠ No peers responded to health check, using first peer");
            endpoints[0].clone()
        });

    for p in &mut peer_infos {
        p.is_active = p.endpoint == active_endpoint;
    }

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
    ws_shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ws_handle: Option<tokio::task::JoinHandle<()>>,
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
                let raw_addrs = derive_addresses(&mut wm);
                self.addresses = raw_addrs.clone();
                let address_infos: Vec<AddressInfo> = raw_addrs
                    .iter()
                    .enumerate()
                    .map(|(i, addr)| {
                        let label = self
                            .wallet_db
                            .as_ref()
                            .and_then(|db| db.get_contact(addr).ok().flatten())
                            .map(|c| c.label)
                            .unwrap_or_else(|| format!("Address #{}", i));
                        AddressInfo {
                            address: addr.clone(),
                            label,
                        }
                    })
                    .collect();
                let is_testnet = self.network_type == NetworkType::Testnet;
                let _ = self.svc_tx.send(ServiceEvent::WalletLoaded {
                    addresses: address_infos,
                    is_testnet,
                });
                self.wallet = Some(wm);
                // Only start WS if we already have a peer connection
                if self.config.active_endpoint.is_some() {
                    self.start_ws();
                }
            }
            Err(e) => {
                let _ = self
                    .svc_tx
                    .send(ServiceEvent::Error(format!("Wallet error: {}", e)));
            }
        }
    }

    /// Start (or restart) the WebSocket client for current addresses.
    fn start_ws(&mut self) {
        if let Some(h) = self.ws_handle.take() {
            h.abort();
        }
        let handle = WsClient::start(
            self.config.ws_url(),
            self.addresses.clone(),
            self.ws_event_tx.clone(),
            self.ws_shutdown_rx.clone(),
        );
        self.ws_handle = Some(handle);
    }
}

/// Derive all known addresses from the wallet manager.
/// Ensures at least one address exists.
fn derive_addresses(wm: &mut WalletManager) -> Vec<String> {
    // Ensure at least one address is derived
    if wm.get_address_count() == 0 {
        let _ = wm.get_next_address();
    }
    (0..wm.get_address_count())
        .filter_map(|i| wm.derive_address(i).ok())
        .collect()
}
