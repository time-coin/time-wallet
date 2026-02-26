use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::masternode_client;
use crate::network::NetworkManager;
use crate::peer_manager::PeerManager;
use crate::wallet_db::{self, WalletDb};
use crate::{AppStateUpdate, BackgroundCommand};

/// Shared resources that the coordinator needs to fulfil commands.
pub struct CoordinatorResources {
    pub peer_manager: Option<Arc<PeerManager>>,
    pub network_manager: Option<Arc<std::sync::RwLock<NetworkManager>>>,
    pub masternode_client: Option<masternode_client::MasternodeClient>,
    pub wallet_db: Option<WalletDb>,
    pub state_tx: Option<mpsc::UnboundedSender<AppStateUpdate>>,
}

/// Spawn the background coordinator task.
///
/// Returns immediately. The task runs until `token` is cancelled
/// or `command_rx` is closed (WalletApp dropped).
pub fn spawn(
    token: CancellationToken,
    mut command_rx: mpsc::UnboundedReceiver<BackgroundCommand>,
    resources: Arc<tokio::sync::RwLock<CoordinatorResources>>,
) {
    tokio::spawn(async move {
        log::info!("🎛️ Background coordinator started");

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    log::info!("🛑 Background coordinator shutting down");
                    break;
                }
                cmd = command_rx.recv() => {
                    let Some(cmd) = cmd else {
                        log::info!("🛑 Command channel closed, coordinator exiting");
                        break;
                    };
                    handle_command(&resources, cmd).await;
                }
            }
        }
    });
}

async fn handle_command(resources: &Arc<tokio::sync::RwLock<CoordinatorResources>>, cmd: BackgroundCommand) {
    match cmd {
        BackgroundCommand::DiscoverPeers => handle_discover_peers(resources).await,
        BackgroundCommand::RefreshNetwork => handle_refresh_network(resources).await,
        BackgroundCommand::RefreshLatency => handle_refresh_latency(resources).await,
        BackgroundCommand::RefreshBalance { addresses } => {
            handle_refresh_balance(resources, &addresses).await;
        }
        BackgroundCommand::SyncTransactions { addresses } => {
            handle_sync_transactions(resources, &addresses).await;
        }
    }
}

async fn handle_discover_peers(resources: &Arc<tokio::sync::RwLock<CoordinatorResources>>) {
    let res = resources.read().await;
    let Some(peer_mgr) = &res.peer_manager else {
        log::debug!("No peer manager available for discovery");
        return;
    };
    let peer_mgr = peer_mgr.clone();
    drop(res);

    log::debug!("Running peer discovery...");
    if let Some(new_peers) = peer_mgr.try_get_peer_list().await {
        peer_mgr.add_peers(new_peers).await;
        log::debug!("Discovered and added peers");
    }
}

async fn handle_refresh_network(resources: &Arc<tokio::sync::RwLock<CoordinatorResources>>) {
    let res = resources.read().await;
    let Some(network_mgr) = &res.network_manager else {
        log::debug!("No network manager available for refresh");
        return;
    };
    let network_mgr = network_mgr.clone();
    drop(res);

    use crate::timeout_util::{safe_timeout, timeouts};

    let result = safe_timeout(timeouts::NETWORK_SLOW, async move {
        let manager = network_mgr.write().unwrap();
        // periodic_refresh is async but called inside sync RwLock — matches existing pattern
        log::debug!("Periodic refresh triggered");
    })
    .await;

    if result.timed_out {
        log::warn!("⏱️ Periodic refresh timeout after 30s");
    }
}

async fn handle_refresh_latency(resources: &Arc<tokio::sync::RwLock<CoordinatorResources>>) {
    let res = resources.read().await;
    let Some(network_mgr) = &res.network_manager else {
        log::debug!("No network manager available for latency refresh");
        return;
    };
    let network_mgr = network_mgr.clone();
    drop(res);

    log::debug!("Refreshing peer latencies...");
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        #[allow(clippy::await_holding_lock)]
        rt.block_on(async {
            let mut net = network_mgr.write().unwrap();
            let _ = net.refresh_peer_latencies().await;
        });
    })
    .await
    .ok();
}

async fn handle_refresh_balance(
    resources: &Arc<tokio::sync::RwLock<CoordinatorResources>>,
    addresses: &[String],
) {
    let res = resources.read().await;
    let Some(client) = &res.masternode_client else {
        log::warn!("No masternode client available for balance refresh");
        return;
    };
    let client = client.clone();
    let state_tx = res.state_tx.clone();
    drop(res);

    log::info!("📡 Fetching balance from masternode...");
    match client.get_balances(addresses).await {
        Ok(balance) => {
            log::info!(
                "✅ Balance: {} TIME (confirmed: {}, pending: {})",
                balance.total,
                balance.confirmed,
                balance.pending
            );
            if let Some(tx) = &state_tx {
                let _ = tx.send(AppStateUpdate::BalanceUpdated(balance.total));
            }
        }
        Err(e) => {
            log::error!("❌ Failed to fetch balance: {}", e);
            if let Some(tx) = &state_tx {
                let _ = tx.send(AppStateUpdate::ErrorOccurred(format!(
                    "Failed to fetch balance: {}",
                    e
                )));
            }
        }
    }
}

async fn handle_sync_transactions(
    resources: &Arc<tokio::sync::RwLock<CoordinatorResources>>,
    addresses: &[String],
) {
    let res = resources.read().await;
    let Some(client) = &res.masternode_client else {
        log::warn!("No masternode client available for transaction sync");
        return;
    };
    let client = client.clone();
    let wallet_db = res.wallet_db.clone();
    let state_tx = res.state_tx.clone();
    drop(res);

    log::info!("📡 Fetching transactions from masternode...");
    match client.get_transactions_multi(addresses, 1000).await {
        Ok(transactions) => {
            log::info!(
                "✅ Received {} transactions from masternode",
                transactions.len()
            );

            if let Some(db) = &wallet_db {
                for tx in transactions {
                    let tx_record = wallet_db::TransactionRecord {
                        tx_hash: tx.txid.clone(),
                        from_address: tx.from.first().cloned(),
                        to_address: tx.to.first().cloned().unwrap_or_default(),
                        amount: tx.amount,
                        timestamp: tx.timestamp,
                        block_height: Some(tx.confirmations as u64),
                        status: match tx.status {
                            masternode_client::TransactionStatus::Confirmed => {
                                wallet_db::TransactionStatus::Confirmed
                            }
                            masternode_client::TransactionStatus::Pending => {
                                wallet_db::TransactionStatus::Pending
                            }
                            masternode_client::TransactionStatus::Failed => {
                                wallet_db::TransactionStatus::Confirmed
                            }
                        },
                        notes: None,
                    };

                    if let Err(e) = db.save_transaction(&tx_record) {
                        log::warn!("Failed to save transaction: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            log::error!("❌ Failed to fetch transactions: {}", e);
            if let Some(tx) = &state_tx {
                let _ = tx.send(AppStateUpdate::ErrorOccurred(format!(
                    "Failed to fetch transactions: {}",
                    e
                )));
            }
        }
    }

    if let Some(tx) = &resources.read().await.state_tx {
        let _ = tx.send(AppStateUpdate::SyncCompleted);
    }
}
