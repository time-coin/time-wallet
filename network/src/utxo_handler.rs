//! UTXO State Protocol Message Handler for P2P Network
//!
//! Handles UTXO-related messages in the P2P network layer, bridging
//! the UTXOStateProtocol with network communication.

use crate::protocol::NetworkMessage;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use time_core::utxo_state_manager::{UTXOStateManager, UTXOStateNotification, UTXOSubscription};
use time_core::OutPoint;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Subscription tracking for wallets
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct WalletSubscription {
    subscriber_id: String,
    ip: IpAddr,
    outpoints: Vec<String>,
    addresses: Vec<String>,
}

/// UTXO Protocol Message Handler
pub struct UTXOProtocolHandler {
    /// Reference to the UTXO state manager
    utxo_manager: Arc<UTXOStateManager>,
    /// Track wallet subscriptions (subscriber_id -> subscription)
    subscriptions: Arc<RwLock<HashMap<String, WalletSubscription>>>,
    /// Track IP to subscriber_id mapping for notifications
    ip_to_subscriber: Arc<RwLock<HashMap<IpAddr, String>>>,
}

impl UTXOProtocolHandler {
    /// Create a new UTXO protocol handler
    pub fn new(utxo_manager: Arc<UTXOStateManager>) -> Self {
        Self {
            utxo_manager,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            ip_to_subscriber: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the notification handler to route to P2P network
    pub async fn setup_notification_handler<F>(&self, sender: F)
    where
        F: Fn(
                IpAddr,
                NetworkMessage,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync
            + 'static
            + Clone,
    {
        let subscriptions = self.subscriptions.clone();
        let ip_to_subscriber = self.ip_to_subscriber.clone();

        self.utxo_manager
            .set_notification_handler(move |notification: UTXOStateNotification| {
                let subscriptions = subscriptions.clone();
                let ip_to_subscriber = ip_to_subscriber.clone();
                let sender = sender.clone();
                let notification = notification.clone();

                Box::pin(async move {
                    // Find all subscribers interested in this UTXO
                    let subs = subscriptions.read().await;
                    let ip_map = ip_to_subscriber.read().await;

                    let interested_subscribers: Vec<_> = subs
                        .iter()
                        .filter(|(_, sub)| {
                            // Check if subscriber is interested in this outpoint or address
                            sub.outpoints.contains(&notification.outpoint.txid)
                                || sub
                                    .addresses
                                    .iter()
                                    .any(|addr| notification.outpoint.txid.contains(addr))
                        })
                        .collect();

                    // Send notification to all interested subscribers
                    for (subscriber_id, _) in interested_subscribers {
                        // Parse subscriber_id as IP (stored in ip_to_subscriber mapping)
                        if let Some(&ip) = ip_map
                            .iter()
                            .find(|(_, id)| *id == subscriber_id)
                            .map(|(ip, _)| ip)
                        {
                            let msg = NetworkMessage::UTXOStateNotification {
                                notification: serde_json::to_string(&notification)
                                    .unwrap_or_default(),
                            };
                            sender(ip, msg).await;
                        }
                    }
                })
            })
            .await;
    }

    /// Handle incoming UTXO protocol messages from peers
    pub async fn handle_message(
        &self,
        message: &NetworkMessage,
        peer_ip: IpAddr,
    ) -> Result<Option<NetworkMessage>, String> {
        match message {
            // Query UTXO states
            NetworkMessage::UTXOStateQuery { outpoints } => {
                debug!(peer = %peer_ip, count = outpoints.len(), "Received UTXO state query");

                let mut states = Vec::new();
                for outpoint_json in outpoints {
                    if let Ok(outpoint) = serde_json::from_str::<OutPoint>(outpoint_json) {
                        if let Some(info) = self.utxo_manager.get_utxo_info(&outpoint).await {
                            states.push((outpoint, info.state));
                        }
                    }
                }

                let response_json = serde_json::to_string(&states)
                    .map_err(|e| format!("Failed to serialize states: {}", e))?;

                Ok(Some(NetworkMessage::UTXOStateResponse {
                    states: response_json,
                }))
            }

            // Subscribe to UTXO updates
            NetworkMessage::UTXOSubscribe {
                outpoints,
                addresses,
                subscriber_id,
            } => {
                info!(
                    peer = %peer_ip,
                    subscriber = %subscriber_id,
                    outpoints = outpoints.len(),
                    addresses = addresses.len(),
                    "Wallet subscribed to UTXO updates"
                );

                let subscription = WalletSubscription {
                    subscriber_id: subscriber_id.clone(),
                    ip: peer_ip,
                    outpoints: outpoints.clone(),
                    addresses: addresses.clone(),
                };

                // Store subscription
                self.subscriptions
                    .write()
                    .await
                    .insert(subscriber_id.clone(), subscription);

                // Map IP to subscriber ID
                self.ip_to_subscriber
                    .write()
                    .await
                    .insert(peer_ip, subscriber_id.clone());

                // Also register in UTXO manager
                let outpoint_set: std::collections::HashSet<_> = outpoints
                    .iter()
                    .filter_map(|op_json| serde_json::from_str::<OutPoint>(op_json).ok())
                    .collect();

                let address_set: std::collections::HashSet<_> = addresses.iter().cloned().collect();

                let utxo_subscription = UTXOSubscription {
                    outpoints: outpoint_set,
                    addresses: address_set,
                    subscriber_id: subscriber_id.clone(),
                };

                self.utxo_manager.add_subscription(utxo_subscription).await;

                Ok(None) // No response needed
            }

            // Unsubscribe from UTXO updates
            NetworkMessage::UTXOUnsubscribe { subscriber_id } => {
                info!(
                    peer = %peer_ip,
                    subscriber = %subscriber_id,
                    "Wallet unsubscribed from UTXO updates"
                );

                // Remove subscription
                self.subscriptions.write().await.remove(subscriber_id);
                self.ip_to_subscriber.write().await.remove(&peer_ip);

                // Remove from UTXO manager
                self.utxo_manager.remove_subscription(subscriber_id).await;

                Ok(None)
            }

            // Handle transaction broadcast - lock UTXOs and trigger voting
            NetworkMessage::TransactionBroadcast(tx) => {
                debug!(
                    peer = %peer_ip,
                    txid = %tx.txid,
                    "Transaction broadcast received - locking UTXOs"
                );

                // Lock all input UTXOs
                for input in &tx.inputs {
                    let outpoint = OutPoint {
                        txid: input.previous_output.txid.clone(),
                        vout: input.previous_output.vout,
                    };

                    match self
                        .utxo_manager
                        .lock_utxo(&outpoint, tx.txid.clone())
                        .await
                    {
                        Ok(_) => {
                            debug!(
                                outpoint = ?outpoint,
                                txid = %tx.txid,
                                "UTXO locked successfully"
                            );
                        }
                        Err(e) => {
                            warn!(
                                outpoint = ?outpoint,
                                txid = %tx.txid,
                                error = %e,
                                "Failed to lock UTXO"
                            );
                            return Err(format!("Failed to lock UTXO: {}", e));
                        }
                    }
                }

                // After locking, the transaction should be forwarded to
                // consensus for voting (handled by caller)
                Ok(None)
            }

            // Process incoming UTXO state notifications from other masternodes
            NetworkMessage::UTXOStateNotification { notification } => {
                if let Ok(notif) = serde_json::from_str::<UTXOStateNotification>(notification) {
                    debug!(
                        peer = %peer_ip,
                        outpoint = ?notif.outpoint,
                        "Received UTXO state notification from peer"
                    );

                    // Update local state based on notification
                    // This keeps our state in sync with the network
                    match &notif.new_state {
                        time_core::utxo_state_manager::UTXOState::Locked { txid, .. } => {
                            let _ = self
                                .utxo_manager
                                .lock_utxo(&notif.outpoint, txid.clone())
                                .await;
                        }
                        time_core::utxo_state_manager::UTXOState::SpentPending {
                            txid,
                            votes,
                            total_nodes,
                            ..
                        } => {
                            let _ = self
                                .utxo_manager
                                .mark_spent_pending(
                                    &notif.outpoint,
                                    txid.clone(),
                                    *votes,
                                    *total_nodes,
                                )
                                .await;
                        }
                        time_core::utxo_state_manager::UTXOState::SpentFinalized {
                            txid,
                            votes,
                            ..
                        } => {
                            let _ = self
                                .utxo_manager
                                .mark_spent_finalized(&notif.outpoint, txid.clone(), *votes)
                                .await;
                        }
                        time_core::utxo_state_manager::UTXOState::Confirmed {
                            txid,
                            block_height,
                            ..
                        } => {
                            let _ = self
                                .utxo_manager
                                .mark_confirmed(&notif.outpoint, txid.clone(), *block_height)
                                .await;
                        }
                        _ => {}
                    }
                }

                Ok(None)
            }

            _ => Ok(None), // Not a UTXO protocol message
        }
    }

    /// Get count of active subscriptions
    pub async fn subscription_count(&self) -> usize {
        self.subscriptions.read().await.len()
    }

    /// Broadcast UTXO state notification to all masternodes
    pub async fn broadcast_state_notification<F>(
        &self,
        notification: UTXOStateNotification,
        broadcast_fn: F,
    ) where
        F: Fn(NetworkMessage),
    {
        let msg = NetworkMessage::UTXOStateNotification {
            notification: serde_json::to_string(&notification).unwrap_or_default(),
        };

        broadcast_fn(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscription_tracking() {
        let utxo_manager = Arc::new(UTXOStateManager::new("test-node".to_string()));
        let handler = UTXOProtocolHandler::new(utxo_manager);

        assert_eq!(handler.subscription_count().await, 0);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let msg = NetworkMessage::UTXOSubscribe {
            outpoints: vec!["test_outpoint".to_string()],
            addresses: vec!["test_address".to_string()],
            subscriber_id: "test_sub".to_string(),
        };

        let _ = handler.handle_message(&msg, ip).await;
        assert_eq!(handler.subscription_count().await, 1);
    }
}
