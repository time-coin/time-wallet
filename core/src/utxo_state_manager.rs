//! UTXO State Protocol for Instant Finality
//!
//! This module implements a real-time UTXO state tracking and notification system
//! that enables instant transaction finality. It tracks the lifecycle of UTXOs
//! and notifies all connected parties about state changes, allowing for sub-second
//! transaction confirmation through masternode consensus.
//!
//! ## UTXO State Lifecycle
//!
//! 1. **Unspent** - UTXO exists and is available for spending
//! 2. **Locked** - UTXO is referenced by a pending transaction (prevents double-spend)
//! 3. **SpentPending** - Transaction spending this UTXO has been broadcast but not finalized
//! 4. **SpentFinalized** - Transaction has reached consensus (instant finality achieved)
//! 5. **Confirmed** - Transaction included in a block
//!
//! ## Protocol Flow
//!
//! ```text
//! 1. User broadcasts transaction spending UTXO_A
//! 2. Node locks UTXO_A and broadcasts state change to network
//! 3. Masternodes validate transaction and vote
//! 4. When quorum reached (67%), UTXO_A moves to SpentFinalized
//! 5. State change notification sent to all connected parties
//! 6. Block producer includes transaction in next block
//! 7. UTXO_A marked as Confirmed
//! ```

use crate::{OutPoint, Transaction, TxOutput};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Type alias for notification handler to reduce type complexity
type NotificationHandler = Arc<
    RwLock<
        Option<
            Box<
                dyn Fn(
                        UTXOStateNotification,
                    )
                        -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        >,
    >,
>;

/// State of a UTXO in the system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UTXOState {
    /// UTXO exists and is available for spending
    Unspent,
    /// UTXO is locked by a pending transaction (prevents double-spend)
    Locked {
        /// Transaction ID that locked this UTXO
        txid: String,
        /// Timestamp when locked
        locked_at: i64,
    },
    /// Transaction spending this UTXO is broadcast but not finalized
    SpentPending {
        /// Transaction ID spending this UTXO
        txid: String,
        /// Number of votes received
        votes: usize,
        /// Total masternode count
        total_nodes: usize,
        /// Timestamp when spending started
        spent_at: i64,
    },
    /// Transaction has reached consensus (instant finality)
    SpentFinalized {
        /// Transaction ID that spent this UTXO
        txid: String,
        /// When finality was achieved
        finalized_at: i64,
        /// Number of votes that approved
        votes: usize,
    },
    /// Transaction confirmed in a block
    Confirmed {
        /// Transaction ID
        txid: String,
        /// Block height
        block_height: u64,
        /// Block timestamp
        confirmed_at: i64,
    },
}

impl UTXOState {
    /// Check if UTXO can be spent
    pub fn is_spendable(&self) -> bool {
        matches!(self, UTXOState::Unspent)
    }

    /// Check if UTXO is locked or spent
    pub fn is_locked_or_spent(&self) -> bool {
        !matches!(self, UTXOState::Unspent)
    }

    /// Get the transaction ID associated with this state
    pub fn txid(&self) -> Option<&str> {
        match self {
            UTXOState::Locked { txid, .. }
            | UTXOState::SpentPending { txid, .. }
            | UTXOState::SpentFinalized { txid, .. }
            | UTXOState::Confirmed { txid, .. } => Some(txid),
            UTXOState::Unspent => None,
        }
    }
}

/// Information about a UTXO and its current state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOInfo {
    /// The outpoint identifying this UTXO
    pub outpoint: OutPoint,
    /// The output data (amount, address)
    pub output: TxOutput,
    /// Current state
    pub state: UTXOState,
    /// When this UTXO was created
    pub created_at: i64,
    /// Last time state was updated
    pub updated_at: i64,
}

/// Notification message for UTXO state changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOStateNotification {
    /// UTXO that changed
    pub outpoint: OutPoint,
    /// Previous state
    pub old_state: UTXOState,
    /// New state
    pub new_state: UTXOState,
    /// Timestamp of change
    pub timestamp: i64,
    /// Node that initiated the change
    pub originator: String,
}

/// Subscription to UTXO state changes
#[derive(Debug, Clone)]
pub struct UTXOSubscription {
    /// Outpoints being watched
    pub outpoints: HashSet<OutPoint>,
    /// Addresses being watched (all UTXOs for these addresses)
    pub addresses: HashSet<String>,
    /// Subscriber identifier (e.g., IP address, node ID)
    pub subscriber_id: String,
}

/// UTXO State Manager - tracks and notifies about UTXO state changes
pub struct UTXOStateManager {
    /// All UTXOs and their current states
    utxos: Arc<RwLock<HashMap<OutPoint, UTXOInfo>>>,
    /// Active subscriptions
    subscriptions: Arc<RwLock<Vec<UTXOSubscription>>>,
    /// Node identifier
    node_id: String,
    /// Callback for sending notifications (async closure)
    notification_handler: NotificationHandler,
}

// Manual Debug implementation since notification_handler cannot derive Debug
impl std::fmt::Debug for UTXOStateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UTXOStateManager")
            .field("node_id", &self.node_id)
            .field("utxo_count", &"<async>")
            .field("subscription_count", &"<async>")
            .finish()
    }
}

impl UTXOStateManager {
    /// Create a new UTXO state manager
    pub fn new(node_id: String) -> Self {
        Self {
            utxos: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            node_id,
            notification_handler: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the notification handler
    pub async fn set_notification_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(UTXOStateNotification) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let boxed_handler = Box::new(move |notification: UTXOStateNotification| {
            Box::pin(handler(notification))
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        });
        let mut handler_guard = self.notification_handler.write().await;
        *handler_guard = Some(boxed_handler);
    }

    /// Add a new UTXO to track
    pub async fn add_utxo(&self, outpoint: OutPoint, output: TxOutput) -> Result<(), String> {
        let mut utxos = self.utxos.write().await;

        if utxos.contains_key(&outpoint) {
            return Err(format!("UTXO {} already exists", outpoint.txid));
        }

        let now = chrono::Utc::now().timestamp();
        let info = UTXOInfo {
            outpoint: outpoint.clone(),
            output,
            state: UTXOState::Unspent,
            created_at: now,
            updated_at: now,
        };

        utxos.insert(outpoint, info);
        Ok(())
    }

    /// Get UTXO state
    pub async fn get_state(&self, outpoint: &OutPoint) -> Option<UTXOState> {
        let utxos = self.utxos.read().await;
        utxos.get(outpoint).map(|info| info.state.clone())
    }

    /// Get full UTXO info
    pub async fn get_utxo_info(&self, outpoint: &OutPoint) -> Option<UTXOInfo> {
        let utxos = self.utxos.read().await;
        utxos.get(outpoint).cloned()
    }

    /// Lock a UTXO for a pending transaction
    pub async fn lock_utxo(&self, outpoint: &OutPoint, txid: String) -> Result<(), String> {
        let mut utxos = self.utxos.write().await;

        let info = utxos
            .get_mut(outpoint)
            .ok_or_else(|| format!("UTXO not found: {:?}", outpoint))?;

        // Only unspent UTXOs can be locked
        if !info.state.is_spendable() {
            return Err(format!(
                "UTXO {} is not spendable (current state: {:?})",
                outpoint.txid, info.state
            ));
        }

        let old_state = info.state.clone();
        let now = chrono::Utc::now().timestamp();

        info.state = UTXOState::Locked {
            txid: txid.clone(),
            locked_at: now,
        };
        info.updated_at = now;

        // Drop the write lock before sending notification
        let notification = UTXOStateNotification {
            outpoint: outpoint.clone(),
            old_state,
            new_state: info.state.clone(),
            timestamp: now,
            originator: self.node_id.clone(),
        };
        drop(utxos);

        self.notify_subscribers(notification).await;

        Ok(())
    }

    /// Mark UTXO as spent (pending finality)
    pub async fn mark_spent_pending(
        &self,
        outpoint: &OutPoint,
        txid: String,
        votes: usize,
        total_nodes: usize,
    ) -> Result<(), String> {
        let mut utxos = self.utxos.write().await;

        let info = utxos
            .get_mut(outpoint)
            .ok_or_else(|| format!("UTXO not found: {:?}", outpoint))?;

        let old_state = info.state.clone();
        let now = chrono::Utc::now().timestamp();

        info.state = UTXOState::SpentPending {
            txid: txid.clone(),
            votes,
            total_nodes,
            spent_at: now,
        };
        info.updated_at = now;

        let notification = UTXOStateNotification {
            outpoint: outpoint.clone(),
            old_state,
            new_state: info.state.clone(),
            timestamp: now,
            originator: self.node_id.clone(),
        };
        drop(utxos);

        self.notify_subscribers(notification).await;

        Ok(())
    }

    /// Mark UTXO as finalized (instant finality achieved)
    pub async fn mark_spent_finalized(
        &self,
        outpoint: &OutPoint,
        txid: String,
        votes: usize,
    ) -> Result<(), String> {
        let mut utxos = self.utxos.write().await;

        let info = utxos
            .get_mut(outpoint)
            .ok_or_else(|| format!("UTXO not found: {:?}", outpoint))?;

        let old_state = info.state.clone();
        let now = chrono::Utc::now().timestamp();

        info.state = UTXOState::SpentFinalized {
            txid: txid.clone(),
            finalized_at: now,
            votes,
        };
        info.updated_at = now;

        let notification = UTXOStateNotification {
            outpoint: outpoint.clone(),
            old_state,
            new_state: info.state.clone(),
            timestamp: now,
            originator: self.node_id.clone(),
        };
        drop(utxos);

        self.notify_subscribers(notification).await;

        Ok(())
    }

    /// Mark UTXO as confirmed in a block
    pub async fn mark_confirmed(
        &self,
        outpoint: &OutPoint,
        txid: String,
        block_height: u64,
    ) -> Result<(), String> {
        let mut utxos = self.utxos.write().await;

        let info = utxos
            .get_mut(outpoint)
            .ok_or_else(|| format!("UTXO not found: {:?}", outpoint))?;

        let old_state = info.state.clone();
        let now = chrono::Utc::now().timestamp();

        info.state = UTXOState::Confirmed {
            txid: txid.clone(),
            block_height,
            confirmed_at: now,
        };
        info.updated_at = now;

        let notification = UTXOStateNotification {
            outpoint: outpoint.clone(),
            old_state,
            new_state: info.state.clone(),
            timestamp: now,
            originator: self.node_id.clone(),
        };
        drop(utxos);

        self.notify_subscribers(notification).await;

        Ok(())
    }

    /// Unlock a UTXO (e.g., if transaction fails)
    pub async fn unlock_utxo(&self, outpoint: &OutPoint) -> Result<(), String> {
        let mut utxos = self.utxos.write().await;

        let info = utxos
            .get_mut(outpoint)
            .ok_or_else(|| format!("UTXO not found: {:?}", outpoint))?;

        let old_state = info.state.clone();
        let now = chrono::Utc::now().timestamp();

        info.state = UTXOState::Unspent;
        info.updated_at = now;

        let notification = UTXOStateNotification {
            outpoint: outpoint.clone(),
            old_state,
            new_state: UTXOState::Unspent,
            timestamp: now,
            originator: self.node_id.clone(),
        };
        drop(utxos);

        self.notify_subscribers(notification).await;

        Ok(())
    }

    /// Process a transaction and update UTXO states
    pub async fn process_transaction(
        &self,
        tx: &Transaction,
        votes: usize,
        total_nodes: usize,
    ) -> Result<(), String> {
        // Lock input UTXOs
        for input in &tx.inputs {
            self.lock_utxo(&input.previous_output, tx.txid.clone())
                .await?;
        }

        // Mark inputs as spent pending
        for input in &tx.inputs {
            self.mark_spent_pending(&input.previous_output, tx.txid.clone(), votes, total_nodes)
                .await?;
        }

        // Add output UTXOs
        for (vout, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(tx.txid.clone(), vout as u32);
            self.add_utxo(outpoint, output.clone()).await?;
        }

        Ok(())
    }

    /// Finalize a transaction (instant finality achieved)
    pub async fn finalize_transaction(&self, tx: &Transaction, votes: usize) -> Result<(), String> {
        // Mark all inputs as finalized
        for input in &tx.inputs {
            self.mark_spent_finalized(&input.previous_output, tx.txid.clone(), votes)
                .await?;
        }

        Ok(())
    }

    /// Subscribe to UTXO state changes
    pub async fn subscribe(&self, subscription: UTXOSubscription) {
        let mut subs = self.subscriptions.write().await;
        subs.push(subscription);
    }

    /// Add a subscription (alias for subscribe for compatibility)
    pub async fn add_subscription(&self, subscription: UTXOSubscription) {
        self.subscribe(subscription).await;
    }

    /// Unsubscribe from UTXO state changes
    pub async fn unsubscribe(&self, subscriber_id: &str) {
        let mut subs = self.subscriptions.write().await;
        subs.retain(|sub| sub.subscriber_id != subscriber_id);
    }

    /// Remove a subscription (alias for unsubscribe for compatibility)
    pub async fn remove_subscription(&self, subscriber_id: &str) {
        self.unsubscribe(subscriber_id).await;
    }

    /// Notify subscribers about state change
    async fn notify_subscribers(&self, notification: UTXOStateNotification) {
        let subs = self.subscriptions.read().await;

        // Find matching subscriptions
        for sub in subs.iter() {
            let should_notify = sub.outpoints.contains(&notification.outpoint)
                || (notification.old_state == UTXOState::Unspent
                    && self
                        .is_address_subscribed(sub, &notification.outpoint)
                        .await);

            if should_notify {
                // Use the notification handler if set
                let handler_guard = self.notification_handler.read().await;
                if let Some(handler) = handler_guard.as_ref() {
                    handler(notification.clone()).await;
                }
            }
        }
    }

    /// Check if an address is subscribed
    async fn is_address_subscribed(&self, sub: &UTXOSubscription, outpoint: &OutPoint) -> bool {
        if sub.addresses.is_empty() {
            return false;
        }

        let utxos = self.utxos.read().await;
        if let Some(info) = utxos.get(outpoint) {
            return sub.addresses.contains(&info.output.address);
        }

        false
    }

    /// Get all UTXOs for an address
    pub async fn get_utxos_by_address(&self, address: &str) -> Vec<UTXOInfo> {
        let utxos = self.utxos.read().await;
        utxos
            .values()
            .filter(|info| info.output.address == address)
            .cloned()
            .collect()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> UTXOStateStats {
        let utxos = self.utxos.read().await;
        let subs = self.subscriptions.read().await;

        let mut stats = UTXOStateStats {
            total_utxos: utxos.len(),
            unspent: 0,
            locked: 0,
            spent_pending: 0,
            spent_finalized: 0,
            confirmed: 0,
            active_subscriptions: subs.len(),
        };

        for info in utxos.values() {
            match info.state {
                UTXOState::Unspent => stats.unspent += 1,
                UTXOState::Locked { .. } => stats.locked += 1,
                UTXOState::SpentPending { .. } => stats.spent_pending += 1,
                UTXOState::SpentFinalized { .. } => stats.spent_finalized += 1,
                UTXOState::Confirmed { .. } => stats.confirmed += 1,
            }
        }

        stats
    }
}

/// Statistics about UTXO states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOStateStats {
    pub total_utxos: usize,
    pub unspent: usize,
    pub locked: usize,
    pub spent_pending: usize,
    pub spent_finalized: usize,
    pub confirmed: usize,
    pub active_subscriptions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_utxo_lifecycle() {
        let manager = UTXOStateManager::new("test_node".to_string());

        // Create a UTXO
        let outpoint = OutPoint::new("tx1".to_string(), 0);
        let output = TxOutput::new(1000, "addr1".to_string());

        manager.add_utxo(outpoint.clone(), output).await.unwrap();

        // Check initial state
        let state = manager.get_state(&outpoint).await.unwrap();
        assert_eq!(state, UTXOState::Unspent);

        // Lock UTXO
        manager
            .lock_utxo(&outpoint, "tx2".to_string())
            .await
            .unwrap();

        let state = manager.get_state(&outpoint).await.unwrap();
        assert!(matches!(state, UTXOState::Locked { .. }));

        // Mark as spent pending
        manager
            .mark_spent_pending(&outpoint, "tx2".to_string(), 2, 3)
            .await
            .unwrap();

        let state = manager.get_state(&outpoint).await.unwrap();
        assert!(matches!(state, UTXOState::SpentPending { .. }));

        // Finalize
        manager
            .mark_spent_finalized(&outpoint, "tx2".to_string(), 2)
            .await
            .unwrap();

        let state = manager.get_state(&outpoint).await.unwrap();
        assert!(matches!(state, UTXOState::SpentFinalized { .. }));

        // Confirm
        manager
            .mark_confirmed(&outpoint, "tx2".to_string(), 100)
            .await
            .unwrap();

        let state = manager.get_state(&outpoint).await.unwrap();
        assert!(matches!(state, UTXOState::Confirmed { .. }));
    }

    #[tokio::test]
    async fn test_double_spend_prevention() {
        let manager = UTXOStateManager::new("test_node".to_string());

        let outpoint = OutPoint::new("tx1".to_string(), 0);
        let output = TxOutput::new(1000, "addr1".to_string());

        manager.add_utxo(outpoint.clone(), output).await.unwrap();

        // Lock UTXO with first transaction
        manager
            .lock_utxo(&outpoint, "tx2".to_string())
            .await
            .unwrap();

        // Try to lock with second transaction - should fail
        let result = manager.lock_utxo(&outpoint, "tx3".to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_subscription() {
        let manager = UTXOStateManager::new("test_node".to_string());

        let outpoint = OutPoint::new("tx1".to_string(), 0);
        let mut watched = HashSet::new();
        watched.insert(outpoint.clone());

        let subscription = UTXOSubscription {
            outpoints: watched,
            addresses: HashSet::new(),
            subscriber_id: "wallet1".to_string(),
        };

        manager.subscribe(subscription).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.active_subscriptions, 1);
    }
}
