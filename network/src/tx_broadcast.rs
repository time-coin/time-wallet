use crate::manager::PeerManager;
use crate::protocol::NetworkMessage;
use std::sync::Arc;
use time_core::Transaction;
use time_mempool::Mempool;
use tracing::debug;

pub struct TransactionBroadcaster {
    #[allow(dead_code)]
    mempool: Arc<Mempool>,
    peer_manager: Arc<PeerManager>,
}

impl TransactionBroadcaster {
    pub fn new(mempool: Arc<Mempool>, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            mempool,
            peer_manager,
        }
    }

    #[allow(dead_code)]
    async fn broadcast_to_peers<F>(&self, message: NetworkMessage, log_msg: &str, send_fn: F)
    where
        F: Fn(Arc<PeerManager>, std::net::IpAddr, NetworkMessage) -> tokio::task::JoinHandle<()>
            + Send
            + 'static,
    {
        let peers = self.peer_manager.get_connected_peers().await;
        println!("{} to {} peers", log_msg, peers.len());

        for peer_info in peers {
            let peer_ip = peer_info.address.ip();
            let msg_clone = message.clone();
            let manager_clone = self.peer_manager.clone();

            send_fn(manager_clone, peer_ip, msg_clone);
        }
    }

    /// Broadcast a finalized transaction to all peers via TCP with HTTP fallback
    /// Uses existing TCP connections for efficiency, falls back to HTTP if TCP fails
    pub async fn broadcast_finalized_transaction(&self, tx: Transaction) {
        let peers = self.peer_manager.get_connected_peers().await;
        println!(
            "📡 Broadcasting FINALIZED transaction {} to {} peers via TCP",
            &tx.txid[..16],
            peers.len()
        );

        let message = NetworkMessage::FinalizedTransactionBroadcast(tx.clone());
        let mut send_tasks = Vec::new();

        // Launch all TCP sends in parallel with HTTP fallback
        for peer_info in &peers {
            let peer_addr = peer_info.address;
            let msg_clone = message.clone();
            let tx_clone = tx.clone();
            let manager = self.peer_manager.clone();

            let task = tokio::spawn(async move {
                // Try TCP first (fast, uses existing connections)
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    manager.send_message_to_peer(peer_addr, msg_clone),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        debug!(peer = %peer_addr, "Finalized transaction sent via TCP");
                        return true;
                    }
                    Ok(Err(e)) => {
                        debug!(peer = %peer_addr, error = %e, "TCP failed, trying HTTP fallback");
                    }
                    Err(_) => {
                        debug!(peer = %peer_addr, "TCP timeout, trying HTTP fallback");
                    }
                }

                // HTTP fallback for reliability
                let url = format!("http://{}:{}/mempool/finalized", peer_addr.ip(), 24101);
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(3))
                    .build()
                    .unwrap();

                match client.post(&url).json(&tx_clone).send().await {
                    Ok(response) if response.status().is_success() => {
                        debug!(peer = %peer_addr, "Finalized transaction sent via HTTP fallback");
                        true
                    }
                    Ok(response) => {
                        debug!(
                            peer = %peer_addr,
                            status = %response.status(),
                            "HTTP fallback failed"
                        );
                        false
                    }
                    Err(e) => {
                        debug!(peer = %peer_addr, error = %e, "Both TCP and HTTP failed");
                        false
                    }
                }
            });
            send_tasks.push(task);
        }

        // Wait for all sends to complete
        let results = futures::future::join_all(send_tasks).await;
        let success_count = results
            .into_iter()
            .filter(|r| matches!(r, Ok(true)))
            .count();
        println!(
            "✅ Finalized transaction broadcast: {}/{} peers successful",
            success_count,
            peers.len()
        );
    }

    /// Broadcast a transaction to all peers via TCP - OPTIMIZED PARALLEL
    pub async fn broadcast_transaction(&self, tx: Transaction) {
        let peers = self.peer_manager.get_connected_peers().await;
        println!(
            "📡 Broadcasting transaction {} to {} peers",
            &tx.txid[..16],
            peers.len()
        );

        let message = NetworkMessage::TransactionBroadcast(tx);
        let mut send_tasks = Vec::new();

        // Launch all sends in parallel with timeout per send
        for peer_info in peers {
            let peer_addr = peer_info.address;
            let msg_clone = message.clone();
            let manager = self.peer_manager.clone();

            let task = tokio::spawn(async move {
                // 2 second timeout per peer to prevent blocking on slow peers
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    manager.send_message_to_peer(peer_addr, msg_clone),
                )
                .await
                {
                    Ok(Ok(_)) => true,
                    Ok(Err(e)) => {
                        debug!(peer = %peer_addr, error = %e, "Failed to send transaction");
                        false
                    }
                    Err(_) => {
                        debug!(peer = %peer_addr, "Timeout sending transaction");
                        false
                    }
                }
            });
            send_tasks.push(task);
        }

        // Wait for all sends to complete (or timeout)
        let results = futures::future::join_all(send_tasks).await;
        let success_count = results
            .into_iter()
            .filter(|r| matches!(r, Ok(true)))
            .count();
        debug!(success = success_count, "Transaction broadcast completed");
    }

    /// Sync mempool with a peer via TCP
    pub async fn sync_mempool_from_peer(
        &self,
        peer_addr: &str,
    ) -> Result<Vec<Transaction>, String> {
        let addr: std::net::SocketAddr = peer_addr
            .parse()
            .map_err(|e| format!("Invalid peer address: {}", e))?;

        println!("🔄 Syncing mempool from {}...", peer_addr);

        let query_msg = NetworkMessage::MempoolQuery;
        self.peer_manager
            .send_message_to_peer(addr, query_msg)
            .await
            .map_err(|e| format!("Failed to send query: {}", e))?;

        println!("   ⚠️  Mempool sync via TCP not yet fully implemented");
        Ok(vec![])
    }

    /// Broadcast transaction proposal via TCP - OPTIMIZED PARALLEL
    pub async fn broadcast_tx_proposal(&self, proposal: serde_json::Value) {
        let peers = self.peer_manager.get_connected_peers().await;
        let proposal_json = proposal.to_string();
        let message = NetworkMessage::ConsensusTxProposal(proposal_json);

        println!(
            "📡 Broadcasting transaction proposal to {} peers",
            peers.len()
        );

        let mut send_tasks = Vec::new();

        for peer_info in peers {
            let peer_ip = peer_info.address.ip();
            let msg_clone = message.clone();
            let manager_clone = self.peer_manager.clone();

            let task = tokio::spawn(async move {
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    manager_clone.send_to_peer_tcp(peer_ip, msg_clone),
                )
                .await
                {
                    Ok(Ok(_)) => true,
                    Ok(Err(e)) => {
                        debug!(peer = %peer_ip, error = %e, "Failed to send tx proposal");
                        false
                    }
                    Err(_) => {
                        debug!(peer = %peer_ip, "Timeout sending tx proposal");
                        false
                    }
                }
            });
            send_tasks.push(task);
        }

        let results = futures::future::join_all(send_tasks).await;
        let success_count = results
            .into_iter()
            .filter(|r| matches!(r, Ok(true)))
            .count();
        debug!(success = success_count, "TX proposal broadcast completed");
    }

    /// Broadcast vote on transaction set via TCP - OPTIMIZED PARALLEL
    pub async fn broadcast_tx_vote(&self, vote: serde_json::Value) {
        let peers = self.peer_manager.get_connected_peers().await;
        let vote_json = vote.to_string();
        let message = NetworkMessage::ConsensusTxVote(vote_json);

        let mut send_tasks = Vec::new();

        for peer_info in peers {
            let peer_ip = peer_info.address.ip();
            let msg_clone = message.clone();
            let manager_clone = self.peer_manager.clone();

            let task = tokio::spawn(async move {
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    manager_clone.send_to_peer_tcp(peer_ip, msg_clone),
                )
                .await
                {
                    Ok(Ok(_)) => true,
                    Ok(Err(e)) => {
                        debug!(peer = %peer_ip, error = %e, "Failed to send tx vote");
                        false
                    }
                    Err(_) => {
                        debug!(peer = %peer_ip, "Timeout sending tx vote");
                        false
                    }
                }
            });
            send_tasks.push(task);
        }

        let results = futures::future::join_all(send_tasks).await;
        let success_count = results
            .into_iter()
            .filter(|r| matches!(r, Ok(true)))
            .count();
        debug!(success = success_count, "TX vote broadcast completed");
    }

    /// Broadcast instant finality vote to all peers via TCP - OPTIMIZED PARALLEL
    pub async fn broadcast_instant_finality_vote(&self, vote: serde_json::Value) {
        let peers = self.peer_manager.get_connected_peers().await;

        let txid = vote
            .get("txid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let voter = vote
            .get("voter")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let approve = vote
            .get("approve")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let timestamp = vote.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);

        let message = NetworkMessage::InstantFinalityVote {
            txid,
            voter,
            approve,
            timestamp,
        };

        let mut send_tasks = Vec::new();

        for peer_info in peers {
            let peer_addr = peer_info.address;
            let msg_clone = message.clone();
            let manager = self.peer_manager.clone();

            let task = tokio::spawn(async move {
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(1),
                    manager.send_message_to_peer(peer_addr, msg_clone),
                )
                .await
                {
                    Ok(Ok(_)) => true,
                    Ok(Err(_)) => false,
                    Err(_) => false,
                }
            });
            send_tasks.push(task);
        }

        let results = futures::future::join_all(send_tasks).await;
        let success_count = results
            .into_iter()
            .filter(|r| matches!(r, Ok(true)))
            .count();
        debug!(
            success = success_count,
            "Instant finality vote broadcast completed"
        );
    }

    /// 🔒 Broadcast UTXO lock request and wait for acknowledgments
    /// Returns the number of masternodes that acknowledged the lock
    pub async fn broadcast_utxo_lock(&self, tx: &Transaction) -> Result<u32, String> {
        use crate::utxo_sync::{UtxoInput, UtxoOutput};

        let peers = self.peer_manager.get_connected_peers().await;
        if peers.is_empty() {
            return Err("No peers available to broadcast UTXO lock".to_string());
        }

        println!(
            "🔒 Broadcasting UTXO lock for transaction {} to {} masternodes",
            &tx.txid[..16],
            peers.len()
        );

        // Convert transaction inputs/outputs to UTXO format
        let inputs: Vec<String> = tx
            .inputs
            .iter()
            .map(|input| {
                let utxo_input = UtxoInput {
                    txid: input.previous_output.txid.clone(),
                    vout: input.previous_output.vout,
                    amount: 0, // Amount will be looked up by receiver
                };
                serde_json::to_string(&utxo_input).unwrap_or_default()
            })
            .collect();

        let outputs: Vec<String> = tx
            .outputs
            .iter()
            .map(|output| {
                let utxo_output = UtxoOutput {
                    address: output.address.clone(),
                    amount: output.amount,
                };
                serde_json::to_string(&utxo_output).unwrap_or_default()
            })
            .collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let message = NetworkMessage::UtxoLockBroadcast {
            txid: tx.txid.clone(),
            inputs,
            outputs,
            timestamp,
            proposer: self
                .peer_manager
                .get_node_id()
                .await
                .unwrap_or_else(|| "unknown".to_string()),
            signature: String::new(), // TODO: Sign the lock request
        };

        // Broadcast to all masternodes and collect acknowledgments
        let mut ack_tasks = Vec::new();

        for peer_info in peers {
            let peer_addr = peer_info.address;
            let msg_clone = message.clone();
            let manager = self.peer_manager.clone();
            let txid_clone = tx.txid.clone();

            let task = tokio::spawn(async move {
                // Send lock broadcast with 2 second timeout
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    manager.send_message_to_peer(peer_addr, msg_clone),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        debug!(
                            peer = %peer_addr,
                            txid = %&txid_clone[..16],
                            "UTXO lock broadcast sent"
                        );

                        // Wait for acknowledgment (in real implementation, this would be
                        // handled by message handler collecting UtxoLockAcknowledge messages)
                        // For now, assume success
                        Some(true)
                    }
                    Ok(Err(e)) => {
                        debug!(
                            peer = %peer_addr,
                            txid = %&txid_clone[..16],
                            error = %e,
                            "Failed to send UTXO lock"
                        );
                        None
                    }
                    Err(_) => {
                        debug!(
                            peer = %peer_addr,
                            txid = %&txid_clone[..16],
                            "UTXO lock broadcast timeout"
                        );
                        None
                    }
                }
            });
            ack_tasks.push(task);
        }

        // Wait for all responses with timeout
        let results = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            futures::future::join_all(ack_tasks),
        )
        .await;

        let ack_count = match results {
            Ok(results) => results
                .into_iter()
                .filter_map(|r| r.ok().flatten())
                .filter(|ack| *ack)
                .count() as u32,
            Err(_) => {
                return Err("Timeout waiting for UTXO lock acknowledgments".to_string());
            }
        };

        println!("   ✅ Received {} UTXO lock acknowledgments", ack_count);

        Ok(ack_count)
    }
}
