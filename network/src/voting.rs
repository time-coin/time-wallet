//! Transaction voting and consensus tracking
//!
//! Tracks votes from masternodes for instant finality consensus

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Vote for a transaction
#[derive(Debug, Clone)]
pub struct Vote {
    pub txid: String,
    pub voter: String,
    pub approve: bool,
    pub timestamp: u64,
}

/// Vote tracker for a single transaction
#[derive(Debug, Clone)]
struct TransactionVotes {
    pub votes: Vec<Vote>,
    pub finalized: bool,
    pub created_at: u64,
}

impl TransactionVotes {
    fn new(_txid: String) -> Self {
        Self {
            votes: Vec::new(),
            finalized: false,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    fn add_vote(&mut self, vote: Vote) -> bool {
        // Check if voter already voted
        if self.votes.iter().any(|v| v.voter == vote.voter) {
            return false;
        }

        self.votes.push(vote);
        true
    }

    fn approval_count(&self) -> usize {
        self.votes.iter().filter(|v| v.approve).count()
    }

    fn rejection_count(&self) -> usize {
        self.votes.iter().filter(|v| !v.approve).count()
    }

    fn total_votes(&self) -> usize {
        self.votes.len()
    }
}

/// Global vote tracker for all transactions
pub struct VoteTracker {
    /// Map of txid -> votes
    transactions: Arc<RwLock<HashMap<String, TransactionVotes>>>,
    /// Required votes for consensus (default 2)
    required_votes: usize,
}

impl VoteTracker {
    pub fn new(required_votes: usize) -> Self {
        Self {
            transactions: Arc::new(RwLock::new(HashMap::new())),
            required_votes,
        }
    }

    /// Record a vote for a transaction
    /// Returns Some(consensus_reached) if consensus was achieved with this vote
    pub async fn record_vote(&self, vote: Vote) -> Option<bool> {
        let mut txs = self.transactions.write().await;

        let tx_votes = txs
            .entry(vote.txid.clone())
            .or_insert_with(|| TransactionVotes::new(vote.txid.clone()));

        // Already finalized?
        if tx_votes.finalized {
            debug!(txid = %vote.txid, "Vote received for already finalized transaction");
            return None;
        }

        // Add the vote
        if !tx_votes.add_vote(vote.clone()) {
            warn!(
                txid = %vote.txid,
                voter = %vote.voter,
                "Duplicate vote from same voter"
            );
            return None;
        }

        info!(
            txid = %vote.txid,
            voter = %vote.voter,
            approve = %vote.approve,
            total = %tx_votes.total_votes(),
            approvals = %tx_votes.approval_count(),
            rejections = %tx_votes.rejection_count(),
            "Vote recorded"
        );

        // Check if consensus reached
        let approvals = tx_votes.approval_count();
        let rejections = tx_votes.rejection_count();

        if approvals >= self.required_votes {
            info!(
                txid = %vote.txid,
                votes = %approvals,
                "✅ Transaction APPROVED - consensus reached"
            );
            tx_votes.finalized = true;
            return Some(true);
        }

        if rejections >= self.required_votes {
            info!(
                txid = %vote.txid,
                votes = %rejections,
                "❌ Transaction REJECTED - consensus reached"
            );
            tx_votes.finalized = true;
            return Some(false);
        }

        // Not enough votes yet
        debug!(
            txid = %vote.txid,
            approvals = %approvals,
            rejections = %rejections,
            required = %self.required_votes,
            "Waiting for more votes"
        );
        None
    }

    /// Check if transaction has reached consensus
    pub async fn is_finalized(&self, txid: &str) -> bool {
        let txs = self.transactions.read().await;
        txs.get(txid).is_some_and(|tx| tx.finalized)
    }

    /// Get vote count for a transaction
    pub async fn get_vote_count(&self, txid: &str) -> (usize, usize, usize) {
        let txs = self.transactions.read().await;
        if let Some(tx) = txs.get(txid) {
            (tx.approval_count(), tx.rejection_count(), tx.total_votes())
        } else {
            (0, 0, 0)
        }
    }

    /// Get all votes for a transaction
    pub async fn get_votes(&self, txid: &str) -> Vec<Vote> {
        let txs = self.transactions.read().await;
        txs.get(txid).map_or(Vec::new(), |tx| tx.votes.clone())
    }

    /// Clean up old finalized transactions (e.g., older than 1 hour)
    pub async fn cleanup_old(&self, max_age_secs: u64) {
        let mut txs = self.transactions.write().await;
        let now = chrono::Utc::now().timestamp() as u64;

        let before_count = txs.len();
        txs.retain(|_, tx| !tx.finalized || (now - tx.created_at) < max_age_secs);
        let after_count = txs.len();

        if before_count != after_count {
            info!(
                removed = %(before_count - after_count),
                remaining = %after_count,
                "Cleaned up old finalized transactions"
            );
        }
    }

    /// Get statistics
    pub async fn get_stats(&self) -> VoteTrackerStats {
        let txs = self.transactions.read().await;
        let total = txs.len();
        let finalized = txs.values().filter(|tx| tx.finalized).count();
        let pending = total - finalized;

        VoteTrackerStats {
            total_tracked: total,
            finalized,
            pending,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VoteTrackerStats {
    pub total_tracked: usize,
    pub finalized: usize,
    pub pending: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vote_tracking() {
        let tracker = VoteTracker::new(2);

        let vote1 = Vote {
            txid: "tx123".to_string(),
            voter: "node1".to_string(),
            approve: true,
            timestamp: 1000,
        };

        let vote2 = Vote {
            txid: "tx123".to_string(),
            voter: "node2".to_string(),
            approve: true,
            timestamp: 1001,
        };

        // First vote - no consensus yet
        assert_eq!(tracker.record_vote(vote1.clone()).await, None);
        assert!(!tracker.is_finalized("tx123").await);

        // Second vote - consensus reached
        assert_eq!(tracker.record_vote(vote2).await, Some(true));
        assert!(tracker.is_finalized("tx123").await);

        // Duplicate vote
        assert_eq!(tracker.record_vote(vote1).await, None);
    }

    #[tokio::test]
    async fn test_rejection_consensus() {
        let tracker = VoteTracker::new(2);

        let vote1 = Vote {
            txid: "tx456".to_string(),
            voter: "node1".to_string(),
            approve: false,
            timestamp: 1000,
        };

        let vote2 = Vote {
            txid: "tx456".to_string(),
            voter: "node2".to_string(),
            approve: false,
            timestamp: 1001,
        };

        assert_eq!(tracker.record_vote(vote1).await, None);
        assert_eq!(tracker.record_vote(vote2).await, Some(false));
        assert!(tracker.is_finalized("tx456").await);
    }
}
