//! Treasury Manager - Integrates treasury state with governance proposals
//!
//! This module provides the main interface for treasury operations including:
//! - Proposal creation and management
//! - Masternode voting
//! - Fund allocation and distribution
//! - Approval workflow with 2/3+ consensus

use crate::state::{StateError, Treasury, TreasuryAllocation, TreasuryWithdrawal};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Proposal status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    Active,
    Approved,
    Rejected,
    Executed,
    Expired,
}

/// Treasury proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryProposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub recipient: String,
    pub amount: u64,
    pub submitter: String,
    pub submission_time: u64,
    pub voting_deadline: u64,
    pub execution_deadline: u64,
    pub status: ProposalStatus,
    pub votes: HashMap<String, Vote>,
    pub total_voting_power: u64,
}

/// Vote on a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub masternode_id: String,
    pub vote_choice: VoteChoice,
    pub voting_power: u64,
    pub timestamp: u64,
}

/// Vote choice
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

/// Parameters for creating a new treasury proposal
#[derive(Debug, Clone)]
pub struct CreateProposalParams {
    pub id: String,
    pub title: String,
    pub description: String,
    pub recipient: String,
    pub amount: u64,
    pub submitter: String,
    pub submission_time: u64,
    pub voting_period_days: u64,
}

/// Treasury manager that handles proposals and voting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryManager {
    /// Active and historical proposals
    proposals: HashMap<String, TreasuryProposal>,

    /// Underlying treasury state
    treasury: Treasury,

    /// Total voting power of all active masternodes
    total_voting_power: u64,
}

impl TreasuryManager {
    /// Create a new treasury manager
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            treasury: Treasury::new(),
            total_voting_power: 0,
        }
    }

    /// Create a new proposal
    pub fn create_proposal(&mut self, params: CreateProposalParams) -> Result<(), StateError> {
        // Check if proposal ID already exists
        if self.proposals.contains_key(&params.id) {
            return Err(StateError::IoError(format!(
                "Proposal {} already exists",
                params.id
            )));
        }

        // Create the proposal
        let proposal = TreasuryProposal {
            id: params.id.clone(),
            title: params.title,
            description: params.description,
            recipient: params.recipient,
            amount: params.amount,
            submitter: params.submitter,
            submission_time: params.submission_time,
            voting_deadline: params.submission_time + (params.voting_period_days * 86400),
            execution_deadline: params.submission_time + ((params.voting_period_days + 30) * 86400),
            status: ProposalStatus::Active,
            votes: HashMap::new(),
            total_voting_power: self.total_voting_power,
        };

        self.proposals.insert(params.id, proposal);
        Ok(())
    }

    /// Add a vote to a proposal
    pub fn vote_on_proposal(
        &mut self,
        proposal_id: &str,
        masternode_id: String,
        vote_choice: VoteChoice,
        voting_power: u64,
        timestamp: u64,
    ) -> Result<(), StateError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| StateError::IoError(format!("Proposal {} not found", proposal_id)))?;

        // Check if proposal is still active
        if proposal.status != ProposalStatus::Active {
            return Err(StateError::IoError(format!(
                "Cannot vote on proposal with status {:?}",
                proposal.status
            )));
        }

        // Check if voting period has ended
        if timestamp > proposal.voting_deadline {
            return Err(StateError::IoError("Voting period has ended".to_string()));
        }

        // Check if masternode has already voted
        if proposal.votes.contains_key(&masternode_id) {
            return Err(StateError::IoError(format!(
                "Masternode {} has already voted",
                masternode_id
            )));
        }

        // Add the vote
        proposal.votes.insert(
            masternode_id.clone(),
            Vote {
                masternode_id,
                vote_choice,
                voting_power,
                timestamp,
            },
        );

        Ok(())
    }

    /// Update proposal statuses based on current time
    pub fn update_proposals(&mut self, current_time: u64) {
        // First collect proposal IDs and their voting results
        let mut updates = Vec::new();

        for (id, proposal) in &self.proposals {
            if proposal.status != ProposalStatus::Active {
                continue;
            }

            // Check if voting period has ended
            if current_time > proposal.voting_deadline {
                let has_approval = self.has_approval(proposal);
                updates.push((id.clone(), has_approval));
            }
        }

        // Now apply the updates
        for (id, approved) in updates {
            if let Some(proposal) = self.proposals.get_mut(&id) {
                if approved {
                    proposal.status = ProposalStatus::Approved;
                } else {
                    proposal.status = ProposalStatus::Rejected;
                }
            }
        }

        // Mark expired approved proposals
        for proposal in self.proposals.values_mut() {
            if proposal.status == ProposalStatus::Approved
                && current_time > proposal.execution_deadline
            {
                proposal.status = ProposalStatus::Expired;
            }
        }
    }

    /// Check if a proposal has 2/3+ approval
    fn has_approval(&self, proposal: &TreasuryProposal) -> bool {
        let mut yes_power = 0;
        let mut total_votes = 0;

        for vote in proposal.votes.values() {
            match vote.vote_choice {
                VoteChoice::Yes => yes_power += vote.voting_power,
                VoteChoice::No | VoteChoice::Abstain => {}
            }
            total_votes += vote.voting_power;
        }

        if total_votes == 0 {
            return false;
        }

        // Require 67% (2/3+) YES votes
        (yes_power * 100) / total_votes >= 67
    }

    /// Execute an approved proposal
    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        block_number: u64,
        timestamp: i64,
    ) -> Result<(), StateError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| StateError::IoError(format!("Proposal {} not found", proposal_id)))?;

        // Check if proposal is approved
        if proposal.status != ProposalStatus::Approved {
            return Err(StateError::IoError(format!(
                "Proposal {} is not approved (status: {:?})",
                proposal_id, proposal.status
            )));
        }

        // Distribute the funds
        self.treasury.distribute(
            proposal_id.to_string(),
            proposal.recipient.clone(),
            proposal.amount,
            block_number,
            timestamp,
        )?;

        // Mark as executed
        proposal.status = ProposalStatus::Executed;

        Ok(())
    }

    /// Get a proposal by ID
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&TreasuryProposal> {
        self.proposals.get(proposal_id)
    }

    /// Get all proposals
    pub fn get_all_proposals(&self) -> Vec<&TreasuryProposal> {
        self.proposals.values().collect()
    }

    /// Get approved proposals ready for execution
    pub fn get_approved_proposals(&self) -> Vec<&TreasuryProposal> {
        self.proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Approved)
            .collect()
    }

    /// Allocate funds from block reward
    pub fn allocate_from_block_reward(
        &mut self,
        block_number: u64,
        block_reward: u64,
        timestamp: i64,
    ) -> Result<u64, StateError> {
        self.treasury
            .allocate_from_block_reward(block_number, block_reward, timestamp)
    }

    /// Allocate funds from fees
    pub fn allocate_from_fees(
        &mut self,
        block_number: u64,
        total_fees: u64,
        timestamp: i64,
    ) -> Result<u64, StateError> {
        self.treasury
            .allocate_from_fees(block_number, total_fees, timestamp)
    }

    /// Get treasury balance
    pub fn balance(&self) -> u64 {
        self.treasury.balance()
    }

    /// Get treasury allocations
    pub fn allocations(&self) -> &[TreasuryAllocation] {
        self.treasury.allocations()
    }

    /// Get treasury withdrawals
    pub fn withdrawals(&self) -> &[TreasuryWithdrawal] {
        self.treasury.withdrawals()
    }

    /// Set total voting power
    pub fn set_total_voting_power(&mut self, power: u64) {
        self.total_voting_power = power;
    }

    /// Get treasury reference
    pub fn treasury(&self) -> &Treasury {
        &self.treasury
    }
}

impl Default for TreasuryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_proposal() {
        let mut manager = TreasuryManager::new();

        manager
            .create_proposal(CreateProposalParams {
                id: "prop-1".to_string(),
                title: "Test Proposal".to_string(),
                description: "Description".to_string(),
                recipient: "recipient123".to_string(),
                amount: 1000000,
                submitter: "submitter123".to_string(),
                submission_time: 1000,
                voting_period_days: 14,
            })
            .unwrap();

        let proposal = manager.get_proposal("prop-1").unwrap();
        assert_eq!(proposal.status, ProposalStatus::Active);
        assert_eq!(proposal.amount, 1000000);
    }

    #[test]
    fn test_voting() {
        let mut manager = TreasuryManager::new();
        manager.set_total_voting_power(300);

        manager
            .create_proposal(CreateProposalParams {
                id: "prop-1".to_string(),
                title: "Test".to_string(),
                description: "Desc".to_string(),
                recipient: "recipient".to_string(),
                amount: 1000000,
                submitter: "submitter".to_string(),
                submission_time: 1000,
                voting_period_days: 14,
            })
            .unwrap();

        // Add votes
        manager
            .vote_on_proposal("prop-1", "mn1".to_string(), VoteChoice::Yes, 200, 2000)
            .unwrap();

        manager
            .vote_on_proposal("prop-1", "mn2".to_string(), VoteChoice::No, 100, 2000)
            .unwrap();

        let proposal = manager.get_proposal("prop-1").unwrap();
        assert_eq!(proposal.votes.len(), 2);
    }

    #[test]
    fn test_proposal_approval() {
        let mut manager = TreasuryManager::new();
        manager.set_total_voting_power(300);

        manager
            .create_proposal(CreateProposalParams {
                id: "prop-1".to_string(),
                title: "Test".to_string(),
                description: "Desc".to_string(),
                recipient: "recipient".to_string(),
                amount: 1000000,
                submitter: "submitter".to_string(),
                submission_time: 1000,
                voting_period_days: 14,
            })
            .unwrap();

        // Add 67% YES votes
        manager
            .vote_on_proposal("prop-1", "mn1".to_string(), VoteChoice::Yes, 67, 2000)
            .unwrap();

        manager
            .vote_on_proposal("prop-1", "mn2".to_string(), VoteChoice::No, 33, 2000)
            .unwrap();

        // Update proposals after voting deadline
        let proposal = manager.get_proposal("prop-1").unwrap();
        let after_deadline = proposal.voting_deadline + 1;
        manager.update_proposals(after_deadline);

        let proposal = manager.get_proposal("prop-1").unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }
}
