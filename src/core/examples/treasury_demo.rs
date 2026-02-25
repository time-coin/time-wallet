//! Demonstration of Treasury Integration in BlockchainState

use std::env;
use time_core::block::{Block, MasternodeCounts, MasternodeTier};
use time_core::state::BlockchainState;
use time_core::transaction::TxOutput;

fn main() {
    println!("=== Treasury Integration Demonstration ===\n");

    let outputs = vec![TxOutput::new(100_000_000_000, "genesis".to_string())];
    let counts = MasternodeCounts {
        free: 0,
        bronze: 0,
        silver: 0,
        gold: 0,
    };
    let genesis = Block::new(
        0,
        "0".repeat(64),
        "genesis_validator".to_string(),
        outputs,
        &counts,
    );
    println!("✅ Genesis block created\n");

    let db_path = env::temp_dir()
        .join(format!(
            "treasury_demo_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .to_str()
        .unwrap()
        .to_string();

    let mut state =
        BlockchainState::new(genesis.clone(), &db_path).expect("Failed to create blockchain state");
    println!("✅ BlockchainState initialized with Treasury\n");

    println!("Initial Treasury State:");
    println!("   Balance: {}", state.treasury().balance());
    println!("   Total allocated: {}", state.treasury().total_allocated());
    println!(
        "   Total distributed: {}\n",
        state.treasury().total_distributed()
    );

    state
        .register_masternode(
            "node1".to_string(),
            MasternodeTier::Free,
            "collateral_tx_1".to_string(),
            "miner1".to_string(),
        )
        .expect("Failed to register masternode");

    let counts = MasternodeCounts {
        free: 1,
        bronze: 0,
        silver: 0,
        gold: 0,
    };
    let masternode_reward = time_core::block::calculate_total_masternode_reward(&counts);
    let outputs = vec![TxOutput::new(masternode_reward, "miner1".to_string())];
    let block1 = Block::new(
        1,
        genesis.hash.clone(),
        "miner1".to_string(),
        outputs,
        &counts,
    );

    state.add_block(block1).expect("Failed to add block");
    println!("✅ Block added, treasury automatically allocated funds\n");

    let treasury_balance = state.treasury().balance();
    let expected_allocation = (masternode_reward * 5) / 100;
    println!("Treasury After Block:");
    println!(
        "   Balance: {} (expected: {})",
        treasury_balance, expected_allocation
    );
    println!("   Allocations: {}\n", state.treasury().allocations().len());

    let proposal_amount = treasury_balance / 2;
    state
        .approve_treasury_proposal("proposal-1".to_string(), proposal_amount)
        .expect("Failed to approve proposal");
    println!("✅ Proposal approved for: {}\n", proposal_amount);

    state
        .distribute_treasury_funds(
            "proposal-1".to_string(),
            "recipient".to_string(),
            proposal_amount,
        )
        .expect("Failed to distribute funds");
    println!("✅ Funds distributed\n");

    let stats = state.treasury_stats();
    println!("Final Treasury Statistics:");
    println!("   Balance: {}", stats.balance);
    println!("   Total allocated: {}", stats.total_allocated);
    println!("   Total distributed: {}", stats.total_distributed);
    println!("   Withdrawals: {}\n", stats.withdrawal_count);

    let chain_stats = state.get_stats();
    println!("Chain Statistics:");
    println!("   Height: {}", chain_stats.chain_height);
    println!("   Treasury balance: {}", chain_stats.treasury_balance);
    println!(
        "   Treasury allocated: {}",
        chain_stats.treasury_total_allocated
    );
    println!(
        "   Treasury distributed: {}\n",
        chain_stats.treasury_total_distributed
    );

    println!("=== All Treasury Features Working! ===");
}
