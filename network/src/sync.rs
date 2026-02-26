//! Unified Blockchain Synchronization
//!
//! This module consolidates all sync functionality into a single, coherent system.
//! Replaces: chain_sync.rs, simple_sync.rs, fast_sync.rs, sync_manager.rs
//!
//! ## Strategy
//!
//! 1. **Quick Sync** (1-100 blocks behind)
//!    - Sequential download with retry
//!    - Used before block production
//!
//! 2. **Batch Sync** (100-1000 blocks behind)
//!    - Parallel batch downloads
//!    - Fork detection and rollback
//!
//! 3. **Snapshot Sync** (1000+ blocks behind)
//!    - State snapshot + recent blocks
//!    - Fast bootstrap for new nodes

use crate::error::NetworkError;
use crate::{PeerManager, PeerQuarantine};
use std::sync::Arc;
use std::time::Duration;
use time_core::block::Block;
use time_core::state::BlockchainState;
use time_core::{current_timestamp, TimeValidator};
use tokio::sync::RwLock;
use tracing::debug;

const QUICK_SYNC_THRESHOLD: u64 = 100;
const BATCH_SYNC_THRESHOLD: u64 = 1000;
const BATCH_SIZE: u64 = 50;
const BLOCK_TIMEOUT_SECS: u64 = 5;

/// Synchronization status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Node is at consensus height
    InSync,
    /// Behind by 1-100 blocks (quick sync)
    SmallGap(u64),
    /// Behind by 100-1000 blocks (batch sync)
    MediumGap(u64),
    /// Behind by 1000+ blocks (snapshot sync)
    LargeGap(u64),
    /// Fork detected or critical issue
    Critical(String),
}

/// Unified blockchain synchronization manager
pub struct BlockchainSync {
    blockchain: Arc<RwLock<BlockchainState>>,
    peer_manager: Arc<PeerManager>,
    _quarantine: Arc<PeerQuarantine>,
    time_validator: TimeValidator,
}

impl BlockchainSync {
    pub fn new(
        blockchain: Arc<RwLock<BlockchainState>>,
        peer_manager: Arc<PeerManager>,
        quarantine: Arc<PeerQuarantine>,
    ) -> Self {
        Self {
            blockchain,
            peer_manager,
            _quarantine: quarantine,
            time_validator: TimeValidator::new_testnet(),
        }
    }

    /// Main entry point: Sync to network consensus
    pub async fn sync(&self) -> Result<u64, String> {
        println!("🔄 Starting blockchain sync...");

        let our_height = self.get_local_height().await;
        let current_time = current_timestamp();

        // Calculate time-based expected height
        let expected_height = self
            .time_validator
            .calculate_expected_height(current_time)
            .map_err(|e| format!("Time calculation error: {}", e))?;

        // Use retry logic for getting network consensus
        let (network_height, best_peer) = self.get_network_consensus_with_retry(3).await?;

        println!("   📊 Heights:");
        println!("      Current:  {} blocks", our_height);
        println!("      Expected: {} blocks (time-based)", expected_height);
        println!("      Network:  {} blocks (from peers)", network_height);

        // Determine target height
        let target_height = network_height.max(expected_height);

        if target_height > network_height {
            println!(
                "   ⚠️  WARNING: Time-based expectation ({}) exceeds network ({})",
                expected_height, network_height
            );
            println!("      Network may be falling behind schedule!");
            println!("      Will sync to network height: {}", network_height);
        }

        if our_height >= target_height {
            // Check if we're behind time expectations even though caught up with network
            if our_height < expected_height {
                println!(
                    "   ⚠️  Synced with network but {} blocks behind time expectation",
                    expected_height - our_height
                );
            }
            println!("   ✓ Blockchain is up to date (height: {})", our_height);
            return Ok(0);
        }

        let gap = target_height - our_height;
        println!("   📊 Gap: {} blocks", gap);

        if gap > 100 {
            println!("   🔄 CATCH-UP MODE: Significantly behind ({} blocks)", gap);
        }

        // CRITICAL: Check for fork before syncing
        // This prevents downloading blocks on wrong chain
        if our_height > 0 {
            self.detect_and_resolve_forks(&best_peer, our_height, network_height)
                .await?;

            // Recheck height after potential rollback
            let current_height = self.get_local_height().await;
            if current_height != our_height {
                println!(
                    "   ℹ️  Height changed from {} to {} after fork resolution",
                    our_height, current_height
                );
                // Recalculate gap with new height
                let new_gap = network_height - current_height;
                println!("   📊 New gap: {} blocks", new_gap);

                // Continue with sync from new height
                let start_height = current_height + 1;
                let synced = if new_gap <= QUICK_SYNC_THRESHOLD {
                    println!("   🚀 Using quick sync");
                    self.quick_sync(&best_peer, start_height, network_height)
                        .await?
                } else if new_gap <= BATCH_SYNC_THRESHOLD {
                    println!("   ⚡ Using batch sync");
                    self.batch_sync(&best_peer, start_height, network_height)
                        .await?
                } else {
                    println!("   📦 Using snapshot sync");
                    self.snapshot_sync(network_height).await?
                };
                println!("   ✅ Sync complete: {} blocks", synced);
                return Ok(synced);
            }
        }

        // Determine sync strategy based on gap size
        let start_height = self.get_local_height().await + 1;
        let synced = if gap <= QUICK_SYNC_THRESHOLD {
            println!("   🚀 Using quick sync");
            self.quick_sync(&best_peer, start_height, network_height)
                .await?
        } else if gap <= BATCH_SYNC_THRESHOLD {
            println!("   ⚡ Using batch sync");
            self.batch_sync(&best_peer, start_height, network_height)
                .await?
        } else {
            println!("   📦 Using snapshot sync");
            self.snapshot_sync(network_height).await?
        };

        println!("   ✅ Sync complete: {} blocks", synced);
        Ok(synced)
    }

    /// Quick sync for small gaps (sequential with retry)
    async fn quick_sync(
        &self,
        peer: &str,
        start_height: u64,
        end_height: u64,
    ) -> Result<u64, String> {
        let mut synced = 0;

        for height in start_height..=end_height {
            let block = self.download_block_with_retry(peer, height, 3).await?;
            self.import_block(block).await?;
            synced += 1;

            if synced % 10 == 0 {
                println!(
                    "      📊 Progress: {}/{}",
                    synced,
                    end_height - start_height + 1
                );
            }
        }

        Ok(synced)
    }

    /// Batch sync for medium gaps (parallel downloads)
    async fn batch_sync(
        &self,
        peer: &str,
        start_height: u64,
        end_height: u64,
    ) -> Result<u64, String> {
        let mut current_height = start_height;
        let mut total_synced = 0;

        while current_height <= end_height {
            let batch_end = (current_height + BATCH_SIZE - 1).min(end_height);

            // Download batch in parallel
            let blocks = self
                .download_batch_parallel(peer, current_height, batch_end)
                .await?;

            // Import blocks sequentially
            for block in blocks {
                self.import_block(block).await?;
                total_synced += 1;
            }

            current_height = batch_end + 1;

            let progress = ((total_synced as f64) / (end_height - start_height + 1) as f64) * 100.0;
            println!("      📊 Progress: {:.0}%", progress);
        }

        Ok(total_synced)
    }

    /// Snapshot sync for large gaps (state snapshot + recent blocks)
    async fn snapshot_sync(&self, target_height: u64) -> Result<u64, String> {
        println!("   📦 Requesting state snapshot...");

        // Find peer with snapshot capability
        let peers = self.peer_manager.get_peer_ips().await;
        if peers.is_empty() {
            return Err("No peers available".to_string());
        }

        let best_peer = &peers[0];
        let peer_addr: std::net::SocketAddr = format!("{}:24100", best_peer)
            .parse()
            .map_err(|e| format!("Invalid peer address: {}", e))?;

        // Request snapshot
        match self
            .peer_manager
            .request_state_snapshot(peer_addr, target_height)
            .await
        {
            Ok(msg) => {
                if let crate::protocol::NetworkMessage::StateSnapshotResponse {
                    height,
                    state_data,
                    ..
                } = msg
                {
                    println!("      ✓ Received snapshot at height {}", height);

                    // Apply snapshot (simplified for now)
                    // In full implementation: decompress, validate, apply UTXO set

                    // Sync last 10 blocks normally for recent data
                    let recent_blocks = 10;
                    if target_height > recent_blocks {
                        println!("      📥 Syncing last {} blocks...", recent_blocks);
                        self.quick_sync(
                            best_peer,
                            target_height - recent_blocks + 1,
                            target_height,
                        )
                        .await?;
                    }

                    Ok(state_data.len() as u64)
                } else {
                    Err("Invalid snapshot response".to_string())
                }
            }
            Err(e) => {
                println!("      ⚠️  Snapshot sync failed: {}", e);
                println!("      🔄 Falling back to batch sync");
                self.batch_sync(best_peer, 1, target_height).await
            }
        }
    }

    /// Detect and resolve forks
    async fn detect_and_resolve_forks(
        &self,
        peer: &str,
        our_height: u64,
        network_height: u64,
    ) -> Result<(), String> {
        println!("   🔍 Checking for forks...");

        // Find common ancestor using binary search-style approach
        let mut common_height = our_height.min(network_height);

        while common_height > 0 {
            let our_hash = {
                let blockchain = self.blockchain.read().await;
                blockchain
                    .get_block_by_height(common_height)
                    .map(|b| b.hash.clone())
            };

            if let Some(our_hash_str) = our_hash {
                // Use exponential backoff for retries
                let mut retries = 0;
                let max_retries = 3;

                loop {
                    let backoff = std::time::Duration::from_secs(2u64.pow(retries));
                    if retries > 0 {
                        tokio::time::sleep(backoff).await;
                    }

                    match self.download_block_with_retry(peer, common_height, 2).await {
                        Ok(peer_block) => {
                            if peer_block.hash == our_hash_str {
                                // Found common ancestor - hashes match at this height
                                if common_height < our_height {
                                    // We have blocks beyond common ancestor - that's a fork!
                                    let blocks_to_remove = our_height - common_height;
                                    println!(
                                        "      ⚠️  FORK DETECTED at height {}!",
                                        common_height + 1
                                    );
                                    println!(
                                        "      🔄 Rolling back {} blocks...",
                                        blocks_to_remove
                                    );

                                    let mut blockchain = self.blockchain.write().await;
                                    blockchain
                                        .rollback_to_height(common_height)
                                        .map_err(|e| format!("Rollback failed: {:?}", e))?;
                                    drop(blockchain);

                                    self.peer_manager
                                        .sync_gate
                                        .update_local_height(common_height)
                                        .await;

                                    println!("      ✅ Rolled back to height {}", common_height);

                                    // Now download the correct chain from the peer
                                    if network_height > common_height {
                                        println!(
                                            "      📥 Downloading {} blocks from peer (heights {}-{})...",
                                            network_height - common_height,
                                            common_height + 1,
                                            network_height
                                        );

                                        // Download blocks sequentially to avoid orphan issues
                                        for height in (common_height + 1)..=network_height {
                                            match self
                                                .download_block_with_retry(peer, height, 3)
                                                .await
                                            {
                                                Ok(block) => {
                                                    match self
                                                        .blockchain
                                                        .write()
                                                        .await
                                                        .add_block(block)
                                                    {
                                                        Ok(_) => {
                                                            if height % 10 == 0 {
                                                                println!("         ✓ Downloaded block {}/{}", height, network_height);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            println!("         ✗ Failed to add block {}: {:?}", height, e);
                                                            return Err(format!(
                                                                "Failed to add block {}: {:?}",
                                                                height, e
                                                            ));
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    println!("         ✗ Failed to download block {}: {}", height, e);
                                                    return Err(format!(
                                                        "Failed to download block {}: {}",
                                                        height, e
                                                    ));
                                                }
                                            }
                                        }

                                        println!("      ✅ Successfully downloaded and applied {} blocks", network_height - common_height);
                                        self.peer_manager
                                            .sync_gate
                                            .update_local_height(network_height)
                                            .await;
                                    }
                                } else {
                                    println!("      ✓ No fork detected - chains match");

                                    // But if network is ahead, still download missing blocks
                                    if network_height > common_height {
                                        println!(
                                            "      📥 Downloading {} missing blocks (heights {}-{})...",
                                            network_height - common_height,
                                            common_height + 1,
                                            network_height
                                        );

                                        for height in (common_height + 1)..=network_height {
                                            match self
                                                .download_block_with_retry(peer, height, 3)
                                                .await
                                            {
                                                Ok(block) => {
                                                    match self
                                                        .blockchain
                                                        .write()
                                                        .await
                                                        .add_block(block)
                                                    {
                                                        Ok(_) => {
                                                            if height % 10 == 0 {
                                                                println!("         ✓ Downloaded block {}/{}", height, network_height);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            println!("         ✗ Failed to add block {}: {:?}", height, e);
                                                            return Err(format!(
                                                                "Failed to add block {}: {:?}",
                                                                height, e
                                                            ));
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    println!("         ✗ Failed to download block {}: {}", height, e);
                                                    return Err(format!(
                                                        "Failed to download block {}: {}",
                                                        height, e
                                                    ));
                                                }
                                            }
                                        }

                                        println!(
                                            "      ✅ Successfully downloaded {} blocks",
                                            network_height - common_height
                                        );
                                        self.peer_manager
                                            .sync_gate
                                            .update_local_height(network_height)
                                            .await;
                                    }
                                }
                                return Ok(());
                            } else {
                                // Hashes don't match - this is where the fork is!
                                println!(
                                    "      ⚠️  Hash mismatch at height {} (our: {}..., peer: {}...)",
                                    common_height,
                                    &our_hash_str[..16.min(our_hash_str.len())],
                                    &peer_block.hash[..16.min(peer_block.hash.len())]
                                );
                                // Continue searching downward for common ancestor
                                common_height -= 1;
                                break; // Exit retry loop, move to next height
                            }
                        }
                        Err(e) => {
                            // Check if timeout - retry with backoff
                            if (e.contains("Timeout") || e.contains("timeout"))
                                && retries < max_retries
                            {
                                retries += 1;
                                println!(
                                    "      ⚠️  Timeout downloading block {} for fork check (attempt {}/{})",
                                    common_height, retries, max_retries
                                );
                                continue; // Retry same height
                            }

                            // After retries exhausted or non-timeout error
                            if retries >= max_retries {
                                println!(
                                    "      ⚠️  Failed to download block {} after {} attempts",
                                    common_height, max_retries
                                );
                                println!("      ℹ️  Skipping fork detection this round");
                                return Ok(());
                            }

                            // Peer doesn't have this block, try lower
                            common_height -= 1;
                            break; // Exit retry loop, move to next height
                        }
                    }
                }
            } else {
                // We don't have this block locally, shouldn't happen but handle it
                common_height -= 1;
            }
        }

        // Reached genesis without finding common ancestor
        println!("      ⚠️  No common ancestor found except genesis");
        println!("      ⚠️  This indicates a severe fork - full resync recommended");
        Ok(())
    }

    /// Download a batch of blocks in parallel
    async fn download_batch_parallel(
        &self,
        peer: &str,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<Block>, String> {
        let mut tasks = Vec::new();

        for height in start_height..=end_height {
            let peer_clone = peer.to_string();
            let peer_manager = self.peer_manager.clone();

            tasks.push(tokio::spawn(async move {
                let p2p_port = match peer_manager.network {
                    crate::discovery::NetworkType::Mainnet => 24000,
                    crate::discovery::NetworkType::Testnet => 24100,
                };
                let peer_addr = format!("{}:{}", peer_clone, p2p_port);

                let result = tokio::time::timeout(
                    Duration::from_secs(BLOCK_TIMEOUT_SECS),
                    peer_manager.request_block_by_height(&peer_addr, height),
                )
                .await;

                match result {
                    Ok(Ok(block)) => Ok((height, block)),
                    Ok(Err(e)) => Err(format!("Block {}: {}", height, e)),
                    Err(_) => Err(format!("Block {}: Timeout", height)),
                }
            }));
        }

        // Collect results
        let results = futures::future::join_all(tasks).await;
        let mut blocks = Vec::new();
        let mut failed = Vec::new();

        for result in results {
            match result {
                Ok(Ok((height, block))) => blocks.push((height, block)),
                Ok(Err(e)) => {
                    eprintln!("      ⚠️  {}", e);
                    failed.push(e);
                }
                Err(e) => eprintln!("      ⚠️  Task error: {}", e),
            }
        }

        if !failed.is_empty() {
            return Err(format!("{} blocks failed to download", failed.len()));
        }

        // Sort by height
        blocks.sort_by_key(|(h, _)| *h);
        Ok(blocks.into_iter().map(|(_, b)| b).collect())
    }

    /// Download a single block with retry logic
    async fn download_block_with_retry(
        &self,
        peer: &str,
        height: u64,
        max_retries: u32,
    ) -> Result<Block, String> {
        let p2p_port = match self.peer_manager.network {
            crate::discovery::NetworkType::Mainnet => 24000,
            crate::discovery::NetworkType::Testnet => 24100,
        };
        let peer_addr = format!("{}:{}", peer, p2p_port);

        for attempt in 1..=max_retries {
            match tokio::time::timeout(
                Duration::from_secs(BLOCK_TIMEOUT_SECS),
                self.peer_manager
                    .request_block_by_height(&peer_addr, height),
            )
            .await
            {
                Ok(Ok(block)) => return Ok(block),
                Ok(Err(e)) => {
                    if attempt == max_retries {
                        return Err(format!("Failed to download block {}: {}", height, e));
                    }
                }
                Err(_) => {
                    if attempt == max_retries {
                        return Err(format!("Timeout downloading block {}", height));
                    }
                }
            }

            // Exponential backoff
            tokio::time::sleep(Duration::from_millis(500 * (1 << (attempt - 1)))).await;
        }

        Err(format!("Failed after {} retries", max_retries))
    }

    /// Import a block into the blockchain
    async fn import_block(&self, block: Block) -> Result<(), String> {
        let height = block.header.block_number;
        let mut blockchain = self.blockchain.write().await;

        blockchain
            .add_block(block)
            .map_err(|e| format!("Failed to import block {}: {:?}", height, e))?;

        drop(blockchain);

        self.peer_manager
            .sync_gate
            .update_local_height(height)
            .await;

        Ok(())
    }

    /// Get local blockchain height
    async fn get_local_height(&self) -> u64 {
        self.blockchain.read().await.chain_tip_height()
    }

    /// Get network consensus height and best peer
    /// This now includes fork detection by comparing block hashes
    async fn get_network_consensus(&self) -> Result<(u64, String), String> {
        let peers = self.peer_manager.get_peer_ips().await;
        if peers.is_empty() {
            return Err("No peers available".to_string());
        }

        let p2p_port = match self.peer_manager.network {
            crate::discovery::NetworkType::Mainnet => 24000,
            crate::discovery::NetworkType::Testnet => 24100,
        };

        let local_height = self.get_local_height().await;
        let mut peer_heights = Vec::new();

        // Query peers with longer timeout for reliability
        for peer_ip in peers.iter() {
            let peer_addr = format!("{}:{}", peer_ip, p2p_port);

            // Increased timeout from 3s to 10s for slow networks
            if let Ok(Ok(Some(height))) = tokio::time::timeout(
                Duration::from_secs(10),
                self.peer_manager.request_blockchain_info(&peer_addr),
            )
            .await
            {
                peer_heights.push((peer_ip.clone(), height));
            }
        }

        if peer_heights.is_empty() {
            return Err("No peers responded".to_string());
        }

        // FORK DETECTION: Check if we're on same chain as peers
        // Compare block hash at our current height with peers
        if local_height > 0 {
            let our_block_hash = {
                let blockchain = self.blockchain.read().await;
                blockchain
                    .get_block_by_height(local_height)
                    .map(|b| b.hash.clone())
            };

            if let Some(our_hash) = our_block_hash {
                // Check peers at our height to see if we're forked
                for (peer_ip, peer_height) in &peer_heights {
                    if *peer_height >= local_height {
                        let peer_addr = format!("{}:{}", peer_ip, p2p_port);

                        // Request block at our height from peer
                        match self
                            .peer_manager
                            .request_block_by_height(&peer_addr, local_height)
                            .await
                        {
                            Ok(peer_block) => {
                                let peer_hash = &peer_block.hash;

                                if peer_hash != &our_hash {
                                    println!("🚨 FORK DETECTED!");
                                    println!("   Our block {} hash: {}", local_height, our_hash);
                                    println!(
                                        "   Peer {} block {} hash: {}",
                                        peer_ip, local_height, peer_hash
                                    );

                                    // Find common ancestor
                                    if let Ok((common_height, common_peer)) =
                                        self.find_common_ancestor(&peer_addr, local_height).await
                                    {
                                        println!(
                                            "   📍 Common ancestor found at height {}",
                                            common_height
                                        );
                                        println!(
                                            "   🔄 Rolling back to height {} and syncing from {}",
                                            common_height, common_peer
                                        );

                                        // Rollback to common ancestor
                                        let mut blockchain = self.blockchain.write().await;
                                        if let Err(e) = blockchain.rollback_to_height(common_height)
                                        {
                                            println!("   ⚠️  Rollback failed: {}", e);
                                        }
                                        drop(blockchain);

                                        // Return peer with longest chain to sync from
                                        peer_heights.sort_by_key(|(_, h)| std::cmp::Reverse(*h));
                                        return Ok((peer_heights[0].1, peer_heights[0].0.clone()));
                                    } else {
                                        println!("   ⚠️  Could not find common ancestor - may need full resync");
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Failed to get block from {}: {:?}", peer_addr, e);
                            }
                        }
                    }
                }
            }
        }

        // Use highest height as consensus
        peer_heights.sort_by_key(|(_, h)| std::cmp::Reverse(*h));
        let (best_peer, network_height) = peer_heights[0].clone();

        Ok((network_height, best_peer))
    }

    /// Find common ancestor with a peer by walking backwards
    async fn find_common_ancestor(
        &self,
        peer_addr: &str,
        start_height: u64,
    ) -> Result<(u64, String), String> {
        let blockchain = self.blockchain.read().await;

        // Walk backwards from start_height looking for matching block hash
        for height in (1..=start_height).rev() {
            if let Some(our_block) = blockchain.get_block_by_height(height) {
                let our_hash = &our_block.hash;

                // Request this block from peer
                match self
                    .peer_manager
                    .request_block_by_height(peer_addr, height)
                    .await
                {
                    Ok(peer_block) => {
                        let peer_hash = &peer_block.hash;

                        if peer_hash == our_hash {
                            // Found common ancestor
                            return Ok((height, peer_addr.to_string()));
                        }
                    }
                    Err(_) => {
                        // Peer doesn't have this block or error occurred, continue to next height
                    }
                }
            }
        }

        Err("No common ancestor found".to_string())
    }

    /// Get network consensus with retry logic for reliability
    async fn get_network_consensus_with_retry(
        &self,
        max_attempts: u32,
    ) -> Result<(u64, String), String> {
        let mut last_error = String::new();

        for attempt in 1..=max_attempts {
            match self.get_network_consensus().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = e.clone();
                    if attempt < max_attempts {
                        let delay_secs = 5 * attempt;
                        eprintln!(
                            "      ⚠️  Attempt {}/{} failed: {}",
                            attempt, max_attempts, e
                        );
                        eprintln!("      ⏳ Retrying in {} seconds...", delay_secs);
                        tokio::time::sleep(Duration::from_secs(delay_secs as u64)).await;
                    }
                }
            }
        }

        Err(format!(
            "Failed to get network consensus after {} attempts: {}",
            max_attempts, last_error
        ))
    }

    /// Get current sync status
    pub async fn get_sync_status(&self) -> Result<SyncStatus, String> {
        let our_height = self.get_local_height().await;

        // Use retry logic for reliability
        let (network_height, _) = match self.get_network_consensus_with_retry(2).await {
            Ok(consensus) => consensus,
            Err(e) => {
                // If we can't get consensus after retries, we cannot determine sync status
                // DO NOT assume we're in sync - this causes forks!
                return Err(format!("Cannot verify network consensus: {}", e));
            }
        };

        let gap = network_height.saturating_sub(our_height);

        Ok(match gap {
            0 => SyncStatus::InSync,
            1..=100 => SyncStatus::SmallGap(gap),
            101..=1000 => SyncStatus::MediumGap(gap),
            _ => SyncStatus::LargeGap(gap),
        })
    }

    /// Detect and resolve forks (public method for external calls)
    /// This can be called independently before syncing
    pub async fn detect_and_resolve_forks_public(&self) -> Result<(), String> {
        println!("   🔍 Checking for forks...");

        let our_height = self.get_local_height().await;
        if our_height == 0 {
            println!("      ✓ At genesis - no forks possible");
            return Ok(());
        }

        // Try to get network consensus with retry logic
        let (network_height, best_peer) = match self.get_network_consensus_with_retry(3).await {
            Ok(consensus) => consensus,
            Err(e) => {
                eprintln!("      ❌ Fork check failed after retries: {}", e);
                eprintln!("      ⚠️  This could indicate network isolation or connectivity issues");
                eprintln!("      ℹ️  Will retry on next sync cycle");
                return Err(e);
            }
        };

        println!(
            "      📡 Network consensus: height {} from {}",
            network_height, best_peer
        );

        // Check if we're ahead of network (potential fork)
        if our_height > network_height {
            eprintln!(
                "      ⚠️  WARNING: We're ahead of network (our: {}, network: {})",
                our_height, network_height
            );
            eprintln!("      🔍 Checking if we're on a fork...");
        }

        self.detect_and_resolve_forks(&best_peer, our_height, network_height)
            .await
    }

    /// Sync before block production (used by block producer)
    pub async fn sync_before_production(&self) -> Result<bool, NetworkError> {
        let status = self
            .get_sync_status()
            .await
            .map_err(|e| NetworkError::SyncFailed(format!("Failed to get sync status: {}", e)))?;

        match status {
            SyncStatus::InSync => Ok(true),
            SyncStatus::SmallGap(_) => match self.sync().await {
                Ok(_) => Ok(true),
                Err(e) => {
                    eprintln!("   ⚠️  Sync failed: {}", e);
                    Ok(false)
                }
            },
            _ => {
                eprintln!("   ⚠️  Large sync gap detected - skipping production");
                Ok(false)
            }
        }
    }
}
