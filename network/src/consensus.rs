
    /// Announce our chain state and get peer consensus
    pub async fn announce_chain_state(&self, height: u64, tip_hash: String) -> (bool, Vec<String>, Vec<String>) {
        let announcement_id = format!("state:{}:{}", height, &tip_hash[..8]);
        
        println!("\n📢 Announcing chain state:");
        println!("   Height: {}", height);
        println!("   Tip hash: {}...", &tip_hash[..16]);
        
        let peers = self.peer_manager.get_peer_ips().await;
        let mut agreements = Vec::new();
        let mut disagreements = Vec::new();
        
        for peer in peers {
            match reqwest::get(format!("http://{}:24101/blockchain/info", peer)).await {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        let peer_height = json.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
                        let peer_hash = json.get("best_block_hash").and_then(|h| h.as_str()).unwrap_or("");
                        
                        if peer_height == height && peer_hash == tip_hash {
                            println!("   ✓ {} agrees", peer);
                            agreements.push(peer.clone());
                        } else {
                            println!("   ✗ {} disagrees (h:{} vs {})", peer, peer_height, height);
                            disagreements.push(peer.clone());
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        
        let total_responses = agreements.len() + disagreements.len();
        let required = (total_responses * 2 + 2) / 3;
        let has_consensus = agreements.len() >= required && total_responses > 0;
        
        println!();
        if has_consensus {
            println!("   ✅ Chain state ACCEPTED by network");
            println!("      {}/{} peers agree (need {})", agreements.len(), total_responses, required);
        } else if total_responses > 0 {
            println!("   ⚠️  Chain state verification inconclusive");
            println!("      {}/{} peers agree (need {})", agreements.len(), total_responses, required);
        }
        
        (has_consensus, agreements, disagreements)
    }
