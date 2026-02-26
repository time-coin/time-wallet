//! Example: Discover peers on the network

use time_network::{NetworkType, PeerDiscovery};

#[tokio::main]
async fn main() {
    println!("TIME Coin - Peer Discovery Example\n");

    // Create discovery for testnet
    let mut discovery = PeerDiscovery::new(NetworkType::Testnet);

    // Bootstrap from all sources
    println!("Starting peer discovery...\n");
    match discovery.bootstrap().await {
        Ok(peers) => {
            println!("\n✓ Successfully discovered {} peers\n", peers.len());

            println!("Peer List:");
            for (i, peer) in peers.iter().take(10).enumerate() {
                println!("  {}. {} ({})", i + 1, peer.address, peer.version);
            }

            if peers.len() > 10 {
                println!("  ... and {} more", peers.len() - 10);
            }
        }
        Err(e) => {
            eprintln!("✗ Discovery failed: {}", e);
        }
    }
}
