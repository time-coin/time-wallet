//! Background service for periodic snapshots
use crate::snapshot::HotStateManager;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Background snapshot service
pub struct SnapshotService {
    manager: Arc<HotStateManager>,
    interval: Duration,
}

impl SnapshotService {
    pub fn new(manager: Arc<HotStateManager>, interval_secs: u64) -> Self {
        SnapshotService {
            manager,
            interval: Duration::from_secs(interval_secs),
        }
    }

    /// Start the snapshot service (runs in background thread)
    pub fn start(self) {
        thread::spawn(move || {
            println!(
                "🚀 Snapshot service started (interval: {:?})",
                self.interval
            );

            loop {
                thread::sleep(self.interval);

                match self.manager.save_snapshot() {
                    Ok(_) => {
                        let stats = self.manager.get_stats();
                        println!(
                            "💾 Snapshot saved - Mempool: {}, Pending UTXOs: {}",
                            stats.mempool_size, stats.pending_utxo_count
                        );
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to save snapshot: {}", e);
                    }
                }
            }
        });
    }
}
