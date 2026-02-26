use std::sync::Arc;
use sysinfo::System;
use tokio::sync::RwLock;

pub struct ResourceMonitor {
    system: Arc<RwLock<System>>,
    warning_threshold_percent: f64,  // 75%
    critical_threshold_percent: f64, // 90%
}

impl Default for ResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            system: Arc::new(RwLock::new(System::new_all())),
            warning_threshold_percent: 75.0,
            critical_threshold_percent: 90.0,
        }
    }

    pub async fn check_memory(&self) -> MemoryStatus {
        let mut sys = self.system.write().await;
        sys.refresh_memory();

        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let available_mem = sys.available_memory();
        let usage_percent = (used_mem as f64 / total_mem as f64) * 100.0;

        let status = if usage_percent >= self.critical_threshold_percent {
            MemoryLevel::Critical
        } else if usage_percent >= self.warning_threshold_percent {
            MemoryLevel::Warning
        } else {
            MemoryLevel::Normal
        };

        MemoryStatus {
            total_gb: total_mem as f64 / 1_073_741_824.0,
            used_gb: used_mem as f64 / 1_073_741_824.0,
            available_gb: available_mem as f64 / 1_073_741_824.0,
            usage_percent,
            level: status,
        }
    }

    pub fn estimate_transaction_capacity(
        &self,
        tx_size_bytes: usize,
        available_memory_bytes: u64,
    ) -> usize {
        (available_memory_bytes as usize / tx_size_bytes).min(10_000_000)
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStatus {
    pub total_gb: f64,
    pub used_gb: f64,
    pub available_gb: f64,
    pub usage_percent: f64,
    pub level: MemoryLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryLevel {
    Normal,   // < 75%
    Warning,  // 75-90%
    Critical, // > 90%
}

impl MemoryStatus {
    pub fn log_status(&self, mempool_count: usize, mempool_size_mb: f64) {
        match self.level {
            MemoryLevel::Normal => {
                // Only log periodically, not every time
            }
            MemoryLevel::Warning => {
                println!();
                println!("⚠️  ═══════════════════════════════════════════════════════");
                println!("⚠️  MEMORY WARNING");
                println!("⚠️  ═══════════════════════════════════════════════════════");
                println!(
                    "   System Memory: {:.1}% used ({:.2} GB / {:.2} GB)",
                    self.usage_percent, self.used_gb, self.total_gb
                );
                println!("   Available: {:.2} GB", self.available_gb);
                println!(
                    "   Mempool: {} transactions ({:.1} MB)",
                    mempool_count, mempool_size_mb
                );
                println!();
                println!("   ACTION: Memory usage is elevated");
                println!("   - Mempool pruning may activate soon");
                println!("   - Consider increasing server RAM");
                println!("   - Monitor for spam attacks");
                println!("⚠️  ═══════════════════════════════════════════════════════");
                println!();
            }
            MemoryLevel::Critical => {
                println!();
                println!("🚨 ═══════════════════════════════════════════════════════");
                println!("🚨 CRITICAL: MEMORY EXHAUSTION");
                println!("🚨 ═══════════════════════════════════════════════════════");
                println!(
                    "   System Memory: {:.1}% used ({:.2} GB / {:.2} GB)",
                    self.usage_percent, self.used_gb, self.total_gb
                );
                println!("   Available: {:.2} GB", self.available_gb);
                println!(
                    "   Mempool: {} transactions ({:.1} MB)",
                    mempool_count, mempool_size_mb
                );
                println!();
                println!("   🚨 EMERGENCY ACTIONS ACTIVE:");
                println!("   ✓ Rejecting new transactions");
                println!("   ✓ Aggressive mempool pruning");
                println!("   ✓ Purging low-fee transactions");
                println!();
                println!("   OPERATOR ACTION REQUIRED:");
                println!("   1. Check for DoS attack (spam transactions)");
                println!("   2. Increase server RAM immediately");
                println!("   3. Review firewall and rate limits");
                println!("   4. Consider restarting node to clear mempool");
                println!("🚨 ═══════════════════════════════════════════════════════");
                println!();
            }
        }
    }
}
