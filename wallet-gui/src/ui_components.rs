use crate::peer_manager::PeerManager;
use crate::wallet_sync::WalletSync;
use eframe::egui;
use std::sync::Arc;

/// Enhanced network status indicator with detailed connection quality
pub fn show_network_status(
    ui: &mut egui::Ui,
    peer_manager: &Option<Arc<PeerManager>>,
    wallet_sync: &Option<Arc<WalletSync>>,
) {
    ui.horizontal(|ui| {
        // Get peer count
        let peer_count = if let Some(pm) = peer_manager {
            pm.connected_peer_count()
        } else {
            0
        };

        // Get sync status
        let (sync_progress, current_height, network_height) = if let Some(sync) = wallet_sync {
            let progress = sync.get_sync_progress();
            let current = sync.get_current_height();
            let network = sync.get_network_height();
            (progress, current, network)
        } else {
            (0.0, 0, 0)
        };

        // Determine connection quality color
        let (status_color, status_text) = match peer_count {
            0..=1 => (egui::Color32::from_rgb(200, 50, 50), "⚠ Critical"),
            2..=4 => (egui::Color32::from_rgb(200, 150, 50), "⚠ Warning"),
            _ => (egui::Color32::from_rgb(50, 200, 50), "✓ Healthy"),
        };

        // Status indicator circle
        ui.add(egui::Label::new(
            egui::RichText::new("●").size(20.0).color(status_color),
        ));

        // Connection status
        ui.label(
            egui::RichText::new(status_text)
                .color(status_color)
                .strong(),
        );

        ui.separator();

        // Peer count
        ui.label(format!("{} peers", peer_count));

        ui.separator();

        // Sync progress
        if sync_progress < 100.0 {
            ui.label(
                egui::RichText::new(format!("⏳ Syncing: {:.1}%", sync_progress))
                    .color(egui::Color32::from_rgb(200, 150, 50)),
            );
        } else {
            ui.label(egui::RichText::new("✓ Synced").color(egui::Color32::from_rgb(50, 200, 50)));
        }

        ui.separator();

        // Block height
        ui.label(format!("Block: {} / {}", current_height, network_height));

        // Show detailed metrics on hover
        ui.label("ℹ").on_hover_ui(|ui| {
            ui.label(egui::RichText::new("Network Details").strong());
            ui.separator();

            if let Some(pm) = peer_manager {
                let avg_latency = pm.get_average_latency();
                let best_peer = pm.get_best_peer();

                ui.label(format!("Average latency: {:.0}ms", avg_latency));
                if let Some(peer) = best_peer {
                    ui.label(format!(
                        "Best peer: {} ({:.0}ms)",
                        peer.address, peer.latency_ms
                    ));
                }

                ui.separator();
                ui.label(format!("Connected peers: {}", peer_count));
                ui.label(format!(
                    "Failed attempts: {}",
                    pm.get_failed_connection_count()
                ));
            }

            if let Some(sync) = wallet_sync {
                ui.separator();
                ui.label(format!("Sync progress: {:.2}%", sync_progress));

                if let Some(eta) = sync.get_estimated_completion() {
                    ui.label(format!("Est. completion: {}s", eta));
                }
            }
        });
    });
}

/// Enhanced transaction record with confirmation status
pub struct TransactionDisplay {
    pub txid: String,
    pub amount: i64,
    pub is_incoming: bool,
    pub timestamp: i64,
    pub confirmations: u32,
    pub fee: Option<u64>,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

impl TransactionDisplay {
    pub fn show(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Status icon
            let (icon, color) = match (&self.status, self.confirmations) {
                (TransactionStatus::Confirmed, _) if self.confirmations >= 3 => {
                    ("✓", egui::Color32::from_rgb(50, 200, 50))
                }
                (TransactionStatus::Confirmed, _) => ("⏳", egui::Color32::from_rgb(200, 150, 50)),
                (TransactionStatus::Pending, _) => ("⏳", egui::Color32::from_rgb(150, 150, 150)),
                (TransactionStatus::Failed, _) => ("✗", egui::Color32::from_rgb(200, 50, 50)),
            };

            ui.label(egui::RichText::new(icon).size(18.0).color(color));

            // Direction indicator
            if self.is_incoming {
                ui.label(egui::RichText::new("↓").color(egui::Color32::from_rgb(50, 200, 50)));
            } else {
                ui.label(egui::RichText::new("↑").color(egui::Color32::from_rgb(200, 50, 50)));
            }

            // Amount
            let amount_text = format!("{:.8} TIME", self.amount as f64 / 100_000_000.0);
            ui.label(
                egui::RichText::new(amount_text)
                    .strong()
                    .color(if self.is_incoming {
                        egui::Color32::from_rgb(50, 200, 50)
                    } else {
                        egui::Color32::from_rgb(200, 50, 50)
                    }),
            );

            ui.separator();

            // Timestamp
            let datetime = chrono::DateTime::from_timestamp(self.timestamp, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            ui.label(datetime);

            ui.separator();

            // Confirmations
            ui.label(format!("{} conf", self.confirmations));

            // Details on hover
            ui.label("ℹ").on_hover_ui(|ui| {
                ui.label(egui::RichText::new("Transaction Details").strong());
                ui.separator();
                ui.label(format!("TXID: {}", &self.txid[..16]));
                ui.label(format!("Confirmations: {}", self.confirmations));

                if let Some(fee) = self.fee {
                    ui.label(format!("Fee: {:.8} TIME", fee as f64 / 100_000_000.0));

                    // Calculate fee/byte if available
                    let fee_per_byte = fee as f64 / 250.0; // Assume ~250 bytes avg
                    ui.label(format!("Fee rate: {:.2} sat/byte", fee_per_byte));
                }

                ui.label(format!("Status: {:?}", self.status));
            });
        });
    }
}

/// Sync progress bar with estimated completion time
pub fn show_sync_progress(ui: &mut egui::Ui, wallet_sync: &Option<Arc<WalletSync>>) {
    if let Some(sync) = wallet_sync {
        let progress = (sync.get_sync_progress() / 100.0) as f32;
        let current = sync.get_current_height();
        let network = sync.get_network_height();

        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label("Syncing blockchain:");
                ui.label(format!("{} / {}", current, network));
            });

            // Progress bar
            let progress_bar = egui::ProgressBar::new(progress)
                .show_percentage()
                .desired_width(ui.available_width());
            ui.add(progress_bar);

            // Estimated completion time
            if let Some(eta_secs) = sync.get_estimated_completion() {
                let eta_text = if eta_secs < 60 {
                    format!("~{} seconds remaining", eta_secs)
                } else if eta_secs < 3600 {
                    format!("~{} minutes remaining", eta_secs / 60)
                } else {
                    format!("~{} hours remaining", eta_secs / 3600)
                };
                ui.label(egui::RichText::new(eta_text).italics());
            }
        });
    }
}

/// Peer list with quality indicators
pub fn show_peer_list(ui: &mut egui::Ui, peer_manager: &Option<Arc<PeerManager>>) {
    if let Some(pm) = peer_manager {
        let peers = pm.get_connected_peers();

        ui.heading("Connected Peers");
        ui.separator();

        let is_empty = peers.is_empty();

        for peer in peers {
            ui.horizontal(|ui| {
                // Quality indicator
                let quality_color = if peer.success_rate > 0.9 {
                    egui::Color32::from_rgb(50, 200, 50)
                } else if peer.success_rate > 0.7 {
                    egui::Color32::from_rgb(200, 150, 50)
                } else {
                    egui::Color32::from_rgb(200, 50, 50)
                };

                ui.label(egui::RichText::new("●").size(16.0).color(quality_color));

                // Peer address
                ui.label(&peer.address);

                ui.separator();

                // Latency
                ui.label(format!("{:.0}ms", peer.latency_ms));

                ui.separator();

                // Success rate
                ui.label(format!("{:.0}% success", peer.success_rate * 100.0));

                // Details on hover
                ui.label("ℹ").on_hover_ui(|ui| {
                    ui.label(egui::RichText::new("Peer Details").strong());
                    ui.separator();
                    ui.label(format!("Address: {}", peer.address));
                    ui.label(format!("Latency: {:.2}ms", peer.latency_ms));
                    ui.label(format!("Success rate: {:.1}%", peer.success_rate * 100.0));
                    ui.label(format!("Requests: {}", peer.request_count));
                    ui.label(format!("Failures: {}", peer.failure_count));
                });
            });
        }

        if is_empty {
            ui.label(
                egui::RichText::new("No peers connected")
                    .italics()
                    .color(egui::Color32::GRAY),
            );
        }
    }
}
