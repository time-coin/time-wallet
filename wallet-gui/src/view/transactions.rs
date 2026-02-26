//! Transactions screen — transaction history list.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::masternode_client::TransactionStatus;
use crate::state::AppState;

/// Render the transactions screen.
pub fn show(ui: &mut Ui, state: &AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.horizontal(|ui| {
        ui.heading("Transactions");
        ui.add_space(10.0);

        if ui.button("Sync").clicked() {
            let _ = ui_tx.send(UiEvent::RefreshTransactions);
        }
    });

    ui.separator();
    ui.add_space(5.0);

    if state.transactions.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(
                egui::RichText::new("No transactions yet")
                    .size(16.0)
                    .color(egui::Color32::GRAY)
                    .italics(),
            );
            ui.add_space(10.0);
            ui.label("Transactions will appear here once you send or receive TIME.");
        });
        return;
    }

    ui.label(format!("{} transactions", state.transactions.len()));
    ui.add_space(5.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        for tx in &state.transactions {
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    // Status icon
                    let (icon, color) = match tx.status {
                        TransactionStatus::Finalized => ("OK", egui::Color32::GREEN),
                        TransactionStatus::Confirmed => ("OK", egui::Color32::GREEN),
                        TransactionStatus::Pending => ("..", egui::Color32::YELLOW),
                        TransactionStatus::Failed => ("!!", egui::Color32::RED),
                    };
                    ui.label(egui::RichText::new(icon).size(16.0).color(color));

                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            let amount = tx.amount as f64 / 100_000_000.0;
                            ui.label(egui::RichText::new(format!("{:.6} TIME", amount)).strong());

                            ui.add_space(10.0);

                            let conf_text = match tx.status {
                                TransactionStatus::Finalized => "Finalized".to_string(),
                                TransactionStatus::Confirmed => {
                                    format!("{} confirmations", tx.confirmations)
                                }
                                TransactionStatus::Pending => "Pending".to_string(),
                                TransactionStatus::Failed => "Failed".to_string(),
                            };
                            ui.label(
                                egui::RichText::new(conf_text)
                                    .color(egui::Color32::GRAY)
                                    .small(),
                            );
                        });

                        // Transaction ID
                        let short_txid = if tx.txid.len() > 32 {
                            format!("{}..", &tx.txid[..32])
                        } else {
                            tx.txid.clone()
                        };
                        ui.label(
                            egui::RichText::new(short_txid)
                                .monospace()
                                .color(egui::Color32::GRAY)
                                .small(),
                        );

                        // Timestamp
                        if tx.timestamp > 0 {
                            let dt = chrono::DateTime::from_timestamp(tx.timestamp, 0);
                            if let Some(dt) = dt {
                                ui.label(
                                    egui::RichText::new(dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                        .color(egui::Color32::DARK_GRAY)
                                        .small(),
                                );
                            }
                        }
                    });
                });
            });
        }
    });
}
