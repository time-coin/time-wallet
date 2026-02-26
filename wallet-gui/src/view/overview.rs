//! Overview screen — balance display and recent transactions.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::state::AppState;

/// Render the overview screen.
pub fn show(ui: &mut Ui, state: &AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.horizontal(|ui| {
        ui.heading("Overview");
        ui.add_space(10.0);

        if ui
            .add_enabled(
                !state.loading,
                egui::Button::new(if state.loading {
                    "Refreshing..."
                } else {
                    "Refresh"
                }),
            )
            .clicked()
        {
            let _ = ui_tx.send(UiEvent::RefreshBalance);
            let _ = ui_tx.send(UiEvent::RefreshTransactions);
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let ws_label = if state.ws_connected {
                egui::RichText::new("Connected").color(egui::Color32::GREEN)
            } else {
                egui::RichText::new("Disconnected").color(egui::Color32::RED)
            };
            ui.label(ws_label);
        });
    });

    ui.separator();
    ui.add_space(10.0);

    // Balance card
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.vertical(|ui| {
            ui.label(
                egui::RichText::new("Balance")
                    .size(14.0)
                    .color(egui::Color32::GRAY),
            );
            ui.add_space(4.0);

            let total_time = state.balance.total as f64 / 1_000_000.0;
            ui.label(
                egui::RichText::new(format!("{:.6} TIME", total_time))
                    .size(32.0)
                    .strong(),
            );

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let confirmed = state.balance.confirmed as f64 / 1_000_000.0;
                let pending = state.balance.pending as f64 / 1_000_000.0;
                ui.label(format!("Confirmed: {:.6}", confirmed));
                ui.add_space(20.0);
                if state.balance.pending > 0 {
                    ui.label(
                        egui::RichText::new(format!("Pending: {:.6}", pending))
                            .color(egui::Color32::YELLOW),
                    );
                }
            });
        });
    });

    ui.add_space(15.0);

    // Recent transactions
    ui.heading("Recent Transactions");
    ui.add_space(5.0);

    if state.transactions.is_empty() {
        ui.label(
            egui::RichText::new("No transactions yet")
                .color(egui::Color32::GRAY)
                .italics(),
        );
    } else {
        egui::ScrollArea::vertical()
            .max_height(400.0)
            .show(ui, |ui| {
                for tx in state.transactions.iter().take(20) {
                    ui.group(|ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let amount_time = tx.amount as f64 / 1_000_000.0;
                            let short_txid = if tx.txid.len() > 16 {
                                format!("{}..", &tx.txid[..16])
                            } else {
                                tx.txid.clone()
                            };

                            ui.label(
                                egui::RichText::new(format!("{:.6} TIME", amount_time)).strong(),
                            );
                            ui.add_space(10.0);
                            ui.label(
                                egui::RichText::new(short_txid)
                                    .color(egui::Color32::GRAY)
                                    .monospace(),
                            );

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let status_label = format!("{} conf", tx.confirmations);
                                    let color = if tx.confirmations > 0 {
                                        egui::Color32::GREEN
                                    } else {
                                        egui::Color32::YELLOW
                                    };
                                    ui.label(egui::RichText::new(status_label).color(color));
                                },
                            );
                        });
                    });
                }
            });
    }

    // Status messages
    if let Some(ref err) = state.error {
        ui.add_space(10.0);
        ui.colored_label(egui::Color32::RED, format!("Error: {}", err));
    }
    if let Some(ref msg) = state.success {
        ui.add_space(10.0);
        ui.colored_label(egui::Color32::GREEN, msg.as_str());
    }
}
