//! Transactions screen — transaction history list with detail view.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::masternode_client::TransactionStatus;
use crate::state::AppState;

/// Render the transactions screen.
pub fn show(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    // If a transaction is selected, show its detail view
    if let Some(idx) = state.selected_transaction {
        if idx < state.transactions.len() {
            show_detail(ui, state, idx);
            return;
        } else {
            state.selected_transaction = None;
        }
    }

    show_list(ui, state, ui_tx);
}

/// Detail view for a single transaction.
fn show_detail(ui: &mut Ui, state: &mut AppState, idx: usize) {
    let tx = &state.transactions[idx];

    ui.horizontal(|ui| {
        if ui.button("← Back").clicked() {
            state.selected_transaction = None;
        }
        ui.heading("Transaction Details");
    });

    ui.separator();
    ui.add_space(10.0);

    // Direction and amount
    let (dir_label, amount_color) = if tx.is_fee {
        ("Fee", egui::Color32::from_rgb(255, 165, 0))
    } else if tx.is_send {
        ("Sent", egui::Color32::from_rgb(255, 80, 80))
    } else {
        ("Received", egui::Color32::from_rgb(80, 200, 80))
    };

    let is_neg = tx.is_send || tx.is_fee;
    ui.label(
        egui::RichText::new(format!(
            "{} {}",
            dir_label,
            state.format_time_signed(tx.amount, is_neg)
        ))
        .size(24.0)
        .strong()
        .color(amount_color),
    );

    ui.add_space(15.0);

    egui::Grid::new("tx_detail_grid")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            // Status
            ui.label(egui::RichText::new("Status:").strong());
            let (status_text, status_color) = match tx.status {
                TransactionStatus::Approved => ("Approved", egui::Color32::GREEN),
                TransactionStatus::Pending => ("Pending", egui::Color32::from_rgb(255, 165, 0)),
                TransactionStatus::Declined => ("Declined", egui::Color32::RED),
            };
            ui.label(egui::RichText::new(status_text).color(status_color));
            ui.end_row();

            // Transaction ID
            ui.label(egui::RichText::new("Transaction ID:").strong());
            if ui
                .add(
                    egui::Label::new(egui::RichText::new(&tx.txid).monospace())
                        .sense(egui::Sense::click()),
                )
                .on_hover_text("Click to copy")
                .clicked()
            {
                ui.ctx().copy_text(tx.txid.clone());
            }
            ui.end_row();

            // Vout
            ui.label(egui::RichText::new("Vout:").strong());
            ui.label(format!("{}", tx.vout));
            ui.end_row();

            // Address
            let addr_label = if tx.is_send { "To:" } else { "From:" };
            ui.label(egui::RichText::new(addr_label).strong());
            ui.vertical(|ui| {
                // Show contact name if known
                if let Some(name) = state.contact_name(&tx.address) {
                    ui.label(egui::RichText::new(name).strong());
                }
                if ui
                    .add(
                        egui::Label::new(egui::RichText::new(&tx.address).monospace())
                            .sense(egui::Sense::click()),
                    )
                    .on_hover_text("Click to copy")
                    .clicked()
                {
                    ui.ctx().copy_text(tx.address.clone());
                }
            });
            ui.end_row();

            // Fee
            if tx.fee > 0 {
                ui.label(egui::RichText::new("Fee:").strong());
                ui.label(state.format_time(tx.fee));
                ui.end_row();
            }

            // Date
            if tx.timestamp > 0 {
                ui.label(egui::RichText::new("Date:").strong());
                if let Some(dt) = chrono::DateTime::from_timestamp(tx.timestamp, 0) {
                    ui.label(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                }
                ui.end_row();
            }
        });
}

/// List view of all transactions.
fn show_list(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.horizontal(|ui| {
        ui.heading("Transactions");
        ui.add_space(10.0);

        if ui.button("Refresh").clicked() {
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

    let mut clicked_idx = None;
    egui::ScrollArea::vertical()
        .id_salt("tx_list_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (i, tx) in state.transactions.iter().enumerate() {
                let resp = ui
                    .group(|ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            // Send/receive/fee icon
                            let (dir_icon, amount_color) = if tx.is_fee {
                                ("Fee", egui::Color32::from_rgb(255, 165, 0))
                            } else if tx.is_send {
                                ("Sent", egui::Color32::from_rgb(255, 80, 80))
                            } else {
                                ("Received", egui::Color32::from_rgb(80, 200, 80))
                            };
                            ui.label(egui::RichText::new(dir_icon).color(amount_color));

                            ui.add_space(8.0);

                            // Amount
                            let is_neg = tx.is_send || tx.is_fee;
                            ui.label(
                                egui::RichText::new(state.format_time_signed(tx.amount, is_neg))
                                    .strong()
                                    .color(amount_color),
                            );

                            ui.add_space(8.0);

                            // Recipient: contact name or abbreviated address
                            let addr_label = if tx.is_fee {
                                tx.address.clone()
                            } else if let Some(name) = state.contact_name(&tx.address) {
                                let addr = &tx.address;
                                let short = if addr.len() > 14 {
                                    format!("{}..{}", &addr[..8], &addr[addr.len() - 4..])
                                } else {
                                    addr.clone()
                                };
                                format!("{} ({})", name, short)
                            } else {
                                let addr = &tx.address;
                                if addr.len() > 14 {
                                    format!("{}..{}", &addr[..8], &addr[addr.len() - 4..])
                                } else {
                                    addr.clone()
                                }
                            };
                            ui.label(egui::RichText::new(addr_label).color(egui::Color32::GRAY));

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    // Status
                                    let (status_text, status_color) = match tx.status {
                                        TransactionStatus::Approved => {
                                            ("Approved", egui::Color32::GREEN)
                                        }
                                        TransactionStatus::Pending => {
                                            ("Pending", egui::Color32::from_rgb(255, 165, 0))
                                        }
                                        TransactionStatus::Declined => {
                                            ("Declined", egui::Color32::RED)
                                        }
                                    };
                                    ui.label(egui::RichText::new(status_text).color(status_color));

                                    ui.add_space(12.0);

                                    // Date
                                    if tx.timestamp > 0 {
                                        if let Some(dt) =
                                            chrono::DateTime::from_timestamp(tx.timestamp, 0)
                                        {
                                            ui.label(
                                                egui::RichText::new(
                                                    dt.format("%Y-%m-%d %H:%M").to_string(),
                                                )
                                                .color(egui::Color32::GRAY),
                                            );
                                        }
                                    }

                                    ui.add_space(12.0);

                                    // Short txid (first 8 .. last 4)
                                    let short_txid = if tx.txid.len() > 12 {
                                        format!(
                                            "{}..{}",
                                            &tx.txid[..8],
                                            &tx.txid[tx.txid.len() - 4..]
                                        )
                                    } else {
                                        tx.txid.clone()
                                    };
                                    ui.label(
                                        egui::RichText::new(short_txid)
                                            .monospace()
                                            .color(egui::Color32::DARK_GRAY),
                                    );
                                },
                            );
                        });
                    })
                    .response;

                if resp.interact(egui::Sense::click()).clicked() {
                    clicked_idx = Some(i);
                }
            }
        });

    if let Some(idx) = clicked_idx {
        state.selected_transaction = Some(idx);
    }
}
