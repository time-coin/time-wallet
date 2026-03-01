//! Overview screen — balance display and recent transactions.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::{Screen, UiEvent};
use crate::masternode_client::TransactionStatus;
use crate::state::AppState;

/// Render the overview screen.
pub fn show(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
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

    // Syncing indicator
    if state.syncing {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(
                egui::RichText::new("Synchronizing with network…")
                    .color(egui::Color32::from_rgb(100, 180, 255)),
            );
        });
        ui.add_space(5.0);
    }

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

            ui.label(
                egui::RichText::new(state.format_time(state.balance.total))
                    .size(32.0)
                    .strong(),
            );

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let confirmed = state.format_time(state.balance.confirmed);
                let pending_str = state.format_time(state.balance.pending);
                ui.label(format!("Confirmed: {}", confirmed));
                ui.add_space(20.0);
                if state.balance.pending > 0 {
                    ui.label(
                        egui::RichText::new(format!("Pending: {}", pending_str))
                            .color(egui::Color32::from_rgb(255, 165, 0)),
                    );
                }
            });
        });
    });

    ui.add_space(15.0);

    // Security warning for unencrypted wallets
    if state.wallet_loaded && !state.wallet_encrypted {
        ui.group(|ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("⚠ Your wallet is not password-protected.")
                        .color(egui::Color32::from_rgb(255, 165, 0))
                        .strong(),
                );
                if ui.button("Set Password").clicked() {
                    state.show_encrypt_dialog = true;
                }
            });
        });

        if state.show_encrypt_dialog {
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.label("Enter a password to encrypt your wallet:");
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let pw = ui.add(
                        egui::TextEdit::singleline(&mut state.encrypt_password_input)
                            .password(true)
                            .hint_text("Password")
                            .desired_width(250.0),
                    );
                    if (pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                        || ui.button("Encrypt").clicked())
                        && !state.encrypt_password_input.is_empty()
                    {
                        let _ = ui_tx.send(UiEvent::EncryptWallet {
                            password: state.encrypt_password_input.clone(),
                        });
                    }
                    if ui.button("Cancel").clicked() {
                        state.show_encrypt_dialog = false;
                        state.encrypt_password_input.clear();
                    }
                });
            });
        }

        ui.add_space(5.0);
    }

    // Real-time notifications
    if !state.recent_notifications.is_empty() {
        ui.heading("Notifications");
        ui.add_space(5.0);
        for notif in state.recent_notifications.iter().rev().take(5) {
            ui.horizontal(|ui| {
                let amount_sats = crate::masternode_client::json_to_satoshis(&notif.amount);
                ui.colored_label(
                    egui::Color32::GREEN,
                    format!("Received {}", state.format_time(amount_sats)),
                );
                let short_addr = if notif.address.len() > 20 {
                    format!("{}..", &notif.address[..20])
                } else {
                    notif.address.clone()
                };
                ui.label(
                    egui::RichText::new(format!("to {}", short_addr))
                        .color(egui::Color32::GRAY)
                        .monospace(),
                );
            });
        }
        ui.add_space(10.0);
    }

    // Recent transactions (last 10, no scroll — compact overview)
    ui.heading("Recent Transactions");
    ui.add_space(5.0);

    if state.transactions.is_empty() {
        ui.label(
            egui::RichText::new("No transactions yet")
                .color(egui::Color32::GRAY)
                .italics(),
        );
    } else {
        let mut clicked_idx = None;
        for (i, tx) in state.transactions.iter().take(10).enumerate() {
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

                        // Amount colored by direction
                        let is_neg = tx.is_send || tx.is_fee;
                        ui.label(
                            egui::RichText::new(state.format_time_signed(tx.amount, is_neg))
                                .strong()
                                .color(amount_color),
                        );

                        ui.add_space(8.0);

                        // Recipient: contact name or abbreviated address
                        let addr_display = if tx.is_fee {
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
                        ui.label(egui::RichText::new(addr_display).color(egui::Color32::GRAY));

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // Status
                            let (status_text, status_color) = match tx.status {
                                TransactionStatus::Approved => ("Approved", egui::Color32::GREEN),
                                TransactionStatus::Pending => {
                                    ("Pending", egui::Color32::from_rgb(255, 165, 0))
                                }
                                TransactionStatus::Declined => ("Declined", egui::Color32::RED),
                            };
                            ui.label(egui::RichText::new(status_text).color(status_color));

                            ui.add_space(12.0);

                            // Date
                            if tx.timestamp > 0 {
                                if let Some(dt) = chrono::DateTime::from_timestamp(tx.timestamp, 0)
                                {
                                    let local: chrono::DateTime<chrono::Local> = dt.into();
                                    ui.label(
                                        egui::RichText::new(
                                            local.format("%Y-%m-%d %H:%M").to_string(),
                                        )
                                        .color(egui::Color32::GRAY),
                                    );
                                }
                            }
                        });
                    });
                })
                .response;

            if resp.interact(egui::Sense::click()).clicked() {
                clicked_idx = Some(i);
            }
        }

        if state.transactions.len() > 10 {
            ui.add_space(4.0);
            if ui
                .link(format!(
                    "View all {} transactions",
                    state.transactions.len()
                ))
                .clicked()
            {
                state.screen = Screen::Transactions;
                let _ = ui_tx.send(UiEvent::NavigatedTo(Screen::Transactions));
            }
        }

        // Navigate to transaction detail
        if let Some(idx) = clicked_idx {
            state.selected_transaction = Some(idx);
            state.screen = Screen::Transactions;
            let _ = ui_tx.send(UiEvent::NavigatedTo(Screen::Transactions));
        }
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
