//! Send screen — transaction form.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::state::AppState;

/// Render the send screen.
pub fn show(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.heading("Send TIME");
    ui.separator();
    ui.add_space(10.0);

    let expected_prefix = if state.is_testnet { "TIME0" } else { "TIME1" };
    let wrong_prefix = if state.is_testnet { "TIME1" } else { "TIME0" };
    let network_name = if state.is_testnet {
        "testnet"
    } else {
        "mainnet"
    };

    ui.group(|ui| {
        ui.set_min_width(ui.available_width());

        ui.label("Recipient Address");
        ui.add(
            egui::TextEdit::singleline(&mut state.send_address)
                .hint_text(format!("{}...", expected_prefix))
                .desired_width(ui.available_width()),
        );

        // Address validation feedback
        if !state.send_address.is_empty() {
            if state.send_address.starts_with(wrong_prefix) {
                ui.colored_label(
                    egui::Color32::RED,
                    format!(
                        "WARNING: This is a {} address. You are on {}.",
                        if state.is_testnet {
                            "mainnet"
                        } else {
                            "testnet"
                        },
                        network_name,
                    ),
                );
            } else if !state.send_address.starts_with(expected_prefix) {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    format!(
                        "WARNING: Expected address starting with {}",
                        expected_prefix
                    ),
                );
            }
        }

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label("Amount (TIME)");
                ui.add(
                    egui::TextEdit::singleline(&mut state.send_amount)
                        .hint_text("0.000000")
                        .desired_width(200.0),
                );
            });

            ui.add_space(20.0);

            ui.vertical(|ui| {
                ui.label("Fee (TIME)");
                ui.add(
                    egui::TextEdit::singleline(&mut state.send_fee)
                        .hint_text("0.001000")
                        .desired_width(200.0),
                );
            });
        });

        ui.add_space(8.0);

        // Available balance
        let available = state.balance.confirmed as f64 / 100_000_000.0;
        ui.label(
            egui::RichText::new(format!("Available: {:.6} TIME", available))
                .color(egui::Color32::GRAY),
        );

        ui.add_space(15.0);

        let address_valid = state.send_address.starts_with(expected_prefix);
        let can_send = address_valid
            && !state.send_address.is_empty()
            && !state.send_amount.is_empty()
            && !state.loading;

        if ui
            .add_enabled(
                can_send,
                egui::Button::new(egui::RichText::new("Send Transaction").size(16.0))
                    .min_size(egui::vec2(200.0, 36.0)),
            )
            .clicked()
        {
            let amount = parse_time_amount(&state.send_amount);
            let fee = if state.send_fee.is_empty() {
                100_000 // default fee: 0.001 TIME
            } else {
                parse_time_amount(&state.send_fee)
            };

            if amount == 0 {
                state.error = Some("Invalid amount".to_string());
            } else {
                let _ = ui_tx.send(UiEvent::SendTransaction {
                    to: state.send_address.clone(),
                    amount,
                    fee,
                });
                state.loading = true;
                state.error = None;
            }
        }

        if state.loading {
            ui.spinner();
        }
    });

    // Status messages
    if let Some(ref err) = state.error {
        ui.add_space(10.0);
        ui.colored_label(egui::Color32::RED, format!("Error: {}", err));
    }
    if let Some(ref msg) = state.success {
        ui.add_space(10.0);
        ui.colored_label(egui::Color32::GREEN, format!("Sent: {}", msg));
    }
}

/// Parse a human-readable TIME amount (e.g. "1.5") into micro-TIME units.
fn parse_time_amount(s: &str) -> u64 {
    s.parse::<f64>()
        .map(|v| (v * 100_000_000.0) as u64)
        .unwrap_or(0)
}
