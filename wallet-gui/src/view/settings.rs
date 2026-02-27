//! Settings screen.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::state::AppState;

const DECIMAL_OPTIONS: &[usize] = &[2, 4, 6, 8];

/// Render the settings screen.
pub fn show(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.heading("Settings");
    ui.separator();
    ui.add_space(10.0);

    // Display preferences
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Display").strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Decimal places:");
            egui::ComboBox::from_id_salt("decimal_places")
                .selected_text(format!("{}", state.decimal_places))
                .show_ui(ui, |ui| {
                    for &dp in DECIMAL_OPTIONS {
                        if ui
                            .selectable_value(&mut state.decimal_places, dp, format!("{}", dp))
                            .changed()
                        {
                            let _ = ui_tx.send(UiEvent::UpdateDecimalPlaces(dp));
                        }
                    }
                });
            // Preview
            let preview = state.format_time(12_345_678_900);
            ui.label(egui::RichText::new(format!("e.g. {}", preview)).color(egui::Color32::GRAY));
        });
    });

    ui.add_space(10.0);

    // Network info
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Network").strong());
        ui.add_space(4.0);
        let network = if state.is_testnet {
            "Testnet"
        } else {
            "Mainnet"
        };
        ui.label(format!("Current network: {}", network));
    });

    ui.add_space(10.0);

    // Wallet info
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Wallet").strong());
        ui.add_space(4.0);
        if state.wallet_loaded {
            ui.label(format!("Addresses: {}", state.addresses.len()));
            ui.label("Status: Loaded");
        } else {
            ui.label("Status: Not loaded");
        }
    });

    ui.add_space(10.0);

    // Connection status
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Connection").strong());
        ui.add_space(4.0);

        let ws_status = if state.ws_connected {
            egui::RichText::new("WebSocket: Connected").color(egui::Color32::GREEN)
        } else {
            egui::RichText::new("WebSocket: Disconnected").color(egui::Color32::RED)
        };
        ui.label(ws_status);

        if let Some(ref health) = state.health {
            ui.label(format!("Block height: {}", health.block_height));
            ui.label(format!("Peers: {}", health.peer_count));
            ui.label(format!("Version: {}", health.version));
        }
    });

    ui.add_space(10.0);

    // Security notes
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Security").strong());
        ui.add_space(4.0);
        ui.label("- Private keys are encrypted with AES-256-GCM");
        ui.label("- Key derivation uses Argon2id (memory-hard)");
        ui.label("- Keys are zeroized from memory after use");
        ui.label("- Always keep your recovery phrase in a safe place");
    });
}
