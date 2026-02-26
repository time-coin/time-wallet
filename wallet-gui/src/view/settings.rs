//! Settings screen.

use egui::Ui;

use crate::state::AppState;

/// Render the settings screen.
pub fn show(ui: &mut Ui, state: &AppState) {
    ui.heading("Settings");
    ui.separator();
    ui.add_space(10.0);

    // Network info
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Network").strong());
        ui.add_space(4.0);
        let network = if state.is_testnet { "Testnet" } else { "Mainnet" };
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
            ui.label("Status: Loaded ✅");
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
            egui::RichText::new("WebSocket: Connected ✅").color(egui::Color32::GREEN)
        } else {
            egui::RichText::new("WebSocket: Disconnected ❌").color(egui::Color32::RED)
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
        ui.label("• Private keys are encrypted with AES-256-GCM");
        ui.label("• Key derivation uses Argon2id (memory-hard)");
        ui.label("• Keys are zeroized from memory after use");
        ui.label("• Always keep your recovery phrase in a safe place");
    });
}
