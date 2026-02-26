//! Welcome screen — shown when no wallet is loaded.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::state::AppState;

/// Render the welcome screen.
pub fn show(ui: &mut Ui, state: &AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.vertical_centered(|ui| {
        ui.add_space(60.0);

        // Logo
        let logo_bytes = include_bytes!("../../assets/logo.png");
        let image = egui::Image::from_bytes("bytes://logo.png", logo_bytes.as_slice())
            .max_width(128.0);
        ui.add(image);

        ui.add_space(20.0);
        ui.heading(
            egui::RichText::new("TIME Coin Wallet")
                .size(28.0)
                .strong(),
        );
        ui.add_space(8.0);

        let network_label = if state.is_testnet { "Testnet" } else { "Mainnet" };
        ui.label(
            egui::RichText::new(format!("Secure thin-client wallet — {}", network_label))
                .size(14.0)
                .color(egui::Color32::GRAY),
        );

        ui.add_space(40.0);

        // Load existing wallet
        if ui
            .add(egui::Button::new(
                egui::RichText::new("🔓 Open Wallet").size(16.0),
            ).min_size(egui::vec2(200.0, 40.0)))
            .clicked()
        {
            let _ = ui_tx.send(UiEvent::LoadWallet { password: None });
        }

        ui.add_space(12.0);

        // Create new wallet
        if ui
            .add(egui::Button::new(
                egui::RichText::new("✨ Create New Wallet").size(16.0),
            ).min_size(egui::vec2(200.0, 40.0)))
            .clicked()
        {
            // Navigate to mnemonic setup — handled by parent
            let _ = ui_tx.send(UiEvent::NavigatedTo(crate::events::Screen::MnemonicSetup));
        }

        ui.add_space(30.0);

        // Error display
        if let Some(ref err) = state.error {
            ui.colored_label(egui::Color32::RED, format!("⚠ {}", err));
        }

        if state.loading {
            ui.spinner();
            ui.label("Loading wallet...");
        }
    });
}
