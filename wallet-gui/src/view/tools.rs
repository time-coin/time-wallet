//! Tools screen — maintenance and diagnostic utilities.

use crate::config_new::Config;
use crate::events::UiEvent;
use crate::state::AppState;
use tokio::sync::mpsc;

pub fn show(ui: &mut egui::Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.heading("🔧 Tools");
    ui.add_space(10.0);

    // -- Resync Wallet --
    ui.group(|ui| {
        ui.label(egui::RichText::new("Resync Wallet").strong().size(16.0));
        ui.add_space(4.0);
        ui.label("Clears cached transactions and UTXOs, then re-downloads everything from the masternode. Use this if your balance looks wrong or transactions are missing.");
        ui.add_space(6.0);

        if state.resync_in_progress {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Resyncing…");
            });
        } else if ui
            .add(egui::Button::new("🔄 Resync Now").min_size(egui::vec2(120.0, 28.0)))
            .clicked()
        {
            state.resync_in_progress = true;
            state.error = None;
            state.success = None;
            let _ = ui_tx.send(UiEvent::ResyncWallet);
        }
    });

    ui.add_space(16.0);

    // -- Open Config Files --
    ui.group(|ui| {
        ui.label(
            egui::RichText::new("Configuration Files")
                .strong()
                .size(16.0),
        );
        ui.add_space(4.0);
        ui.label("Open configuration files in your system text editor.");
        ui.add_space(6.0);

        if let Ok(data_dir) = Config::data_dir() {
            let config_path = data_dir.join("config.toml");
            let config_exists = config_path.exists();

            ui.horizontal(|ui| {
                let btn = ui.add_enabled(
                    config_exists,
                    egui::Button::new("📝 Open config.toml").min_size(egui::vec2(160.0, 28.0)),
                );
                if btn.clicked() {
                    let _ = ui_tx.send(UiEvent::OpenConfigFile {
                        path: config_path.clone(),
                    });
                }
                ui.label(
                    egui::RichText::new(config_path.display().to_string())
                        .weak()
                        .small(),
                );
            });

            if !config_exists {
                ui.label(
                    egui::RichText::new(
                        "Config file does not exist yet. It will be created on first save.",
                    )
                    .weak()
                    .italics(),
                );
            }
        } else {
            ui.label(egui::RichText::new("Could not determine data directory.").weak());
        }
    });

    ui.add_space(16.0);

    // -- Status messages --
    if let Some(ref msg) = state.success {
        ui.label(egui::RichText::new(format!("✅ {msg}")).color(egui::Color32::GREEN));
    }
    if let Some(ref msg) = state.error {
        ui.label(egui::RichText::new(format!("❌ {msg}")).color(egui::Color32::RED));
    }
}
