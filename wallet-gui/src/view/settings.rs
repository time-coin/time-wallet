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

    // Editor preference
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("External Editor").strong());
        ui.add_space(4.0);
        ui.label("Editor used to open configuration files. Leave empty to use the OS default.");
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut state.editor_input)
                    .hint_text("OS default")
                    .desired_width(300.0),
            );

            if ui.button("Browse…").clicked() {
                let filter = if cfg!(target_os = "windows") {
                    rfd::FileDialog::new().add_filter("Executables", &["exe"])
                } else {
                    rfd::FileDialog::new().add_filter("All files", &["*"])
                };
                if let Some(path) = filter.pick_file() {
                    state.editor_input = path.display().to_string();
                    let editor = Some(state.editor_input.clone());
                    let _ = ui_tx.send(UiEvent::SetEditor { editor });
                }
            }

            // Save when the text field loses focus or enter is pressed
            if response.lost_focus() {
                let editor = if state.editor_input.trim().is_empty() {
                    None
                } else {
                    Some(state.editor_input.trim().to_string())
                };
                let _ = ui_tx.send(UiEvent::SetEditor { editor });
            }
        });
    });

    ui.add_space(10.0);

    // Network section — shows current network with a toggle button
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Network").strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let (network_label, bg, fg) = if state.is_testnet {
                (
                    "Testnet",
                    egui::Color32::from_rgb(255, 250, 200),
                    egui::Color32::from_rgb(120, 100, 0),
                )
            } else {
                (
                    "Mainnet",
                    egui::Color32::from_rgb(200, 225, 255),
                    egui::Color32::from_rgb(0, 60, 120),
                )
            };
            egui::Frame::new()
                .fill(bg)
                .corner_radius(4.0)
                .inner_margin(egui::Margin::symmetric(8, 3))
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(network_label).strong().color(fg));
                });
            ui.add_space(8.0);
            let switch_label = if state.is_testnet {
                "Switch to Mainnet"
            } else {
                "Switch to Testnet"
            };
            if state.switching_network {
                ui.spinner();
            } else if ui.button(switch_label).clicked() {
                state.switching_network = true;
                let new_network = if state.is_testnet {
                    "mainnet"
                } else {
                    "testnet"
                };
                let _ = ui_tx.send(UiEvent::SelectNetwork {
                    network: new_network.to_string(),
                });
            }
        });
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new("Switching network will reload the wallet for that network.")
                .small()
                .color(egui::Color32::GRAY),
        );
    });

    ui.add_space(10.0);

    // Wallet info
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());
        ui.label(egui::RichText::new("Wallet").strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(format!("Version: {}", env!("CARGO_PKG_VERSION")));
            if let Some(ref latest) = state.latest_version {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("▲ v{} available", latest))
                        .color(egui::Color32::from_rgb(255, 165, 0))
                        .strong(),
                );
                if let Some(ref url) = state.latest_version_url {
                    ui.hyperlink_to("Download", url.as_str());
                }
            }
        });
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

        let healthy_peers = state.peers.iter().filter(|p| p.is_healthy).count();
        ui.label(format!("Connections: {}", healthy_peers));
        if let Some(ref health) = state.health {
            ui.label(format!("Block height: {}", health.block_height));
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
