//! Connections screen — shows all discovered peers with health and ping info.

use egui::Ui;

use crate::state::AppState;

/// Render the connections screen.
pub fn show(ui: &mut Ui, state: &AppState) {
    ui.heading("Connections");
    ui.separator();
    ui.add_space(10.0);

    // WebSocket status
    ui.horizontal(|ui| {
        ui.label("WebSocket:");
        if state.ws_connected {
            ui.colored_label(egui::Color32::GREEN, "● Connected");
        } else {
            ui.colored_label(egui::Color32::RED, "● Disconnected");
        }
    });

    ui.add_space(15.0);

    if state.peers.is_empty() {
        ui.label(
            egui::RichText::new("Discovering peers...")
                .color(egui::Color32::GRAY)
                .italics(),
        );
        ui.spinner();
        return;
    }

    ui.label(format!("{} peers discovered", state.peers.len()));
    ui.add_space(10.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        for peer in &state.peers {
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    // Status indicator
                    if peer.is_active {
                        ui.label(egui::RichText::new("★").color(egui::Color32::GOLD));
                    }

                    let status_color = if peer.is_healthy {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    };
                    ui.colored_label(status_color, "●");

                    // Endpoint
                    ui.label(
                        egui::RichText::new(&peer.endpoint)
                            .monospace()
                            .strong(),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Ping
                        if let Some(ms) = peer.ping_ms {
                            let ping_color = if ms < 100 {
                                egui::Color32::GREEN
                            } else if ms < 500 {
                                egui::Color32::YELLOW
                            } else {
                                egui::Color32::RED
                            };
                            ui.colored_label(ping_color, format!("{}ms", ms));
                        } else {
                            ui.colored_label(egui::Color32::GRAY, "—");
                        }

                        // Block height
                        if let Some(height) = peer.block_height {
                            ui.label(format!("#{}", height));
                        }

                        // Version
                        if let Some(ref ver) = peer.version {
                            ui.label(
                                egui::RichText::new(ver)
                                    .color(egui::Color32::GRAY)
                                    .small(),
                            );
                        }
                    });
                });
            });
        }
    });
}
