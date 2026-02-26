//! Connections screen — shows all discovered peers with health and ping info.

use egui::Ui;

use crate::state::AppState;

/// Extract the IP from an endpoint like "http://1.2.3.4:24001".
fn peer_ip(endpoint: &str) -> &str {
    let s = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    // Strip port
    s.rsplit_once(':').map(|(host, _)| host).unwrap_or(s)
}

/// Render the connections screen.
pub fn show(ui: &mut Ui, state: &AppState) {
    ui.heading("Connections");
    ui.separator();
    ui.add_space(10.0);

    if state.peers.is_empty() {
        ui.label(
            egui::RichText::new("Discovering peers...")
                .color(egui::Color32::GRAY)
                .italics(),
        );
        ui.spinner();
        return;
    }

    ui.label(format!("{} peers", state.peers.len()));
    ui.add_space(10.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        for peer in &state.peers {
            ui.horizontal(|ui| {
                // Colored dot based on ping
                let dot_color = if !peer.is_healthy {
                    egui::Color32::RED
                } else if let Some(ms) = peer.ping_ms {
                    if ms < 100 {
                        egui::Color32::GREEN
                    } else if ms < 500 {
                        egui::Color32::YELLOW
                    } else {
                        egui::Color32::RED
                    }
                } else {
                    egui::Color32::GRAY
                };
                ui.colored_label(dot_color, "●");

                // IP address
                let ip = peer_ip(&peer.endpoint);
                ui.label(egui::RichText::new(ip).monospace());

                // WS status
                if peer.ws_available {
                    ui.colored_label(egui::Color32::GREEN, "WS");
                } else if peer.is_healthy {
                    ui.colored_label(egui::Color32::GRAY, "WS");
                }

                // Ping on the right
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(ms) = peer.ping_ms {
                        ui.label(format!("{}ms", ms));
                    } else {
                        ui.colored_label(egui::Color32::GRAY, "—");
                    }
                });
            });
        }
    });
}
