//! Receive screen — display wallet addresses.

use egui::Ui;

use crate::state::AppState;

/// Render the receive screen.
pub fn show(ui: &mut Ui, state: &AppState) {
    ui.heading("Receive TIME");
    ui.separator();
    ui.add_space(10.0);

    if state.addresses.is_empty() {
        ui.label(
            egui::RichText::new("No addresses available — load or create a wallet first.")
                .color(egui::Color32::GRAY)
                .italics(),
        );
        return;
    }

    ui.label("Share one of your addresses to receive TIME coins:");
    ui.add_space(10.0);

    egui::ScrollArea::vertical()
        .max_height(500.0)
        .show(ui, |ui| {
            for (i, addr) in state.addresses.iter().enumerate() {
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("#{}", i))
                                .color(egui::Color32::GRAY)
                                .monospace(),
                        );
                        ui.add_space(8.0);

                        ui.label(egui::RichText::new(addr).monospace());

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("📋 Copy").clicked() {
                                ui.ctx().copy_text(addr.clone());
                            }
                        });
                    });
                });
            }
        });
}
