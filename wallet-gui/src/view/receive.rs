//! Receive screen — display wallet addresses with QR codes and editable labels.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::state::AppState;

/// Render the receive screen.
pub fn show(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
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

    // Clamp selected address
    if state.selected_address >= state.addresses.len() {
        state.selected_address = 0;
    }

    // Clone selected address data to avoid borrow conflicts
    let selected_addr = state.addresses[state.selected_address].address.clone();
    let selected_label = state.addresses[state.selected_address].label.clone();

    // Top section: QR code and selected address details
    ui.horizontal(|ui| {
        let uri = format!("bytes://qr_{}", selected_addr);
        if let Some(png) = qr_png_bytes(&selected_addr) {
            let image =
                egui::Image::from_bytes(uri, png).fit_to_exact_size(egui::vec2(180.0, 180.0));
            ui.add(image);
        }

        ui.add_space(16.0);

        ui.vertical(|ui| {
            ui.add_space(20.0);
            ui.label(egui::RichText::new(&selected_label).size(16.0).strong());
            ui.add_space(8.0);
            ui.label(egui::RichText::new(&selected_addr).monospace().size(13.0));
            ui.add_space(8.0);
            if ui.button("📋 Copy Address").clicked() {
                ui.ctx().copy_text(selected_addr.clone());
            }
        });
    });

    ui.add_space(15.0);
    ui.separator();
    ui.add_space(10.0);

    // Header with generate button
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Your Addresses").size(14.0).strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("+ New Address").clicked() {
                let _ = ui_tx.send(UiEvent::GenerateAddress);
            }
        });
    });
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(
            "Generate a new address for each sender or transaction to improve privacy.",
        )
        .color(egui::Color32::GRAY)
        .italics()
        .size(11.0),
    );
    ui.add_space(8.0);

    // Address list
    egui::ScrollArea::vertical()
        .max_height(400.0)
        .show(ui, |ui| {
            let mut label_updates = Vec::new();

            for i in 0..state.addresses.len() {
                let is_selected = i == state.selected_address;
                let fill = if is_selected {
                    ui.visuals().selection.bg_fill
                } else {
                    ui.visuals().window_fill
                };

                egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        // Radio button for selection
                        ui.radio_value(&mut state.selected_address, i, "");

                        // Editable label
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut state.addresses[i].label)
                                .desired_width(150.0)
                                .hint_text("Label..."),
                        );
                        if response.lost_focus() {
                            label_updates.push((i, state.addresses[i].label.clone()));
                        }

                        ui.add_space(8.0);

                        // Truncated address
                        let addr = &state.addresses[i].address;
                        let display = if addr.len() > 24 {
                            format!("{}…{}", &addr[..14], &addr[addr.len() - 8..])
                        } else {
                            addr.clone()
                        };
                        ui.label(egui::RichText::new(display).monospace());

                        // Copy button
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.button("📋").clicked() {
                                    ui.ctx()
                                        .copy_text(state.addresses[i].address.clone());
                                }
                            },
                        );
                    });
                });
            }

            // Persist label changes
            for (index, label) in label_updates {
                let _ = ui_tx.send(UiEvent::UpdateAddressLabel { index, label });
            }
        });
}

/// Generate QR code as PNG bytes for the given data string.
fn qr_png_bytes(data: &str) -> Option<Vec<u8>> {
    use image::{ImageEncoder, Rgba, RgbaImage};
    use qrcode::QrCode;

    let code = QrCode::new(data.as_bytes()).ok()?;
    let colors = code.to_colors();
    let w = code.width();
    let scale = 8u32;
    let border = 2u32;
    let size = (w as u32 + border * 2) * scale;

    let mut img = RgbaImage::from_pixel(size, size, Rgba([255, 255, 255, 255]));
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        let px = (x as u32 + border) * scale + dx;
                        let py = (y as u32 + border) * scale + dy;
                        img.put_pixel(px, py, Rgba([0, 0, 0, 255]));
                    }
                }
            }
        }
    }

    let mut buf = std::io::Cursor::new(Vec::new());
    let encoder = image::codecs::png::PngEncoder::new(&mut buf);
    encoder
        .write_image(img.as_raw(), size, size, image::ExtendedColorType::Rgba8)
        .ok()?;
    Some(buf.into_inner())
}
