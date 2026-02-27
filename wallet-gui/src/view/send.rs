//! Send screen — transaction form with contact address book.

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

    // -- Send form --
    ui.group(|ui| {
        ui.set_min_width(ui.available_width());

        ui.label("Recipient Address");

        // Show contact name if the current address matches a contact
        let contact_name = state
            .contacts
            .iter()
            .find(|c| c.address == state.send_address)
            .map(|c| c.name.clone());
        if let Some(ref name) = contact_name {
            ui.label(
                egui::RichText::new(format!("Sending to: {}", name))
                    .strong()
                    .color(egui::Color32::LIGHT_BLUE),
            );
        }

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
                    egui::Color32::from_rgb(255, 165, 0),
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

        // Available balance and insufficient funds check
        let available = state.balance.confirmed;
        let available_time = available as f64 / 100_000_000.0;
        let send_amount = parse_time_amount(&state.send_amount);
        let send_fee = if state.send_fee.is_empty() {
            100_000 // default fee: 0.001 TIME
        } else {
            parse_time_amount(&state.send_fee)
        };
        let total_cost = send_amount.saturating_add(send_fee);
        let insufficient = send_amount > 0 && total_cost > available;

        if insufficient {
            ui.label(
                egui::RichText::new(format!("Available: {:.6} TIME", available_time))
                    .color(egui::Color32::RED),
            );
            let total_time = total_cost as f64 / 100_000_000.0;
            ui.colored_label(
                egui::Color32::RED,
                format!(
                    "Insufficient funds. Amount + fee = {:.6} TIME exceeds balance.",
                    total_time
                ),
            );
        } else {
            ui.label(
                egui::RichText::new(format!("Available: {:.6} TIME", available_time))
                    .color(egui::Color32::GRAY),
            );
        }

        ui.add_space(15.0);

        let address_valid = state.send_address.starts_with(expected_prefix);
        let can_send = address_valid
            && !state.send_address.is_empty()
            && !state.send_amount.is_empty()
            && !insufficient
            && !state.loading;

        if ui
            .add_enabled(
                can_send,
                egui::Button::new(egui::RichText::new("Send Transaction").size(16.0))
                    .min_size(egui::vec2(200.0, 36.0)),
            )
            .clicked()
        {
            if send_amount == 0 {
                state.error = Some("Invalid amount".to_string());
            } else {
                let _ = ui_tx.send(UiEvent::SendTransaction {
                    to: state.send_address.clone(),
                    amount: send_amount,
                    fee: send_fee,
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

    ui.add_space(15.0);
    ui.separator();
    ui.add_space(5.0);

    // -- Address Book --
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Address Book").strong().size(16.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .selectable_label(state.show_add_contact, "+ Add Contact")
                .clicked()
            {
                state.show_add_contact = !state.show_add_contact;
            }
        });
    });

    // Add contact form
    if state.show_add_contact {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.new_contact_name)
                        .hint_text("e.g. Alice")
                        .desired_width(150.0),
                );
                ui.label("Address:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.new_contact_address)
                        .hint_text(format!("{}...", expected_prefix))
                        .desired_width(250.0),
                );
                let can_save = !state.new_contact_name.is_empty()
                    && state.new_contact_address.starts_with(expected_prefix);
                if ui
                    .add_enabled(can_save, egui::Button::new("Save"))
                    .clicked()
                {
                    let _ = ui_tx.send(UiEvent::SaveContact {
                        name: state.new_contact_name.clone(),
                        address: state.new_contact_address.clone(),
                    });
                    state.new_contact_name.clear();
                    state.new_contact_address.clear();
                    state.show_add_contact = false;
                }
            });
        });
    }

    ui.add_space(4.0);

    if state.contacts.is_empty() {
        ui.label(
            egui::RichText::new("No contacts yet. Add one to quickly send TIME.")
                .color(egui::Color32::GRAY)
                .italics(),
        );
    } else {
        // Search box
        ui.add(
            egui::TextEdit::singleline(&mut state.contact_search)
                .hint_text("Search contacts...")
                .desired_width(ui.available_width()),
        );
        ui.add_space(4.0);

        let search = state.contact_search.to_lowercase();
        let filtered: Vec<_> = state
            .contacts
            .iter()
            .filter(|c| {
                search.is_empty()
                    || c.name.to_lowercase().contains(&search)
                    || c.address.to_lowercase().contains(&search)
            })
            .collect();

        if filtered.is_empty() {
            ui.label(
                egui::RichText::new("No contacts match your search.")
                    .color(egui::Color32::GRAY)
                    .italics(),
            );
        } else {
            ui.label(
                egui::RichText::new(format!("{} contacts", filtered.len()))
                    .color(egui::Color32::GRAY)
                    .small(),
            );
            let mut delete_addr = None;
            let mut save_edit = None;
            egui::ScrollArea::vertical()
                .id_salt("contacts_scroll")
                .max_height(200.0)
                .show(ui, |ui| {
                    for contact in &filtered {
                        let is_editing =
                            state.editing_contact_address.as_deref() == Some(&contact.address);

                        if is_editing {
                            // Inline edit row
                            ui.horizontal(|ui| {
                                ui.label("Name:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut state.editing_contact_name)
                                        .desired_width(150.0),
                                );
                                ui.label(
                                    egui::RichText::new(&contact.address)
                                        .monospace()
                                        .color(egui::Color32::GRAY),
                                );
                                if ui.small_button("Save").clicked() {
                                    save_edit = Some((
                                        state.editing_contact_name.clone(),
                                        contact.address.clone(),
                                    ));
                                }
                                if ui.small_button("Cancel").clicked() {
                                    state.editing_contact_address = None;
                                }
                            });
                        } else {
                            // Normal display row
                            ui.horizontal(|ui| {
                                let selected = state.send_address == contact.address;
                                if ui
                                    .selectable_label(
                                        selected,
                                        format!("{} — {}", contact.name, &contact.address),
                                    )
                                    .clicked()
                                {
                                    state.send_address = contact.address.clone();
                                }
                                if ui
                                    .small_button("Edit")
                                    .on_hover_text("Edit contact name")
                                    .clicked()
                                {
                                    state.editing_contact_address = Some(contact.address.clone());
                                    state.editing_contact_name = contact.name.clone();
                                }
                                if ui
                                    .small_button("X")
                                    .on_hover_text("Remove contact")
                                    .clicked()
                                {
                                    delete_addr = Some(contact.address.clone());
                                }
                            });
                        }
                    }
                });
            if let Some(addr) = delete_addr {
                // Clear edit state if we deleted the one being edited
                if state.editing_contact_address.as_deref() == Some(addr.as_str()) {
                    state.editing_contact_address = None;
                }
                let _ = ui_tx.send(UiEvent::DeleteContact { address: addr });
            }
            if let Some((name, address)) = save_edit {
                let _ = ui_tx.send(UiEvent::SaveContact { name, address });
                state.editing_contact_address = None;
            }
        }
    }
}

/// Parse a human-readable TIME amount (e.g. "1.5") into micro-TIME units.
fn parse_time_amount(s: &str) -> u64 {
    s.parse::<f64>()
        .map(|v| (v * 100_000_000.0).round() as u64)
        .unwrap_or(0)
}
