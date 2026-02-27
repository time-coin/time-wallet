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
        });

        ui.add_space(8.0);

        // Auto-calculate tiered fee (matches masternode consensus rule)
        let send_amount = parse_time_amount(&state.send_amount);
        let available = state.balance.confirmed;
        let auto_fee = if send_amount > 0 {
            wallet::calculate_fee(send_amount)
        } else {
            0
        };
        if send_amount > 0 {
            let fee_pct = if send_amount < 100 * 100_000_000 {
                "1%"
            } else if send_amount < 1_000 * 100_000_000 {
                "0.5%"
            } else if send_amount < 10_000 * 100_000_000 {
                "0.25%"
            } else {
                "0.1%"
            };
            ui.label(
                egui::RichText::new(format!(
                    "Network fee: {}.{:06} TIME ({})",
                    auto_fee / 100_000_000,
                    (auto_fee % 100_000_000) / 100,
                    fee_pct,
                ))
                .color(egui::Color32::GRAY),
            );
        }

        ui.add_space(4.0);

        // Available balance and insufficient funds check
        let total_cost = send_amount.saturating_add(auto_fee);
        let insufficient = send_amount > 0 && total_cost > available;

        if insufficient {
            ui.label(
                egui::RichText::new(format!(
                    "Available: {}.{:06} TIME",
                    available / 100_000_000,
                    (available % 100_000_000) / 100
                ))
                .color(egui::Color32::RED),
            );
            ui.colored_label(
                egui::Color32::RED,
                format!(
                    "Insufficient funds. Amount + fee = {}.{:06} TIME exceeds balance.",
                    total_cost / 100_000_000,
                    (total_cost % 100_000_000) / 100
                ),
            );
        } else {
            ui.label(
                egui::RichText::new(format!(
                    "Available: {}.{:06} TIME",
                    available / 100_000_000,
                    (available % 100_000_000) / 100
                ))
                .color(egui::Color32::GRAY),
            );
        }

        ui.add_space(15.0);

        // Full address validation with checksum
        let address_valid = if state.send_address.starts_with(expected_prefix) {
            wallet::address::Address::from_string(&state.send_address).is_ok()
        } else {
            false
        };

        // Show checksum error if prefix is right but checksum fails
        if !state.send_address.is_empty()
            && state.send_address.starts_with(expected_prefix)
            && !address_valid
        {
            ui.colored_label(
                egui::Color32::RED,
                "Invalid address checksum — check for typos",
            );
        }

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
                    fee: auto_fee,
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
                let contact_addr_valid = !state.new_contact_name.is_empty()
                    && wallet::address::Address::from_string(&state.new_contact_address).is_ok();
                if ui
                    .add_enabled(contact_addr_valid, egui::Button::new("Save"))
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
                // Clear send form if the deleted contact was selected
                if state.send_address == addr {
                    state.send_address.clear();
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

/// Parse a human-readable TIME amount (e.g. "1.5") into satoshi units.
fn parse_time_amount(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    let (whole, frac) = if let Some(dot) = s.find('.') {
        (&s[..dot], &s[dot + 1..])
    } else {
        (s, "")
    };
    let whole_val: u64 = whole.parse().unwrap_or(0);
    let frac_padded = format!("{:0<8}", frac);
    let frac_val: u64 = frac_padded[..8].parse().unwrap_or(0);
    whole_val
        .saturating_mul(100_000_000)
        .saturating_add(frac_val)
}
