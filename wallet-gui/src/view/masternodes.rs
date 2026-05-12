use egui::{Color32, RichText, Ui};

use crate::events::UiEvent;
use crate::state::AppState;
use crate::wallet_db::{masternode_tier_from_satoshis, MasternodeEntry};

/// Colored tier label text (no emoji — relies on color for distinction).
fn tier_label(tier: &str) -> (&'static str, Color32) {
    match tier {
        "Gold" => ("Gold", Color32::from_rgb(255, 200, 50)),
        "Silver" => ("Silver", Color32::from_rgb(192, 192, 192)),
        "Bronze" => ("Bronze", Color32::from_rgb(180, 100, 50)),
        _ => ("Free", Color32::GRAY),
    }
}

/// Render the Masternodes management screen.
pub fn render(
    ui: &mut Ui,
    state: &mut AppState,
    ui_tx: &tokio::sync::mpsc::UnboundedSender<UiEvent>,
) {
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
    ui.heading("Masternodes");
    ui.add_space(8.0);

    // ---------- Tier requirements info box ----------
    egui::CollapsingHeader::new("Tier Requirements & Setup Guide")
        .default_open(false)
        .show(ui, |ui| {
            ui.add_space(4.0);
            egui::Grid::new("tier_req_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Tier").strong());
                    ui.label(RichText::new("Collateral Required").strong());
                    ui.end_row();
                    ui.label(
                        RichText::new("Gold")
                            .color(Color32::from_rgb(255, 200, 50))
                            .strong(),
                    );
                    ui.label("100,000 TIME");
                    ui.end_row();
                    ui.label(
                        RichText::new("Silver")
                            .color(Color32::from_rgb(192, 192, 192))
                            .strong(),
                    );
                    ui.label("10,000 TIME");
                    ui.end_row();
                    ui.label(
                        RichText::new("Bronze")
                            .color(Color32::from_rgb(180, 100, 50))
                            .strong(),
                    );
                    ui.label("1,000 TIME");
                    ui.end_row();
                });
            ui.add_space(6.0);
            ui.label(RichText::new("How to activate a tiered masternode:").strong());
            ui.label("1. Send the required collateral to a wallet address and note the TXID/vout.");
            ui.label("2. Add the entry below with the collateral TXID and vout.");
            ui.label("3. Click Copy Conf to get the line for your masternode's masternode.conf.");
            ui.add_space(4.0);
        });

    ui.add_space(8.0);

    // ---------- Add button ----------
    ui.horizontal(|ui| {
        if ui.button("➕ Add Masternode").clicked() {
            state.mn_show_add_form = !state.mn_show_add_form;
            if state.mn_show_add_form && state.mn_add_name.is_empty() {
                // Auto-suggest next available name
                let existing: std::collections::HashSet<&str> = state
                    .masternode_entries
                    .iter()
                    .map(|e| e.alias.as_str())
                    .collect();
                let mut n = 1u32;
                loop {
                    let candidate = format!("mn{}", n);
                    if !existing.contains(candidate.as_str()) {
                        state.mn_add_name = candidate;
                        break;
                    }
                    n += 1;
                }
            }
        }
    });

    // ---------- Add form ----------
    if state.mn_show_add_form {
        ui.add_space(8.0);
        egui::Frame::group(ui.style())
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.label(RichText::new("New Masternode Entry").strong());
                ui.add_space(4.0);

                egui::Grid::new("mn_add_grid")
                    .num_columns(2)
                    .spacing([8.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Name:")
                            .on_hover_text("A short label for this masternode, e.g. mn1");
                        ui.text_edit_singleline(&mut state.mn_add_name)
                            .on_hover_text("e.g. mn1");
                        ui.end_row();

                        ui.label("Collateral TXID:");
                        let resp = ui.text_edit_singleline(&mut state.mn_add_txid);
                        resp.context_menu(|ui| {
                            if ui.button("📋 Paste").clicked() {
                                if let Ok(mut cb) = arboard::Clipboard::new() {
                                    if let Ok(t) = cb.get_text() {
                                        state.mn_add_txid = t.trim().to_string();
                                    }
                                }
                                ui.close_menu();
                            }
                        });
                        ui.end_row();

                        ui.label("Collateral Vout:");
                        ui.text_edit_singleline(&mut state.mn_add_vout);
                        ui.end_row();
                    });

                // Duplicate collateral warning
                {
                    let txid = state.mn_add_txid.trim();
                    let vout: u32 = state.mn_add_vout.trim().parse().unwrap_or(0);
                    if !txid.is_empty() && state.masternode_entries.iter().any(|e| e.collateral_txid == txid && e.collateral_vout == vout) {
                        ui.add_space(4.0);
                        egui::Frame::new()
                            .fill(Color32::from_rgba_unmultiplied(200, 60, 60, 40))
                            .corner_radius(4.0)
                            .inner_margin(egui::Margin::symmetric(8, 4))
                            .show(ui, |ui| {
                                ui.label(RichText::new("⚠ Duplicate TXID detected — please fix to avoid being blacklisted").color(Color32::from_rgb(220, 60, 60)).size(12.0));
                            });
                    }
                }

                // Preview tier from collateral UTXO if available
                if !state.mn_add_txid.trim().is_empty() {
                    let txid = state.mn_add_txid.trim().to_string();
                    let vout: u32 = state.mn_add_vout.trim().parse().unwrap_or(0);
                    if let Some(utxo) = state
                        .utxos
                        .iter()
                        .find(|u| u.txid == txid && u.vout == vout)
                    {
                        let amount_time = utxo.amount as f64 / 100_000_000.0;
                        ui.add_space(4.0);
                        match masternode_tier_from_satoshis(utxo.amount) {
                            Some(tier) => {
                                let (label, color) = tier_label(tier);
                                ui.horizontal(|ui| {
                                    ui.label("Detected tier:");
                                    ui.label(RichText::new(label).color(color).strong());
                                    ui.label(format!("({:.0} TIME)", amount_time));
                                });
                            }
                            None => {
                                ui.colored_label(
                                    Color32::YELLOW,
                                    format!(
                                        "⚠ Collateral {:.0} TIME is below Bronze minimum (1,000 TIME)",
                                        amount_time
                                    ),
                                );
                            }
                        }
                    }
                }

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let name_trimmed = state.mn_add_name.trim().to_string();
                    let can_save = !name_trimmed.is_empty()
                        && !state.mn_add_txid.trim().is_empty()
                        && state.mn_add_vout.trim().parse::<u32>().is_ok();

                    if ui
                        .add_enabled(can_save, egui::Button::new("💾 Save"))
                        .clicked()
                    {
                        let alias = name_trimmed;
                        let txid = state.mn_add_txid.trim().to_string();
                        let vout: u32 = state.mn_add_vout.trim().parse().unwrap_or(0);
                        let collateral_amount = state
                            .utxos
                            .iter()
                            .find(|u| u.txid == txid && u.vout == vout)
                            .map(|u| u.amount);
                        let entry = MasternodeEntry {
                            alias,
                            collateral_txid: txid,
                            collateral_vout: vout,
                            payout_address: None,
                            collateral_amount,
                            reg_txid: None,
                            registered_ip: None,
                        };
                        let _ = ui_tx.send(UiEvent::SaveMasternodeEntry(entry.clone()));
                        // Optimistic update — show immediately without waiting for async confirmation
                        state.locked_utxos.insert(format!("{}:{}", entry.collateral_txid, entry.collateral_vout));
                        state.masternode_entries.retain(|e| e.alias != entry.alias);
                        state.masternode_entries.push(entry);
                        state.masternode_entries.sort_by(|a, b| a.alias.cmp(&b.alias));
                        state.mn_add_name.clear();
                        state.mn_add_txid.clear();
                        state.mn_add_vout = "0".to_string();
                        state.mn_show_add_form = false;
                    }
                    if ui.button("Cancel").clicked() {
                        state.mn_add_name.clear();
                        state.mn_show_add_form = false;
                    }
                });
            });
    }

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    // ---------- Masternode list ----------
    if state.masternode_entries.is_empty() {
        ui.label("No masternodes configured. Add one manually or import a masternode.conf file.");
    } else {
        let mut to_delete: Option<String> = None;
        let mut update_event: Option<UiEvent> = None;
        let mut optimistic_update: Option<(String, MasternodeEntry)> = None; // (old_alias, new_entry)
        let mut register_event: Option<UiEvent> = None;
        let mut deregister_event: Option<UiEvent> = None;

        for entry in &state.masternode_entries {
            // Resolve collateral UTXO: live data first, cached amount as fallback.
            let collateral_utxo = state
                .utxos
                .iter()
                .find(|u| u.txid == entry.collateral_txid && u.vout == entry.collateral_vout);
            let live_amount = collateral_utxo.map(|u| u.amount);
            let effective_amount = live_amount.or(entry.collateral_amount);
            let tier = effective_amount.and_then(masternode_tier_from_satoshis);
            // None = UTXO not yet synced; Some(true) = locked; Some(false) = spendable/unlocked.
            let collateral_locked = collateral_utxo.map(|u| !u.spendable);

            egui::Frame::group(ui.style())
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&entry.alias).strong().size(16.0));
                        // Tier badge
                        match tier {
                            Some(t) => {
                                let (label, color) = tier_label(t);
                                ui.label(RichText::new(label).color(color).strong());
                            }
                            None => {
                                match effective_amount {
                                    Some(_) => {
                                        ui.label(RichText::new("⚠ Below threshold").color(Color32::YELLOW));
                                    }
                                    None => {
                                        ui.label(RichText::new("? Tier pending").color(Color32::GRAY))
                                            .on_hover_text("Collateral UTXO not yet fetched — tier will appear after the next sync");
                                    }
                                }
                            }
                        }
                        // Collateral locked badge — derived from spendable field on the live UTXO.
                        match collateral_locked {
                            Some(true) => {
                                ui.label(
                                    RichText::new("🔒 Locked")
                                        .color(Color32::from_rgb(80, 200, 120))
                                        .size(12.0),
                                )
                                .on_hover_text(
                                    "Collateral is locked by the masternode — not spendable while active.",
                                );
                            }
                            Some(false) => {
                                ui.label(
                                    RichText::new("🔓 Not Locked")
                                        .color(Color32::from_rgb(255, 160, 40))
                                        .size(12.0),
                                )
                                .on_hover_text(
                                    "Collateral UTXO is spendable — the masternode has not locked it.\n\
                                     Register on-chain or check your masternode server.",
                                );
                            }
                            None => {
                                // UTXO not yet in the synced set — show nothing; will appear after sync.
                            }
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Del").on_hover_text("Delete").clicked() {
                                to_delete = Some(entry.alias.clone());
                            }
                        });
                    });

                    egui::Grid::new(format!("mn_detail_{}", entry.alias))
                        .num_columns(2)
                        .spacing([8.0, 2.0])
                        .show(ui, |ui| {
                            ui.label("Collateral:");
                            let short_txid = if entry.collateral_txid.len() > 16 {
                                format!(
                                    "{}…{}",
                                    &entry.collateral_txid[..8],
                                    &entry.collateral_txid[entry.collateral_txid.len() - 8..]
                                )
                            } else {
                                entry.collateral_txid.clone()
                            };
                            ui.label(format!("{}:{}", short_txid, entry.collateral_vout));
                            ui.end_row();

                            if let Some(amount) = effective_amount {
                                ui.label("Amount:");
                                ui.label(format!("{:.0} TIME", amount as f64 / 100_000_000.0));
                                ui.end_row();
                            }
                        });

                    // --- Action buttons ---
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        // Copy daemon conf line
                        let daemon_line = entry.to_daemon_conf_line();
                        if ui
                            .button("Copy Conf")
                            .on_hover_text(format!(
                                "Copies the line for your masternode server's masternode.conf:\n\n{}\n\nPaste into ~/.timed/masternode.conf on your server, then restart timed.",
                                daemon_line
                            ))
                            .clicked()
                        {
                            ui.ctx().copy_text(daemon_line);
                            state.success = Some(format!(
                                "Daemon conf line for '{}' copied to clipboard.",
                                entry.alias
                            ));
                        }

                        if ui
                            .button("Edit")
                            .on_hover_text("Edit this masternode entry")
                            .clicked()
                        {
                            state.mn_edit_alias = Some(entry.alias.clone());
                            state.mn_edit_name = entry.alias.clone();
                            state.mn_edit_txid = entry.collateral_txid.clone();
                            state.mn_edit_vout = entry.collateral_vout.to_string();
                        }

                        let reg_open = state.mn_reg_alias.as_deref() == Some(&entry.alias);
                        // Show Deregister when either this wallet registered the node
                        // (reg_txid stored) OR when the live UTXO set confirms the
                        // collateral is still locked on-chain (e.g. a recovered entry).
                        let confirmed_locked = collateral_locked == Some(true);
                        if entry.reg_txid.is_some() || confirmed_locked {
                            // Already registered — show Deregister button
                            if ui
                                .button(RichText::new("🔓 Deregister").color(Color32::from_rgb(220, 80, 80)))
                                .on_hover_text("Broadcast a CollateralUnlock transaction to remove this masternode from the chain.")
                                .clicked()
                            {
                                deregister_event = Some(UiEvent::DeregisterMasternode {
                                    alias: entry.alias.clone(),
                                    collateral_txid: entry.collateral_txid.clone(),
                                    collateral_vout: entry.collateral_vout,
                                    masternode_ip: entry.registered_ip.clone().unwrap_or_default(),
                                });
                            }
                        } else {
                            let reg_label = if reg_open { "▲ Register" } else { "🔗 Register On-Chain" };
                            if ui
                                .button(reg_label)
                                .on_hover_text("Prove collateral ownership on-chain to evict squatters.\nSigns with your wallet key and submits a MasternodeReg transaction.")
                                .clicked()
                            {
                                if reg_open {
                                    state.mn_reg_alias = None;
                                } else {
                                    state.mn_reg_alias = Some(entry.alias.clone());
                                    // Pre-fill IP from stored record
                                    if let Some(ref ip) = entry.registered_ip {
                                        state.mn_reg_ip = ip.clone();
                                    }
                                    // Pre-fill payout address from entry if available
                                    if let Some(ref pa) = entry.payout_address {
                                        state.mn_reg_payout = pa.clone();
                                    } else if state.mn_reg_payout.is_empty() {
                                        // Fall back to first wallet address
                                        if let Some(first_addr) = state.addresses.first() {
                                            state.mn_reg_payout = first_addr.address.clone();
                                        }
                                    }
                                }
                            }
                        }
                    });

                    // Inline edit form
                    if state.mn_edit_alias.as_deref() == Some(&entry.alias) {
                        let old_alias = entry.alias.clone();
                        let old_payout = entry.payout_address.clone();
                        ui.add_space(4.0);
                        egui::Grid::new(format!("mn_edit_{}", entry.alias))
                            .num_columns(2)
                            .spacing([8.0, 4.0])
                            .show(ui, |ui| {
                                ui.label("Name:");
                                ui.text_edit_singleline(&mut state.mn_edit_name);
                                ui.end_row();
                                ui.label("Collateral TXID:");
                                let r = ui.text_edit_singleline(&mut state.mn_edit_txid);
                                r.context_menu(|ui| {
                                    if ui.button("Paste").clicked() {
                                        if let Ok(mut cb) = arboard::Clipboard::new() {
                                            if let Ok(t) = cb.get_text() {
                                                state.mn_edit_txid = t.trim().to_string();
                                            }
                                        }
                                        ui.close_menu();
                                    }
                                });
                                ui.end_row();
                                ui.label("Collateral Vout:");
                                ui.text_edit_singleline(&mut state.mn_edit_vout);
                                ui.end_row();
                            });
                        // Duplicate collateral warning (exclude the entry being edited)
                        {
                            let edit_txid = state.mn_edit_txid.trim();
                            let edit_vout: u32 = state.mn_edit_vout.trim().parse().unwrap_or(0);
                            let current_alias = state.mn_edit_alias.as_deref().unwrap_or("");
                            if !edit_txid.is_empty() && state.masternode_entries.iter().any(|e| {
                                e.alias != current_alias && e.collateral_txid == edit_txid && e.collateral_vout == edit_vout
                            }) {
                                ui.add_space(4.0);
                                egui::Frame::new()
                                    .fill(Color32::from_rgba_unmultiplied(200, 60, 60, 40))
                                    .corner_radius(4.0)
                                    .inner_margin(egui::Margin::symmetric(8, 4))
                                    .show(ui, |ui| {
                                        ui.label(RichText::new("⚠ Duplicate TXID detected — please fix to avoid being blacklisted").color(Color32::from_rgb(220, 60, 60)).size(12.0));
                                    });
                                ui.add_space(4.0);
                            }
                        }

                        ui.horizontal(|ui| {
                            let name_t = state.mn_edit_name.trim().to_string();
                            let valid = !name_t.is_empty()
                                && !state.mn_edit_txid.trim().is_empty()
                                && state.mn_edit_vout.trim().parse::<u32>().is_ok();
                            if ui.add_enabled(valid, egui::Button::new("Save")).clicked() {
                                let txid = state.mn_edit_txid.trim().to_string();
                                let vout: u32 = state.mn_edit_vout.trim().parse().unwrap_or(0);
                                let collateral_amount = state
                                    .utxos
                                    .iter()
                                    .find(|u| u.txid == txid && u.vout == vout)
                                    .map(|u| u.amount);
                                update_event = Some(UiEvent::UpdateMasternodeEntry {
                                    old_alias: old_alias.clone(),
                                    new_entry: MasternodeEntry {
                                        alias: name_t.clone(),
                                        collateral_txid: txid.clone(),
                                        collateral_vout: vout,
                                        payout_address: old_payout,
                                        collateral_amount,
                                        reg_txid: None, // preserved by service handler
                                        registered_ip: None,
                                    },
                                });
                                optimistic_update = Some((old_alias, MasternodeEntry {
                                    alias: name_t,
                                    collateral_txid: txid,
                                    collateral_vout: vout,
                                    payout_address: None,
                                    collateral_amount,
                                    reg_txid: None,
                                    registered_ip: None,
                                }));
                                state.mn_edit_alias = None;
                            }
                            if ui.button("Cancel").clicked() {
                                state.mn_edit_alias = None;
                            }
                        });
                    }

                    // --- On-chain registration form ---
                    if state.mn_reg_alias.as_deref() == Some(&entry.alias) {
                        ui.add_space(6.0);
                        egui::Frame::new()
                            .fill(ui.visuals().faint_bg_color)
                            .corner_radius(4.0)
                            .inner_margin(egui::Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                ui.label(RichText::new("Register On-Chain").strong());
                                ui.add_space(2.0);
                                ui.label(RichText::new(
                                    "Signs with your wallet key to prove collateral ownership. \
                                     Broadcasts a MasternodeReg transaction that evicts any squatter."
                                ).size(11.0).color(ui.visuals().weak_text_color()));
                                ui.label(RichText::new(
                                    "⚠ 0.01 TIME registration fee. Your collateral is not spent or moved."
                                ).size(11.0).color(Color32::YELLOW));
                                ui.add_space(6.0);
                                egui::Grid::new(format!("mn_reg_{}", entry.alias))
                                    .num_columns(2)
                                    .spacing([8.0, 4.0])
                                    .show(ui, |ui| {
                                        ui.label("Server IP:");
                                        ui.text_edit_singleline(&mut state.mn_reg_ip)
                                            .on_hover_text("Public IP of the server running timed, e.g. 1.2.3.4");
                                        ui.end_row();
                                        ui.label("Port:");
                                        ui.text_edit_singleline(&mut state.mn_reg_port)
                                            .on_hover_text("P2P port (default 24000 mainnet, 24100 testnet)");
                                        ui.end_row();
                                        ui.label("Payout address:");
                                        ui.label(
                                            egui::RichText::new(
                                                "Automatically set to the collateral owner address",
                                            )
                                            .italics()
                                            .weak(),
                                        )
                                        .on_hover_text(
                                            "The protocol requires rewards to be paid to the \
                                             collateral owner's address. This cannot be changed.",
                                        );
                                        ui.end_row();
                                    });
                                ui.add_space(6.0);
                                let ip_ok = !state.mn_reg_ip.trim().is_empty();
                                let port_ok = state.mn_reg_port.trim().parse::<u16>().is_ok();
                                let can_register = ip_ok && port_ok;
                                ui.horizontal(|ui| {
                                    if ui
                                        .add_enabled(can_register, egui::Button::new("✅ Submit Registration"))
                                        .on_disabled_hover_text("Fill in server IP and port")
                                        .clicked()
                                    {
                                        register_event = Some(UiEvent::RegisterMasternode {
                                            alias: entry.alias.clone(),
                                            ip: state.mn_reg_ip.trim().to_string(),
                                            port: state.mn_reg_port.trim().parse().unwrap_or(24000),
                                            collateral_txid: entry.collateral_txid.clone(),
                                            collateral_vout: entry.collateral_vout,
                                            payout_address: state.mn_reg_payout.trim().to_string(),
                                        });
                                        state.mn_reg_alias = None;
                                    }
                                    if ui.button("Cancel").clicked() {
                                        state.mn_reg_alias = None;
                                    }
                                });
                            });
                    }
                });
            ui.add_space(4.0);
        }

        if let Some(alias) = to_delete {
            let _ = ui_tx.send(UiEvent::DeleteMasternodeEntry {
                alias: alias.clone(),
            });
            state.masternode_entries.retain(|e| e.alias != alias);
            state.locked_utxos = state
                .masternode_entries
                .iter()
                .map(|e| format!("{}:{}", e.collateral_txid, e.collateral_vout))
                .collect();
        }
        if let Some(event) = update_event {
            let _ = ui_tx.send(event);
        }
        if let Some(event) = register_event {
            let _ = ui_tx.send(event);
        }
        if let Some(event) = deregister_event {
            let _ = ui_tx.send(event);
        }
        if let Some((old_alias, new_entry)) = optimistic_update {
            state.locked_utxos.retain(|k| {
                !state.masternode_entries.iter().any(|e| {
                    e.alias == old_alias
                        && format!("{}:{}", e.collateral_txid, e.collateral_vout) == *k
                })
            });
            state.masternode_entries.retain(|e| e.alias != old_alias);
            state.locked_utxos.insert(format!(
                "{}:{}",
                new_entry.collateral_txid, new_entry.collateral_vout
            ));
            state.masternode_entries.push(new_entry);
            state
                .masternode_entries
                .sort_by(|a, b| a.alias.cmp(&b.alias));
        }
    }
    }); // end ScrollArea
}
