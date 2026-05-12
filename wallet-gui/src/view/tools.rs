//! Tools screen — maintenance and diagnostic utilities.

use crate::config_new::Config;
use crate::events::UiEvent;
use crate::state::AppState;
use tokio::sync::mpsc;

/// Ensure `path` exists (writing a template if new), then open it with the OS default app.
/// Runs entirely on a background thread — never touches the service loop.
fn open_conf_file(path: std::path::PathBuf) {
    std::thread::spawn(move || {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let template = crate::service::config_file_template(&path);
            if let Err(e) = std::fs::write(&path, template) {
                log::error!("Failed to create {}: {}", path.display(), e);
                return;
            }
            log::info!("Created {}", path.display());
        }
        if let Err(e) = open::that(&path) {
            log::error!("Failed to open {}: {}", path.display(), e);
        }
    });
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
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

    // -- Repair Database --
    ui.group(|ui| {
        ui.label(egui::RichText::new("Repair Database").strong().size(16.0));
        ui.add_space(4.0);
        ui.label("If the wallet database is corrupted (e.g. from an improper shutdown), this will back up the damaged database and create a fresh one. Transactions, UTXOs, and balances are re-fetched from the masternodes. Contacts and masternode configurations will need to be re-entered.");
        ui.add_space(6.0);

        if state.repair_in_progress {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Repairing…");
            });
        } else if ui
            .add(egui::Button::new("🛠 Repair Database").min_size(egui::vec2(160.0, 28.0)))
            .clicked()
        {
            state.repair_in_progress = true;
            state.error = None;
            state.success = None;
            let _ = ui_tx.send(UiEvent::RepairDatabase);
        }
    });

    ui.add_space(16.0);

    // -- Consolidate UTXOs --
    ui.group(|ui| {
        ui.label(egui::RichText::new("Consolidate UTXOs").strong().size(16.0));
        ui.add_space(4.0);
        ui.label(
            format!(
                "Combines many small UTXOs into fewer large ones, making future transactions faster and smaller. You currently have {} UTXOs.",
                state.utxos.len()
            ),
        );
        ui.add_space(6.0);

        if state.consolidation_in_progress {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(&state.consolidation_status);
                ui.add_space(12.0);
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("✕ Cancel")
                                .color(egui::Color32::from_rgb(200, 60, 60)),
                        )
                        .min_size(egui::vec2(80.0, 24.0)),
                    )
                    .clicked()
                {
                    let _ = ui_tx.send(UiEvent::CancelConsolidation);
                }
            });
        } else if ui
            .add_enabled(
                state.utxos.len() > 1 && !state.syncing,
                egui::Button::new("🔗 Consolidate Now").min_size(egui::vec2(160.0, 28.0)),
            )
            .clicked()
        {
            state.consolidation_in_progress = true;
            state.consolidation_status = "Starting consolidation...".to_string();
            state.error = None;
            state.success = None;
            let _ = ui_tx.send(UiEvent::ConsolidateUtxos);
        }
    });

    ui.add_space(16.0);

    // -- Collateral Lock Audit --
    ui.group(|ui| {
        egui::CollapsingHeader::new(
            egui::RichText::new("Collateral Lock Audit").strong().size(16.0),
        )
        .default_open(false)
        .show(ui, |ui| {
        ui.add_space(4.0);

        let locked_utxos: Vec<_> = state.utxos.iter().filter(|u| !u.spendable).collect();

        if locked_utxos.is_empty() {
            if state.utxos.is_empty() {
                ui.label(egui::RichText::new("No UTXO data yet — sync first.").weak());
            } else {
                ui.label(egui::RichText::new("✅ No locked collateral UTXOs found.").color(egui::Color32::GREEN));
            }
        } else {
            ui.label(format!(
                "{} locked UTXO(s) reported by the node, {} masternode entries in wallet.",
                locked_utxos.len(),
                state.masternode_entries.len()
            ));
            ui.add_space(6.0);

            let mut has_phantom = false;
            egui::Grid::new("collateral_audit_grid")
                .num_columns(4)
                .spacing([12.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("TXID (short)").strong());
                    ui.label(egui::RichText::new("Vout").strong());
                    ui.label(egui::RichText::new("Amount").strong());
                    ui.label(egui::RichText::new("Wallet entry").strong());
                    ui.end_row();

                    for u in &locked_utxos {
                        let matched_entry = state.masternode_entries.iter().find(|e| {
                            e.collateral_txid == u.txid && e.collateral_vout == u.vout
                        });

                        // Short txid for display
                        let short_txid = if u.txid.len() >= 16 {
                            format!("{}…{}", &u.txid[..8], &u.txid[u.txid.len()-8..])
                        } else {
                            u.txid.clone()
                        };
                        let amount_time = u.amount as f64 / 100_000_000.0;

                        ui.label(egui::RichText::new(&short_txid).monospace())
                            .on_hover_text(&u.txid);
                        ui.label(u.vout.to_string());
                        ui.label(format!("{:.0} TIME", amount_time));

                        match matched_entry {
                            Some(entry) => {
                                ui.label(
                                    egui::RichText::new(format!("✔ {}", entry.alias))
                                        .color(egui::Color32::GREEN),
                                );
                            }
                            None => {
                                has_phantom = true;
                                ui.vertical(|ui| {
                                    ui.label(
                                        egui::RichText::new("⚠ No entry — phantom lock")
                                            .color(egui::Color32::from_rgb(255, 80, 80))
                                            .strong(),
                                    );
                                    // Full txid on its own line so it can be copied
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(&u.txid)
                                                .monospace()
                                                .small()
                                                .color(egui::Color32::GRAY),
                                        );
                                        if ui.small_button("📋 Copy").clicked() {
                                            if let Ok(mut cb) = arboard::Clipboard::new() {
                                                let _ = cb.set_text(u.txid.clone());
                                            }
                                        }
                                    });
                                });
                            }
                        }
                        ui.end_row();
                    }
                });

            if has_phantom {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "⚠ One or more locked UTXOs have no matching wallet entry. \
                         Add the missing masternode entry (using the TXID/vout above) \
                         to track it, or deregister the masternode on-chain to free the collateral.",
                    )
                    .color(egui::Color32::from_rgb(255, 160, 40))
                    .small(),
                );
            }
        }
        }); // end CollapsingHeader
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

        match (Config::startup_prefs_path(), Config::data_dir()) {
            (Ok(prefs_path), Ok(data_dir)) => {
                let net_conf_path = if state.is_testnet {
                    data_dir.join("testnet").join("time.conf")
                } else {
                    data_dir.join("time.conf")
                };

                // time.toml — startup preference
                ui.horizontal(|ui| {
                    let btn = ui.add(
                        egui::Button::new("📝 Open time.toml").min_size(egui::vec2(160.0, 28.0)),
                    );
                    if btn.clicked() {
                        open_conf_file(prefs_path.clone());
                    }
                    ui.label(
                        egui::RichText::new(prefs_path.display().to_string())
                            .weak()
                            .small(),
                    );
                });

                ui.add_space(4.0);

                // network-specific time.conf
                let label = if state.is_testnet {
                    "📝 Open time.conf (testnet)"
                } else {
                    "📝 Open time.conf (mainnet)"
                };
                ui.horizontal(|ui| {
                    let btn = ui.add(egui::Button::new(label).min_size(egui::vec2(160.0, 28.0)));
                    if btn.clicked() {
                        open_conf_file(net_conf_path.clone());
                    }
                    ui.label(
                        egui::RichText::new(net_conf_path.display().to_string())
                            .weak()
                            .small(),
                    );
                });
            }
            _ => {
                ui.label(egui::RichText::new("Could not determine data directory.").weak());
            }
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
    ui.add_space(16.0);
    }); // end ScrollArea
}
