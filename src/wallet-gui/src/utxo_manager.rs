use eframe::egui;
use std::collections::HashMap;
use wallet::UTXO as Utxo;

#[derive(Default)]
pub struct UtxoManager {
    pub show_consolidation_dialog: bool,
    pub consolidation_threshold: String,
    pub consolidation_target_size: String,
    pub selected_utxos: HashMap<String, bool>,
    pub auto_consolidate: bool,
    pub auto_consolidate_threshold: usize,
    pub consolidation_in_progress: bool,
    pub last_consolidation_result: Option<ConsolidationResult>,
}

pub struct ConsolidationResult {
    pub success: bool,
    pub utxos_consolidated: usize,
    pub resulting_utxos: usize,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

impl UtxoManager {
    pub fn new() -> Self {
        Self {
            show_consolidation_dialog: false,
            consolidation_threshold: "10".to_string(),
            consolidation_target_size: "1".to_string(),
            selected_utxos: HashMap::new(),
            auto_consolidate: false,
            auto_consolidate_threshold: 50,
            consolidation_in_progress: false,
            last_consolidation_result: None,
        }
    }

    pub fn show(&mut self, ctx: &egui::Context, utxos: &[Utxo]) -> Option<UtxoAction> {
        let mut action = None;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("📦 UTXO Management");
            ui.add_space(10.0);

            // Summary stats
            self.render_summary(ui, utxos);
            ui.add_space(20.0);

            // Auto-consolidation settings
            self.render_auto_consolidation_settings(ui);
            ui.add_space(20.0);

            // UTXO list with selection
            ui.heading("Your UTXOs");
            ui.label("Select UTXOs to consolidate or view details:");
            ui.add_space(5.0);

            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    action = self.render_utxo_list(ui, utxos);
                });

            ui.add_space(20.0);

            // Action buttons
            ui.horizontal(|ui| {
                let selected_count = self.selected_utxos.values().filter(|&&v| v).count();

                if ui
                    .add_enabled(
                        selected_count >= 2,
                        egui::Button::new(format!("🔗 Consolidate Selected ({})", selected_count)),
                    )
                    .clicked()
                {
                    action = Some(UtxoAction::ConsolidateSelected(
                        self.selected_utxos
                            .iter()
                            .filter_map(|(k, &v)| if v { Some(k.clone()) } else { None })
                            .collect(),
                    ));
                }

                if ui
                    .add_enabled(
                        utxos.len() >= 2,
                        egui::Button::new("🔄 Smart Consolidation"),
                    )
                    .clicked()
                {
                    self.show_consolidation_dialog = true;
                }

                if ui.button("🗑️ Clear Selection").clicked() {
                    self.selected_utxos.clear();
                }
            });

            // Show consolidation results
            if let Some(result) = &self.last_consolidation_result {
                ui.add_space(10.0);
                self.render_consolidation_result(ui, result);
            }
        });

        // Consolidation dialog
        if self.show_consolidation_dialog {
            if let Some(dialog_action) = self.render_consolidation_dialog(ctx, utxos) {
                action = Some(dialog_action);
                self.show_consolidation_dialog = false;
            }
        }

        action
    }

    fn render_summary(&self, ui: &mut egui::Ui, utxos: &[Utxo]) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("Total UTXOs:");
                    ui.heading(utxos.len().to_string());
                });

                ui.add_space(30.0);

                ui.vertical(|ui| {
                    ui.label("Total Balance:");
                    let total: u64 = utxos.iter().map(|u| u.amount).sum();
                    ui.heading(format!("{} TIME", total as f64 / 100_000_000.0));
                });

                ui.add_space(30.0);

                ui.vertical(|ui| {
                    ui.label("Average UTXO Size:");
                    let avg = if !utxos.is_empty() {
                        utxos.iter().map(|u| u.amount).sum::<u64>() / utxos.len() as u64
                    } else {
                        0
                    };
                    ui.heading(format!("{} TIME", avg as f64 / 100_000_000.0));
                });

                ui.add_space(30.0);

                ui.vertical(|ui| {
                    ui.label("Small UTXOs (<0.1):");
                    let small_count = utxos.iter().filter(|u| u.amount < 10_000_000).count();
                    ui.heading(format!("{}", small_count));
                });
            });
        });
    }

    fn render_auto_consolidation_settings(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.auto_consolidate, "⚡ Auto-consolidate");
                ui.label("|");
                ui.label("When UTXO count exceeds:");
                ui.add(
                    egui::Slider::new(&mut self.auto_consolidate_threshold, 10..=200)
                        .text("UTXOs"),
                );
            });

            if self.auto_consolidate {
                ui.label("💡 Wallet will automatically consolidate UTXOs in the background when threshold is reached");
            }
        });
    }

    fn render_utxo_list(&mut self, ui: &mut egui::Ui, utxos: &[Utxo]) -> Option<UtxoAction> {
        if utxos.is_empty() {
            ui.label("No UTXOs available");
            return None;
        }

        let action = None;

        for utxo in utxos {
            let utxo_id = format!("{}:{}", hex::encode(utxo.tx_hash), utxo.output_index);
            let is_selected = self.selected_utxos.get(&utxo_id).copied().unwrap_or(false);

            ui.horizontal(|ui| {
                let mut selected = is_selected;
                if ui.checkbox(&mut selected, "").changed() {
                    self.selected_utxos.insert(utxo_id.clone(), selected);
                }

                ui.label(format!("💰 {:.8} TIME", utxo.amount as f64 / 100_000_000.0));
                ui.separator();
                ui.label(format!(
                    "{}...{}",
                    &hex::encode(utxo.tx_hash)[..8],
                    &hex::encode(utxo.tx_hash)[56..]
                ));
                ui.label(format!(":{}", utxo.output_index));
            });
        }

        action
    }

    fn render_consolidation_dialog(
        &mut self,
        ctx: &egui::Context,
        utxos: &[Utxo],
    ) -> Option<UtxoAction> {
        let mut action = None;
        let mut keep_open = true;

        egui::Window::new("🔄 Smart Consolidation")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("Configure automatic UTXO consolidation:");
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    ui.label("Consolidate UTXOs smaller than:");
                    ui.text_edit_singleline(&mut self.consolidation_threshold);
                    ui.label("TIME");
                });

                ui.horizontal(|ui| {
                    ui.label("Target number of resulting UTXOs:");
                    ui.text_edit_singleline(&mut self.consolidation_target_size);
                });

                ui.add_space(10.0);

                // Show preview
                if let Ok(threshold) = self.consolidation_threshold.parse::<f64>() {
                    let threshold_sats = (threshold * 100_000_000.0) as u64;
                    let candidates: Vec<_> =
                        utxos.iter().filter(|u| u.amount < threshold_sats).collect();

                    ui.label(format!(
                        "📊 {} UTXOs will be consolidated",
                        candidates.len()
                    ));
                    let total: u64 = candidates.iter().map(|u| u.amount).sum();
                    ui.label(format!(
                        "Total amount: {:.8} TIME",
                        total as f64 / 100_000_000.0
                    ));
                }

                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    if ui.button("✓ Consolidate").clicked() {
                        if let Ok(threshold) = self.consolidation_threshold.parse::<f64>() {
                            let target =
                                self.consolidation_target_size.parse::<usize>().unwrap_or(1);
                            action = Some(UtxoAction::SmartConsolidate {
                                threshold_amount: (threshold * 100_000_000.0) as u64,
                                target_utxo_count: target,
                            });
                            keep_open = false;
                        }
                    }

                    if ui.button("✗ Cancel").clicked() {
                        keep_open = false;
                    }
                });
            });

        if !keep_open {
            self.show_consolidation_dialog = false;
        }

        action
    }

    fn render_consolidation_result(&self, ui: &mut egui::Ui, result: &ConsolidationResult) {
        ui.group(|ui| {
            if result.success {
                ui.colored_label(egui::Color32::GREEN, "✓ Consolidation Successful");
                ui.label(format!(
                    "Consolidated {} UTXOs into {} UTXO(s)",
                    result.utxos_consolidated, result.resulting_utxos
                ));
                if let Some(tx_hash) = &result.tx_hash {
                    ui.label(format!(
                        "Transaction: {}...{}",
                        &tx_hash[..8],
                        &tx_hash[tx_hash.len() - 8..]
                    ));
                }
            } else {
                ui.colored_label(egui::Color32::RED, "✗ Consolidation Failed");
                if let Some(error) = &result.error {
                    ui.label(error);
                }
            }
        });
    }

    pub fn set_consolidation_result(&mut self, result: ConsolidationResult) {
        self.consolidation_in_progress = false;
        self.last_consolidation_result = Some(result);
    }
}

#[derive(Debug, Clone)]
pub enum UtxoAction {
    ConsolidateSelected(Vec<String>),
    SmartConsolidate {
        threshold_amount: u64,
        target_utxo_count: usize,
    },
    ViewDetails(String),
}
