//! Welcome screen — shown when no wallet is loaded.
//!
//! Handles three sub-screens: Welcome (open/create), MnemonicSetup (enter or
//! generate a mnemonic), and MnemonicConfirm (not yet implemented separately).

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::{Screen, UiEvent};
use crate::state::AppState;
use crate::wallet_manager::WalletManager;

/// Render the welcome screen.
pub fn show(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    match state.screen {
        Screen::NetworkSelect => {
            show_network_select(ui, ui_tx);
        }
        Screen::MnemonicSetup | Screen::MnemonicConfirm => {
            show_mnemonic_setup(ui, state, ui_tx);
        }
        _ => {
            // If no wallet file exists, skip straight to mnemonic setup
            if !state.wallet_exists && !state.password_required {
                state.screen = Screen::MnemonicSetup;
                show_mnemonic_setup(ui, state, ui_tx);
            } else {
                show_welcome(ui, state, ui_tx);
            }
        }
    }
}

/// First-run network selection — Mainnet or Testnet.
fn show_network_select(ui: &mut Ui, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.vertical_centered(|ui| {
        ui.add_space(60.0);

        // Logo
        let logo_bytes = include_bytes!("../../assets/logo.png");
        let image =
            egui::Image::from_bytes("bytes://logo.png", logo_bytes.as_slice()).max_width(128.0);
        ui.add(image);

        ui.add_space(20.0);
        ui.heading(egui::RichText::new("TIME Coin Wallet").size(28.0).strong());
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Welcome! Select a network to get started.")
                .size(14.0)
                .color(egui::Color32::GRAY),
        );

        ui.add_space(40.0);

        let button_size = egui::vec2(260.0, 50.0);

        if ui
            .add(
                egui::Button::new(egui::RichText::new("🌐 Mainnet").size(18.0))
                    .min_size(button_size),
            )
            .clicked()
        {
            let _ = ui_tx.send(UiEvent::SelectNetwork {
                network: "mainnet".to_string(),
            });
        }
        ui.label(
            egui::RichText::new("Production network — real TIME coins")
                .size(12.0)
                .color(egui::Color32::GRAY),
        );

        ui.add_space(16.0);

        if ui
            .add(
                egui::Button::new(egui::RichText::new("🧪 Testnet").size(18.0))
                    .min_size(button_size),
            )
            .clicked()
        {
            let _ = ui_tx.send(UiEvent::SelectNetwork {
                network: "testnet".to_string(),
            });
        }
        ui.label(
            egui::RichText::new("Test network — for development and testing")
                .size(12.0)
                .color(egui::Color32::GRAY),
        );
    });
}

/// Welcome landing page — open an existing wallet or create a new one.
fn show_welcome(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.vertical_centered(|ui| {
        ui.add_space(60.0);

        // Logo
        let logo_bytes = include_bytes!("../../assets/logo.png");
        let image =
            egui::Image::from_bytes("bytes://logo.png", logo_bytes.as_slice()).max_width(128.0);
        ui.add(image);

        ui.add_space(20.0);
        ui.heading(egui::RichText::new("TIME Coin Wallet").size(28.0).strong());
        ui.add_space(8.0);

        let network_label = if state.is_testnet {
            "Testnet"
        } else {
            "Mainnet"
        };
        ui.label(
            egui::RichText::new(format!("Secure thin-client wallet — {}", network_label))
                .size(14.0)
                .color(egui::Color32::GRAY),
        );

        ui.add_space(40.0);

        if state.password_required {
            // Password unlock prompt
            ui.label("This wallet is encrypted. Enter your password to unlock.");
            ui.add_space(10.0);

            let response = ui.add(
                egui::TextEdit::singleline(&mut state.password_input)
                    .password(!state.show_password)
                    .hint_text("Password")
                    .desired_width(250.0),
            );

            ui.checkbox(&mut state.show_password, "Show password");

            ui.add_space(10.0);

            let submitted = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            let unlock_clicked = ui
                .add(
                    egui::Button::new(egui::RichText::new("Unlock").size(16.0))
                        .min_size(egui::vec2(200.0, 40.0)),
                )
                .clicked();

            if (unlock_clicked || submitted) && !state.password_input.is_empty() {
                let _ = ui_tx.send(UiEvent::LoadWallet {
                    password: Some(state.password_input.clone()),
                });
                state.loading = true;
                state.error = None;
            }

            // Focus the password field on first show
            response.request_focus();
        } else {
            // Load existing wallet
            if ui
                .add(
                    egui::Button::new(egui::RichText::new("Open Wallet").size(16.0))
                        .min_size(egui::vec2(200.0, 40.0)),
                )
                .clicked()
            {
                let _ = ui_tx.send(UiEvent::LoadWallet { password: None });
            }

            ui.add_space(12.0);

            // Create new wallet
            if ui
                .add(
                    egui::Button::new(egui::RichText::new("Create New Wallet").size(16.0))
                        .min_size(egui::vec2(200.0, 40.0)),
                )
                .clicked()
            {
                let _ = ui_tx.send(UiEvent::PrepareNewWallet);
            }
        }

        ui.add_space(30.0);

        // Error display
        if let Some(ref err) = state.error {
            ui.colored_label(egui::Color32::RED, format!("Error: {}", err));
        }

        if state.loading {
            ui.spinner();
            ui.label("Loading wallet...");
        }
    });
}

/// Mnemonic setup screen — enter an existing mnemonic or generate a new one.
fn show_mnemonic_setup(ui: &mut Ui, state: &mut AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    let word_count = if state.mnemonic_use_24 { 24 } else { 12 };

    // Print dialog (modal window)
    if state.show_print_dialog {
        render_print_dialog(ui.ctx(), state);
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.heading(
                egui::RichText::new("Set Up Your Wallet")
                    .size(24.0)
                    .strong(),
            );
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("Enter an existing recovery phrase or generate a new one.")
                    .size(14.0)
                    .color(egui::Color32::GRAY),
            );

            if let Some(ref path) = state.backed_up_path {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(format!("Previous wallet backed up to: {}", path))
                        .size(12.0)
                        .color(egui::Color32::LIGHT_GRAY)
                        .italics(),
                );
            }

            ui.add_space(16.0);

            // Action buttons row
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("Generate Random Phrase").size(14.0))
                            .min_size(egui::vec2(200.0, 34.0)),
                    )
                    .clicked()
                {
                    match WalletManager::generate_mnemonic() {
                        Ok(mnemonic) => {
                            let words: Vec<String> =
                                mnemonic.split_whitespace().map(|s| s.to_string()).collect();
                            state.mnemonic_words = words;
                            state.mnemonic_words.resize(word_count, String::new());
                            state.mnemonic_valid = Some(true);
                            state.error = None;
                        }
                        Err(e) => {
                            state.error = Some(format!("Failed to generate mnemonic: {}", e));
                        }
                    }
                }

                if ui
                    .add(egui::Button::new("Clear All").min_size(egui::vec2(80.0, 34.0)))
                    .clicked()
                {
                    state.mnemonic_words = vec![String::new(); word_count];
                    state.mnemonic_valid = None;
                    state.error = None;
                }

                // Print button — only when phrase has words
                let has_any_words = state.mnemonic_words.iter().any(|w| !w.trim().is_empty());
                if has_any_words
                    && ui
                        .add(
                            egui::Button::new("Print Paper Backup")
                                .min_size(egui::vec2(130.0, 34.0)),
                        )
                        .clicked()
                {
                    state.show_print_dialog = true;
                }
            });

            ui.add_space(8.0);

            // Word count toggle
            if ui
                .checkbox(
                    &mut state.mnemonic_use_24,
                    "Use 24 words (advanced security)",
                )
                .changed()
            {
                let new_count = if state.mnemonic_use_24 { 24 } else { 12 };
                state.mnemonic_words.resize(new_count, String::new());
                state.mnemonic_valid = None;
            }

            ui.add_space(12.0);

            // Validation status
            match state.mnemonic_valid {
                Some(true) => {
                    ui.colored_label(
                        egui::Color32::GREEN,
                        egui::RichText::new("Valid mnemonic phrase").size(14.0),
                    );
                }
                Some(false) => {
                    if let Some(ref err) = state.error {
                        ui.colored_label(
                            egui::Color32::RED,
                            egui::RichText::new(format!("Invalid: {}", err)).size(13.0),
                        );
                    }
                }
                None => {}
            }

            ui.add_space(10.0);
        });

        // Word input grid — two columns
        let words_per_col = word_count / 2;

        ui.horizontal(|ui| {
            ui.add_space(ui.available_width() / 2.0 - 260.0);

            // Left column
            ui.vertical(|ui| {
                for i in 0..words_per_col {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("{:>2}.", i + 1))
                                .size(16.0)
                                .monospace(),
                        );
                        let word = state.mnemonic_words[i].trim().to_lowercase();
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut state.mnemonic_words[i])
                                .desired_width(160.0)
                                .font(egui::TextStyle::Body)
                                .hint_text("word"),
                        );
                        // Show per-word validation
                        if !word.is_empty() && !wallet::is_valid_bip39_word(&word) {
                            ui.colored_label(egui::Color32::RED, "invalid word");
                        }
                        if response.changed() {
                            state.mnemonic_valid = None;
                        }
                    });
                    ui.add_space(2.0);
                }
            });

            ui.add_space(20.0);

            // Right column
            ui.vertical(|ui| {
                for i in words_per_col..word_count {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("{:>2}.", i + 1))
                                .size(16.0)
                                .monospace(),
                        );
                        let word = state.mnemonic_words[i].trim().to_lowercase();
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut state.mnemonic_words[i])
                                .desired_width(160.0)
                                .font(egui::TextStyle::Body)
                                .hint_text("word"),
                        );
                        if !word.is_empty() && !wallet::is_valid_bip39_word(&word) {
                            ui.colored_label(egui::Color32::RED, "invalid word");
                        }
                        if response.changed() {
                            state.mnemonic_valid = None;
                        }
                    });
                    ui.add_space(2.0);
                }
            });
        });

        ui.add_space(16.0);

        ui.vertical_centered(|ui| {
            // Auto-validate when all word slots are filled
            let filled_words: Vec<&str> = state
                .mnemonic_words
                .iter()
                .map(|w| w.trim())
                .filter(|w| !w.is_empty())
                .collect();
            let all_filled = filled_words.len() == word_count;

            if all_filled && state.mnemonic_valid.is_none() {
                let phrase = filled_words.join(" ");
                match WalletManager::validate_mnemonic(&phrase) {
                    Ok(_) => {
                        state.mnemonic_valid = Some(true);
                        state.error = None;
                    }
                    Err(e) => {
                        state.mnemonic_valid = Some(false);
                        state.error = Some(e.to_string());
                    }
                }
            } else if !all_filled && state.mnemonic_valid.is_none() {
                // Show Validate button for partial input
                let has_words = !filled_words.is_empty();
                if has_words {
                    if ui
                        .add(
                            egui::Button::new(egui::RichText::new("Validate Phrase").size(14.0))
                                .min_size(egui::vec2(160.0, 34.0)),
                        )
                        .clicked()
                    {
                        let phrase = filled_words.join(" ");
                        match WalletManager::validate_mnemonic(&phrase) {
                            Ok(_) => {
                                state.mnemonic_valid = Some(true);
                                state.error = None;
                            }
                            Err(e) => {
                                state.mnemonic_valid = Some(false);
                                state.error = Some(e.to_string());
                            }
                        }
                    }
                    ui.add_space(12.0);
                }
            }

            // Optional password
            ui.label(egui::RichText::new("Encryption Password (optional)").size(13.0));
            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut state.new_wallet_password)
                    .password(true)
                    .desired_width(300.0)
                    .hint_text("Leave blank for no encryption"),
            );

            ui.add_space(16.0);

            // Create wallet button — only enabled when valid
            let can_create = state.mnemonic_valid == Some(true);

            let create_btn = ui.add_enabled(
                can_create,
                egui::Button::new(egui::RichText::new("Create Wallet").size(16.0))
                    .min_size(egui::vec2(200.0, 40.0)),
            );

            if create_btn.clicked() && can_create {
                let phrase: String = state
                    .mnemonic_words
                    .iter()
                    .map(|w| w.trim())
                    .filter(|w| !w.is_empty())
                    .collect::<Vec<&str>>()
                    .join(" ");
                let password = if state.new_wallet_password.is_empty() {
                    None
                } else {
                    Some(state.new_wallet_password.clone())
                };
                let _ = ui_tx.send(UiEvent::CreateWallet {
                    mnemonic: phrase,
                    password,
                });
                state.loading = true;
                state.error = None;
            }

            // Back button (only if a wallet file exists to go back to)
            if state.wallet_exists {
                ui.add_space(12.0);
                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("Back").size(14.0))
                            .min_size(egui::vec2(100.0, 32.0)),
                    )
                    .clicked()
                {
                    state.screen = Screen::Welcome;
                    state.mnemonic_words = vec![String::new(); word_count];
                    state.mnemonic_valid = None;
                    state.new_wallet_password.clear();
                    state.error = None;
                }
            }

            ui.add_space(20.0);

            if state.loading {
                ui.spinner();
                ui.label("Creating wallet...");
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Print dialog & PDF generation
// ---------------------------------------------------------------------------

/// Render the print preview / export dialog as a modal window.
fn render_print_dialog(ctx: &egui::Context, state: &mut AppState) {
    let mut open = true;
    egui::Window::new("Paper Backup")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(480.0)
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading(
                    egui::RichText::new("Recovery Phrase Backup")
                        .size(20.0)
                        .strong(),
                );
            });
            ui.add_space(10.0);

            // Security warning
            egui::Frame::group(ui.style())
                .fill(egui::Color32::from_rgb(50, 30, 30))
                .show(ui, |ui| {
                    ui.colored_label(
                        egui::Color32::RED,
                        egui::RichText::new("SECURITY WARNING").strong(),
                    );
                    ui.label("Store this document in a safe, secure location.");
                    ui.label("Never share your recovery phrase with anyone.");
                    ui.label("This is the ONLY way to recover your wallet.");
                });

            ui.add_space(12.0);

            // Preview of words in a nice grid
            let words: Vec<&str> = state
                .mnemonic_words
                .iter()
                .map(|w| w.trim())
                .filter(|w| !w.is_empty())
                .collect();
            let mid = words.len().div_ceil(2);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_width(420.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("TIME Coin Recovery Phrase")
                            .size(15.0)
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "{} words  |  {}",
                            words.len(),
                            chrono::Local::now().format("%Y-%m-%d")
                        ))
                        .size(11.0)
                        .color(egui::Color32::GRAY),
                    );
                });
                ui.add_space(8.0);

                egui::Grid::new("print_preview_grid")
                    .num_columns(2)
                    .spacing([40.0, 4.0])
                    .min_col_width(180.0)
                    .show(ui, |ui| {
                        for i in 0..mid {
                            if let Some(word) = words.get(i) {
                                ui.label(
                                    egui::RichText::new(format!("{:>2}. {}", i + 1, word))
                                        .monospace()
                                        .size(14.0),
                                );
                            }
                            if let Some(word) = words.get(i + mid) {
                                ui.label(
                                    egui::RichText::new(format!("{:>2}. {}", i + mid + 1, word))
                                        .monospace()
                                        .size(14.0),
                                );
                            }
                            ui.end_row();
                        }
                    });
            });

            ui.add_space(16.0);

            // Action buttons
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("Copy to Clipboard").size(14.0))
                            .min_size(egui::vec2(150.0, 34.0)),
                    )
                    .clicked()
                {
                    let phrase = words.join(" ");
                    ui.ctx().copy_text(phrase);
                }

                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("🖨 Print PDF").size(14.0))
                            .min_size(egui::vec2(120.0, 34.0)),
                    )
                    .clicked()
                {
                    match generate_backup_pdf(&words) {
                        Ok(path) => {
                            log::info!("Paper backup PDF opened for printing: {}", path.display());
                            let _ = open::that(&path);
                            state.success = Some(
                                "Paper backup opened — use your PDF viewer to print".to_string(),
                            );
                            // Securely delete the PDF after a delay
                            let cleanup_path = path.clone();
                            std::thread::spawn(move || {
                                std::thread::sleep(std::time::Duration::from_secs(60));
                                if cleanup_path.exists() {
                                    // Overwrite with zeros before deleting
                                    if let Ok(len) =
                                        std::fs::metadata(&cleanup_path).map(|m| m.len())
                                    {
                                        if let Ok(mut f) = std::fs::OpenOptions::new()
                                            .write(true)
                                            .open(&cleanup_path)
                                        {
                                            use std::io::Write;
                                            let zeros = vec![0u8; len as usize];
                                            let _ = f.write_all(&zeros);
                                            let _ = f.sync_all();
                                        }
                                    }
                                    let _ = std::fs::remove_file(&cleanup_path);
                                    log::info!("Securely cleaned up paper backup PDF");
                                }
                            });
                        }
                        Err(e) => {
                            state.error = Some(format!("Failed to create PDF: {}", e));
                        }
                    }
                }

                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("Close").size(14.0))
                            .min_size(egui::vec2(80.0, 34.0)),
                    )
                    .clicked()
                {
                    state.show_print_dialog = false;
                }
            });

            if let Some(ref msg) = state.success {
                ui.add_space(8.0);
                ui.colored_label(egui::Color32::GREEN, msg);
            }
        });

    if !open {
        state.show_print_dialog = false;
    }
}

/// Generate a nicely formatted PDF paper backup of the recovery phrase.
fn generate_backup_pdf(words: &[&str]) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use printpdf::*;

    let (doc, page1, layer1) =
        PdfDocument::new("TIME Coin Recovery Phrase", Mm(210.0), Mm(297.0), "Layer 1");

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;
    let layer = doc.get_page(page1).get_layer(layer1);

    let left = Mm(25.0);
    let right_margin = Mm(185.0);
    let mut y = Mm(270.0);

    // ---- Header ----
    layer.use_text("TIME Coin Wallet", 28.0, left, y, &font_bold);
    y -= Mm(10.0);
    layer.use_text("Recovery Phrase - Paper Backup", 16.0, left, y, &font);
    y -= Mm(8.0);

    let date = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    layer.use_text(format!("Generated: {}", date), 10.0, left, y, &font);
    y -= Mm(6.0);
    layer.use_text(format!("{} words", words.len()), 10.0, left, y, &font);

    // ---- Divider line ----
    y -= Mm(6.0);
    let divider = Line {
        points: vec![
            (Point::new(left, y), false),
            (Point::new(right_margin, y), false),
        ],
        is_closed: false,
    };
    layer.add_line(divider);

    // ---- Security warning ----
    y -= Mm(12.0);
    layer.use_text("IMPORTANT - READ CAREFULLY", 12.0, left, y, &font_bold);
    y -= Mm(7.0);
    let warnings = [
        "1. Store this document in a secure location (e.g. safe, safety deposit box).",
        "2. NEVER share these words with anyone - they give full access to your funds.",
        "3. Do NOT store this digitally - print and keep the physical copy only.",
        "4. These words are the ONLY way to recover your wallet if your device is lost.",
        "5. Anyone with these words can steal all your TIME coins.",
    ];
    for w in &warnings {
        layer.use_text(*w, 9.0, Mm(30.0), y, &font);
        y -= Mm(5.0);
    }

    // ---- Recovery phrase grid ----
    y -= Mm(10.0);
    layer.use_text("Your Recovery Phrase", 14.0, left, y, &font_bold);
    y -= Mm(10.0);

    let mid = words.len().div_ceil(2);
    let col_left = Mm(35.0);
    let col_right = Mm(120.0);
    let row_height = Mm(8.5);

    // Draw a border around the word grid
    let grid_top = y + Mm(4.0);
    let grid_bottom = y - Mm(mid as f32 * 8.5) - Mm(2.0);
    let box_outline = Line {
        points: vec![
            (Point::new(Mm(28.0), grid_top), false),
            (Point::new(right_margin, grid_top), false),
            (Point::new(right_margin, grid_bottom), false),
            (Point::new(Mm(28.0), grid_bottom), false),
        ],
        is_closed: true,
    };
    layer.set_outline_color(printpdf::Color::Greyscale(Greyscale::new(0.75, None)));
    layer.set_outline_thickness(0.5);
    layer.add_line(box_outline);
    layer.set_outline_color(printpdf::Color::Greyscale(Greyscale::new(0.0, None)));

    for i in 0..mid {
        if let Some(word) = words.get(i) {
            let num = format!("{:>2}.", i + 1);
            layer.use_text(&num, 11.0, col_left, y, &font);
            layer.use_text(*word, 12.0, col_left + Mm(12.0), y, &font_mono);
        }
        if let Some(word) = words.get(i + mid) {
            let num = format!("{:>2}.", i + mid + 1);
            layer.use_text(&num, 11.0, col_right, y, &font);
            layer.use_text(*word, 12.0, col_right + Mm(12.0), y, &font_mono);
        }
        y -= row_height;
    }

    // ---- Verification section ----
    y -= Mm(12.0);
    layer.use_text("Verification", 12.0, left, y, &font_bold);
    y -= Mm(7.0);
    layer.use_text(
        "After writing down or printing these words, verify them by restoring",
        9.0,
        left,
        y,
        &font,
    );
    y -= Mm(5.0);
    layer.use_text(
        "your wallet in the TIME Coin Wallet app using the recovery phrase above.",
        9.0,
        left,
        y,
        &font,
    );

    // ---- Notes section (blank lines for user) ----
    y -= Mm(14.0);
    layer.use_text("Notes:", 11.0, left, y, &font_bold);
    y -= Mm(8.0);
    for _ in 0..3 {
        let underline = Line {
            points: vec![
                (Point::new(left, y), false),
                (Point::new(right_margin, y), false),
            ],
            is_closed: false,
        };
        layer.set_outline_color(printpdf::Color::Greyscale(Greyscale::new(0.8, None)));
        layer.add_line(underline);
        layer.set_outline_color(printpdf::Color::Greyscale(Greyscale::new(0.0, None)));
        y -= Mm(10.0);
    }

    // ---- Footer ----
    let footer_y = Mm(15.0);
    layer.use_text(
        "TIME Coin Wallet - https://timecoin.network",
        8.0,
        left,
        footer_y,
        &font,
    );
    layer.use_text(
        "This document is confidential. Destroy securely when no longer needed.",
        8.0,
        left,
        footer_y - Mm(4.0),
        &font,
    );

    // Save to temp directory with randomized filename
    let random_id: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let filename = format!(".tc_print_{:x}.pdf", random_id);
    let path = std::env::temp_dir().join(filename);
    doc.save(&mut std::io::BufWriter::new(std::fs::File::create(&path)?))?;

    Ok(path)
}
