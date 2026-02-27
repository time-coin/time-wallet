//! Application struct — the eframe::App implementation.
//!
//! Thin wrapper: drains service events, dispatches to view modules.
//! No async, no network, no wallet logic.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config_new::Config;
use crate::events::{Screen, ServiceEvent, UiEvent};
use crate::state::AppState;
use crate::view;

/// The wallet application.
pub struct App {
    pub state: AppState,
    pub ui_tx: mpsc::UnboundedSender<UiEvent>,
    svc_rx: mpsc::UnboundedReceiver<ServiceEvent>,
    shutdown_token: CancellationToken,
}

impl App {
    /// Create a new App, spawning the background service task.
    pub fn new(cc: &eframe::CreationContext<'_>, config: Config) -> Self {
        setup_fonts(&cc.egui_ctx);

        let (ui_tx, ui_rx) = mpsc::unbounded_channel();
        let (svc_tx, svc_rx) = mpsc::unbounded_channel();
        let token = CancellationToken::new();

        // Spawn the single background service task
        let svc_token = token.clone();
        tokio::spawn(crate::service::run(svc_token, ui_rx, svc_tx, config));

        Self {
            state: AppState::default(),
            ui_tx,
            svc_rx,
            shutdown_token: token,
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Ensure we repaint regularly to pick up background service events
        ctx.request_repaint_after(std::time::Duration::from_secs(1));

        // 1. Drain all pending service events (non-blocking)
        while let Ok(event) = self.svc_rx.try_recv() {
            self.state.apply(event);
            ctx.request_repaint();
        }

        // 2. Navigation sidebar
        egui::SidePanel::left("nav").show(ctx, |ui| {
            ui.add_space(10.0);

            // Logo
            let logo_bytes = include_bytes!("../assets/logo.png");
            let image =
                egui::Image::from_bytes("bytes://logo.png", logo_bytes.as_slice()).max_width(48.0);
            ui.add(image);

            ui.add_space(5.0);
            ui.label(egui::RichText::new("TIME Coin").strong());
            ui.separator();
            ui.add_space(5.0);

            if self.state.wallet_loaded {
                nav_button(
                    ui,
                    &mut self.state,
                    "🏠 Overview",
                    Screen::Overview,
                    &self.ui_tx,
                );
                nav_button(ui, &mut self.state, "📤 Send", Screen::Send, &self.ui_tx);
                nav_button(
                    ui,
                    &mut self.state,
                    "📥 Receive",
                    Screen::Receive,
                    &self.ui_tx,
                );
                nav_button(
                    ui,
                    &mut self.state,
                    "📋 Transactions",
                    Screen::Transactions,
                    &self.ui_tx,
                );
                ui.separator();
                nav_button(
                    ui,
                    &mut self.state,
                    "🔗 Connections",
                    Screen::Connections,
                    &self.ui_tx,
                );
                nav_button(
                    ui,
                    &mut self.state,
                    "⚙ Settings",
                    Screen::Settings,
                    &self.ui_tx,
                );
            }
        });

        // 3. Central panel — route to the active view
        egui::CentralPanel::default().show(ctx, |ui| match self.state.screen {
            Screen::Welcome | Screen::MnemonicSetup | Screen::MnemonicConfirm => {
                view::welcome::show(ui, &mut self.state, &self.ui_tx);
            }
            Screen::Overview => {
                view::overview::show(ui, &mut self.state, &self.ui_tx);
            }
            Screen::Send => {
                view::send::show(ui, &mut self.state, &self.ui_tx);
            }
            Screen::Receive => {
                view::receive::show(ui, &mut self.state, &self.ui_tx);
            }
            Screen::Transactions => {
                view::transactions::show(ui, &mut self.state, &self.ui_tx);
            }
            Screen::Settings => {
                view::settings::show(ui, &self.state);
            }
            Screen::Connections => {
                view::connections::show(ui, &self.state);
            }
            Screen::Utxos => {
                view::overview::show(ui, &mut self.state, &self.ui_tx);
            }
        });
    }
}

/// Render a navigation button, highlighting the active screen.
fn nav_button(
    ui: &mut egui::Ui,
    state: &mut AppState,
    label: &str,
    screen: Screen,
    ui_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let is_active = state.screen == screen;
    let button = egui::Button::new(egui::RichText::new(label).size(14.0))
        .selected(is_active)
        .min_size(egui::vec2(140.0, 28.0));

    if ui.add(button).clicked() && !is_active {
        state.screen = screen;
        let _ = ui_tx.send(UiEvent::NavigatedTo(screen));
    }
}

/// Setup fonts and image loaders.
fn setup_fonts(ctx: &egui::Context) {
    egui_extras::install_image_loaders(ctx);
    ctx.set_fonts(egui::FontDefinitions::default());
}
