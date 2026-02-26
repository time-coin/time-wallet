use eframe::egui;

mod app;
#[allow(dead_code)]
mod config_new;
#[allow(dead_code)]
mod encryption;
#[allow(dead_code)]
mod events;
#[allow(dead_code)]
mod masternode_client;
mod peer_discovery;
mod service;
#[allow(dead_code)]
mod state;
mod view;
#[allow(dead_code)]
mod wallet_dat;
#[allow(dead_code)]
mod wallet_db;
#[allow(dead_code)]
mod wallet_manager;
#[allow(dead_code)]
mod ws_client;

fn main() -> Result<(), eframe::Error> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    env_logger::init();

    let config = config_new::Config::load().unwrap_or_default();
    let icon = load_icon();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(icon),
        ..Default::default()
    };

    let result = eframe::run_native(
        "TIME Coin Wallet",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, config)))),
    );

    drop(_guard);
    rt.shutdown_timeout(std::time::Duration::from_secs(2));

    result
}

/// Load the logo PNG as an eframe window icon.
fn load_icon() -> egui::IconData {
    let png_data = include_bytes!("../assets/logo.png");
    let image = image::load_from_memory(png_data).unwrap_or_else(|_| {
        image::DynamicImage::new_rgba8(32, 32)
    });
    let rgba = image.to_rgba8();
    let (w, h) = rgba.dimensions();
    egui::IconData {
        rgba: rgba.into_raw(),
        width: w,
        height: h,
    }
}