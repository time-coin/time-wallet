//! Connections screen — shows all discovered peers with health and ping info.

use egui::Ui;
use tokio::sync::mpsc;

use crate::events::UiEvent;
use crate::state::AppState;

/// Extract the host from an endpoint like "http://1.2.3.4:24001".
fn peer_ip(endpoint: &str) -> &str {
    let s = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    // Strip port
    s.rsplit_once(':').map(|(host, _)| host).unwrap_or(s)
}

/// Extract the host from a WS URL like "wss://1.2.3.4:24002" or "ws://1.2.3.4:24002".
fn ws_url_host(url: &str) -> &str {
    let s = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);
    s.rsplit_once(':').map(|(host, _)| host).unwrap_or(s)
}

/// Paint a filled circle as a health indicator.
fn health_dot(ui: &mut Ui, color: egui::Color32) {
    let size = egui::vec2(12.0, 12.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

/// Render the connections screen.
pub fn show(ui: &mut Ui, state: &AppState, ui_tx: &mpsc::UnboundedSender<UiEvent>) {
    ui.heading("Connections");
    ui.separator();
    ui.add_space(10.0);

    if state.peers.is_empty() {
        ui.label(
            egui::RichText::new("Discovering peers...")
                .color(egui::Color32::GRAY)
                .italics(),
        );
        ui.spinner();
        return;
    }

    ui.label(format!("{} healthy peers", state.peers.len()));
    ui.add_space(10.0);

    egui::ScrollArea::both()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            // Sort: syncing nodes to the bottom; otherwise preserve service ordering.
            let mut sorted_peers: Vec<&crate::state::PeerInfo> = state.peers.iter().collect();
            sorted_peers.sort_by_key(|p| p.is_syncing);

            egui::Grid::new("peers_table")
                .num_columns(10)
                .spacing([12.0, 6.0])
                .striped(true)
                .show(ui, |ui| {
                    // Header
                    ui.label(egui::RichText::new("#").strong());
                    ui.label(egui::RichText::new("").strong());
                    ui.label(egui::RichText::new("IP Address").strong());
                    ui.label(egui::RichText::new("Tier").strong());
                    ui.label(egui::RichText::new("Status").strong());
                    ui.label(egui::RichText::new("WebSocket").strong());
                    ui.label(egui::RichText::new("Ping").strong());
                    ui.label(egui::RichText::new("Block").strong());
                    ui.label(egui::RichText::new("").strong());
                    ui.with_layout(
                        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                        |ui| {
                            ui.label(egui::RichText::new("Consensus").strong());
                        },
                    );
                    ui.end_row();

                    // Determine best (highest) block height for consensus check.
                    // Exclude wrong-chain peers so their bogus heights don't distort the view.
                    let best_height = state
                        .peers
                        .iter()
                        .filter(|p| p.genesis_ok != Some(false))
                        .filter_map(|p| p.block_height)
                        .max()
                        .unwrap_or(0);

                    for (i, peer) in sorted_peers.iter().enumerate() {
                        let peer = *peer;
                        // Row number
                        ui.label(egui::RichText::new(format!("{}", i + 1)).weak().monospace());

                        // Health dot
                        let dot_color = if !peer.is_healthy {
                            egui::Color32::RED
                        } else if let Some(ms) = peer.ping_ms {
                            if ms < 100 {
                                egui::Color32::GREEN
                            } else if ms < 500 {
                                egui::Color32::YELLOW
                            } else {
                                egui::Color32::RED
                            }
                        } else {
                            egui::Color32::GRAY
                        };
                        health_dot(ui, dot_color);

                        // IP
                        let ip = peer_ip(&peer.endpoint);
                        ui.label(egui::RichText::new(ip).monospace());

                        // Tier
                        match peer.tier.as_deref() {
                            Some("Gold") => {
                                ui.colored_label(egui::Color32::from_rgb(255, 200, 50), "Gold");
                            }
                            Some("Silver") => {
                                ui.colored_label(egui::Color32::from_rgb(200, 210, 220), "Silver");
                            }
                            Some("Bronze") => {
                                ui.colored_label(egui::Color32::from_rgb(205, 127, 50), "Bronze");
                            }
                            Some("Free") => {
                                ui.colored_label(egui::Color32::GRAY, "Free");
                            }
                            Some(other) => {
                                ui.label(other);
                            }
                            None => {
                                ui.colored_label(egui::Color32::GRAY, "--");
                            }
                        }

                        // Status
                        if peer.genesis_ok == Some(false) {
                            ui.colored_label(egui::Color32::RED, "Wrong chain")
                                .on_hover_text(
                                    "This peer is on a different blockchain (genesis mismatch). \
                                     It cannot be used with this wallet.",
                                );
                        } else if peer.is_active && peer.is_syncing {
                            ui.colored_label(egui::Color32::from_rgb(255, 180, 0), "Syncing")
                                .on_hover_text(
                                    "This masternode is still downloading the blockchain. \
                             Balance and transaction data may be incomplete.",
                                );
                        } else if peer.is_syncing {
                            ui.colored_label(egui::Color32::from_rgb(200, 140, 0), "Syncing")
                                .on_hover_text(
                                    "This masternode is still downloading the blockchain. \
                             Consider selecting a fully-synced node.",
                                );
                        } else if peer.is_active {
                            ui.colored_label(egui::Color32::GREEN, "Active");
                        } else {
                            ui.colored_label(egui::Color32::GREEN, "Healthy");
                        }

                        // WS — show whether we're actively connected, just available, or unsupported
                        let host = peer_ip(&peer.endpoint);
                        let ws_live = state.ws_active_urls.iter().any(|u| ws_url_host(u) == host);
                        if ws_live {
                            ui.colored_label(egui::Color32::GREEN, "Connected")
                                .on_hover_text("Active WebSocket connection to this peer");
                        } else if peer.ws_available {
                            ui.colored_label(egui::Color32::GRAY, "Available")
                                .on_hover_text(
                                    "Peer supports WebSocket but wallet is not currently connected",
                                );
                        } else if peer.is_healthy {
                            ui.colored_label(egui::Color32::GRAY, "No");
                        } else {
                            ui.colored_label(egui::Color32::GRAY, "--");
                        }

                        // Ping
                        if let Some(ms) = peer.ping_ms {
                            ui.label(format!("{}ms", ms));
                        } else {
                            ui.colored_label(egui::Color32::GRAY, "--");
                        }

                        // Block height
                        if let Some(height) = peer.block_height {
                            ui.label(format!("#{}", height));
                        } else {
                            ui.colored_label(egui::Color32::GRAY, "--");
                        }

                        // Select / deselect link — never shown for wrong-chain peers
                        if peer.genesis_ok == Some(false) {
                            ui.label("");
                        } else if peer.is_active {
                            let link = ui.add(
                                egui::Label::new(
                                    egui::RichText::new("selected")
                                        .color(egui::Color32::GREEN)
                                        .strong(),
                                )
                                .sense(egui::Sense::click()),
                            );
                            if link.clicked() {
                                let _ = ui_tx.send(UiEvent::ClearPreferredPeer);
                            }
                            link.on_hover_text(
                                "Click to deselect and return to automatic peer selection",
                            );
                        } else if peer.is_healthy {
                            let link = ui.link("select");
                            if link.clicked() {
                                let _ = ui_tx.send(UiEvent::SwitchPeer {
                                    endpoint: peer.endpoint.clone(),
                                });
                            }
                        } else {
                            ui.label("");
                        }

                        // Consensus
                        ui.with_layout(
                            egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                            |ui| {
                                if peer.genesis_ok == Some(false) {
                                    ui.colored_label(egui::Color32::RED, "✗").on_hover_text(
                                        "Incompatible genesis block — different chain",
                                    );
                                } else if best_height == 0 {
                                    ui.colored_label(egui::Color32::GRAY, "--");
                                } else {
                                    let height = peer.block_height.unwrap_or(0);
                                    let lag = best_height.saturating_sub(height);
                                    if lag <= 3 {
                                        ui.colored_label(egui::Color32::GREEN, "✔").on_hover_text(
                                            format!(
                                                "Within {} block(s) of best height {}",
                                                lag, best_height
                                            ),
                                        );
                                    } else {
                                        ui.colored_label(egui::Color32::RED, "✗").on_hover_text(
                                            format!(
                                                "{} blocks behind consensus height {}",
                                                lag, best_height
                                            ),
                                        );
                                    }
                                }
                            },
                        );

                        ui.end_row();
                    }
                });
        }); // end ScrollArea
}
