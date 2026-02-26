//! UI view modules — pure rendering functions.
//!
//! Each submodule renders one screen. Views read from [`AppState`] and send
//! [`UiEvent`]s on user interaction. No async, no network, no wallet logic.

pub mod connections;
pub mod overview;
pub mod receive;
pub mod send;
pub mod settings;
pub mod transactions;
pub mod welcome;
