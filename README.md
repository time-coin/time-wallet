# TIME Coin Wallet ⏰

[![CI](https://github.com/time-coin/time-coin/actions/workflows/ci.yml/badge.svg)](https://github.com/time-coin/time-coin/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](https://github.com/time-coin/time-coin/blob/main/LICENSE)

A cross-platform GUI wallet for the TIME Coin network. Built with Rust and [egui](https://github.com/emilk/egui).

## Features

- 🔑 **HD wallet** — BIP39 mnemonic seed with BIP32 key derivation
- 💸 **Send & receive** — UTXO-based transactions with address book
- 🔒 **Encrypted storage** — AES-256-GCM encryption with Argon2 key derivation
- 📱 **QR codes** — Generate and scan QR codes for addresses
- 🌐 **P2P networking** — Connects directly to the TIME Coin network
- 💾 **Bitcoin-style wallet.dat** — Compatible backup and restore
- 📄 **PDF mnemonic backup** — Printable seed phrase backup

## Getting started

### Prerequisites

- [Rust](https://rustup.rs/) 1.75 or higher

### Build and run

```bash
git clone https://github.com/time-coin/time-coin.git
cd time-coin

# Run the wallet
cargo run --release

# Or build first, then run
cargo build --release
./target/release/wallet-gui
```

### Run tests

```bash
# All tests
cargo test --workspace

# Tests for a single crate
cargo test -p wallet

# A specific test
cargo test -p wallet test_address_generation
```

### Lint

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Project structure

```
time-coin/
├── src/
│   ├── wallet-gui/   # GUI application (egui/eframe)
│   ├── wallet/       # Wallet logic, key management, signing
│   ├── core/         # Blockchain types (blocks, transactions, UTXO)
│   ├── crypto/       # Ed25519 signatures, SHA-256 hashing
│   ├── network/      # P2P networking and peer discovery
│   └── mempool/      # Transaction pool
├── Cargo.toml        # Workspace configuration
└── deny.toml         # Dependency audit rules
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Community

- Website: https://time-coin.io
- Telegram: https://t.me/+CaN6EflYM-83OTY0
- Twitter: [@TIMEcoin515010](https://twitter.com/TIMEcoin515010)
- GitHub: https://github.com/time-coin/time-coin

## License

BUSL-1.1 — see [LICENSE](LICENSE) for details.