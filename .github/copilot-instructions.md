# Copilot Instructions for TIME Coin Wallet

## Build, Test, and Lint

```bash
cargo build --workspace              # Build all crates
cargo run --release                  # Run the wallet GUI (default member)
cargo test --workspace               # All tests
cargo test -p wallet                 # Tests for one crate
cargo test -p wallet test_address_generation  # Single test by name
cargo clippy --workspace --all-targets -- -D warnings  # Lint (CI treats warnings as errors)
cargo fmt --all -- --check           # Format check
cargo check --workspace              # Fast type-check without codegen
```

CI also runs `cargo-deny` for advisory/license/ban/source audits (configured in `deny.toml`).

## Architecture

This is a **thin-client GUI wallet** for the TIME Coin blockchain. The wallet handles key management, transaction signing, and address derivation locally. All blockchain state (UTXO set, blocks, mempool) lives on masternodes — the wallet queries them via JSON-RPC 2.0 over TCP (port 24101 testnet, 24001 mainnet).

### Workspace Crates

```
wallet-gui  (binary, default member — egui/eframe desktop app)
├── wallet       (key management, BIP39/BIP44, signing, encrypted storage)
├── time-network (P2P protocol, peer discovery, masternode RPC)
│   ├── time-core
│   └── time-mempool
└── time-core    (shared blockchain types: blocks, transactions, UTXO)
    └── time-crypto (Ed25519 signatures, SHA-256 hashing)
```

The `wallet` crate is standalone (no internal crate deps) — it reimplements crypto primitives directly rather than depending on `time-crypto`.

### GUI Layer (`wallet-gui`)

Built with `eframe`/`egui`. The app entry point is `wallet-gui/src/main.rs`. Key modules include multiple client implementations (TCP-first with HTTP fallback via `hybrid_client`, WebSocket, protocol-level), a `wallet_manager` for lifecycle, `utxo_manager` for coin selection, and `wallet_db` using sled for local storage.

### Masternode Communication

The wallet uses a hybrid connectivity strategy: TCP first, falling back to HTTP. Messages are newline-delimited JSON-RPC 2.0. Connection health is monitored via `monitoring.rs`.

## Key Conventions

- **Error handling**: Use `thiserror` for custom error types with `Result<T, E>`. Prefer explicit error handling over panics.
- **Sensitive data**: Use the `zeroize` crate to securely clear private keys and mnemonics from memory.
- **Encryption**: AES-256-GCM for wallet files, Argon2id (19 MB memory, 2 iterations) for password-based key derivation.
- **Address format**: `TIME{0|1}{base58(payload + checksum)}` — `TIME0` for testnet, `TIME1` for mainnet. Payload is 20-byte SHA-256 of the Ed25519 public key.
- **Key derivation**: BIP39 mnemonic (12–24 words) → BIP44 path → Ed25519 keypair.
- **Async runtime**: Tokio with full features. Async tests use `#[tokio::test]`.
- **Commit messages**: Conventional format — `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.
- **Branch naming**: `feature/`, `fix/`, `docs/`, `refactor/`, `test/` prefixes.
- **Public API docs**: Document with rustdoc comments (`///`), including `# Arguments`, `# Returns`, and `# Errors` sections.
- **Rust toolchain**: Stable channel, pinned via `rust-toolchain.toml`. Clippy and rustfmt are required components.
