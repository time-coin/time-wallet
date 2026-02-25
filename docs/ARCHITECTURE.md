# TIME Coin Wallet — Architecture

## Overview

The TIME Coin Wallet is a desktop GUI application built with Rust and [egui](https://github.com/emilk/egui). It is a thin client — all blockchain state is managed by masternodes. The wallet handles key management, transaction signing, and address derivation locally.

## Workspace Structure

```
time-coin/
├── Cargo.toml              # Workspace root
├── src/
│   ├── core/               # Shared blockchain types (blocks, transactions, UTXO)
│   ├── crypto/             # Cryptographic primitives
│   ├── wallet/             # Key management, BIP39, signing, encryption
│   ├── wallet-gui/         # Desktop GUI application (default binary)
│   ├── network/            # P2P networking and protocol messages
│   └── mempool/            # Transaction mempool
```

## Crate Dependency Graph

```
wallet-gui
├── wallet
│   ├── core
│   │   └── crypto
│   ├── network
│   │   └── core
│   └── mempool
│       └── core
└── (egui/eframe)
```

## Key Crates

### `wallet-gui` (binary)

The main application. Built with `eframe`/`egui` for cross-platform desktop rendering.

**Modules:**

| Module | Purpose |
|--------|---------|
| `main.rs` | App entry point, UI rendering, screen management |
| `masternode_client.rs` | RPC client for masternode communication |
| `hybrid_client.rs` | TCP-first client with HTTP fallback |
| `simple_client.rs` | Lightweight async client |
| `protocol_client.rs` | P2P protocol client |
| `mnemonic_ui.rs` | Mnemonic creation/recovery UI |
| `password_ui.rs` | Password entry with strength indicator |
| `wallet_manager.rs` | Wallet lifecycle management |
| `wallet_db.rs` | Local wallet database (sled) |
| `wallet_sync.rs` | Background sync with masternode |
| `utxo_manager.rs` | UTXO tracking and coin selection |
| `config.rs` | Configuration file management |
| `encryption.rs` | AES-256-GCM wallet encryption |
| `monitoring.rs` | Connection health monitoring |

### `wallet` (library)

Core wallet logic — no UI dependencies.

**Key exports:**
- `Keypair` — Ed25519 key generation and signing
- `Address`, `NetworkType` — Address derivation matching masternode format
- `Transaction`, `UTXO` — Transaction building and signing
- `Wallet` — Wallet state and key storage
- `EncryptedWallet` — Encrypted wallet file I/O
- `generate_mnemonic()`, `mnemonic_to_keypair_bip44()` — BIP39/BIP44 HD key derivation
- `mnemonic_to_xpub()`, `xpub_to_address()` — Extended public key operations

### `core` (library)

Shared blockchain types used by both wallet and network crates. Includes block headers, transaction structures, UTXO types, and chain selection logic.

### `network` (library)

P2P networking layer. Defines the `NetworkMessage` protocol, peer discovery, connection management, and rate limiting.

### `mempool` (library)

Transaction mempool with priority queue ordering and resource monitoring.

## Security Architecture

- **Key storage**: Ed25519 private keys encrypted with AES-256-GCM
- **Key derivation**: Argon2id (19 MB memory, 2 iterations) from user password
- **Mnemonic**: BIP39 standard (12–24 words), BIP44 derivation paths
- **Memory**: `zeroize` crate for secure cleanup of sensitive data
- **Signing**: All transaction signing happens locally — private keys never leave the device
