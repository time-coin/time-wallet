# Building the TIME Coin Wallet

## Prerequisites

- **Rust** 1.75 or later — install from [rustup.rs](https://rustup.rs)
- **Git** — for cloning the repository

### Platform-Specific

**Linux:**
```bash
sudo apt install build-essential libssl-dev pkg-config libgtk-3-dev
```

**macOS:**
```bash
xcode-select --install
```

**Windows:**
- Visual Studio Build Tools with C++ workload, or
- MSYS2 with `mingw-w64-x86_64-toolchain`

## Clone & Build

```bash
git clone https://github.com/time-coin/time-coin.git
cd time-coin
cargo build --release
```

The wallet binary will be at `target/release/wallet-gui` (or `wallet-gui.exe` on Windows).

## Run

```bash
cargo run --release
```

Or run the binary directly:

```bash
./target/release/wallet-gui
```

## Development

Build in debug mode for faster compilation:

```bash
cargo build
cargo run
```

### Useful Commands

```bash
cargo fmt --all          # Format all code
cargo check --workspace  # Fast compilation check
cargo clippy --workspace # Lint checks
cargo test --workspace   # Run all tests
```

## Configuration

On first run, the wallet creates a configuration file at:

| Platform | Path |
|----------|------|
| Linux | `~/.timecoin/config.json` |
| macOS | `~/.timecoin/config.json` |
| Windows | `%USERPROFILE%\.timecoin\config.json` |

See [WALLET_USAGE.md](WALLET_USAGE.md) for configuration options.

## Release Profile

Release builds use aggressive optimizations:

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 16
```
