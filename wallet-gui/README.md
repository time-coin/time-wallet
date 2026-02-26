# TIME Coin GUI Wallet

A cross-platform graphical hot wallet for TIME Coin, featuring a Bitcoin-style `wallet.dat` file for key storage.

## Features

- ✅ **wallet.dat File Format**: Similar to Bitcoin Core, stores all keys in a single file
- ✅ **Multi-Address Support**: Create and manage multiple addresses
- ✅ **Cross-Platform**: Works on Windows, Linux, and macOS
- ✅ **Clean GUI**: Built with egui for native performance
- ✅ **Send/Receive**: Create transactions and display receiving addresses
- ✅ **Balance Tracking**: View balance and unspent outputs (UTXOs)
- ✅ **Key Import/Export**: Import existing keys or export for backup
- ⏳ **Encryption Ready**: Structure in place for future encryption support
- ⏳ **Network Integration**: Will connect to TIME Coin masternode network

## Installation

### Prerequisites

- Rust 1.75 or higher
- Cargo
- Development libraries (Linux only):
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
  
  # Fedora
  sudo dnf install gtk3-devel libxcb-devel
  ```

### Build from Source

```bash
cd time-coin
cargo build --release --bin wallet-gui
```

### Run

```bash
# Run in development mode
cargo run --bin wallet-gui

# Or run the release binary
./target/release/wallet-gui
```

## Usage

### First Time Setup

When you first run the wallet, you'll see the welcome screen with two options:

1. **Create New Wallet**: Generate a new wallet with a random key
2. **Import Existing Key**: Import a wallet from a private key

### wallet.dat Location

The wallet.dat file is stored in the following locations by default:

- **Linux**: `~/.local/share/time-coin/testnet/wallet.dat`
- **macOS**: `~/Library/Application Support/time-coin/testnet/wallet.dat`
- **Windows**: `%APPDATA%\time-coin\testnet\wallet.dat`

For mainnet, replace `testnet` with `mainnet`.

### Backing Up Your Wallet

**Important**: Always backup your wallet.dat file and private keys!

#### Method 1: Copy wallet.dat
```bash
# Linux/macOS
cp ~/.local/share/time-coin/testnet/wallet.dat ~/backup/

# Windows
copy %APPDATA%\time-coin\testnet\wallet.dat C:\backup\
```

#### Method 2: Export Private Key
1. Go to Settings
2. Check "Show Private Key"
3. Copy and securely store your private key
4. ⚠️ **Never share your private key with anyone!**

### Restoring Your Wallet

#### Method 1: Restore wallet.dat
Simply copy your backed-up wallet.dat file back to the default location before starting the wallet.

#### Method 2: Import Private Key
1. Start the wallet
2. On the welcome screen, choose "Import Existing Key"
3. Paste your private key (hex format)
4. Click "Import Key"

## Wallet Features

### Overview Screen
- View your current balance
- See your primary address
- List all unspent outputs (UTXOs)

### Send Screen
- Enter recipient address
- Specify amount in TIME
- Set transaction fee
- Create and broadcast transactions

### Receive Screen
- Display your receiving address
- Copy address to clipboard
- View all addresses in your wallet

### Transactions Screen
- View transaction history (coming soon)
- Filter and search transactions (coming soon)

### Settings Screen
- View network information
- Access wallet file location
- Export private keys (with warnings)
- Future: Encrypt wallet

## Security

### Current (Testnet)
- wallet.dat is **NOT encrypted** - suitable for testnet only
- File permissions are set to owner read/write only (Unix)
- Private keys stored in binary format using bincode

### Future (Mainnet)
- AES-256 encryption for wallet.dat
- Password-protected wallet
- Optional passphrase for spending
- Secure key derivation (PBKDF2/Argon2)

**⚠️ DO NOT use unencrypted wallets for mainnet!**

## wallet.dat Format

The wallet.dat file uses a custom binary format:

```rust
struct WalletDat {
    version: u32,                    // Format version
    network: NetworkType,            // Mainnet/Testnet
    keys: Vec<KeyEntry>,            // All stored keys
    created_at: i64,                // Creation timestamp
    modified_at: i64,               // Last modification
    encryption_salt: Option<Vec<u8>>, // For future encryption
    is_encrypted: bool,             // Encryption flag
}

struct KeyEntry {
    keypair_bytes: [u8; 32],        // Secret key
    public_key: [u8; 32],           // Public key
    address: String,                 // TIME Coin address
    label: String,                   // User-defined label
    created_at: i64,                 // Creation timestamp
    is_default: bool,                // Default key flag
}
```

## Development

### Project Structure

```
wallet-gui/
├── src/
│   ├── main.rs           # GUI application
│   ├── wallet_dat.rs     # wallet.dat file format
│   └── wallet_manager.rs # High-level wallet operations
├── Cargo.toml
└── README.md
```

### Running Tests

```bash
cargo test --package wallet-gui
```

### Development Mode

```bash
RUST_LOG=debug cargo run --bin wallet-gui
```

## Troubleshooting

### Wallet won't start
- Check that development libraries are installed (Linux)
- Verify wallet.dat is not corrupted
- Try creating a new wallet

### Can't see balance
- Network integration is still in progress
- Manually add UTXOs for testing (via code)

### GUI looks wrong
- Update your graphics drivers
- Try running with software rendering:
  ```bash
  LIBGL_ALWAYS_SOFTWARE=1 cargo run --bin wallet-gui
  ```

## Roadmap

- [ ] Network integration with masternode
- [ ] Transaction history from blockchain
- [ ] Wallet encryption (AES-256)
- [ ] HD wallet support (BIP32/BIP44)
- [ ] Hardware wallet support
- [ ] Multi-wallet management
- [ ] QR code support
- [ ] Address book
- [ ] Transaction notes
- [ ] Coin control

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Support

- GitHub Issues: https://github.com/time-coin/time-coin/issues
- Telegram: https://t.me/+CaN6EflYM-83OTY0
- Documentation: https://time-coin.io/docs

---

⏰ **Remember**: Always backup your wallet.dat and private keys securely!
