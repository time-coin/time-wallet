# Wallet Usage Guide

## First Launch

On first launch, the wallet presents two options:

1. **Create New Wallet** — generates a new BIP39 mnemonic phrase
2. **Restore Wallet** — enter an existing mnemonic phrase to recover

### Creating a New Wallet

1. Choose word count (12 or 24 words recommended)
2. **Write down your mnemonic phrase** — this is the only way to recover your wallet
3. Set a password to encrypt your wallet file
4. The wallet generates your first receiving address

### Restoring a Wallet

1. Enter your mnemonic phrase (12–24 words)
2. Set a new password for the local wallet file
3. The wallet derives your addresses and syncs with a masternode

## Configuration

The wallet configuration is stored in `~/.timecoin/config.json`:

```json
{
  "network": "testnet",
  "rpc_port": 24101,
  "bootstrap_nodes": ["134.199.175.106:24100"],
  "data_dir": "~/.timecoin"
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `network` | `"testnet"` | `"testnet"` or `"mainnet"` |
| `data_dir` | `~/.timecoin` | Data storage directory |
| `rpc_port` | `24101` | Masternode RPC port |
| `bootstrap_nodes` | `[]` | Seed node addresses |
| `addnode` | `[]` | Additional nodes to connect to |

### Network Ports

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| Testnet | 24100 | 24101 |
| Mainnet | 24000 | 24001 |

## Sending Coins

1. Navigate to the **Send** tab
2. Enter the recipient address (`TIME0...` for testnet, `TIME1...` for mainnet)
3. Enter the amount in TIME
4. Review the transaction details and fee
5. Confirm to sign and broadcast

The wallet automatically selects UTXOs and creates change outputs.

## Receiving Coins

1. Navigate to the **Receive** tab
2. Copy your address or scan the QR code
3. Share the address with the sender

The wallet derives new addresses from your HD key chain as needed.

## Transaction History

The **Transactions** tab shows all sent and received transactions with:
- Transaction ID
- Amount and direction (sent/received)
- Confirmation status
- Timestamp

## Security

### Password Protection

Your wallet file is encrypted with AES-256-GCM. The encryption key is derived from your password using Argon2id with:
- 19 MB memory cost
- 2 time iterations
- 12-byte random nonce per encryption

### Password Strength

The wallet enforces minimum requirements:
- At least 8 characters
- Strength indicator shows: Very Weak → Weak → Fair → Strong → Very Strong
- Uses character diversity (uppercase, lowercase, digits, special characters)

### Mnemonic Phrase

Your 12–24 word mnemonic phrase is the master backup for your wallet. Anyone with this phrase can access your funds. Store it securely offline.

### Key Isolation

Private keys never leave your device. Transaction signing is performed locally, and only the signed transaction is broadcast to the masternode.

## Troubleshooting

### Cannot connect to masternode

1. Check your internet connection
2. Verify `bootstrap_nodes` in config contains reachable addresses
3. Ensure firewall allows outbound TCP on port 24100/24101 (testnet) or 24000/24001 (mainnet)

### Wallet shows zero balance

1. Confirm you are on the correct network (testnet vs mainnet)
2. Wait for sync to complete — check the status bar
3. If restored from mnemonic, ensure the phrase was entered correctly

### Forgot password

The wallet password cannot be recovered. If you have your mnemonic phrase, create a new wallet and restore from the mnemonic.
