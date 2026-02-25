# TIME Coin Address Format

## Overview

TIME Coin addresses use a custom format with a human-readable prefix, a 20-byte payload derived from the public key, and a 4-byte checksum. The format is identical between the wallet and the masternode.

## Format

```
TIME{network_digit}{base58(payload + checksum)}

Examples:
  Testnet:  TIME0<~33 base58 characters>
  Mainnet:  TIME1<~33 base58 characters>
```

| Component | Size | Description |
|-----------|------|-------------|
| Prefix | 5 chars | `TIME0` (testnet) or `TIME1` (mainnet) |
| Payload | 20 bytes | Truncated SHA-256 of public key |
| Checksum | 4 bytes | First 4 bytes of double SHA-256 of payload |
| **Total encoded** | **~38 chars** | Variable due to base58 encoding (35–45 range) |

## Derivation

Given a 32-byte Ed25519 public key:

```
1. payload   = SHA256(public_key)[0..20]      # first 20 bytes
2. checksum  = SHA256(SHA256(payload))[0..4]   # first 4 bytes
3. data      = payload || checksum             # 24 bytes
4. encoded   = base58_encode(data)
5. address   = "TIME" + network_digit + encoded
```

## Network Types

| Network | Digit | Prefix | P2P Port | RPC Port |
|---------|-------|--------|----------|----------|
| Testnet | `0` | `TIME0` | 24100 | 24101 |
| Mainnet | `1` | `TIME1` | 24000 | 24001 |

## Base58 Encoding

Uses the standard Bitcoin base58 alphabet:

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Characters `0`, `O`, `I`, and `l` are excluded to avoid visual ambiguity.

## Key Derivation (HD Wallet)

The wallet supports BIP39 mnemonics with BIP44 derivation:

```
Mnemonic (12–24 words)
  → BIP39 Seed (512 bits)
    → BIP32 Extended Private Key
      → BIP44 Path: m/44'/0'/account'/change/index
        → Ed25519 Private Key (32 bytes)
          → Ed25519 Public Key (32 bytes)
            → TIME Address
```

- **Coin type**: `0'` (to be registered with SLIP-0044)
- **Receiving addresses**: `change = 0`
- **Change addresses**: `change = 1`

## Validation

An address is valid if:

1. Length is between 35 and 45 characters
2. Starts with `TIME0` or `TIME1`
3. Remaining characters are valid base58
4. Base58-decoded data is exactly 24 bytes
5. Last 4 bytes match `SHA256(SHA256(first 20 bytes))[0..4]`

## Transaction Script

TIME Coin uses a simplified script model. The `script_pubkey` field in transaction outputs stores the address string as UTF-8 bytes (not Bitcoin-style opcodes). During verification, the masternode:

1. Extracts the public key from the input's `script_sig`
2. Derives the address using the same `SHA256[0:20]` algorithm
3. Compares the derived address to the `script_pubkey` stored in the UTXO
