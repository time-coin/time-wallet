# BIP-39 Mnemonic UI Flow Documentation

## Overview
This document describes the user interface flow for BIP-39 mnemonic phrase integration in the TIME Coin Wallet GUI.

## User Flow Diagram

```
┌─────────────────┐
│  Welcome Screen │
└────────┬────────┘
         │
         ├─ Wallet Exists? ─── Yes ──> Unlock with Password ─> Overview Screen
         │
         └─ No ─> Create New Wallet
                        │
                        v
           ┌────────────────────────┐
           │  Mnemonic Setup Screen │
           └───────────┬────────────┘
                       │
                       ├─ Option 1: Generate New Mnemonic
                       │      │
                       │      v
                       │  [Generate Recovery Phrase] Button
                       │      │
                       │      v
                       │  Mnemonic Confirm Screen
                       │      │
                       │      ├─ Display 12 words
                       │      ├─ Security warnings
                       │      ├─ [Copy to Clipboard] Button
                       │      ├─ [✓] I have saved my phrase
                       │      └─ [Create Wallet] Button
                       │             │
                       │             v
                       │         Overview Screen
                       │
                       └─ Option 2: Import Existing Mnemonic
                              │
                              ├─ Text area for 12 words
                              ├─ Real-time validation
                              └─ [Import Wallet] Button
                                     │
                                     v
                                 Overview Screen
```

## Screen Descriptions

### 1. Welcome Screen (Existing Wallet)
```
┌─────────────────────────────────────────┐
│              ⏳ (80px)                   │
│                                         │
│         TIME Coin Wallet                │
│                                         │
│         Select Network:                 │
│     [Mainnet]  [Testnet*]              │
│                                         │
│          Welcome Back!                  │
│                                         │
│            Password:                    │
│         [_______________]               │
│                                         │
│        [Unlock Wallet]                  │
│                                         │
└─────────────────────────────────────────┘
```

### 2. Welcome Screen (New Wallet)
```
┌─────────────────────────────────────────┐
│              ⏳ (80px)                   │
│                                         │
│         TIME Coin Wallet                │
│                                         │
│         Select Network:                 │
│     [Mainnet]  [Testnet*]              │
│                                         │
│        Create New Wallet                │
│                                         │
│        [Create Wallet]                  │
│                                         │
└─────────────────────────────────────────┘
```

### 3. Mnemonic Setup Screen (Generate Mode)
```
┌─────────────────────────────────────────┐
│     Wallet Recovery Phrase              │
│                                         │
│ [Generate New Phrase*] [Import Phrase] │
│                                         │
│ A 12-word recovery phrase will be      │
│ generated for you.                     │
│                                         │
│ This phrase is the ONLY way to         │
│ recover your wallet.                   │
│                                         │
│   [Generate Recovery Phrase]            │
│                                         │
│           [← Back]                      │
│                                         │
└─────────────────────────────────────────┘
```

### 4. Mnemonic Setup Screen (Import Mode)
```
┌─────────────────────────────────────────┐
│     Wallet Recovery Phrase              │
│                                         │
│ [Generate New Phrase] [Import Phrase*] │
│                                         │
│ Enter your 12-word recovery phrase:    │
│                                         │
│ ┌─────────────────────────────────┐   │
│ │ word1 word2 word3 word4 word5   │   │
│ │ word6 word7 word8 word9 word10  │   │
│ │ word11 word12                   │   │
│ └─────────────────────────────────┘   │
│                                         │
│ ✓ Valid recovery phrase                │
│                                         │
│        [Import Wallet]                  │
│                                         │
│           [← Back]                      │
│                                         │
└─────────────────────────────────────────┘
```

### 5. Mnemonic Confirm Screen
```
┌─────────────────────────────────────────┐
│   ⚠️ Save Your Recovery Phrase          │
│                                         │
│ ┌─────────────────────────────────────┐│
│ │ ⚠️ Write down these 12 words in     ││
│ │    order and keep them safe          ││
│ │ ⚠️ Anyone with this phrase can       ││
│ │    access your funds                 ││
│ │ ⚠️ We cannot recover your wallet     ││
│ │    without this phrase               ││
│ └─────────────────────────────────────┘│
│                                         │
│ ┌─────────────────────────────────────┐│
│ │  1. abandon    5. example   9. test ││
│ │  2. ability    6. excuse   10. more ││
│ │  3. able       7. father   11. word ││
│ │  4. about      8. feature  12. last ││
│ └─────────────────────────────────────┘│
│                                         │
│      [📋 Copy to Clipboard]             │
│                                         │
│ [✓] I have written down my recovery    │
│     phrase in a safe place             │
│                                         │
│        [Create Wallet]                  │
│                                         │
│           [← Back]                      │
│                                         │
└─────────────────────────────────────────┘
```

### 6. Settings Screen (with Mnemonic)
```
┌─────────────────────────────────────────┐
│ Settings                                │
│                                         │
│ Network Information                     │
│ ┌─────────────────────────────────────┐│
│ │ Network: Testnet                    ││
│ │ Wallet File: ~/.local/share/...     ││
│ └─────────────────────────────────────┘│
│                                         │
│ Recovery Phrase                         │
│ ┌─────────────────────────────────────┐│
│ │ [✓] Show Recovery Phrase            ││
│ │                                     ││
│ │ ⚠️ WARNING: Never share your        ││
│ │    recovery phrase!                 ││
│ │                                     ││
│ │ ┌─────────────────────────────────┐││
│ │ │ 1. abandon   5. exam    9. test │││
│ │ │ 2. ability   6. excuse 10. more │││
│ │ │ 3. able      7. father 11. word │││
│ │ │ 4. about     8. feature 12. last│││
│ │ └─────────────────────────────────┘││
│ │                                     ││
│ │  [📋 Copy Recovery Phrase]          ││
│ └─────────────────────────────────────┘│
│                                         │
│ Security                                │
│ ┌─────────────────────────────────────┐│
│ │ [ ] Show Private Key                ││
│ └─────────────────────────────────────┘│
│                                         │
└─────────────────────────────────────────┘
```

## Features Implemented

### ✅ Core Functionality
- [x] BIP-39 mnemonic generation (12 words)
- [x] Mnemonic validation
- [x] Deterministic wallet creation from mnemonic
- [x] Mnemonic storage in wallet.dat
- [x] Mnemonic display in settings
- [x] Copy to clipboard functionality

### ✅ User Experience
- [x] Two-mode mnemonic setup (Generate/Import)
- [x] Real-time validation for import
- [x] Confirmation checkbox before wallet creation
- [x] Security warnings displayed prominently
- [x] Clean navigation between screens

### ✅ Security
- [x] Mnemonic stored in wallet.dat (ready for future encryption)
- [x] Clear warnings about phrase importance
- [x] Checkbox confirmation before proceeding
- [x] Hidden by default in settings screen

## Testing Coverage

All tests pass (10 tests total):
1. ✅ Mnemonic generation (12 words)
2. ✅ Wallet creation from mnemonic
3. ✅ Deterministic address generation
4. ✅ Mnemonic validation (valid cases)
5. ✅ Mnemonic validation (invalid cases)
6. ✅ Complete wallet flow
7. ✅ Key import/export
8. ✅ Multiple UTXOs
9. ✅ Insufficient funds handling
10. ✅ Wallet persistence

## Code Changes Summary

### Modified Files
1. **wallet-gui/src/wallet_dat.rs**
   - Added `mnemonic_phrase: Option<String>` field to `WalletDat`
   - Updated serialization to include mnemonic

2. **wallet-gui/src/wallet_manager.rs**
   - Added `create_from_mnemonic()` method
   - Added `generate_mnemonic()` method
   - Added `validate_mnemonic()` method
   - Added `get_mnemonic()` method

3. **wallet-gui/src/main.rs**
   - Added `MnemonicSetup` and `MnemonicConfirm` screen variants
   - Added `MnemonicMode` enum (Generate/Import)
   - Added mnemonic-related fields to `WalletApp`
   - Implemented `show_mnemonic_setup_screen()`
   - Implemented `show_mnemonic_confirm_screen()`
   - Implemented `create_wallet_from_mnemonic()`
   - Updated welcome screen flow
   - Enhanced settings screen with mnemonic display

4. **wallet-gui/tests/integration_test.rs**
   - Added mnemonic-specific integration tests

## Usage Instructions

### First-Time Wallet Creation
1. Launch wallet application
2. Select network (Mainnet/Testnet)
3. Click "Create Wallet"
4. Choose "Generate New Phrase" (default)
5. Click "Generate Recovery Phrase"
6. **IMPORTANT**: Write down all 12 words in order
7. Check the confirmation box
8. Click "Create Wallet"

### Import Existing Wallet
1. Launch wallet application
2. Select network (Mainnet/Testnet)
3. Click "Create Wallet"
4. Choose "Import Existing Phrase"
5. Enter your 12-word recovery phrase
6. Wait for green checkmark (validation)
7. Click "Import Wallet"

### View Recovery Phrase (Existing Wallet)
1. Unlock wallet with password
2. Navigate to Settings screen
3. Check "Show Recovery Phrase"
4. View or copy your recovery phrase
5. **IMPORTANT**: Never share this phrase!

## Future Enhancements
- [ ] Passphrase support for additional security
- [ ] Encryption of mnemonic in wallet.dat
- [ ] Password protection for wallet unlock
- [ ] 24-word mnemonic option
- [ ] Multiple language support (currently English only)
- [ ] QR code for mnemonic backup
- [ ] Backup verification (type random words to confirm)
