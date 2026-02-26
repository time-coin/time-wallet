# Wallet Security Features

## Overview

The TIME Coin wallet now includes enterprise-grade encryption for secure storage of private keys and sensitive data.

## Features

### ✅ Password-Based Encryption

**Implemented:**
- ✅ AES-256-GCM encryption
- ✅ Argon2id key derivation (memory-hard, GPU-resistant)
- ✅ Random salt and nonce per encryption
- ✅ Password verification without decryption
- ✅ Secure password change functionality
- ✅ Memory zeroization for passwords

**Security Properties:**
- **Confidentiality**: AES-256-GCM provides strong encryption
- **Integrity**: Authenticated encryption prevents tampering
- **Key Derivation**: Argon2id is resistant to brute-force and GPU attacks
- **Forward Secrecy**: Each encryption uses unique salt/nonce

### 🔐 Cryptographic Details

#### Key Derivation: Argon2id
- **Algorithm**: Argon2id (winner of Password Hashing Competition)
- **Purpose**: Derives 256-bit encryption key from password
- **Parameters**:
  - Memory: 4 MiB (default)
  - Iterations: 3 (default)
  - Parallelism: 1 (default)
- **Resistance**: 
  - Memory-hard (prevents ASIC attacks)
  - Time-hard (prevents brute force)
  - Side-channel resistant

#### Encryption: AES-256-GCM
- **Algorithm**: Advanced Encryption Standard, 256-bit key
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **IV/Nonce**: 96-bit random nonce per encryption
- **Authentication**: Built-in authentication tag
- **Security**: 
  - NIST approved
  - Quantum-resistant (current standards)
  - Prevents tampering

## Usage

### Basic Encryption

```rust
use wallet::{Wallet, NetworkType, SecurePassword};

// Create wallet
let wallet = Wallet::new(NetworkType::Mainnet)?;

// Create secure password (auto-zeroized on drop)
let password = SecurePassword::new("your_strong_password".to_string());

// Save encrypted
wallet.save_encrypted("wallet.enc", &password)?;

// Load encrypted
let loaded = Wallet::load_encrypted("wallet.enc", &password)?;
```

### Password Verification

```rust
use wallet::{Wallet, SecurePassword};

let password = SecurePassword::new("password".to_string());

// Verify without loading entire wallet (faster)
if Wallet::verify_encrypted_password("wallet.enc", &password)? {
    println!("Password correct!");
    let wallet = Wallet::load_encrypted("wallet.enc", &password)?;
}
```

### Password Change

```rust
use wallet::{Wallet, SecurePassword};

let old_pwd = SecurePassword::new("old_password".to_string());
let new_pwd = SecurePassword::new("new_password".to_string());

// Change password without loading wallet
Wallet::change_encrypted_password("wallet.enc", &old_pwd, &new_pwd)?;
```

## File Format

### Encrypted Wallet Structure

```json
{
  "password_hash": "...",  // Argon2id hash for verification
  "salt": "...",           // Base64 salt for key derivation
  "ciphertext": [...],     // Encrypted wallet data
  "nonce": [...],          // AES-GCM nonce
  "version": 1             // Format version for upgrades
}
```

### Legacy Compatibility

- Unencrypted wallets: Use `save_to_file()` / `load_from_file()`
- Encrypted wallets: Use `save_encrypted()` / `load_encrypted()`
- Both formats supported side-by-side

## Security Best Practices

### For Users

1. **Strong Passwords**
   - Minimum 12 characters
   - Mix uppercase, lowercase, numbers, symbols
   - Use a passphrase: "correct horse battery staple"
   - Use password manager

2. **Secure Storage**
   - Keep encrypted wallet file safe
   - Backup to multiple locations
   - Consider hardware wallet for large amounts

3. **Password Management**
   - Don't write password down
   - Don't share password
   - Change password if compromised
   - Use different password per wallet

### For Developers

1. **Memory Safety**
   ```rust
   // Good: Password auto-zeroized
   let password = SecurePassword::new(pwd_string);
   wallet.load_encrypted(path, &password)?;
   // password memory cleared on drop
   
   // Bad: Password stays in memory
   let pwd_string = "password".to_string();
   // pwd_string stays in memory until GC
   ```

2. **Error Handling**
   ```rust
   match Wallet::load_encrypted(path, &password) {
       Ok(wallet) => { /* success */ },
       Err(WalletError::InvalidPassword) => {
           // Show generic error to prevent timing attacks
           println!("Invalid password");
       },
       Err(e) => println!("Error: {}", e),
   }
   ```

3. **Timing Attack Prevention**
   - Argon2 provides constant-time verification
   - Don't reveal password strength hints
   - Use generic error messages

## Performance

### Encryption Performance
- **Key Derivation**: ~100-200ms (intentionally slow, prevents brute force)
- **Encryption**: <1ms for typical wallet (~10 KB)
- **Decryption**: ~100-200ms (key derivation dominates)

### Memory Usage
- **Peak Memory**: ~4 MiB during key derivation (Argon2id)
- **Steady State**: Minimal overhead after decryption

## Future Enhancements

### Planned Features

- [ ] PIN Authentication (4-6 digit PIN for quick access)
- [ ] Biometric Authentication (Face ID, Touch ID, Fingerprint)
- [ ] Hardware Wallet Integration (Ledger, Trezor)
- [ ] Multi-signature Wallets (2-of-3, 3-of-5, etc.)
- [ ] Time-locked Transactions
- [ ] Auto-lock After Inactivity
- [ ] Secure Clipboard (auto-clear after 30s)
- [ ] Keychain Integration (macOS Keychain, Windows Credential Manager)

### Mobile-Specific

- [ ] Secure Enclave/TEE Storage (iOS/Android)
- [ ] Biometric + Password (2FA)
- [ ] Background Key Derivation (reduce UI lag)
- [ ] Emergency Recovery Codes

## Testing

Run encryption tests:

```bash
cargo test -p wallet encryption
```

Run example:

```bash
cd wallet
cargo run --example encrypted_wallet
```

## Dependencies

```toml
# Encryption
aes-gcm = "0.10"        # AES-256-GCM encryption
argon2 = "0.5"          # Argon2id key derivation
zeroize = "1.7"         # Memory zeroization
```

## References

- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [AES-GCM NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## License

MIT OR Apache-2.0 (same as TIME Coin project)

---

**Status**: ✅ Implemented and Tested  
**Version**: 1.0  
**Last Updated**: 2025-12-09
