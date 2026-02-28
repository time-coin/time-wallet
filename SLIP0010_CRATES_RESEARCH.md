# SLIP-0010 Crates Research

## Summary
Multiple SLIP-0010 related crates are available on crates.io. Below is a comprehensive analysis of the options found.

---

## Primary SLIP-0010 Crates

### 1. **slip10** v0.4.3 ⭐ RECOMMENDED
- **Description**: SLIP-0010 : Universal private key derivation from master private key
- **License**: Apache-2.0 OR MIT
- **Repository**: https://github.com/wusyong/slip10
- **Documentation**: https://docs.rs/slip10
- **Crates.io**: https://crates.io/crates/slip10/0.4.3
- **Status**: Active, stable, supports multiple curves

### 2. **slipped10** v0.4.6 ⭐ ALTERNATIVE
- **Description**: SLIP-0010 : ed25519 private key derivation from master private key
- **License**: MIT
- **Repository**: https://github.com/dj8yfo/slipped10
- **Documentation**: https://docs.rs/slipped10/0.4.6
- **Crates.io**: https://crates.io/crates/slipped10/0.4.6
- **Focus**: Specifically for Ed25519 private key derivation

### 3. **slip10_ed25519** v0.1.3
- **Description**: Private key derivation for SLIP-0010 Ed25519
- **License**: MIT OR Apache-2.0
- **Repository**: https://gitlab.com/westonian/slip10-ed25519-rust-crate
- **Documentation**: https://docs.rs/slip10_ed25519/
- **Crates.io**: https://crates.io/crates/slip10_ed25519/0.1.3
- **Focus**: Specific to Ed25519 implementation

### 4. **ed25519-hd-key** v0.3.0
- **Description**: Rust implementation for SLIP-0010 using curve ed25519
- **License**: MIT OR Apache-2.0
- **Documentation**: https://docs.rs/ed25519-hd-key/0.3.0
- **Crates.io**: https://crates.io/crates/ed25519-hd-key/0.3.0
- **Focus**: HD wallet support for Ed25519

---

## BIP32 Related Crates

### 5. **ed25519-bip32** v0.4.1 ✓ EXISTS
- **Description**: Ed25519 BIP32
- **License**: MIT OR Apache-2.0
- **Repository**: https://github.com/typed-io/rust-ed25519-bip32/
- **Documentation**: https://docs.rs/ed25519-bip32/0.4.1
- **Crates.io**: https://crates.io/crates/ed25519-bip32/0.4.1
- **Features**: Supports BIP32 for Ed25519
- **Note**: While not explicitly named SLIP-0010, ed25519-bip32 is related to Ed25519 hierarchical deterministic key derivation

### 6. **ed25519-bip32-core** v0.1.1
- **Description**: Ed25519 BIP32 core
- **Crates.io**: https://crates.io/crates/ed25519-bip32-core/0.1.1

### 7. **slip-10** v0.4.1
- **Description**: SLIP10 implementation in Rust
- **Crates.io**: https://crates.io/crates/slip-10/0.4.1

### 8. **bip0032** v0.1.0
- **Description**: Another Rust implementation of BIP-0032 standard
- **Crates.io**: https://crates.io/crates/bip0032/0.1.0

---

## Related Crates
- **iota-crypto** v0.23.2 - Contains cryptographic utilities including SLIP-0010 support
- **iota_stronghold** v2.1.0 - Client interface with crypto support
- **hd-wallet** v0.6.1 - HD wallet derivation

---

## Analysis & Recommendations

### For Time-Coin Project:

#### **Option 1: slip10 (RECOMMENDED) ✅**
- **Best for**: General-purpose SLIP-0010 implementation
- **Advantages**:
  - Universal support (not just Ed25519)
  - Most mature and actively maintained
  - Supports multiple curves
  - Well-documented
- **Use case**: If you need broad SLIP-0010 support

#### **Option 2: slipped10 ✅**
- **Best for**: Ed25519-specific SLIP-0010
- **Advantages**:
  - Specifically optimized for Ed25519
  - Active maintenance
  - Lightweight and focused
- **Use case**: If you're committed to Ed25519 curve only

#### **Option 3: ed25519-bip32 ✅**
- **Best for**: Ed25519 + BIP32 compatibility
- **Advantages**:
  - Supports both Ed25519 and BIP32 standards
  - Well-maintained library
  - Good for wallet implementations
- **Use case**: If you need both BIP32 and Ed25519 support

#### **Option 4: ed25519-hd-key ✅**
- **Best for**: HD wallet functionality with Ed25519
- **Advantages**:
  - Explicit SLIP-0010 support for Ed25519
  - HD wallet design
- **Use case**: If building a complete HD wallet system

---

## Findings Summary

| Question | Answer |
|----------|--------|
| Does `slip10` exist? | ✅ **YES** - v0.4.3 (Universal SLIP-0010) |
| Does `slip-0010` exist? | ✅ **YES** - v0.4.1 (slip-10 crate) |
| Does `ed25519-bip32` exist? | ✅ **YES** - v0.4.1 (Ed25519 + BIP32) |
| Does `bip32` v0.5 support Ed25519 via SLIP-0010? | ⚠️ **Partially** - Found `bip0032` v0.1.0, but need to verify version |
| Does `ed25519-dalek` have built-in SLIP-0010? | ❓ **Not found in search** - Would need separate investigation |

---

## Next Steps
1. Run `cargo info slip10` to examine detailed dependencies
2. Review source code at GitHub repositories to understand feature sets
3. Test integration with ed25519-dalek if needed
4. Check for compatibility with other time-coin dependencies
