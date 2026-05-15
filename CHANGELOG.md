# Changelog

All notable changes to the TIME Coin Wallet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.7] - 2026-05-15

### Added
- **Collateral lock audit** — Tools screen now shows a collateral audit panel (behind a collapsing header) listing all locked UTXOs with their masternode assignment and lock status
- **Collateral locked badge** — Masternode list entries show a locked badge; Register On-Chain pre-fills the node IP from the stored entry

### Changed
- **Incremental startup sync** — Eliminated full chain rescan on startup; wallet now performs an incremental sync so the UI is responsive within seconds
- **Parallel peer probing** — Peer probe sub-checks are now parallelised and deduplicate TLS handshakes, cutting connection setup time significantly
- **Parallel UTXO and transaction scans** — UTXO and transaction syncs are now parallelised after peer connect, eliminating the post-connect delay

### Fixed
- **Consolidation balance inflation after UTXO finalization** — Consolidation outputs are now correctly excluded until they reach masternode finality, preventing double-counting
- **Broken transactions (v2 signing)** — Upgraded to v2 transaction signing format; previously signed transactions were rejected by the masternode due to format mismatch
- **Live fee schedule for consolidation** — Consolidation now fetches the current fee schedule from the masternode instead of using a hardcoded value
- **Deregistration used wrong key** — Deregistration now signs with the collateral owner key; the Masternodes screen correctly shows a "Deregister" button for locked entries
- **Tools screen not scrollable** — Tools screen is now scrollable; collateral audit is hidden behind a collapsing header to keep the layout clean
- **Peer list flicker and verified badge** — Fixed flicker on peer list refresh, stale connecting state, slow peer switching, and incorrect verified badge display
- **Peers rejected on genesis chain mismatch** — Peers reporting an incompatible genesis chain are now rejected early instead of causing downstream sync errors

## [0.6.4] - 2026-04-09

### Added
- **Single-instance lock** — A second wallet instance targeting the same network now shows a native error dialog ("Already Running") and exits cleanly instead of corrupting the sled database. Uses an OS advisory file lock (auto-released on crash) per network directory

### Changed
- **Overview status bar** — Block height, peer count, Mainnet/Testnet badge, and version label are now rendered at 13 px instead of the previous small (~10 px) size for improved readability

### Added
- **Payment Requests screen** — Send payment requests to other wallets via the masternode P2P network. Incoming requests show amount, sender, and expiry timer; approve to pre-fill the Send form or decline to reject
- **Incoming payment request persistence** — Received payment requests are saved to the local sled database and restored on startup so they survive restarts
- **Sent payment request persistence** — Sent requests are saved locally before the RPC call; they appear immediately in the Sent section and show a red "Failed" badge if the network call does not succeed
- **"Request Payment" button on Requests page** — Replaced the non-functional unicode toggle with a plain button; form opens by default when the page loads

### Changed
- **Payment request acknowledgement deferred until send** — Clicking "Approve" on an incoming request no longer immediately fires `acknowledged = paid` on the masternode; the acknowledgement is sent only after the transaction is successfully broadcast, preventing the sender from seeing "Paid" when the payer navigated away without confirming
- **Transaction status: Approved on block inclusion** — Transactions transition to `✅ Approved` once included in a block (`blockhash` present), or when the masternode RPC returns `finalized: true`. Block rewards (`generate` category) are always Approved since they cannot exist outside a block
- **Payment request amount wire format** — Amount is now sent as float TIME (e.g. `1.0`) in the `sendpaymentrequest` RPC call; previously raw satoshis were sent (e.g. `100000`) which the masternode rejected. Incoming amounts from the poll RPC are now correctly converted from float TIME to satoshis

### Fixed
- **UTXO consolidation balance inflation** — Consolidation send records are now marked `is_consolidation: true` so they are excluded from `computed_balance()`. Consolidation output receive entries are now treated as change (not income) during transaction list reconstruction, preventing the consolidated amount from being double-counted alongside the original input receive entries
- **Transactions not appearing on receiving wallet** — The transaction hash (`txid()`) now excludes `encrypted_memo` before hashing. Previously, the memo was attached to the transaction *after* signing, causing the masternode to fail signature verification (hash mismatch) and reject the transaction

## [0.2.0] - 2026-03-11

### Added
- **Consensus column on Connections page** — each peer shows ✔ (green) or ✗ (red) indicating whether it is within 3 blocks of the best known height; hover for exact lag
- **Transaction detail enrichment** — detail view now shows Block Height, Confirmations, and Block Hash (copyable) in addition to existing fields
- **Consensus-based peer filtering** — masternodes more than 3 blocks behind the best peer are automatically dropped from the pool and trigger failover to an in-consensus peer
- **Masternode tier display** — Bronze / Silver / Gold badges with colored text (no emoji) based on collateral amount
- **Locked balance display** — Overview shows Available (large, green), Locked (orange), and Total on a secondary row; locked row only shown when collateral is present
- **"Use as Masternode Collateral" button** — Click any confirmed received transaction to pre-fill the masternode add form and navigate to Masternodes tab
- **Auto-name suggestion** — Add form pre-fills name as `mn1`, `mn2`, etc. based on existing entries
- **Optimistic masternode updates** — Save / edit / delete apply immediately to UI state without waiting for async confirmation
- **Locked UTXO tracking** — `listunspentmulti` now returns locked collateral UTXOs alongside spendable ones; `spendable` field propagated to avoid including them in sends or consolidation
- **Collateral amount persistence** — On each UTXO sync, `collateral_amount` is backfilled on masternode entries and saved to the sled database; amount and tier are available immediately on next startup
- **Instant startup data** — Heavy data (balance, transactions, UTXOs) is fetched on the very first poll tick (5 s) instead of waiting for the 3rd tick (15 s)

### Changed
- **UTXO consolidation order** — Consolidation now processes smallest UTXOs first (dust first), leaving larger UTXOs intact if the run is interrupted
- **Consolidation dismiss** — Dismissing the consolidation banner suppresses it until the next consolidation completes (previously it reappeared within seconds)
- **Settings page** — "Version" label renamed to "Network"; now shows actual daemon version (e.g. `testnet (timed:0.1.0)`) and real peer count from `getnetworkinfo`
- **Masternode form simplified** — IP address, masternode key, and payout address fields removed; the wallet only stores alias, collateral TXID, and vout
- **masternode.conf removed from Tools** — The `masternode.conf` button and template have been removed; masternode configuration lives on the daemon
- **masternode.conf format** — Entries now use 3-field format: `alias txid vout` (old 4–6 field format still accepted for backward compatibility)
- **Masternode entry storage** — Switched from `bincode` to `serde_json`; old bincode entries are auto-migrated on first read
- **Overview balance layout** — Available is now the primary (large) number; Locked and Total appear on a smaller secondary row below
- **Tier requirements table** — Reward Weight column removed; only Tier, Collateral Required shown
- **Per-address balance in Receive tab** — Now shows only spendable balance (excludes locked collateral UTXOs)
- **Send form** — Recipient name field now clears after a successful send alongside address and amount

### Fixed
- **Zero-amount received transactions** — Scientific notation amounts (e.g. `1e-8`) now parse correctly; staking-input-only entries are filtered at the masternode and wallet layers
- **HTTP endpoint scheme** — Bare IP addresses and hostnames now use `http://` (masternodes do not use TLS on ports 24001/24101)
- **Peer discovery count** — Gossip-discovered peers are now added to the peer list instead of replacing existing ones; wallet correctly shows all reachable peers
- **Locked balance for all tiers** — Gold and Bronze entries now register correctly; previously only Silver was counted because locked UTXOs were filtered out before reaching state
- **Tier detection on startup** — `collateral_amount` is loaded from disk and tier badge resolves without waiting for a UTXO sync

## [0.1.0] - 2026-02-25

### Added
- Cross-platform GUI wallet built with egui/eframe
- HD wallet support with BIP39 mnemonic seed and BIP32 key derivation
- Send and receive TIME coins via UTXO-based transactions
- AES-256-GCM encrypted wallet storage with Argon2 key derivation
- QR code generation for receiving addresses
- Bitcoin-style wallet.dat backup and restore
- PDF export for mnemonic seed backup
- P2P network connectivity with peer discovery
- Address book with contact management
- Transaction history view
