//! Masternode JSON-RPC client
//!
//! Communicates with masternodes using JSON-RPC 2.0 over HTTP.
//! The masternode exposes an axum-based HTTP server on the RPC port
//! (24101 for testnet, 24001 for mainnet).

use futures_util::future::join_all;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Parse a JSON numeric value to satoshis (1 TIME = 100_000_000 satoshis).
/// Handles plain decimal strings ("12.34567890") and scientific notation
/// ("1e-8", "1.5e2") that serde_json may emit for very small/large floats.
pub fn json_to_satoshis(val: &serde_json::Value) -> u64 {
    let s = match val {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => return 0,
    };

    let s = s.trim();
    let negative = s.starts_with('-');
    let s = s.trim_start_matches('-');

    if negative {
        return 0;
    }

    parse_time_string_to_satoshis(s)
}

/// Like `json_to_satoshis` but returns the absolute value (for amounts/fees
/// that may be negative in the RPC response).
fn json_to_satoshis_abs(val: &serde_json::Value) -> u64 {
    let s = match val {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => return 0,
    };

    parse_time_string_to_satoshis(s.trim().trim_start_matches('-'))
}

/// Convert a non-negative decimal or scientific-notation string to satoshis.
/// Falls back to f64 parsing when the string contains 'e'/'E'.
fn parse_time_string_to_satoshis(s: &str) -> u64 {
    // Fast path: plain decimal (no scientific notation)
    if !s.contains('e') && !s.contains('E') {
        let (whole, frac) = if let Some(dot) = s.find('.') {
            (&s[..dot], &s[dot + 1..])
        } else {
            (s, "")
        };
        let whole_val: u64 = whole.parse().unwrap_or(0);
        let frac_padded = format!("{:0<8}", &frac[..frac.len().min(8)]);
        let frac_val: u64 = frac_padded[..8].parse().unwrap_or(0);
        return whole_val
            .saturating_mul(100_000_000)
            .saturating_add(frac_val);
    }

    // Fallback: scientific notation — use f64 arithmetic
    match s.parse::<f64>() {
        Ok(f) if f >= 0.0 => (f * 100_000_000.0).round() as u64,
        _ => 0,
    }
}

#[derive(Debug, Clone)]
pub struct MasternodeClient {
    rpc_endpoint: String,
    client: Client,
    /// Optional HTTP Basic Auth credentials (user, password)
    rpc_credentials: Option<(String, String)>,
}

/// JSON-RPC 2.0 request
#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: String,
    method: String,
    params: serde_json::Value,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl MasternodeClient {
    pub fn new(endpoint: String, credentials: Option<(String, String)>) -> Self {
        // Preserve http:// if explicitly provided (for nodes without TLS configured).
        // Add https:// prefix only for bare hostnames with no scheme.
        let rpc_endpoint = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint
        } else {
            format!("http://{}", endpoint)
        };

        // Accept self-signed certificates — masternodes use auto-generated certs (TOFU model).
        // Timeout is set to 5 minutes to accommodate slow chain-scan RPCs
        // (listtransactionsmulti on a large chain can take 60–90 s per chunk).
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .connect_timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to create HTTP client");

        if credentials.is_some() {
            log::info!(
                "📡 Masternode JSON-RPC client initialized: {} (with auth)",
                rpc_endpoint
            );
        } else {
            log::info!(
                "📡 Masternode JSON-RPC client initialized: {} (no auth)",
                rpc_endpoint
            );
        }

        Self {
            rpc_endpoint,
            client,
            rpc_credentials: credentials,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.rpc_endpoint
    }

    /// Send a JSON-RPC 2.0 request and return the result
    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: id.to_string(),
            method: method.to_string(),
            params,
        };

        log::debug!("→ RPC {}: {:?}", method, request.params);

        let mut req = self.client.post(&self.rpc_endpoint).json(&request);

        if let Some((ref user, ref pass)) = self.rpc_credentials {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            return Err(ClientError::http(response.status().as_u16()));
        }

        let bytes = response.bytes().await.map_err(|e| {
            log::error!("Failed to read response body for '{}': {:#?}", method, e);
            ClientError::InvalidResponse(format!("Failed to read response body: {}", e))
        })?;

        let rpc_response: JsonRpcResponse = serde_json::from_slice(&bytes).map_err(|e| {
            let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
            log::error!(
                "Failed to parse JSON-RPC response for '{}': {}\nRaw body ({} bytes): {}",
                method,
                e,
                bytes.len(),
                preview,
            );
            ClientError::InvalidResponse(format!("Failed to parse JSON-RPC response: {}", e))
        })?;

        if let Some(error) = rpc_response.error {
            return Err(ClientError::RpcError(error.code, error.message));
        }

        rpc_response
            .result
            .ok_or_else(|| ClientError::InvalidResponse("No result in JSON-RPC response".into()))
    }

    /// Get balance for an address
    pub async fn get_balance(&self, address: &str) -> Result<Balance, ClientError> {
        let result = self
            .rpc_call("getbalance", serde_json::json!([address]))
            .await?;

        // Masternode returns {balance, locked, available} in TIME
        let confirmed = result.get("available").map(json_to_satoshis).unwrap_or(0);
        let total = result.get("balance").map(json_to_satoshis).unwrap_or(0);
        let locked = result.get("locked").map(json_to_satoshis).unwrap_or(0);

        let balance = Balance {
            confirmed,
            pending: 0,
            total,
            locked,
        };
        log::info!(
            "✅ Balance: {} sats (available: {} sats, locked: {} sats)",
            total,
            confirmed,
            locked
        );
        Ok(balance)
    }

    /// Get combined balance across multiple addresses (batch query for HD wallets)
    pub async fn get_balances(&self, addresses: &[String]) -> Result<Balance, ClientError> {
        let result = self
            .rpc_call("getbalances", serde_json::json!([addresses]))
            .await?;

        let confirmed = result.get("available").map(json_to_satoshis).unwrap_or(0);
        let total = result.get("balance").map(json_to_satoshis).unwrap_or(0);
        let locked = result.get("locked").map(json_to_satoshis).unwrap_or(0);

        let balance = Balance {
            confirmed,
            pending: 0,
            total,
            locked,
        };

        let addr_count = result
            .get("address_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        log::info!(
            "✅ Batch balance ({} addresses): {} sats (available: {} sats)",
            addr_count,
            total,
            confirmed
        );
        Ok(balance)
    }

    /// Get transaction history for a single address
    pub async fn get_transactions(
        &self,
        address: &str,
        limit: u32,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        let result = self
            .rpc_call("listtransactions", serde_json::json!([address, limit]))
            .await?;

        Self::parse_transaction_list(result)
    }

    /// Get transaction history across multiple addresses.
    ///
    /// `from_height` enables incremental polling: pass the last-known block
    /// height so the masternode only scans newer blocks.  Use 0 for a full
    /// historical scan (first load or explicit refresh).
    ///
    /// Returns a [`TransactionBatch`] containing the records and the current
    /// chain height reported by the masternode, which the caller should store
    /// and pass back as `from_height` on the next poll.
    pub async fn get_transactions_multi(
        &self,
        addresses: &[String],
        limit: u32,
        from_height: u64,
    ) -> Result<TransactionBatch, ClientError> {
        const CHUNK_SIZE: usize = 25;

        if addresses.len() <= CHUNK_SIZE {
            // Fast path — single call for small wallets.
            let result = self
                .rpc_call(
                    "listtransactionsmulti",
                    serde_json::json!([addresses, limit, from_height]),
                )
                .await?;
            return Self::parse_transaction_batch(result);
        }

        // Slow path — send all chunks in parallel and merge.
        let chunk_futs: Vec<_> = addresses
            .chunks(CHUNK_SIZE)
            .map(|chunk| {
                let c = self.clone();
                let chunk = chunk.to_vec();
                async move {
                    c.rpc_call(
                        "listtransactionsmulti",
                        serde_json::json!([chunk, limit, from_height]),
                    )
                    .await
                    .and_then(Self::parse_transaction_batch)
                }
            })
            .collect();

        let chunk_results = join_all(chunk_futs).await;

        let mut all: Vec<TransactionRecord> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut max_chain_height: u64 = 0;

        for result in chunk_results {
            match result {
                Ok(batch) => {
                    if batch.chain_height > max_chain_height {
                        max_chain_height = batch.chain_height;
                    }
                    for r in batch.transactions {
                        let key = (r.txid.clone(), r.is_send, r.vout);
                        if seen.insert(key) {
                            all.push(r);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("listtransactionsmulti chunk failed: {}", e);
                }
            }
        }

        // Sort newest-first (mirrors single-call ordering).
        all.sort_by_key(|t| std::cmp::Reverse(t.timestamp));
        Ok(TransactionBatch {
            transactions: all,
            chain_height: max_chain_height,
        })
    }

    /// Parse a wrapped `{"transactions":[...], "chain_height":N}` response from
    /// the masternode, returning a [`TransactionBatch`].
    fn parse_transaction_batch(result: serde_json::Value) -> Result<TransactionBatch, ClientError> {
        // Support both the new wrapped format and the legacy plain-array format
        // (older masternodes that have not yet been updated).
        let (txs_value, chain_height) = if result.is_array() {
            (result, 0u64)
        } else {
            let ch = result
                .get("chain_height")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let txs = result
                .get("transactions")
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![]));
            (txs, ch)
        };

        let records = Self::parse_transaction_list(txs_value)?;
        Ok(TransactionBatch {
            transactions: records,
            chain_height,
        })
    }

    /// Parse a JSON array of transaction objects into TransactionRecords
    fn parse_transaction_list(
        result: serde_json::Value,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        let txs: Vec<serde_json::Value> = serde_json::from_value(result).unwrap_or_default();

        let records: Vec<TransactionRecord> = txs
            .into_iter()
            .filter_map(|tx| {
                let txid = tx.get("txid")?.as_str()?.to_string();
                let category = tx.get("category")?.as_str().unwrap_or("unknown");
                let amount = tx.get("amount").map(json_to_satoshis_abs).unwrap_or(0);
                let fee = tx.get("fee").map(json_to_satoshis_abs).unwrap_or(0);
                let block_hash = tx
                    .get("blockhash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let block_height = tx.get("blockheight").and_then(|v| v.as_u64()).unwrap_or(0);
                let confirmations = tx
                    .get("confirmations")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let timestamp = tx.get("time").and_then(|v| v.as_i64()).unwrap_or(0);

                // Approved once the transaction is included in a block (synchronized),
                // or earlier if the masternode consensus has already finalized it.
                // Block rewards (generate) are always in a block even if blockhash is absent.
                let in_block = !block_hash.is_empty() || category == "generate";
                let finalized = tx
                    .get("finalized")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let status = if in_block || finalized {
                    TransactionStatus::Approved
                } else {
                    TransactionStatus::Pending
                };

                let vout = tx.get("vout").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let is_send = category == "send";
                let address = tx
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // RPC includes fee in the send amount — subtract it so we
                // display only the actual transferred value.
                let display_amount = if is_send && fee > 0 {
                    amount.saturating_sub(fee)
                } else {
                    amount
                };

                // Skip zero-amount received/generate entries — these are staking
                // inputs with no corresponding payout in that transaction.
                // (Sent transactions with fee but 0 net are valid and kept.)
                if display_amount == 0 && !is_send {
                    return None;
                }

                // The masternode stores the memo as `encrypted_memo: Option<Vec<u8>>`
                // and returns it in the RPC response under "encrypted_memo". It may
                // be serialized as a hex string or a JSON array of integers. We
                // normalise to a hex string here so decrypt_memos can handle it
                // uniformly. Fall back to a plain-text "memo" field if present.
                let memo = if let Some(enc) = tx.get("encrypted_memo") {
                    if let Some(s) = enc.as_str() {
                        // Hex (or other) string — keep as-is for decryption.
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else if let Some(arr) = enc.as_array() {
                        // JSON integer array → hex string.
                        let bytes: Vec<u8> = arr
                            .iter()
                            .filter_map(|b| b.as_u64().map(|n| n as u8))
                            .collect();
                        if bytes.is_empty() {
                            None
                        } else {
                            Some(hex::encode(bytes))
                        }
                    } else {
                        None
                    }
                } else {
                    // Plain-text fallback (locally-inserted send records, payment
                    // request memos, etc.).
                    tx.get("memo")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                };

                // Block rewards (coinbase / reward-distribution) always show
                // "Block Reward". The masternode now emits this as a plain-text
                // "memo" field directly, so memo will already be Some("Block Reward")
                // here. This override covers any edge case where it isn't.
                let memo = if category == "generate" {
                    Some("Block Reward".to_string())
                } else {
                    memo
                };

                Some(TransactionRecord {
                    txid,
                    vout,
                    is_send,
                    address,
                    amount: display_amount,
                    fee,
                    timestamp,
                    status,
                    is_fee: false,
                    is_change: false,
                    block_hash,
                    block_height,
                    confirmations,
                    memo,
                    is_consolidation: category == "consolidate",
                })
            })
            .collect();

        log::info!("✅ Retrieved {} transactions", records.len());
        Ok(records)
    }

    /// Get UTXOs for an address
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, ClientError> {
        // listunspentmulti returns all UTXOs by default (no limit)
        let result = self
            .rpc_call("listunspentmulti", serde_json::json!([[address]]))
            .await?;

        let utxo_values: Vec<serde_json::Value> =
            serde_json::from_value(result).unwrap_or_default();

        let utxos: Vec<Utxo> = utxo_values
            .into_iter()
            .filter_map(|u| {
                let txid = u.get("txid")?.as_str()?.to_string();
                let vout = u.get("vout")?.as_u64()? as u32;
                let amount = u.get("amount").map(json_to_satoshis).unwrap_or(0);
                let addr = u
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let confirmations =
                    u.get("confirmations").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let spendable = u.get("spendable").and_then(|v| v.as_bool()).unwrap_or(true);

                Some(Utxo {
                    txid,
                    vout,
                    amount,
                    address: addr,
                    confirmations,
                    spendable,
                })
            })
            .collect();

        let spendable_count = utxos.iter().filter(|u| u.spendable).count();
        log::info!(
            "✅ Retrieved {} UTXOs ({} spendable, {} locked)",
            utxos.len(),
            spendable_count,
            utxos.len() - spendable_count
        );
        Ok(utxos)
    }

    /// Fetch UTXOs for a batch of addresses in a single `listunspentmulti` call.
    ///
    /// Returns a set of addresses that have at least one unspent output, keyed
    /// by address string.  This is used by the address-recovery scanner to
    /// identify which derived addresses have on-chain activity.
    pub async fn get_active_addresses_by_utxo(
        &self,
        addresses: &[String],
    ) -> Result<std::collections::HashSet<String>, ClientError> {
        if addresses.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let result = self
            .rpc_call("listunspentmulti", serde_json::json!([addresses]))
            .await?;
        let utxo_values: Vec<serde_json::Value> =
            serde_json::from_value(result).unwrap_or_default();
        let active = utxo_values
            .iter()
            .filter_map(|u| u.get("address")?.as_str().map(String::from))
            .collect();
        Ok(active)
    }

    /// Look up an unspent transaction output by txid and vout index.
    ///
    /// Returns `(amount_sats, address)` if the output is unspent, or `None` if
    /// it is spent, unknown, or the node returned null.
    pub async fn get_tx_out(
        &self,
        txid: &str,
        vout: u32,
    ) -> Result<Option<(u64, String)>, ClientError> {
        let result = self
            .rpc_call("gettxout", serde_json::json!([txid, vout, true]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let amount_time = result.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let amount_sats = (amount_time * 100_000_000.0).round() as u64;
        let address = result
            .get("scriptPubKey")
            .and_then(|sp| sp.get("address"))
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string();
        Ok(Some((amount_sats, address)))
    }

    /// Fetch the current governance-voted fee schedule from the masternode.
    ///
    /// Falls back to `FeeSchedule::default()` on any error so callers can
    /// always proceed with a sensible schedule.
    pub async fn get_fee_schedule(&self) -> wallet::FeeSchedule {
        match self.rpc_call("getfeeschedule", serde_json::json!([])).await {
            Ok(val) => serde_json::from_value(val).unwrap_or_default(),
            Err(e) => {
                log::warn!("get_fee_schedule RPC failed (using default): {}", e);
                wallet::FeeSchedule::default()
            }
        }
    }

    /// Broadcast a signed transaction (hex-encoded bincode)
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, ClientError> {
        let result = self
            .rpc_call("sendrawtransaction", serde_json::json!([tx_hex]))
            .await?;

        let txid = result
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| result.to_string().trim_matches('"').to_string());

        log::info!("✅ Transaction broadcast: {}", txid);
        Ok(txid)
    }

    /// Validate an address
    pub async fn validate_address(&self, address: &str) -> Result<bool, ClientError> {
        let result = self
            .rpc_call("validateaddress", serde_json::json!([address]))
            .await?;

        let valid = result
            .get("isvalid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(valid)
    }

    /// Look up the Ed25519 public key for an address from the masternode's
    /// pubkey cache. Returns `None` if the address has never signed a
    /// transaction on-chain (pubkey unknown).
    pub async fn get_address_pubkey(&self, address: &str) -> Result<Option<[u8; 32]>, ClientError> {
        let result = self
            .rpc_call("getaddresspubkey", serde_json::json!([address]))
            .await?;

        let hex_str = match result.get("pubkey").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };

        let bytes = hex::decode(hex_str)
            .map_err(|_| ClientError::InvalidResponse("invalid pubkey hex".into()))?;
        if bytes.len() != 32 {
            return Ok(None);
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes);
        Ok(Some(pubkey))
    }

    /// Pre-register an Ed25519 public key for a TIME address on the node.
    ///
    /// This allows the node to encrypt memos to this address before any
    /// on-chain transaction reveals the pubkey via script_sig.
    pub async fn register_address_pubkey(
        &self,
        address: &str,
        pubkey: &[u8; 32],
    ) -> Result<(), ClientError> {
        let pubkey_hex = hex::encode(pubkey);
        self.rpc_call(
            "registeraddresspubkey",
            serde_json::json!([address, pubkey_hex]),
        )
        .await?;
        Ok(())
    }

    /// Send a signed payment request to the masternode for P2P relay.
    ///
    /// The masternode expects params[0] to be a JSON object with named fields.
    /// Amount is in satoshis (u64). The client-computed `id` is passed so the
    /// masternode stores the request under the same ID the wallet already saved locally.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_payment_request(
        &self,
        id: &str,
        from_address: &str,
        to_address: &str,
        amount: u64,
        label: &str,
        memo: &str,
        pubkey_hex: &str,
        signature_hex: &str,
        timestamp: i64,
    ) -> Result<serde_json::Value, ClientError> {
        self.rpc_call(
            "sendpaymentrequest",
            serde_json::json!([{
                "id": id,
                "requester_address": from_address,
                "payer_address": to_address,
                "amount": amount,
                "memo": memo,
                "requester_name": label,
                "pubkey_hex": pubkey_hex,
                "signature_hex": signature_hex,
                "timestamp": timestamp,
            }]),
        )
        .await
    }

    /// Get pending payment requests for the given addresses.
    pub async fn get_payment_requests(
        &self,
        addresses: &[String],
    ) -> Result<Vec<serde_json::Value>, ClientError> {
        let result = self
            .rpc_call("getpaymentrequests", serde_json::json!([addresses]))
            .await?;
        match result.as_array() {
            Some(arr) => Ok(arr.clone()),
            None => Ok(Vec::new()),
        }
    }

    /// Notify the masternode that the payer has accepted or declined a payment request.
    pub async fn respond_payment_request(
        &self,
        request_id: &str,
        payer_address: &str,
        accepted: bool,
        txid: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut obj = serde_json::json!({
            "id": request_id,
            "payer_address": payer_address,
            "accepted": accepted,
        });
        if let Some(t) = txid {
            obj["txid"] = serde_json::json!(t);
        }
        self.rpc_call("respondpaymentrequest", serde_json::json!([obj]))
            .await
    }

    /// Cancel a sent payment request (requester withdraws it before the payer responds).
    pub async fn cancel_payment_request(
        &self,
        request_id: &str,
        requester_address: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.rpc_call(
            "cancelpaymentrequest",
            serde_json::json!([{
                "id": request_id,
                "requester_address": requester_address,
            }]),
        )
        .await
    }

    /// Mark a received payment request as viewed by the payer.
    pub async fn mark_payment_request_viewed(
        &self,
        request_id: &str,
        payer_address: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.rpc_call(
            "markpaymentrequestviewed",
            serde_json::json!([{
                "id": request_id,
                "payer_address": payer_address,
            }]),
        )
        .await
    }

    /// Check if masternode is reachable via getblockchaininfo
    pub async fn health_check(&self) -> Result<HealthStatus, ClientError> {
        let result = self
            .rpc_call("getblockchaininfo", serde_json::json!([]))
            .await?;

        // Masternode returns "blocks", fall back to "height" for compat
        let height = result
            .get("blocks")
            .or_else(|| result.get("height"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // "chain" is network type (mainnet/testnet)
        let network = result
            .get("chain")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Fetch connection count and daemon version from getnetworkinfo
        let (peer_count, version) =
            if let Ok(ni) = self.rpc_call("getnetworkinfo", serde_json::json!([])).await {
                let peers = ni.get("connections").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                // subversion is "/timed:0.1.0/" — strip the slashes
                let ver = ni
                    .get("subversion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim_matches('/')
                    .to_string();
                (peers, ver)
            } else {
                (0, String::new())
            };

        let is_syncing = result
            .get("initialblockdownload")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let sync_progress = result
            .get("verificationprogress")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);

        let status = HealthStatus {
            status: if is_syncing {
                "syncing".to_string()
            } else {
                "healthy".to_string()
            },
            version: format!("{} ({})", network, version),
            block_height: height,
            peer_count,
            is_syncing,
            sync_progress,
        };

        log::info!(
            "✅ Masternode healthy: height={}, peers={}",
            height,
            peer_count
        );
        Ok(status)
    }

    /// Fetch the hex-encoded hash of block 0 (the genesis block).
    pub async fn get_genesis_hash(&self) -> Result<String, ClientError> {
        let result = self
            .rpc_call("getblockhash", serde_json::json!([0u64]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ClientError::InvalidResponse("getblockhash returned non-string".to_string()))
    }

    /// Attempt to determine this masternode's tier.
    ///
    /// Uses `masternodestatus` (the canonical RPC used by the masternode
    /// dashboard) which returns `{ "tier": "Bronze"|"Silver"|"Gold"|"Free", … }`.
    /// Falls back to `getpeerinfo` scanning if the first call fails.
    /// Returns `None` if the node doesn't support either call.
    pub async fn get_tier(&self) -> Option<String> {
        // Primary: masternodestatus
        if let Ok(resp) = self
            .rpc_call("masternodestatus", serde_json::json!([]))
            .await
        {
            if let Some(t) = resp.get("tier").and_then(|v| v.as_str()) {
                return Some(capitalise(t));
            }
        }

        // Fallback: getpeerinfo — each entry has an "addr" and "tier" field
        if let Ok(resp) = self.rpc_call("getpeerinfo", serde_json::json!([])).await {
            if let Some(peers) = resp.as_array() {
                // We want the tier of the node itself; it self-reports its own
                // tier on all peer entries — take the first non-empty one.
                for peer in peers {
                    if let Some(t) = peer.get("tier").and_then(|v| v.as_str()) {
                        if !t.is_empty() {
                            return Some(capitalise(t));
                        }
                    }
                }
            }
        }

        None
    }

    /// Get current blockchain height
    pub async fn get_block_height(&self) -> Result<u64, ClientError> {
        let result = self
            .rpc_call("getblockcount", serde_json::json!([]))
            .await?;

        let height = result.as_u64().unwrap_or(0);
        Ok(height)
    }

    /// Query instant finality status for a transaction
    pub async fn get_transaction_finality(
        &self,
        txid: &str,
    ) -> Result<FinalityStatus, ClientError> {
        let result = self
            .rpc_call("gettransactionfinality", serde_json::json!([txid]))
            .await?;

        let finalized = result
            .get("finalized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let confirmations = result
            .get("confirmations")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        Ok(FinalityStatus {
            txid: txid.to_string(),
            finalized,
            confirmations,
        })
    }

    /// Fetch the raw per-address masternode rewards for a block by height.
    ///
    /// Returns the address→amount pairs from `getblock`. Filtering to the
    /// user's own masternodes is done in the UI using wallet state.
    pub async fn get_block_reward_breakdown(
        &self,
        height: u64,
    ) -> Result<BlockRewardBreakdown, ClientError> {
        let block_val = self
            .rpc_call("getblock", serde_json::json!([height]))
            .await?;

        let rewards: Vec<(String, u64)> = block_val["masternode_rewards"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|r| {
                let addr = r["address"].as_str()?.to_string();
                let amount = r["amount"].as_u64()?;
                Some((addr, amount))
            })
            .collect();

        Ok(BlockRewardBreakdown {
            block_height: height,
            rewards,
        })
    }

    /// Get peer info from masternode
    pub async fn get_peer_info(&self) -> Result<Vec<PeerInfoResult>, ClientError> {
        let result = self.rpc_call("getpeerinfo", serde_json::json!([])).await?;

        let peers: Vec<serde_json::Value> = serde_json::from_value(result).unwrap_or_default();

        let peer_info: Vec<PeerInfoResult> = peers
            .into_iter()
            .filter_map(|p| {
                let addr = p.get("addr")?.as_str()?.to_string();
                let active = p.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                Some(PeerInfoResult { addr, active })
            })
            .collect();

        Ok(peer_info)
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// Raw per-address masternode rewards for a single block.
///
/// Cross-referencing with the user's own masternodes is done in the UI.
#[derive(Debug, Clone)]
pub struct BlockRewardBreakdown {
    pub block_height: u64,
    /// All `(wallet_address, amount_satoshis)` pairs from `masternode_rewards`.
    pub rewards: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: u64,
    pub pending: u64,
    pub total: u64,
    /// Locked collateral amount as reported by the masternode.
    #[serde(default)]
    pub locked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub txid: String,
    pub vout: u32,
    pub is_send: bool,
    pub address: String,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: i64,
    pub status: TransactionStatus,
    /// True if this entry represents a network fee (ledger line item).
    #[serde(default)]
    pub is_fee: bool,
    /// True if this is a change output returning to the sender's own wallet.
    #[serde(default)]
    pub is_change: bool,
    /// Hash of the block containing this transaction (empty if unconfirmed).
    #[serde(default)]
    pub block_hash: String,
    /// Height of the block containing this transaction (0 if unconfirmed).
    #[serde(default)]
    pub block_height: u64,
    /// Number of confirmations (0 if unconfirmed).
    #[serde(default)]
    pub confirmations: u64,
    /// Decrypted memo text (populated from masternode response).
    #[serde(default)]
    pub memo: Option<String>,
    /// True when this transaction is a UTXO consolidation (coins sent to
    /// self).  Consolidations should not be counted as income in charts
    /// or balance calculations — the underlying UTXOs are already accounted
    /// for by the individual receive entries that created them.
    #[serde(default)]
    pub is_consolidation: bool,
}

impl Default for TransactionRecord {
    fn default() -> Self {
        Self {
            txid: String::new(),
            vout: 0,
            is_send: false,
            address: String::new(),
            amount: 0,
            fee: 0,
            timestamp: 0,
            status: TransactionStatus::Pending,
            is_fee: false,
            is_change: false,
            block_hash: String::new(),
            block_height: 0,
            confirmations: 0,
            memo: None,
            is_consolidation: false,
        }
    }
}

/// Result of a [`MasternodeClient::get_transactions_multi`] call.
///
/// `chain_height` is the masternode's current tip height at the time of the
/// query.  The caller should store it and pass it back as `from_height` on the
/// next poll to enable incremental scanning (only new blocks).
#[derive(Debug, Clone)]
pub struct TransactionBatch {
    pub transactions: Vec<TransactionRecord>,
    /// Current chain tip height as reported by the masternode.
    pub chain_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    /// In the mempool but not yet in a block.
    Pending,
    /// Included in a block — instant finality means this is final.
    Approved,
    /// Transaction was rejected or conflicted.
    Declined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub confirmations: u32,
    /// False for UTXOs locked as masternode collateral or pending finality.
    #[serde(default = "default_true")]
    pub spendable: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub block_height: u64,
    pub peer_count: u32,
    /// True when the masternode is still performing initial block download.
    pub is_syncing: bool,
    /// Sync progress 0.0–1.0 (1.0 when fully synced).
    pub sync_progress: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityStatus {
    pub txid: String,
    pub finalized: bool,
    pub confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfoResult {
    pub addr: String,
    pub active: bool,
}

// ============================================================================
// Tier helpers
// ============================================================================

/// Capitalise the first letter of a tier string.
fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error {0}: {1}")]
    Http(u16, String),

    #[error("RPC error {0}: {1}")]
    RpcError(i64, String),

    #[error("Request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Network timeout")]
    Timeout,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Transaction broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Masternode unavailable")]
    Unavailable,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ClientError {
    pub fn http(status: u16) -> Self {
        let message = match status {
            401 => "Unauthorized — check rpc_user/rpc_password in config.toml or masternode .cookie file",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Unknown Error",
        };
        Self::Http(status, message.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = MasternodeClient::new("http://127.0.0.1:24101".to_string(), None);
        assert_eq!(client.endpoint(), "http://127.0.0.1:24101");
    }

    #[tokio::test]
    async fn test_client_creation_bare_endpoint() {
        let client = MasternodeClient::new("127.0.0.1:24101".to_string(), None);
        assert_eq!(client.endpoint(), "http://127.0.0.1:24101");
    }

    #[test]
    fn test_balance_serialization() {
        let balance = Balance {
            confirmed: 1000,
            pending: 500,
            total: 1500,
            locked: 500,
        };

        let json = serde_json::to_string(&balance).unwrap();
        let deserialized: Balance = serde_json::from_str(&json).unwrap();

        assert_eq!(balance.total, deserialized.total);
    }

    #[test]
    fn test_transaction_status() {
        let status = TransactionStatus::Approved;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""approved""#);
    }
}
