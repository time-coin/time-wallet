# RPC Protocol

## Overview

The wallet communicates with masternodes via **JSON-RPC 2.0** over TCP. The masternode listens on port **24101** (testnet) or **24001** (mainnet).

## Connection

```
TCP connect → masternode_host:24101 (testnet)
TCP connect → masternode_host:24001 (mainnet)
```

Messages are newline-delimited JSON.

## Request Format

```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "method": "method_name",
  "params": [...]
}
```

## Response Format

```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "result": { ... }
}
```

Error response:

```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "error": {
    "code": -32601,
    "message": "Method not found"
  }
}
```

## Wallet-Relevant RPC Methods

### Balance & UTXOs

| Method | Params | Description |
|--------|--------|-------------|
| `getbalance` | `[address]` | Returns balance, locked, and available amounts |
| `listunspent` | `[address]` | Returns list of spendable UTXOs |
| `mergeutxos` | `[address, max_inputs]` | Consolidate small UTXOs |

### Transactions

| Method | Params | Description |
|--------|--------|-------------|
| `sendrawtransaction` | `[hex_encoded_tx]` | Broadcast a signed transaction |
| `gettransaction` | `[txid]` | Get transaction details by ID |
| `getrawtransaction` | `[txid, verbose]` | Get raw transaction data |
| `listtransactions` | `[address, count]` | List transaction history |
| `gettransactionfinality` | `[txid]` | Check confirmation status |
| `sendtoaddress` | `[address, amount]` | Send coins (if masternode holds keys) |

### Address

| Method | Params | Description |
|--------|--------|-------------|
| `validateaddress` | `[address]` | Validate address format |
| `listreceivedbyaddress` | `[min_confirmations]` | List received amounts per address |

### Blockchain Info

| Method | Params | Description |
|--------|--------|-------------|
| `getblockchaininfo` | `[]` | Chain height, network, sync status |
| `getblockcount` | `[]` | Current block height |
| `getnetworkinfo` | `[]` | Network peers, version info |
| `getblock` | `[hash_or_height]` | Get block details |
| `getblockhash` | `[height]` | Get block hash at height |

### Masternode Info

| Method | Params | Description |
|--------|--------|-------------|
| `masternodelist` | `[]` | List all registered masternodes |
| `masternodestatus` | `[]` | Current masternode status |
| `getwalletinfo` | `[]` | Wallet metadata |

## Example: Check Balance

```json
→ {"jsonrpc":"2.0","id":"1","method":"getbalance","params":["TIME0abc..."]}
← {"jsonrpc":"2.0","id":"1","result":{"balance":100000000,"locked":0,"available":100000000}}
```

## Example: Broadcast Transaction

```json
→ {"jsonrpc":"2.0","id":"2","method":"sendrawtransaction","params":["0a1b2c3d..."]}
← {"jsonrpc":"2.0","id":"2","result":{"txid":"abc123..."}}
```

## Error Codes

| Code | Meaning |
|------|---------|
| `-32600` | Invalid request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |
