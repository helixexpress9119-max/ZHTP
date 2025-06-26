# ZHTP API Reference

Complete documentation for the ZHTP backend API endpoints.

## 🔌 Base URL

All API endpoints are relative to: `http://localhost:3000/api`

## 📊 Network Status

### GET `/status`
Get current network status and statistics.

**Response:**
```json
{
  "status": "operational",
  "connected_nodes": 12,
  "consensus_rounds": 1547,
  "zk_transactions": 2891,
  "dapp_count": 8,
  "network_health": "excellent",
  "timestamp": "2025-06-25T10:30:00Z"
}
```

### GET `/network/activity`
Get live network activity feed.

**Response:**
```json
{
  "success": true,
  "activities": [
    {
      "timestamp": "2025-06-25T10:29:45Z",
      "type": "info",
      "message": "New node connected from 192.168.1.100"
    },
    {
      "timestamp": "2025-06-25T10:29:30Z",
      "type": "success",
      "message": "ZK transaction verified: tx_hash_123"
    }
  ]
}
```

## 🚀 DApp Management

### GET `/dapps`
List all deployed DApps.

**Response:**
```json
{
  "success": true,
  "dapps": [
    {
      "id": "dapp_001",
      "name": "ZHTP News Hub",
      "domain": "news.zhtp",
      "description": "Decentralized news platform",
      "status": "active",
      "deployed_at": "2025-06-20T14:30:00Z",
      "owner": "0x742d35Cc..."
    }
  ]
}
```

### POST `/dapps/deploy`
Deploy a new DApp to the network.

**Request:**
```json
{
  "name": "My DApp",
  "description": "A revolutionary decentralized application",
  "code": "base64_encoded_code",
  "domain": "mydapp.zhtp"
}
```

**Response:**
```json
{
  "success": true,
  "dapp_id": "dapp_002",
  "domain": "mydapp.zhtp",
  "deployment_hash": "0x1234567...",
  "message": "DApp deployed successfully"
}
```

## 💳 Wallet Operations

### POST `/wallet/create`
Create a new quantum-resistant wallet.

**Request:**
```json
{
  "wallet_type": "quantum",
  "passphrase": "optional_passphrase"
}
```

**Response:**
```json
{
  "success": true,
  "wallet": {
    "address": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1",
    "public_key": "0x04a1b2c3...",
    "mnemonic": "abandon ability able about above absent absorb abstract absurd abuse access accident",
    "zk_identity": "zk_id_123"
  }
}
```

### POST `/wallet/faucet`
Request test tokens from the faucet.

**Request:**
```json
{
  "wallet_address": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1"
}
```

**Response:**
```json
{
  "success": true,
  "amount": 1000,
  "transaction_hash": "0xabcdef123...",
  "message": "Test tokens sent successfully"
}
```

### GET `/wallet/{address}/balance`
Get wallet balance and transaction history.

**Response:**
```json
{
  "success": true,
  "address": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1",
  "balance": 1500.0,
  "transactions": [
    {
      "hash": "0xabcdef123...",
      "type": "received",
      "amount": 1000.0,
      "from": "faucet",
      "timestamp": "2025-06-25T09:15:00Z"
    }
  ]
}
```

### POST `/wallet/send`
Send ZHTP tokens to another address.

**Request:**
```json
{
  "from": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1",
  "to": "0x123456789abcdef...",
  "amount": 100.0,
  "message": "Payment for services",
  "private_key": "0x1234567..."
}
```

**Response:**
```json
{
  "success": true,
  "transaction_hash": "0x987654321...",
  "gas_used": 21000,
  "confirmation_time": "~30 seconds"
}
```

## 🌍 DNS System

### GET `/dns/resolve`
Resolve a ZHTP domain to its addresses.

**Parameters:**
- `domain` (string) - The domain to resolve (e.g., "news.zhtp")

**Response:**
```json
{
  "success": true,
  "domain": "news.zhtp",
  "addresses": ["192.168.1.100", "10.0.0.50"],
  "ttl": 3600,
  "zk_verified": true,
  "owner": "0x742d35Cc...",
  "registered_at": "2025-06-20T14:30:00Z"
}
```

### POST `/dns/register`
Register a new ZHTP domain.

**Request:**
```json
{
  "domain": "mynewsite.zhtp",
  "addresses": ["192.168.1.200"],
  "owner": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1",
  "ttl": 3600
}
```

**Response:**
```json
{
  "success": true,
  "domain": "mynewsite.zhtp",
  "registration_hash": "0xfedcba987...",
  "expiry": "2026-06-25T10:30:00Z"
}
```

### GET `/dns/list`
List all registered domains.

**Response:**
```json
{
  "success": true,
  "domains": [
    {
      "domain": "news.zhtp",
      "owner": "0x742d35Cc...",
      "addresses": ["192.168.1.100"],
      "registered_at": "2025-06-20T14:30:00Z",
      "expires_at": "2026-06-20T14:30:00Z"
    }
  ]
}
```

## 🏛️ DAO Governance

### GET `/dao/proposals`
Get all governance proposals.

**Response:**
```json
{
  "success": true,
  "proposals": [
    {
      "id": "prop_001",
      "title": "Increase block size limit",
      "description": "Proposal to increase the maximum block size from 1MB to 2MB",
      "type": "upgrade",
      "status": "active",
      "votes_for": 150,
      "votes_against": 30,
      "voting_ends": "2025-07-01T00:00:00Z",
      "proposed_by": "0x742d35Cc..."
    }
  ]
}
```

### POST `/dao/propose`
Submit a new governance proposal.

**Request:**
```json
{
  "title": "Add new feature X",
  "description": "Detailed description of the proposed feature",
  "type": "feature",
  "proposer": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1"
}
```

**Response:**
```json
{
  "success": true,
  "proposal_id": "prop_002",
  "voting_period": "7 days",
  "minimum_votes": 100
}
```

### POST `/dao/vote`
Vote on a governance proposal.

**Request:**
```json
{
  "proposal_id": "prop_001",
  "vote": "for",
  "voter": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1",
  "voting_power": 50
}
```

**Response:**
```json
{
  "success": true,
  "vote_hash": "0x111222333...",
  "message": "Vote recorded successfully"
}
```

## 🔧 Developer Tools

### POST `/contracts/deploy`
Deploy a smart contract.

**Request:**
```json
{
  "name": "MyContract",
  "code": "base64_encoded_wasm_or_js",
  "constructor_args": ["arg1", "arg2"],
  "deployer": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1"
}
```

**Response:**
```json
{
  "success": true,
  "contract_address": "0xcontract123...",
  "deployment_hash": "0xdeploy456...",
  "gas_used": 500000
}
```

### GET `/test/network`
Run network connectivity tests.

**Response:**
```json
{
  "success": true,
  "tests": {
    "peer_connectivity": "passed",
    "consensus_participation": "passed",
    "zk_proof_verification": "passed",
    "latency_ms": 45
  }
}
```

## 🔐 Security & ZK Proofs

### POST `/zk/generate-proof`
Generate a zero-knowledge proof.

**Request:**
```json
{
  "circuit": "private_transfer",
  "inputs": {
    "amount": 100,
    "recipient": "0x123...",
    "sender_balance": 1000
  }
}
```

**Response:**
```json
{
  "success": true,
  "proof": "0xproof_data...",
  "public_signals": ["signal1", "signal2"],
  "verification_key": "0xvk_data..."
}
```

### POST `/zk/verify-proof`
Verify a zero-knowledge proof.

**Request:**
```json
{
  "proof": "0xproof_data...",
  "public_signals": ["signal1", "signal2"],
  "verification_key": "0xvk_data..."
}
```

**Response:**
```json
{
  "success": true,
  "valid": true,
  "verification_time_ms": 150
}
```

## 📡 WebSocket Events

### Connection
Connect to live updates: `ws://localhost:3000/ws`

### Event Types

**Network Status Updates:**
```json
{
  "type": "network_status",
  "data": {
    "connected_nodes": 13,
    "status": "operational"
  }
}
```

**New Transactions:**
```json
{
  "type": "new_transaction",
  "data": {
    "hash": "0x123...",
    "amount": 50.0,
    "from": "0xabc...",
    "to": "0xdef..."
  }
}
```

**DApp Events:**
```json
{
  "type": "dapp_deployed",
  "data": {
    "name": "New DApp",
    "domain": "newdapp.zhtp",
    "owner": "0x123..."
  }
}
```

## ❌ Error Handling

All API endpoints return consistent error formats:

```json
{
  "success": false,
  "error": {
    "code": "INSUFFICIENT_BALANCE",
    "message": "Insufficient balance for transaction",
    "details": {
      "required": 100.0,
      "available": 50.0
    }
  }
}
```

### Common Error Codes
- `INVALID_ADDRESS` - Malformed wallet address
- `INSUFFICIENT_BALANCE` - Not enough tokens for operation
- `DOMAIN_ALREADY_EXISTS` - Domain is already registered
- `INVALID_PROOF` - ZK proof verification failed
- `NETWORK_ERROR` - Network connectivity issues
- `RATE_LIMITED` - Too many requests

## 🔄 Rate Limiting

API endpoints are rate-limited to prevent abuse:

- **General endpoints:** 100 requests per minute
- **Wallet operations:** 10 requests per minute
- **Deployment operations:** 5 requests per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

---

Next: [Security Documentation](security.md)
