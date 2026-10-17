# Solana Token Risk, Bundler Detection & MEV Intelligence API (Gated by x402)

High-speed, sub-cent Solana token risk, honeypot & bundler detection, and MEV intelligence API built specifically for autonomous AI agents. Gated natively by the **x402 (HTTP 402 Payment Required)** protocol with USDC micropayment settlement on Solana.

Includes:
1. **x402 Resource Server (`src/server`)**: Express server with x402 middleware returning HTTP 402 challenges and cryptographically verifying Solana payment signatures.
2. **Intelligence Services (`src/services`)**:
   - `TokenRiskService`: Honeypot detection, mint/freeze authority checks, LP lock verification, top-holder concentration, and composite risk scoring (0-100).
   - `BundlerDetectorService`: Jito bundle sniper detection, genesis block analysis, and multi-wallet stealth cabal identification.
   - `MevIntelService`: Sandwich vulnerability scoring, recent searcher detection, dynamic priority fees (microLamports/CU), and slippage safety guardrails.
3. **Autonomous Agent Client (`src/client`)**: End-to-end client that intercepts `402 Payment Required`, signs Ed25519 payment payloads with the agent's Solana wallet, and unlocks data automatically.
4. **Model Context Protocol (MCP) Server (`src/mcp`)**: Native MCP server wrapper allowing Claude, Cursor, and any LLM to execute security audits with autonomous payment abstraction.

---

## ⚡ Architecture & x402 Payment Flow

```text
  AI Agent / MCP Client                          x402 Gateway Server
        |                                                 |
        |--- 1. GET /api/token/risk/:address ------------>|
        |                                                 | (Checks for payment)
        |<-- 2. HTTP 402 Payment Required ----------------| (Contains PAYMENT-REQUIRED header,
        |       [Nonce, Network, PayTo, Amount]           |  nonce, price: $0.002 USDC)
        |                                                 |
  (Agent signs challenge with                             |
   Solana Ed25519 private key)                            |
        |                                                 |
        |--- 3. Retry GET with PAYMENT-SIGNATURE -------->|
        |       [Payer, Sig, Nonce, Timestamp]            | (Verifies Ed25519 signature,
        |                                                 |  checks replay protection)
        |<-- 4. HTTP 200 OK + Data -----------------------| (Delivers Token Risk Data +
        |       [PAYMENT-RESPONSE receipt]                |  settlement receipt)
```

---

## 🛠️ API Endpoints & Pricing (Sub-Cent Micropayments)

| Endpoint | Method | Price (USDC) | Description |
| :--- | :---: | :---: | :--- |
| `/api/health` | `GET` | **Free** | Public service metadata, health, and pricing table |
| `/api/token/risk/:address` | `GET` | **$0.002** | Honeypot analysis, mint/freeze authorities, LP burned %, risk score |
| `/api/token/bundler/:address` | `GET` | **$0.003** | Jito bundler snipers, cluster identification, developer dump threat |
| `/api/token/mev/:address` | `GET` | **$0.002** | Sandwich attack vulnerability, priority fee recommendations, slippage caps |
| `/api/token/full-audit` | `POST` | **$0.005** | Combined comprehensive scan with an executive `canAgentSafelyTrade` verdict |

---

## 🚀 Quick Start

### 1. Installation
```bash
npm install
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 3. Run Automated Tests
Execute the Vitest test suite covering risk logic, bundler heuristics, MEV telemetry, and x402 402-challenge negotiation:
```bash
npm test
```

### 4. Start the x402 Gateway Server
```bash
npm run start
# Server listens on http://localhost:4020
```

### 5. Run Autonomous Agent Demo
In another terminal, run the autonomous payment client:
```bash
npm run client
```

---

## 🧠 Model Context Protocol (MCP) Integration

To use this with Claude Desktop, Cursor, or any MCP-compatible agent host, add the server to your configuration:

```json
{
  "mcpServers": {
    "solana-x402-intelligence": {
      "command": "npx",
      "args": ["tsx", "src/mcp/index.ts", "--run-mcp"],
      "cwd": "c:/Users/AK/Downloads/Crypto"
    }
  }
}
```

### Exposed MCP Tools:
- `solana_token_risk_audit`: Audit token mint address for honeypots, authorities, and risk score.
- `solana_detect_bundlers`: Scan token launch for coordinated bundle snipers and insider supply hold.
- `solana_mev_intel`: Retrieve real-time MEV sandwich threat, optimal priority fee, and safe slippage.
- `solana_full_security_scan`: Full executive security scan with trading viability verdict.

---

## 🔒 Security & Replay Attack Defense
- **Cryptographic Signatures**: Challenges require an Ed25519 signature over `${nonce}:${payer}:${payTo}:${amount}:${timestamp}`.
- **Single-Use Nonces**: Each challenge nonce is strictly single-use and invalidated immediately upon successful settlement.
- **TTL Expiration**: Challenges expire automatically after 5 minutes if unconsumed.

---

## 🤖 Machine-Readable Agent Discovery & Registries

Autonomous crawlers, x402scan, and the Coinbase x402 Bazaar can automatically discover endpoints, schemas, and USDC pricing:

- **x402 Discovery Manifest**: `GET /.well-known/x402.json` (Machine-readable discovery schema according to x402 v2 and Coinbase Bazaar standards)
- **LLM Context & System Prompt Spec**: `GET /llms.txt` (Structured plain text context adhering to the [llms.txt](https://llmstxt.org) standard)
- **Service Health & Metadata**: `GET /api/health`

---

## 🔌 ElizaOS & Solana Agent Kit Plugin

A ready-to-publish NPM plugin package is available in [`packages/plugin-rugcheck-x402`](./packages/plugin-rugcheck-x402):

```bash
# In your ElizaOS character config:
import { rugcheckX402Plugin } from "@elizaos/plugin-rugcheck-x402";

export const agent = {
  name: "SolanaTrader",
  plugins: [rugcheckX402Plugin],
  // ...
};
```

Supports:
- ElizaOS Action `SOLANA_RUGCHECK_X402`
- Solana Agent Kit tool helper `createRugcheckTool()`
- Standalone programmatic client `RugcheckX402Client`

---

## ☁️ Cloud & Production Deployment

Production-ready deployment manifests are included:

- **Docker**: Multi-stage `Dockerfile` (Node 20 Alpine)
- **Docker Compose**: `docker-compose.yml` with health checks
- **Fly.io**: `fly.toml`
- **Railway**: `railway.json`
- **CI/CD**: GitHub Actions workflow at `.github/workflows/ci.yml` (matrices across Node 20.x & 22.x)

```bash
# Build and run with Docker Compose
docker compose up -d --build
```

