# @lordkade/plugin-rugcheck-x402

> Autonomous Solana token risk audit, honeypot detection, genesis bundler/sniper identification, and MEV telemetry plugin for **ElizaOS** and **Solana Agent Kit**, powered by **x402 HTTP micropayments**.

[![npm version](https://img.shields.io/npm/v/@lordkade/plugin-rugcheck-x402.svg)](https://www.npmjs.com/package/@lordkade/plugin-rugcheck-x402)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ Overview

When autonomous AI agents trade on Solana, they face severe risks:
1. **Honeypots & Freezes**: Tokens with active freeze authorities or unrenounced mint permissions.
2. **Bundler & Sniper Cabals**: Coordinated multi-wallet groups that buy up to 80% of supply in the genesis block via Jito tips, waiting to dump on your agent.
3. **MEV Sandwich Attacks**: Searcher bots frontrunning trades on Raydium or Pump.fun due to misconfigured slippage and low priority fees.

`@lordkade/plugin-rugcheck-x402` equips your agents with an autonomous pre-flight security scan that costs mere **fractions of a cent ($0.002 - $0.005 USDC)**, paid completely machine-to-machine via the open **x402 protocol**.

---

## 📦 Installation

```bash
npm install @lordkade/plugin-rugcheck-x402 @solana/web3.js
```

---

## 🚀 Quick Start: ElizaOS

### 1. Register Plugin in Your Agent Character

Add `rugcheckX402Plugin` to your Eliza character's plugin list:

```typescript
import { Character } from "@elizaos/core";
import { rugcheckX402Plugin } from "@lordkade/plugin-rugcheck-x402";

export const tradingAgent: Character = {
  name: "SolanaSafeguard",
  plugins: [rugcheckX402Plugin],
  settings: {
    secrets: {
      SOLANA_PRIVATE_KEY: process.env.SOLANA_PRIVATE_KEY,
      RUGCHECK_API_URL: process.env.RUGCHECK_API_URL || "http://localhost:4020",
    },
  },
  // ...
};
```

### 2. Conversational Interaction

Once installed, your agent automatically recognizes token audit requests and handles x402 payment autonomously:

```text
User: "Audit 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU before I swap."
Agent: "🔍 [x402 Autonomy] Intercepting challenge & settling sub-cent USDC payment to audit 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU...
🛡️ Solana Token Security Audit (x402 Verified)
Token: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
Verdict: ✅ SAFE TO TRADE (Safety Score: 92/100)
- Honeypot Trap: 🛡️ Clean (No honeypot)
- Freeze Authority: 🛡️ Revoked/None
- Mint Authority: 🛡️ Revoked/None
- Sniper Threat: 15/100 (PROCEED_SAFE)
- MEV Sandwich Risk: LOW (Priority fee: 50,000 microLamports/CU)
💳 Settled via x402 Micropayment (TX: sim_3b2f...)"
```

---

## 🛠️ Quick Start: Solana Agent Kit

You can also use this package with Solana Agent Kit:

```typescript
import { createRugcheckTool } from "@elizaos/plugin-rugcheck-x402";

const rugcheckTool = createRugcheckTool({
  baseUrl: process.env.RUGCHECK_API_URL || "http://localhost:4020",
  privateKey: process.env.SOLANA_PRIVATE_KEY,
});

// Run audit
const auditResult = await rugcheckTool.execute(null, {
  tokenAddress: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
});

console.log("Can agent safely trade?", auditResult.canAgentSafelyTrade);
console.log("Safety score:", auditResult.overallSafetyScore);
```

---

## 💻 Direct Programmatic Client

Use `RugcheckX402Client` directly in any Node.js, Bun, or TypeScript script:

```typescript
import { RugcheckX402Client } from "@elizaos/plugin-rugcheck-x402";

const client = new RugcheckX402Client({
  baseUrl: "http://localhost:4020",
  privateKey: process.env.AGENT_SOLANA_PRIVATE_KEY,
});

// 1. Audit Token Risk & Honeypot ($0.002 USDC)
const risk = await client.auditToken("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
console.log("Risk level:", risk.riskLevel);

// 2. Detect Launch Bundlers & Snipers ($0.003 USDC)
const bundlers = await client.detectBundlers("GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse");
console.log("Sniper threat:", bundlers.summary.threatScore);

// 3. MEV Protection & Priority Gas ($0.002 USDC)
const mev = await client.getMevIntel("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
console.log("Priority fee:", mev.recommendedPriorityFeeMicroLamports);

// 4. Full Executive Scan ($0.005 USDC)
const fullAudit = await client.fullSecurityAudit("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
if (fullAudit.canAgentSafelyTrade) {
  console.log("Proceeding with trade execution...");
}
```

---

## 🔒 How x402 Micropayments Work

```text
  Agent (Client)                                          x402 API Gateway
      |                                                          |
      |--- 1. POST /api/token/full-audit ----------------------->|
      |                                                          | (Unpaid request)
      |<-- 2. HTTP 402 Payment Required -------------------------|
      |       Header: PAYMENT-REQUIRED                           |
      |       { nonce, network, payTo, amount: 5000 }            |
      |                                                          |
   (Agent signs payload with Solana keypair)                     |
      |                                                          |
      |--- 3. Retry POST with PAYMENT-SIGNATURE ----------------->|
      |       { payer, nonce, signature, timestamp }             | (Verifies Ed25519 sig,
      |                                                          |  checks replay protection)
      |<-- 4. HTTP 200 OK + Full Security Report ----------------|
              Header: PAYMENT-RESPONSE (Settlement TX receipt)
```

No API keys, no monthly SaaS subscriptions. Autonomous agents pay precisely per query via on-chain USDC.

---

## ⚙️ Environment Variables

| Variable | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `SOLANA_PRIVATE_KEY` | Optional | Auto-generated | Base58 or JSON array secret key for x402 signatures |
| `AGENT_SOLANA_PRIVATE_KEY`| Optional | None | Alternative env name for Solana secret key |
| `RUGCHECK_API_URL` | Optional | `http://localhost:4020` | Base URL of x402 Solana Intelligence Gateway |
| `API_BASE_URL` | Optional | `http://localhost:4020` | Fallback API gateway URL |

---

## 📄 License

MIT © 2026
