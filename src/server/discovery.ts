/**
 * Machine-Readable Agent Discovery Endpoints
 * 
 * Implements:
 * 1. /.well-known/x402.json - Payment-aware discovery manifest for AI crawlers,
 *    x402scan, and Coinbase x402 Bazaar.
 * 2. /llms.txt - Structured LLM context specification conforming to https://llmstxt.org
 */

export interface DiscoveryConfig {
  baseUrl?: string;
  recipientAddress?: string;
  network?: string;
}

export function getDiscoveryManifest(config: DiscoveryConfig = {}) {
  const recipientAddress =
    config.recipientAddress ||
    process.env.SOLANA_RECIPIENT_WALLET ||
    process.env.SOLANA_RECIPIENT_ADDRESS ||
    "RVmRQMtMAdyWk3dq678N6GUPkrK9yDeDLqTQsFZMpcU";
  const rawNetwork =
    config.network ||
    process.env.SOLANA_NETWORK ||
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
  const baseUrl = (config.baseUrl || process.env.API_BASE_URL || "http://localhost:4020").replace(/\/$/, "");

  const isDevnet = rawNetwork.toLowerCase().includes("devnet") || rawNetwork.toLowerCase().includes("etwtrabzayq6imfeykouru166vu2xqa1");
  const network = rawNetwork.startsWith("solana:")
    ? rawNetwork
    : isDevnet
    ? "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    : "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
  const usdcMint = isDevnet
    ? "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" // Devnet USDC
    : "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // Mainnet USDC

  return {
    $schema: "https://x402.org/schemas/discovery.schema.json",
    x402Version: 2,
    name: "solana-agent-x402-intelligence",
    title: "Solana Token Risk, Bundler Detection & MEV Intelligence API",
    description: "High-speed, sub-cent Solana token risk, honeypot/bundler detection, and MEV intelligence API built specifically for autonomous AI agents, gated natively by x402 HTTP micropayments in USDC on Solana.",
    version: "1.0.0",
    homepage: baseUrl,
    documentationUrl: `${baseUrl}/llms.txt`,
    contact: {
      url: `${baseUrl}/api/health`,
    },
    paymentProtocol: {
      name: "x402",
      version: "2.0",
      scheme: "exact",
      defaultNetwork: network,
      supportedNetworks: [
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", // Solana Mainnet-beta
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", // Solana Devnet
      ],
      recipient: recipientAddress,
      settlementAsset: {
        symbol: "USDC",
        name: isDevnet ? "USD Coin (Devnet)" : "USD Coin",
        mint: usdcMint,
        decimals: 6,
      },
    },
    endpoints: [
      {
        path: "/api/token/risk/:address",
        fullUrl: `${baseUrl}/api/token/risk/:address`,
        method: "GET",
        summary: "Solana Token Risk & Honeypot Audit",
        description: "Evaluates honeypot traps, mutable metadata, mint authority, freeze authority, LP lock status, and holder concentration (0-100 risk score).",
        priceUsd: "$0.002",
        priceBaseUnits: "2000",
        asset: "USDC",
        assetDecimals: 6,
        parameters: [
          {
            name: "address",
            in: "path",
            required: true,
            type: "string",
            description: "Base58-encoded Solana SPL token mint address",
          },
        ],
        outputSchema: {
          type: "object",
          properties: {
            tokenAddress: { type: "string" },
            riskScore: { type: "number", minimum: 0, maximum: 100 },
            riskLevel: { type: "string", enum: ["LOW", "MODERATE", "HIGH", "CRITICAL_DANGER"] },
            flags: {
              type: "object",
              properties: {
                isHoneypot: { type: "boolean" },
                hasMintAuthority: { type: "boolean" },
                hasFreezeAuthority: { type: "boolean" },
                isLpBurned: { type: "boolean" },
                topHoldersConcentration: { type: "number" },
              },
            },
            topHolders: { type: "array" },
          },
        },
      },
      {
        path: "/api/token/bundler/:address",
        fullUrl: `${baseUrl}/api/token/bundler/:address`,
        method: "GET",
        summary: "Genesis Bundler & Sniper Cluster Detection",
        description: "Detects coordinated genesis block snipers, Jito tip bundles, multi-wallet stealth cabals, and developer supply dump threats.",
        priceUsd: "$0.003",
        priceBaseUnits: "3000",
        asset: "USDC",
        assetDecimals: 6,
        parameters: [
          {
            name: "address",
            in: "path",
            required: true,
            type: "string",
            description: "Base58-encoded Solana SPL token mint address",
          },
        ],
        outputSchema: {
          type: "object",
          properties: {
            tokenAddress: { type: "string" },
            summary: {
              type: "object",
              properties: {
                threatScore: { type: "number", minimum: 0, maximum: 100 },
                recommendation: { type: "string", enum: ["PROCEED_SAFE", "CAUTION_SNIPERS_ACTIVE", "EXTREME_DUMP_RISK"] },
                bundledSupplyPercent: { type: "number" },
                activeSniperCount: { type: "number" },
              },
            },
            bundlerClusters: { type: "array" },
            sniperWallets: { type: "array" },
          },
        },
      },
      {
        path: "/api/token/mev/:address",
        fullUrl: `${baseUrl}/api/token/mev/:address`,
        method: "GET",
        summary: "MEV Sandwich Vulnerability & Priority Gas Intelligence",
        description: "Assesses real-time sandwich attack risk, active searcher presence, dynamic priority fee recommendations (microLamports/CU), and slippage tolerance guardrails.",
        priceUsd: "$0.002",
        priceBaseUnits: "2000",
        asset: "USDC",
        assetDecimals: 6,
        parameters: [
          {
            name: "address",
            in: "path",
            required: true,
            type: "string",
            description: "Base58-encoded Solana SPL token mint address",
          },
        ],
        outputSchema: {
          type: "object",
          properties: {
            tokenAddress: { type: "string" },
            sandwichVulnerability: { type: "string", enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
            searcherPresence: { type: "boolean" },
            recommendedPriorityFeeMicroLamports: { type: "number" },
            recommendedMaxSlippageBps: { type: "number" },
            agentExecutionAdvice: { type: "string" },
          },
        },
      },
      {
        path: "/api/token/full-audit",
        fullUrl: `${baseUrl}/api/token/full-audit`,
        method: "POST",
        summary: "Comprehensive Solana Token Security & Trading Viability Audit",
        description: "Executes composite risk, bundler, and MEV telemetry in parallel, returning overallSafetyScore and an executive canAgentSafelyTrade verdict.",
        priceUsd: "$0.005",
        priceBaseUnits: "5000",
        asset: "USDC",
        assetDecimals: 6,
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["tokenAddress"],
                properties: {
                  tokenAddress: { type: "string", description: "Base58 Solana token mint address" },
                },
              },
            },
          },
        },
        outputSchema: {
          type: "object",
          properties: {
            tokenAddress: { type: "string" },
            overallSafetyScore: { type: "number", minimum: 0, maximum: 100 },
            canAgentSafelyTrade: { type: "boolean" },
            verdict: { type: "string" },
            riskReport: { type: "object" },
            bundlerReport: { type: "object" },
            mevReport: { type: "object" },
            paymentReceipt: { type: "object" },
          },
        },
      },
    ],
    // Coinbase Bazaar / x402 resource catalog
    resources: [
      {
        url: `${baseUrl}/api/token/risk/:address`,
        type: "http",
        mimeType: "application/json",
        description: "Solana Token Risk & Honeypot Audit",
        accepts: [
          {
            scheme: "exact",
            network,
            amount: "2000",
            asset: usdcMint,
            payTo: recipientAddress,
            maxTimeoutSeconds: 300,
          },
        ],
      },
      {
        url: `${baseUrl}/api/token/bundler/:address`,
        type: "http",
        mimeType: "application/json",
        description: "Solana Genesis Bundler & Sniper Cluster Detection",
        accepts: [
          {
            scheme: "exact",
            network,
            amount: "3000",
            asset: usdcMint,
            payTo: recipientAddress,
            maxTimeoutSeconds: 300,
          },
        ],
      },
      {
        url: `${baseUrl}/api/token/mev/:address`,
        type: "http",
        mimeType: "application/json",
        description: "Solana MEV Sandwich Vulnerability & Priority Gas Intelligence",
        accepts: [
          {
            scheme: "exact",
            network,
            amount: "2000",
            asset: usdcMint,
            payTo: recipientAddress,
            maxTimeoutSeconds: 300,
          },
        ],
      },
      {
        url: `${baseUrl}/api/token/full-audit`,
        type: "http",
        mimeType: "application/json",
        description: "Comprehensive Solana Token Security & Trading Viability Audit",
        accepts: [
          {
            scheme: "exact",
            network,
            amount: "5000",
            asset: usdcMint,
            payTo: recipientAddress,
            maxTimeoutSeconds: 300,
          },
        ],
      },
    ],
  };
}

export function getLlmsTxt(config: DiscoveryConfig = {}): string {
  const recipientAddress =
    config.recipientAddress ||
    process.env.SOLANA_RECIPIENT_WALLET ||
    process.env.SOLANA_RECIPIENT_ADDRESS ||
    "RVmRQMtMAdyWk3dq678N6GUPkrK9yDeDLqTQsFZMpcU";
  const network =
    config.network ||
    process.env.SOLANA_NETWORK ||
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
  const baseUrl = (config.baseUrl || process.env.API_BASE_URL || "http://localhost:4020").replace(/\/$/, "");

  return `# Solana Token Risk, Bundler Detection & MEV Intelligence API (x402)
> High-speed sub-cent Solana token risk, honeypot/bundler detection, and MEV intelligence API built specifically for autonomous AI agents, gated natively by x402 HTTP micropayments in USDC on Solana.

## System Overview
This service provides deterministic, low-latency pre-execution security audits on Solana SPL tokens before autonomous trading agents execute swaps on DEXs (Raydium, Pump.fun, Orca, Jupiter).

All protected endpoints are gated with the **x402 (HTTP 402 Payment Required)** open protocol with sub-cent micro-settlement in USDC on Solana.

- **Base URL**: ${baseUrl}
- **Payment Protocol**: x402 (v2.0)
- **Settlement Network**: ${network}
- **Recipient Address**: ${recipientAddress}
- **OpenAPI 3.1 Spec**: ${baseUrl}/openapi.json
- **Discovery Manifest**: ${baseUrl}/.well-known/x402.json
- **Health & Info**: ${baseUrl}/api/health

---

## Machine Payment Protocol (x402) Flow
When an autonomous agent queries a paid endpoint without payment credentials:
1. Server returns \`HTTP 402 Payment Required\` with headers:
   - \`PAYMENT-REQUIRED\`: JSON payment requirement spec.
   - \`x402-network\`: Target Solana network CAIP-2 identifier.
   - \`x402-pay-to\`: Recipient Solana wallet address.
   - \`x402-amount\`: Required USDC base units (6 decimals).
   - \`x402-nonce\`: Single-use cryptographic challenge nonce.
2. The agent formats the signing message:
   \`\${nonce}:\${payerPublicKey}:\${payTo}:\${amount}:\${timestamp}\`
3. The agent signs this string with its Solana Ed25519 private key.
4. The agent retries the exact same HTTP request with header:
   \`PAYMENT-SIGNATURE: <base64-encoded JSON payload>\`
5. The server cryptographically validates the signature and nonce replay protection, unlocks \`HTTP 200 OK\`, and attaches a \`PAYMENT-RESPONSE\` receipt header.

---

## API Endpoints & Pricing (USDC Base Units)

### 1. Token Risk & Honeypot Analysis
- **Endpoint**: \`GET /api/token/risk/:address\`
- **Price**: $0.002 USDC (2,000 base units)
- **Description**: Verifies honeypot status, mint authority, freeze authority, LP lock status, holder concentration, and calculates composite risk score (0-100).
- **Parameters**: \`address\` (string, path) - Base58-encoded Solana SPL token mint address.
- **Key Output Fields**:
  - \`riskScore\`: 0-100 composite risk (higher is more dangerous).
  - \`riskLevel\`: LOW | MODERATE | HIGH | CRITICAL_DANGER.
  - \`flags.isHoneypot\`: boolean.
  - \`flags.hasFreezeAuthority\`: boolean (can freeze token transfers).
  - \`flags.isLpBurned\`: boolean (liquidity pool locked or burned).

### 2. Genesis Bundler & Sniper Cluster Detection
- **Endpoint**: \`GET /api/token/bundler/:address\`
- **Price**: $0.003 USDC (3,000 base units)
- **Description**: Analyzes block zero transactions, Jito bundle tips, multi-wallet stealth cabals, and developer supply dump threats.
- **Parameters**: \`address\` (string, path) - Base58-encoded Solana SPL token mint address.
- **Key Output Fields**:
  - \`summary.threatScore\`: 0-100 sniper threat score.
  - \`summary.recommendation\`: PROCEED_SAFE | CAUTION_SNIPERS_ACTIVE | EXTREME_DUMP_RISK.
  - \`summary.bundledSupplyPercent\`: Percentage of total supply acquired via launch bundles.

### 3. MEV Sandwich Vulnerability & Priority Gas Intelligence
- **Endpoint**: \`GET /api/token/mev/:address\`
- **Price**: $0.002 USDC (2,000 base units)
- **Description**: Real-time sandwich attack risk, active searcher presence, recommended priority fee, and safe slippage guardrails.
- **Parameters**: \`address\` (string, path) - Base58-encoded Solana SPL token mint address.
- **Key Output Fields**:
  - \`sandwichVulnerability\`: LOW | MEDIUM | HIGH | CRITICAL.
  - \`recommendedPriorityFeeMicroLamports\`: Dynamic priority fee to outpace searchers.
  - \`recommendedMaxSlippageBps\`: Maximum recommended slippage in basis points.
  - \`agentExecutionAdvice\`: Clear actionable trading advice for the AI agent.

### 4. Comprehensive Executive Audit
- **Endpoint**: \`POST /api/token/full-audit\`
- **Price**: $0.005 USDC (5,000 base units)
- **Description**: Executes composite risk, bundler, and MEV telemetry in parallel, returning overallSafetyScore and executive canAgentSafelyTrade verdict.
- **Request Body**: \`{ "tokenAddress": "<Solana Mint Address>" }\`
- **Key Output Fields**:
  - \`overallSafetyScore\`: 0-100 overall security score.
  - \`canAgentSafelyTrade\`: boolean - deterministic green light for autonomous agents.
  - \`verdict\`: Plain English summary rationale.

---

## Agent SDK & MCP Integration
- **Client Runner**: \`src/client/agent-client.ts\` (\`SolanaAgentClient\`)
- **MCP Server**: \`src/mcp/index.ts\` (compatible with Claude Desktop, Cursor, and any MCP host)
- **ElizaOS & Solana Agent Kit Plugin**: \`packages/plugin-rugcheck-x402\`
`;
}

export function getOpenApiSpec(config: DiscoveryConfig = {}) {
  const recipientAddress =
    config.recipientAddress ||
    process.env.SOLANA_RECIPIENT_WALLET ||
    process.env.SOLANA_RECIPIENT_ADDRESS ||
    "RVmRQMtMAdyWk3dq678N6GUPkrK9yDeDLqTQsFZMpcU";
  const rawNetwork =
    config.network ||
    process.env.SOLANA_NETWORK ||
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
  const baseUrl = (config.baseUrl || process.env.API_BASE_URL || "https://solana-agent-x402.onrender.com").replace(/\/$/, "");

  const isDevnet = rawNetwork.toLowerCase().includes("devnet") || rawNetwork.toLowerCase().includes("etwtrabzayq6imfeykouru166vu2xqa1");
  const network = rawNetwork.startsWith("solana:")
    ? rawNetwork
    : isDevnet
    ? "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    : "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

  return {
    openapi: "3.1.0",
    info: {
      title: "Solana Token Risk, Bundler Detection & MEV Intelligence API",
      version: "1.0.0",
      description: "High-speed, sub-cent Solana token risk, honeypot/bundler detection, and MEV intelligence API built specifically for autonomous AI agents, gated natively by x402 HTTP micropayments in USDC on Solana.",
      "x-guidance": "Autonomous AI agent guide: Query GET /api/health for service status and pricing. Protected endpoints (/api/token/risk/{address}, /api/token/bundler/{address}, /api/token/mev/{address}, /api/token/full-audit) require x402 payment in USDC on Solana. Unauthenticated requests return HTTP 402 with PAYMENT-REQUIRED specifications. Sign the challenge with your Solana wallet Ed25519 key and retry with PAYMENT-SIGNATURE header. Full markdown documentation is available at /llms.txt.",
      contact: {
        name: "Merit Systems Merchant Support",
        email: "merchants@merit.systems",
        url: "https://github.com/Heir-to-Aether/solana-agent-x402"
      }
    },
    servers: [
      {
        url: baseUrl,
        description: "Solana Agent Intelligence API Gateway"
      }
    ],
    "x-agentcash-guidance": {
      llmsTxtUrl: `${baseUrl}/llms.txt`
    },
    "x-agentcash-provenance": {
      ownershipProofs: [
        "https://github.com/Heir-to-Aether/solana-agent-x402"
      ]
    },
    components: {
      securitySchemes: {
        x402: {
          type: "http",
          scheme: "x402",
          description: "x402 HTTP micropayment signature in USDC on Solana (Ed25519 signature of nonce challenge payload)"
        },
        siwx: {
          type: "apiKey",
          name: "SIGN-IN-WITH-X",
          in: "header",
          "x-agentcash-auth-kind": "siwx",
          description: "Sign-In with X (SIWX) wallet identity authentication"
        }
      },
      schemas: {
        TokenRiskReport: {
          type: "object",
          required: ["tokenAddress", "riskScore", "riskLevel", "flags", "topHolders"],
          properties: {
            tokenAddress: { type: "string", description: "Base58-encoded Solana SPL token mint address" },
            riskScore: { type: "number", minimum: 0, maximum: 100, description: "Composite risk score (0=safe, 100=critical danger)" },
            riskLevel: { type: "string", enum: ["LOW", "MODERATE", "HIGH", "CRITICAL_DANGER"] },
            flags: {
              type: "object",
              required: ["isHoneypot", "hasMintAuthority", "hasFreezeAuthority", "isLpBurned", "topHoldersConcentration"],
              properties: {
                isHoneypot: { type: "boolean", description: "Whether honeypot or transfer blacklist trap is present" },
                hasMintAuthority: { type: "boolean", description: "Whether mint authority can inflate supply" },
                hasFreezeAuthority: { type: "boolean", description: "Whether freeze authority can freeze token balances" },
                isLpBurned: { type: "boolean", description: "Whether liquidity pool LP tokens are locked/burned" },
                topHoldersConcentration: { type: "number", description: "Percentage of supply held by top 10 holders" }
              }
            },
            topHolders: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  address: { type: "string" },
                  amount: { type: "number" },
                  percent: { type: "number" },
                  isInsider: { type: "boolean" }
                }
              }
            }
          }
        },
        BundlerAnalysis: {
          type: "object",
          required: ["tokenAddress", "summary", "bundlerClusters", "sniperWallets"],
          properties: {
            tokenAddress: { type: "string", description: "Base58-encoded Solana SPL token mint address" },
            summary: {
              type: "object",
              required: ["threatScore", "recommendation", "bundledSupplyPercent", "activeSniperCount"],
              properties: {
                threatScore: { type: "number", minimum: 0, maximum: 100 },
                recommendation: { type: "string", enum: ["PROCEED_SAFE", "CAUTION_SNIPERS_ACTIVE", "EXTREME_DUMP_RISK"] },
                bundledSupplyPercent: { type: "number" },
                activeSniperCount: { type: "number" }
              }
            },
            bundlerClusters: { type: "array", items: { type: "object" } },
            sniperWallets: { type: "array", items: { type: "object" } }
          }
        },
        MevIntelligence: {
          type: "object",
          required: ["tokenAddress", "sandwichVulnerability", "searcherPresence", "recommendedPriorityFeeMicroLamports", "recommendedMaxSlippageBps", "agentExecutionAdvice"],
          properties: {
            tokenAddress: { type: "string", description: "Base58-encoded Solana SPL token mint address" },
            sandwichVulnerability: { type: "string", enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
            searcherPresence: { type: "boolean" },
            recommendedPriorityFeeMicroLamports: { type: "number" },
            recommendedMaxSlippageBps: { type: "number" },
            agentExecutionAdvice: { type: "string" }
          }
        },
        FullSecurityAudit: {
          type: "object",
          required: ["tokenAddress", "overallSafetyScore", "canAgentSafelyTrade", "verdict", "riskReport", "bundlerReport", "mevReport"],
          properties: {
            tokenAddress: { type: "string" },
            overallSafetyScore: { type: "number", minimum: 0, maximum: 100 },
            canAgentSafelyTrade: { type: "boolean" },
            verdict: { type: "string" },
            riskReport: { $ref: "#/components/schemas/TokenRiskReport" },
            bundlerReport: { $ref: "#/components/schemas/BundlerAnalysis" },
            mevReport: { $ref: "#/components/schemas/MevIntelligence" },
            paymentReceipt: { type: "object" }
          }
        },
        ApiErrorResponse: {
          type: "object",
          required: ["success", "error"],
          properties: {
            success: { type: "boolean", example: false },
            error: { type: "string" }
          }
        },
        PaymentRequiredResponse: {
          type: "object",
          required: ["x402Version", "error", "resource", "accepts"],
          properties: {
            x402Version: { type: "number", example: 2 },
            error: { type: "string", example: "Payment Required" },
            message: { type: "string" },
            resource: {
              type: "object",
              properties: {
                url: { type: "string" },
                description: { type: "string" },
                mimeType: { type: "string" }
              }
            },
            accepts: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  scheme: { type: "string", example: "exact" },
                  network: { type: "string" },
                  amount: { type: "string" },
                  asset: { type: "string" },
                  payTo: { type: "string" },
                  maxTimeoutSeconds: { type: "number" },
                  extra: { type: "object" }
                }
              }
            }
          }
        }
      }
    },
    paths: {
      "/": {
        get: {
          summary: "API Overview & Service Links",
          description: "Free root overview endpoint providing service status, version, and links to machine documentation and discovery specifications.",
          operationId: "getRoot",
          security: [],
          responses: {
            "200": {
              description: "API gateway discovery metadata",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      message: { type: "string" },
                      openapi: { type: "string" },
                      documentation: { type: "string" },
                      discovery: { type: "string" },
                      health: { type: "string" },
                      version: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/health": {
        get: {
          summary: "Health Check & Service Pricing",
          description: "Free public health check providing system status, supported Solana networks, and current x402 pricing schedule.",
          operationId: "getHealth",
          security: [],
          responses: {
            "200": {
              description: "Service operational status and pricing metadata",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      status: { type: "string" },
                      service: { type: "string" },
                      protocol: { type: "string" },
                      supportedNetworks: { type: "array", items: { type: "string" } },
                      pricing: { type: "object" },
                      discoveryManifest: { type: "string" },
                      openapiSpec: { type: "string" },
                      llmsTxt: { type: "string" },
                      agentDocumentation: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/llms.txt": {
        get: {
          summary: "LLM Agent Context & Guidance",
          description: "Free plaintext Markdown guide structured according to the llmstxt.org specification for LLMs and autonomous agents.",
          operationId: "getLlmsTxt",
          security: [],
          responses: {
            "200": {
              description: "LLM system prompt integration context",
              content: {
                "text/plain": {
                  schema: { type: "string" }
                }
              }
            }
          }
        }
      },
      "/.well-known/x402.json": {
        get: {
          summary: "x402 Agent Discovery Manifest",
          description: "Free payment-aware discovery manifest for AI crawlers, x402scan, and Coinbase x402 Bazaar.",
          operationId: "getDiscoveryManifest",
          security: [],
          responses: {
            "200": {
              description: "x402 discovery manifest document",
              content: {
                "application/json": {
                  schema: { type: "object" }
                }
              }
            }
          }
        }
      },
      "/openapi.json": {
        get: {
          summary: "OpenAPI 3.1.0 Discovery Specification",
          description: "Free canonical OpenAPI 3.1.0 specification defining all free and paid x402 routes with schemas, pricing, and payment protocols.",
          operationId: "getOpenApiSpec",
          security: [],
          responses: {
            "200": {
              description: "Canonical OpenAPI 3.1.0 discovery document",
              content: {
                "application/json": {
                  schema: { type: "object" }
                }
              }
            }
          }
        }
      },
      "/api/token/risk/{address}": {
        get: {
          summary: "Solana Token Risk & Honeypot Audit",
          description: "Audits honeypot traps, mutable metadata, mint authority, freeze authority, LP lock status, and holder concentration (0-100 composite risk score). Gated by x402 ($0.002 USDC).",
          operationId: "getTokenRisk",
          tags: ["Token Intelligence"],
          security: [{ x402: [] }],
          "x-payment-info": {
            price: {
              mode: "fixed",
              currency: "USD",
              amount: "0.002000"
            },
            protocols: [{ x402: {} }]
          },
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              description: "Base58-encoded Solana SPL token mint address (e.g. 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU)",
              schema: {
                type: "string",
                pattern: "^[1-9A-HJ-NP-za-km-z]{32,44}$"
              }
            }
          ],
          responses: {
            "200": {
              description: "Successful token risk analysis report",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["success", "data"],
                    properties: {
                      success: { type: "boolean", example: true },
                      data: { $ref: "#/components/schemas/TokenRiskReport" },
                      paymentReceipt: { type: "object" }
                    }
                  }
                }
              }
            },
            "400": {
              description: "Invalid Solana token address",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiErrorResponse" }
                }
              }
            },
            "402": {
              description: "Payment Required - returns x402 payment challenge in USDC on Solana",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/PaymentRequiredResponse" }
                }
              }
            }
          }
        }
      },
      "/api/token/bundler/{address}": {
        get: {
          summary: "Genesis Bundler & Sniper Cluster Detection",
          description: "Detects coordinated block-zero sniper clusters, Jito bundle tips, multi-wallet stealth cabals, and developer supply dump threats. Gated by x402 ($0.003 USDC).",
          operationId: "getBundlerDetection",
          tags: ["Token Intelligence"],
          security: [{ x402: [] }],
          "x-payment-info": {
            price: {
              mode: "fixed",
              currency: "USD",
              amount: "0.003000"
            },
            protocols: [{ x402: {} }]
          },
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              description: "Base58-encoded Solana SPL token mint address (e.g. 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU)",
              schema: {
                type: "string",
                pattern: "^[1-9A-HJ-NP-za-km-z]{32,44}$"
              }
            }
          ],
          responses: {
            "200": {
              description: "Successful bundler & sniper cluster analysis report",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["success", "data"],
                    properties: {
                      success: { type: "boolean", example: true },
                      data: { $ref: "#/components/schemas/BundlerAnalysis" },
                      paymentReceipt: { type: "object" }
                    }
                  }
                }
              }
            },
            "400": {
              description: "Invalid Solana token address",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiErrorResponse" }
                }
              }
            },
            "402": {
              description: "Payment Required - returns x402 payment challenge in USDC on Solana",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/PaymentRequiredResponse" }
                }
              }
            }
          }
        }
      },
      "/api/token/mev/{address}": {
        get: {
          summary: "MEV Sandwich Vulnerability & Priority Gas Intelligence",
          description: "Real-time sandwich attack telemetry, active searcher presence detection, dynamic priority fee recommendations (microLamports/CU), and slippage tolerance guardrails. Gated by x402 ($0.002 USDC).",
          operationId: "getMevIntelligence",
          tags: ["Token Intelligence"],
          security: [{ x402: [] }],
          "x-payment-info": {
            price: {
              mode: "fixed",
              currency: "USD",
              amount: "0.002000"
            },
            protocols: [{ x402: {} }]
          },
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              description: "Base58-encoded Solana SPL token mint address (e.g. 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU)",
              schema: {
                type: "string",
                pattern: "^[1-9A-HJ-NP-za-km-z]{32,44}$"
              }
            }
          ],
          responses: {
            "200": {
              description: "Successful MEV vulnerability and gas advice report",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["success", "data"],
                    properties: {
                      success: { type: "boolean", example: true },
                      data: { $ref: "#/components/schemas/MevIntelligence" },
                      paymentReceipt: { type: "object" }
                    }
                  }
                }
              }
            },
            "400": {
              description: "Invalid Solana token address",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiErrorResponse" }
                }
              }
            },
            "402": {
              description: "Payment Required - returns x402 payment challenge in USDC on Solana",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/PaymentRequiredResponse" }
                }
              }
            }
          }
        }
      },
      "/api/token/full-audit": {
        post: {
          summary: "Comprehensive Solana Token Security & Trading Viability Audit",
          description: "Runs composite risk, bundler, and MEV telemetry in parallel, returning overallSafetyScore (0-100) and an executive canAgentSafelyTrade verdict. Gated by x402 ($0.005 USDC).",
          operationId: "postFullAudit",
          tags: ["Token Intelligence"],
          security: [{ x402: [] }],
          "x-payment-info": {
            price: {
              mode: "fixed",
              currency: "USD",
              amount: "0.005000"
            },
            protocols: [{ x402: {} }]
          },
          requestBody: {
            required: true,
            description: "Target Solana SPL token mint address payload",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["tokenAddress"],
                  properties: {
                    tokenAddress: {
                      type: "string",
                      description: "Base58-encoded Solana SPL token mint address",
                      pattern: "^[1-9A-HJ-NP-za-km-z]{32,44}$"
                    }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Successful comprehensive security audit report",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["success", "data"],
                    properties: {
                      success: { type: "boolean", example: true },
                      data: { $ref: "#/components/schemas/FullSecurityAudit" },
                      paymentReceipt: { type: "object" }
                    }
                  }
                }
              }
            },
            "400": {
              description: "Missing or invalid tokenAddress in request body",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiErrorResponse" }
                }
              }
            },
            "402": {
              description: "Payment Required - returns x402 payment challenge in USDC on Solana",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/PaymentRequiredResponse" }
                }
              }
            }
          }
        }
      }
    }
  };
}

