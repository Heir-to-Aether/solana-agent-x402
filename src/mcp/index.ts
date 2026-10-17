import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SolanaAgentClient } from "../client/agent-client.js";
import { TokenRiskService } from "../services/token-risk.js";
import { BundlerDetectorService } from "../services/bundler-detector.js";
import { MevIntelService } from "../services/mev-intel.js";
import { SolanaRpcService } from "../services/solana-rpc.js";

import { computeFullSecurityAudit } from "../services/security-audit.js";

export function createMcpServer(options: { agentClient?: SolanaAgentClient; embedded?: boolean } = {}) {
  const server = new Server(
    {
      name: "solana-risk-mev-x402-server",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  const rpcService = new SolanaRpcService();
  const riskService = new TokenRiskService(rpcService);
  const bundlerService = new BundlerDetectorService(rpcService);
  const mevService = new MevIntelService(rpcService);
  const agentClient = options.agentClient || new SolanaAgentClient({ debug: false });
  const embedded = options.embedded ?? false;

  // 1. List Available Tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "solana_token_risk_audit",
          description:
            "Audit a Solana SPL token or memecoin for honeypots, mint/freeze authorities, LP locks, top holder concentration, and security risk score (gated by x402 USDC micropayment).",
          inputSchema: {
            type: "object",
            properties: {
              tokenAddress: {
                type: "string",
                description: "The Solana token mint address to audit",
              },
            },
            required: ["tokenAddress"],
          },
        },
        {
          name: "solana_detect_bundlers",
          description:
            "Scan a Solana token launch for Jito bundler snipers, coordinated multi-wallet genesis buys, and developer stealth clusters.",
          inputSchema: {
            type: "object",
            properties: {
              tokenAddress: {
                type: "string",
                description: "The Solana token mint address to inspect for bundlers",
              },
            },
            required: ["tokenAddress"],
          },
        },
        {
          name: "solana_mev_intel",
          description:
            "Fetch real-time MEV sandwich vulnerability, recent sandwich attacks, optimal dynamic priority fees (microLamports/CU), and max safe slippage recommendations for AI agents executing swaps.",
          inputSchema: {
            type: "object",
            properties: {
              tokenAddress: {
                type: "string",
                description: "The Solana token mint address to check MEV dynamics for",
              },
            },
            required: ["tokenAddress"],
          },
        },
        {
          name: "solana_full_security_scan",
          description:
            "Run a comprehensive Solana token security scan combining risk audit, bundler analysis, and MEV intel, with an executive safety verdict on whether an autonomous agent can safely trade.",
          inputSchema: {
            type: "object",
            properties: {
              tokenAddress: {
                type: "string",
                description: "The Solana token mint address for the full audit",
              },
            },
            required: ["tokenAddress"],
          },
        },
      ],
    };
  });

  // 2. Handle Tool Invocations
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const tokenAddress = String(args?.tokenAddress || args?.address || args?.mint || "").trim();

    if (!tokenAddress) {
      return {
        isError: true,
        content: [{ type: "text", text: "Error: Missing required parameter 'tokenAddress'" }],
      };
    }

    try {
      if (name === "solana_token_risk_audit") {
        let result: any;
        if (!embedded) {
          try {
            result = await agentClient.getTokenRisk(tokenAddress);
          } catch {
            result = await riskService.auditToken(tokenAddress);
          }
        } else {
          result = await riskService.auditToken(tokenAddress);
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      if (name === "solana_detect_bundlers") {
        let result: any;
        if (!embedded) {
          try {
            result = await agentClient.getBundlerDetection(tokenAddress);
          } catch {
            result = await bundlerService.detectBundlers(tokenAddress);
          }
        } else {
          result = await bundlerService.detectBundlers(tokenAddress);
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      if (name === "solana_mev_intel") {
        let result: any;
        if (!embedded) {
          try {
            result = await agentClient.getMevIntelligence(tokenAddress);
          } catch {
            result = await mevService.getMevIntelligence(tokenAddress);
          }
        } else {
          result = await mevService.getMevIntelligence(tokenAddress);
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      if (name === "solana_full_security_scan") {
        let result: any;
        if (!embedded) {
          try {
            result = await agentClient.getFullSecurityAudit(tokenAddress);
          } catch {
            const [risk, bundler, mev] = await Promise.all([
              riskService.auditToken(tokenAddress),
              bundlerService.detectBundlers(tokenAddress),
              mevService.getMevIntelligence(tokenAddress),
            ]);
            result = computeFullSecurityAudit(risk, bundler, mev, tokenAddress);
          }
        } else {
          const [risk, bundler, mev] = await Promise.all([
            riskService.auditToken(tokenAddress),
            bundlerService.detectBundlers(tokenAddress),
            mevService.getMevIntelligence(tokenAddress),
          ]);
          result = computeFullSecurityAudit(risk, bundler, mev, tokenAddress);
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      return {
        isError: true,
        content: [{ type: "text", text: `Unknown tool name: ${name}` }],
      };
    } catch (err: any) {
      return {
        isError: true,
        content: [{ type: "text", text: `Error executing ${name}: ${err.message}` }],
      };
    }
  });

  return server;
}

export async function runMcpServer() {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Solana x402 Risk & MEV Intelligence MCP Server running on stdio");
}

const normalizedArgv1 = (process.argv[1] || "").replace(/\\/g, "/");
const isMainExecution =
  normalizedArgv1.endsWith("mcp/index.ts") ||
  normalizedArgv1.endsWith("mcp/index.js") ||
  normalizedArgv1.includes("src/mcp") ||
  normalizedArgv1.includes("dist/mcp") ||
  process.argv.includes("--run-mcp");

if (isMainExecution) {
  runMcpServer().catch((err) => {
    console.error("MCP Server fatal error:", err);
    process.exit(1);
  });
}
