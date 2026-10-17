import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createX402Middleware, X402RouteConfig } from "./x402-middleware.js";
import { createApiRouter } from "./routes.js";
import { TokenRiskService } from "../services/token-risk.js";
import { BundlerDetectorService } from "../services/bundler-detector.js";
import { MevIntelService } from "../services/mev-intel.js";
import { SolanaRpcService } from "../services/solana-rpc.js";
import { getDiscoveryManifest, getLlmsTxt } from "./discovery.js";

dotenv.config();

export function createApp() {
  const app = express();

  app.set("trust proxy", true);
  app.use(cors());
  app.use(express.json());

  // Machine-Readable Agent Discovery Endpoints (un-gated for crawlers, x402scan, Bazaar)
  app.get("/.well-known/x402.json", (req, res) => {
    const proto = (req.headers["x-forwarded-proto"] as string)?.split(",")[0].trim() || req.protocol || "http";
    const host = req.get("host");
    const baseUrl = process.env.API_BASE_URL || (host ? `${proto}://${host}` : undefined);
    res.setHeader("Content-Type", "application/json");
    res.json(getDiscoveryManifest({ baseUrl }));
  });

  app.get("/llms.txt", (req, res) => {
    const proto = (req.headers["x-forwarded-proto"] as string)?.split(",")[0].trim() || req.protocol || "http";
    const host = req.get("host");
    const baseUrl = process.env.API_BASE_URL || (host ? `${proto}://${host}` : undefined);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(getLlmsTxt({ baseUrl }));
  });

  // Instantiate services
  const rpcService = new SolanaRpcService();
  const riskService = new TokenRiskService(rpcService);
  const bundlerService = new BundlerDetectorService(rpcService);
  const mevService = new MevIntelService(rpcService);

  // Define x402 paywall route configurations
  const x402Routes: Record<string, X402RouteConfig> = {
    "GET /api/token/risk/:address": {
      priceUsd: "$0.002",
      amountBaseUnits: "2000", // 0.002 USDC (6 decimals)
      description: "Solana Token Risk & Honeypot Audit",
    },
    "GET /api/token/bundler/:address": {
      priceUsd: "$0.003",
      amountBaseUnits: "3000", // 0.003 USDC (6 decimals)
      description: "Solana Genesis Bundler & Sniper Cluster Detection",
    },
    "GET /api/token/mev/:address": {
      priceUsd: "$0.002",
      amountBaseUnits: "2000", // 0.002 USDC (6 decimals)
      description: "Solana MEV Sandwich Vulnerability & Priority Gas Intelligence",
    },
    "POST /api/token/full-audit": {
      priceUsd: "$0.005",
      amountBaseUnits: "5000", // 0.005 USDC (6 decimals)
      description: "Comprehensive Solana Token Security & Trading Viability Audit",
    },
  };

  // Mount x402 payment challenge & verification middleware
  const x402Middleware = createX402Middleware(x402Routes, {
    recipientAddress: process.env.SOLANA_RECIPIENT_ADDRESS || "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    network: process.env.SOLANA_NETWORK || "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    allowSimulatedDevnet: true,
  });

  app.use(x402Middleware);

  // Mount API endpoints
  const apiRouter = createApiRouter(riskService, bundlerService, mevService);
  app.use("/api", apiRouter);

  // Fallback root endpoint
  app.get("/", (req, res) => {
    res.json({
      message: "x402 Solana Intelligence API for AI Agents",
      documentation: "/llms.txt",
      discovery: "/.well-known/x402.json",
      health: "/api/health",
      version: "2.0.0",
    });
  });

  return { app, riskService, bundlerService, mevService };
}

export function startServer(port: number = Number(process.env.PORT) || 4020) {
  const { app } = createApp();
  const server = app.listen(port, () => {
    console.log(`=======================================================`);
    console.log(`x402 Solana Token & MEV Intelligence API Gateway`);
    console.log(`Server listening on http://localhost:${port}`);
    console.log(`Health check: http://localhost:${port}/api/health`);
    console.log(`x402 Protocol: HTTP 402 challenge with USDC settlement`);
    console.log(`=======================================================`);
  });
  return server;
}

// Auto-run if executed directly
const normalizedServerArgv1 = (process.argv[1] || "").replace(/\\/g, "/");
const isServerMain =
  normalizedServerArgv1.endsWith("server/index.ts") ||
  normalizedServerArgv1.endsWith("server/index.js") ||
  normalizedServerArgv1.includes("src/server") ||
  normalizedServerArgv1.includes("dist/server");

if (isServerMain) {
  startServer();
}
