import { Router, Request, Response } from "express";
import { TokenRiskService } from "../services/token-risk.js";
import { BundlerDetectorService } from "../services/bundler-detector.js";
import { MevIntelService } from "../services/mev-intel.js";
import { FullSecurityAudit } from "../types/index.js";

import { computeFullSecurityAudit } from "../services/security-audit.js";

export function createApiRouter(
  riskService: TokenRiskService,
  bundlerService: BundlerDetectorService,
  mevService: MevIntelService
): Router {
  const router = Router();

  // Public Health & Metadata Endpoint
  router.get("/health", (req: Request, res: Response) => {
    res.json({
      status: "ok",
      service: "Solana Token Risk & MEV Intelligence API",
      protocol: "x402 Payment Required (v2.0)",
      supportedNetworks: [
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", // Solana Mainnet-beta
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", // Solana Devnet
      ],
      pricing: {
        tokenRisk: "$0.002 USDC (2,000 base units)",
        bundlerDetection: "$0.003 USDC (3,000 base units)",
        mevIntelligence: "$0.002 USDC (2,000 base units)",
        fullSecurityAudit: "$0.005 USDC (5,000 base units)",
      },
      discoveryManifest: "/.well-known/x402.json",
      openapiSpec: "/openapi.json",
      llmsTxt: "/llms.txt",
      agentDocumentation: "/llms.txt",
    });
  });

  // Protected: Token Risk Audit
  router.get("/token/risk/:address", async (req: Request, res: Response) => {
    try {
      const { address } = req.params;
      const report = await riskService.auditToken(address);
      res.json({
        success: true,
        data: report,
        paymentReceipt: (req as any).paymentReceipt,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Protected: Bundler & Sniper Cluster Detection
  router.get("/token/bundler/:address", async (req: Request, res: Response) => {
    try {
      const { address } = req.params;
      const analysis = await bundlerService.detectBundlers(address);
      res.json({
        success: true,
        data: analysis,
        paymentReceipt: (req as any).paymentReceipt,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Protected: MEV & Frontrunning Intelligence
  router.get("/token/mev/:address", async (req: Request, res: Response) => {
    try {
      const { address } = req.params;
      const intel = await mevService.getMevIntelligence(address);
      res.json({
        success: true,
        data: intel,
        paymentReceipt: (req as any).paymentReceipt,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Protected: Full Security & Trading Safety Audit
  router.post("/token/full-audit", async (req: Request, res: Response) => {
    try {
      const address =
        req.body?.tokenAddress ||
        req.body?.address ||
        req.body?.mint ||
        req.query?.tokenAddress ||
        req.query?.address;
      if (!address || typeof address !== "string") {
        res.status(400).json({ success: false, error: "Missing required parameter 'tokenAddress'" });
        return;
      }

      // Execute all 3 intelligence checks in parallel
      const [riskReport, bundlerReport, mevReport] = await Promise.all([
        riskService.auditToken(address),
        bundlerService.detectBundlers(address),
        mevService.getMevIntelligence(address),
      ]);

      const receipt = (req as any).paymentReceipt;
      const fullAudit = computeFullSecurityAudit(
        riskReport,
        bundlerReport,
        mevReport,
        address,
        receipt
      );

      res.json({
        success: true,
        data: fullAudit,
        paymentReceipt: receipt,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  return router;
}
