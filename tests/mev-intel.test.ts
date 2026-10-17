import { describe, it, expect } from "vitest";
import { MevIntelService } from "../src/services/mev-intel.js";
import { SolanaRpcService, KNOWN_FIXTURES } from "../src/services/solana-rpc.js";

describe("MevIntelService", () => {
  const rpcService = new SolanaRpcService();
  const mevService = new MevIntelService(rpcService);

  it("should calculate low sandwich vulnerability for deep liquid tokens", async () => {
    const liquidMint = KNOWN_FIXTURES.SAFE_TOKEN;
    const intel = await mevService.getMevIntelligence(liquidMint);

    expect(intel.tokenAddress).toBe(liquidMint);
    expect(intel.sandwichVulnerability).toBe("LOW");
    expect(intel.liquidityDepth.priceImpactPer1Sol).toBeLessThan(1.0);
    expect(intel.recommendedGasAndFees.maxSafeSlippagePercent).toBeGreaterThanOrEqual(1.0);
    expect(intel.agentExecutionAdvice).toContain("STABLE");
  });

  it("should warn about extreme sandwich vulnerability and recommend high priority fee / Jito tip for thin liquidity", async () => {
    const thinMint = KNOWN_FIXTURES.THIN_LIQUIDITY_MEV;
    const intel = await mevService.getMevIntelligence(thinMint);

    expect(intel.sandwichVulnerability).toBe("EXTREME");
    expect(intel.activeMevBotsLast100Blocks).toBeGreaterThan(10);
    expect(intel.recommendedGasAndFees.priorityFeeMicroLamports.turboJitoTipLamports).toBeGreaterThanOrEqual(1_000_000);
    expect(intel.recommendedGasAndFees.maxSafeSlippagePercent).toBeLessThanOrEqual(0.5);
    expect(intel.recentSandwichAttacksDetected.length).toBeGreaterThan(0);
    expect(intel.agentExecutionAdvice).toContain("CRITICAL");
  });

  it("should reject invalid Solana address format", async () => {
    await expect(mevService.getMevIntelligence("not-valid")).rejects.toThrow("Invalid Solana mint address");
  });
});
