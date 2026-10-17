import { describe, it, expect } from "vitest";
import { BundlerDetectorService } from "../src/services/bundler-detector.js";
import { SolanaRpcService, KNOWN_FIXTURES } from "../src/services/solana-rpc.js";

describe("BundlerDetectorService", () => {
  const rpcService = new SolanaRpcService();
  const bundlerService = new BundlerDetectorService(rpcService);

  it("should evaluate clean organic launch with no bundlers as PROCEED_SAFE", async () => {
    const cleanMint = KNOWN_FIXTURES.SAFE_TOKEN;
    const analysis = await bundlerService.detectBundlers(cleanMint);

    expect(analysis.bundleDetected).toBe(false);
    expect(analysis.totalBundledSupplyPercent).toBe(0);
    expect(analysis.summary.threatScore).toBeLessThan(20);
    expect(analysis.summary.recommendation).toBe("PROCEED_SAFE");
    expect(analysis.clusters.length).toBe(0);
  });

  it("should identify coordinated Jito bundle snipers and flag SNIPED_CABAL", async () => {
    const snipedMint = KNOWN_FIXTURES.SNIPED_BUNDLER;
    const analysis = await bundlerService.detectBundlers(snipedMint);

    expect(analysis.bundleDetected).toBe(true);
    expect(analysis.totalBundledSupplyPercent).toBeGreaterThan(50);
    expect(analysis.developerClusterDetected).toBe(true);
    expect(analysis.summary.recommendation).toBe("SNIPED_CABAL");
    expect(analysis.summary.threatScore).toBeGreaterThanOrEqual(75);
    expect(analysis.clusters.length).toBeGreaterThan(0);
    expect(analysis.clusters[0].jitoTipPaidSol).toBeGreaterThan(0);
    expect(analysis.clusters[0].walletsInvolved.length).toBeGreaterThan(1);
  });

  it("should reject invalid Solana address format", async () => {
    await expect(bundlerService.detectBundlers("not-a-valid-solana-address")).rejects.toThrow(
      "Invalid Solana mint address"
    );
  });
});
