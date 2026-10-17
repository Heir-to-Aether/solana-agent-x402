import { describe, it, expect } from "vitest";
import { TokenRiskService } from "../src/services/token-risk.js";
import { SolanaRpcService, KNOWN_FIXTURES } from "../src/services/solana-rpc.js";

describe("TokenRiskService", () => {
  const rpcService = new SolanaRpcService();
  const riskService = new TokenRiskService(rpcService);

  it("should accurately score a safe token with revoked authorities and locked LP", async () => {
    const safeMint = KNOWN_FIXTURES.SAFE_TOKEN;
    const report = await riskService.auditToken(safeMint);

    expect(report.tokenAddress).toBe(safeMint);
    expect(report.riskScore).toBeLessThan(30);
    expect(report.riskLevel).toBe("LOW");
    expect(report.flags.freezeAuthorityRevoked).toBe(true);
    expect(report.flags.mintAuthorityRevoked).toBe(true);
    expect(report.flags.isHoneypot).toBe(false);
    expect(report.liquidityPool.lpBurnedOrLocked).toBe(true);
  });

  it("should flag a honeypot with active freeze authority and high sell tax as CRITICAL_DANGER", async () => {
    const honeypotMint = KNOWN_FIXTURES.HONEYPOT_TOKEN;
    const report = await riskService.auditToken(honeypotMint);

    expect(report.flags.isHoneypot).toBe(true);
    expect(report.flags.freezeAuthorityRevoked).toBe(false);
    expect(report.flags.sellTaxPercent).toBeGreaterThanOrEqual(99);
    expect(report.riskScore).toBeGreaterThanOrEqual(75);
    expect(report.riskLevel).toBe("CRITICAL_DANGER");
    expect(report.verdict).toContain("DO NOT TRADE");
    expect(report.warnings.some((w) => w.includes("Freeze Authority"))).toBe(true);
  });

  it("should detect active mint authority and raise risk score", async () => {
    const scamMint = KNOWN_FIXTURES.ACTIVE_MINT_SCAM;
    const report = await riskService.auditToken(scamMint);

    expect(report.flags.mintAuthorityRevoked).toBe(false);
    expect(report.warnings.some((w) => w.includes("Mint Authority"))).toBe(true);
    expect(report.riskScore).toBeGreaterThanOrEqual(45);
  });

  it("should reject invalid Solana base58 address", async () => {
    await expect(riskService.auditToken("invalid-not-base58-!!!")).rejects.toThrow("Invalid Solana mint address");
  });

  it("should score non-existent or uninitialized Solana token as CRITICAL_DANGER with risk score 100", async () => {
    // Generate an arbitrary valid base58 address that does not exist on chain
    const nonExistentMint = "11111111111111111111111111111112";
    const report = await riskService.auditToken(nonExistentMint);

    expect(report.tokenAddress).toBe(nonExistentMint);
    expect(report.riskScore).toBe(100);
    expect(report.riskLevel).toBe("CRITICAL_DANGER");
    expect(report.verdict).toContain("DO NOT TRADE");
    expect(report.flags.isHoneypot).toBe(true);
    expect(report.warnings.some((w) => w.includes("does not exist") || w.includes("not an SPL Token mint"))).toBe(true);
  });

  it("should identify ungraduated pump.fun token dex as Pump.fun", async () => {
    const pumpToken = KNOWN_FIXTURES.PUMP_FUN_TOKEN;
    const report = await riskService.auditToken(pumpToken);
    expect(report.liquidityPool.dex).toBe("Pump.fun");
    expect(report.flags.isPumpFunGraduated).toBe(false);
  });
});
