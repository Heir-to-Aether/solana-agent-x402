import { TokenRiskReport, BundlerAnalysis, MevIntelligence, FullSecurityAudit, X402PaymentReceipt } from "../types/index.js";

/**
 * Single source of truth for synthesizing a unified security audit report
 * Used consistently across REST API endpoints and MCP tool handlers.
 */
export function computeFullSecurityAudit(
  riskReport: TokenRiskReport,
  bundlerReport: BundlerAnalysis,
  mevReport: MevIntelligence,
  address: string,
  receipt?: X402PaymentReceipt | any
): FullSecurityAudit {
  // Calculate safety sub-scores (100 = completely safe, 0 = critical scam)
  const safetyFromRisk = 100 - riskReport.riskScore;
  const safetyFromBundlers = 100 - bundlerReport.summary.threatScore;

  // Deduct penalty based on frontrunning / sandwich risk
  const mevPenalty =
    mevReport.sandwichVulnerability === "EXTREME"
      ? 25
      : mevReport.sandwichVulnerability === "HIGH"
      ? 10
      : 0;

  // Weighted composite score
  const overallSafetyScore = Math.max(
    0,
    Math.min(
      100,
      Math.round(safetyFromRisk * 0.5 + safetyFromBundlers * 0.35 - mevPenalty)
    )
  );

  // Autonomous agent trade viability guardrails
  const canAgentSafelyTrade =
    overallSafetyScore >= 60 &&
    !riskReport.flags.isHoneypot &&
    riskReport.flags.freezeAuthorityRevoked &&
    bundlerReport.summary.recommendation !== "SNIPED_CABAL" &&
    riskReport.riskLevel !== "CRITICAL_DANGER";

  return {
    tokenAddress: address,
    auditTimestamp: new Date().toISOString(),
    overallSafetyScore,
    canAgentSafelyTrade,
    riskReport,
    bundlerReport,
    mevReport,
    paymentReceipt: receipt
      ? {
          payer: receipt.payer,
          amountUsd: receipt.amountUsd || "$0.005",
          settlementNetwork: receipt.network || receipt.settlementNetwork || "solana",
          signature: receipt.settlementTx || receipt.nonce || receipt.signature,
        }
      : undefined,
  };
}
