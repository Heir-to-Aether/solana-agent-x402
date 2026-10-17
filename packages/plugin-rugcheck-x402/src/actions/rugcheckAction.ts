import { Action, IAgentRuntime, Memory, State, HandlerCallback, ActionExample } from "../types.js";
import { RugcheckX402Client } from "../client.js";
import { PublicKey } from "@solana/web3.js";

// Helper to extract verified Solana base58 public keys from conversational message text
export function extractValidSolanaAddresses(text: string): string[] {
  const matches = text.match(/\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g) || [];
  const valid: string[] = [];
  for (const candidate of matches) {
    try {
      new PublicKey(candidate);
      if (!valid.includes(candidate)) {
        valid.push(candidate);
      }
    } catch {
      // Ignore invalid public key byte length or decoding errors
    }
  }
  return valid;
}

export const rugcheckAction: Action = {
  name: "SOLANA_RUGCHECK_X402",
  similes: [
    "CHECK_TOKEN_RISK",
    "RUGCHECK_TOKEN",
    "AUDIT_SOLANA_TOKEN",
    "CHECK_HONEYPOT",
    "DETECT_BUNDLERS",
    "MEV_INTEL_CHECK",
    "SECURITY_SCAN_TOKEN",
  ],
  description:
    "Executes deep autonomous security audit for Solana SPL tokens using x402 sub-cent micropayments, evaluating honeypot traps, mint/freeze authority, bundler snipers, and MEV sandwich risk.",

  validate: async (_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> => {
    const text = message.content?.text || "";
    return extractValidSolanaAddresses(text).length > 0;
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    _options?: any,
    callback?: HandlerCallback
  ): Promise<boolean> => {
    const text = message.content?.text || "";
    const addresses = extractValidSolanaAddresses(text);

    if (addresses.length === 0) {
      if (callback) {
        await callback({
          text: "Please provide a valid Solana token mint address to audit.",
        });
      }
      return false;
    }

    const mintAddress = addresses[0];

    const privateKey =
      runtime.getSetting("AGENT_SOLANA_PRIVATE_KEY") ||
      runtime.getSetting("SOLANA_PRIVATE_KEY") ||
      process.env.AGENT_SOLANA_PRIVATE_KEY ||
      process.env.SOLANA_PRIVATE_KEY;

    const baseUrl =
      runtime.getSetting("RUGCHECK_API_URL") ||
      runtime.getSetting("API_BASE_URL") ||
      process.env.RUGCHECK_API_URL ||
      process.env.API_BASE_URL ||
      "http://localhost:4020";

    const client = new RugcheckX402Client({
      baseUrl,
      privateKey,
    });

    try {
      if (callback) {
        await callback({
          text: `🔍 [x402 Autonomy] Intercepting challenge & settling sub-cent USDC payment to audit \`${mintAddress}\`...`,
        });
      }

      const audit = await client.fullSecurityAudit(mintAddress);

      const safetyBadge = audit.canAgentSafelyTrade ? "✅ SAFE TO TRADE" : "❌ HIGH RISK - DO NOT TRADE";
      const honeypotStatus = audit.riskReport.flags.isHoneypot ? "🚨 YES (HONEYPOT)" : "🛡️ Clean (No honeypot)";
      const freezeStatus = audit.riskReport.flags.freezeAuthorityRevoked ? "🛡️ Revoked/Safe" : "⚠️ ACTIVE (Can freeze funds)";
      const mintStatus = audit.riskReport.flags.mintAuthorityRevoked ? "🛡️ Revoked/Safe" : "⚠️ ACTIVE (Can mint new tokens)";
      const lpStatus = `${audit.riskReport.flags.lpBurnedPercent}% Locked/Burned`;

      const priorityGas = audit.mevReport.recommendedGasAndFees?.priorityFeeMicroLamports?.fast ?? 50000;
      const maxSlippage = audit.mevReport.recommendedGasAndFees?.maxSafeSlippagePercent ?? 1.5;

      const replyText = [
        `🛡️ **Solana Token Security Audit (x402 Verified)**`,
        `**Token**: \`${audit.tokenAddress}\``,
        `**Verdict**: ${safetyBadge} (Safety Score: **${audit.overallSafetyScore}/100**)`,
        `**Summary**: ${audit.verdict || audit.actionableSummary || audit.riskReport.verdict}`,
        ``,
        `📊 **Smart Contract & Honeypot Analysis**:`,
        `- Honeypot Trap: ${honeypotStatus}`,
        `- Freeze Authority: ${freezeStatus}`,
        `- Mint Authority: ${mintStatus}`,
        `- Liquidity Pool: ${lpStatus}`,
        `- Risk Level: ${audit.riskReport.riskLevel} (Score: ${audit.riskReport.riskScore}/100)`,
        ``,
        `🎯 **Bundler & Sniper Cabal Telemetry**:`,
        `- Sniper Threat: ${audit.bundlerReport.summary.threatScore}/100 (${audit.bundlerReport.summary.recommendation})`,
        `- Bundled Launch Supply: ${audit.bundlerReport.totalBundledSupplyPercent}%`,
        `- Stealth Wallets: ${audit.bundlerReport.stealthWalletCount}`,
        ``,
        `⚡ **MEV & Frontrunning Protection**:`,
        `- Sandwich Threat: **${audit.mevReport.sandwichVulnerability}**`,
        `- Optimal Priority Gas: \`${priorityGas} microLamports/CU\``,
        `- Safe Max Slippage: \`${maxSlippage}%\``,
        `- Agent Advice: ${audit.mevReport.agentExecutionAdvice}`,
        audit.paymentReceipt
          ? `\n💳 *Settled via x402 Micropayment (TX: \`${audit.paymentReceipt.signature}\`)*`
          : "",
      ].join("\n");

      if (callback) {
        await callback({
          text: replyText,
          action: "SOLANA_RUGCHECK_X402",
          data: audit,
        });
      }

      return true;
    } catch (err: any) {
      if (callback) {
        await callback({
          text: `❌ Error auditing token \`${mintAddress}\`: ${err.message}`,
        });
      }
      return false;
    }
  },

  examples: [
    [
      {
        user: "user",
        content: { text: "Can you audit 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU for rugpull or honeypot risk?" },
      },
      {
        user: "agent",
        content: {
          text: "I'll run a full x402 security audit on that Solana token right away.",
          action: "SOLANA_RUGCHECK_X402",
        },
      },
    ],
    [
      {
        user: "user",
        content: { text: "Is GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse safe to buy, or was it bundled?" },
      },
      {
        user: "agent",
        content: {
          text: "Scanning genesis bundles and sniper clusters for this mint...",
          action: "SOLANA_RUGCHECK_X402",
        },
      },
    ],
  ] as ActionExample[][],
};
