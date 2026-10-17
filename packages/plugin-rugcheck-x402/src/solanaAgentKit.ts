import { Keypair } from "@solana/web3.js";
import { RugcheckX402Client } from "./client.js";
import { FullSecurityAudit, TokenRiskReport, BundlerAnalysis, MevIntelligence } from "./types.js";

export interface SolanaAgentKitWallet {
  secretKey?: Uint8Array;
  publicKey?: { toBase58(): string };
}

export interface SolanaAgentKitAgent {
  wallet?: SolanaAgentKitWallet;
  keypair?: Keypair;
}

export interface RugcheckToolOptions {
  baseUrl?: string;
  privateKey?: string;
}

/**
 * Creates a Solana Agent Kit compatible tool for token security auditing
 */
export function createRugcheckTool(options: RugcheckToolOptions = {}) {
  return {
    name: "solana_rugcheck_x402",
    description:
      "Performs a comprehensive Solana token risk, honeypot, bundler sniping, and MEV intelligence audit using x402 USDC micropayments.",
    parameters: {
      type: "object",
      properties: {
        tokenAddress: {
          type: "string",
          description: "The Solana SPL token mint address (base58) to audit",
        },
      },
      required: ["tokenAddress"],
    },
    execute: async (
      agent: SolanaAgentKitAgent | null,
      input: { tokenAddress: string }
    ): Promise<FullSecurityAudit> => {
      let keypair: Keypair | undefined;
      if (agent?.keypair) {
        keypair = agent.keypair;
      } else if (agent?.wallet?.secretKey) {
        keypair = Keypair.fromSecretKey(agent.wallet.secretKey);
      }

      const client = new RugcheckX402Client({
        baseUrl: options.baseUrl,
        privateKey: options.privateKey,
        keypair,
      });

      return await client.fullSecurityAudit(input.tokenAddress);
    },
  };
}
