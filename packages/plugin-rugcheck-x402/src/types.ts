/**
 * Types for @elizaos/plugin-rugcheck-x402
 * Matches core Solana Intelligence types
 */

export interface TokenSecurityFlags {
  mintAuthorityRevoked: boolean;
  freezeAuthorityRevoked: boolean;
  isHoneypot: boolean;
  buyTaxPercent: number;
  sellTaxPercent: number;
  lpBurnedPercent: number;
  top10HoldersPercent: number;
  hasMutableMetadata: boolean;
  isPumpFunGraduated: boolean;
}

export type RiskLevel = "LOW" | "MODERATE" | "HIGH" | "CRITICAL_DANGER";

export interface TokenRiskReport {
  tokenAddress: string;
  symbol: string;
  name: string;
  timestamp: string;
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: string;
  flags: TokenSecurityFlags;
  holderDistribution: {
    address: string;
    percentage: number;
    isKnownExchangeOrContract: boolean;
    tag?: string;
  }[];
  liquidityPool: {
    dex: "Raydium" | "Meteora" | "Pump.fun" | "Orca" | "Unknown";
    poolAddress: string;
    baseLiquiditySol: number;
    quoteLiquidityUsd: number;
    lpBurnedOrLocked: boolean;
    lpLockedPercentage: number;
  };
  warnings: string[];
}

export interface BundlerCluster {
  clusterId: string;
  funderAddress: string;
  walletsInvolved: string[];
  totalTokensBought: number;
  totalPercentSupply: number;
  slotPurchased: number;
  timestamp: string;
  jitoTipPaidSol: number;
  isStillHolding: boolean;
  tokensDumpedPercent: number;
}

export interface BundlerAnalysis {
  tokenAddress: string;
  analyzedSlots: number;
  bundleDetected: boolean;
  totalBundledSupplyPercent: number;
  developerClusterDetected: boolean;
  stealthWalletCount: number;
  clusters: BundlerCluster[];
  summary: {
    threatScore: number;
    recommendation: "PROCEED_SAFE" | "CAUTION_BUNDLED" | "HIGH_DUMP_RISK" | "SNIPED_CABAL";
    analysisText: string;
  };
}

export interface MevIntelligence {
  tokenAddress: string;
  timestamp: string;
  sandwichVulnerability: "LOW" | "MEDIUM" | "HIGH" | "EXTREME";
  activeMevBotsLast100Blocks: number;
  liquidityDepth: {
    priceImpactPer1Sol: number;
    priceImpactPer5Sol: number;
    priceImpactPer20Sol: number;
  };
  recommendedGasAndFees: {
    baseLamports: number;
    priorityFeeMicroLamports: {
      low: number;
      medium: number;
      fast: number;
      turboJitoTipLamports: number;
    };
    maxSafeSlippagePercent: number;
  };
  recentSandwichAttacksDetected: {
    slot: number;
    attacker: string;
    victimLossUsd: number;
    extractedSol: number;
  }[];
  agentExecutionAdvice: string;
}

export interface FullSecurityAudit {
  tokenAddress: string;
  auditTimestamp: string;
  overallSafetyScore: number;
  canAgentSafelyTrade: boolean;
  verdict?: string;
  actionableSummary?: string;
  riskReport: TokenRiskReport;
  bundlerReport: BundlerAnalysis;
  mevReport: MevIntelligence;
  paymentReceipt?: {
    payer: string;
    amountUsd: string;
    settlementNetwork: string;
    signature: string;
  };
}

export interface X402PaymentRequirement {
  version: string;
  network: string;
  scheme: string;
  payTo: string;
  amount: string;
  asset?: string;
  assetDecimals?: number;
  nonce: string;
  timestamp: number;
  expiresAt: number;
  description: string;
}

export interface X402PaymentSignature {
  version: string;
  network: string;
  scheme: string;
  payer: string;
  payTo: string;
  amount: string;
  nonce: string;
  timestamp: number;
  signature: string;
  txHash?: string;
}

export interface X402PaymentReceipt {
  status: "settled" | "simulated";
  payer: string;
  amount: string;
  asset: string;
  network: string;
  nonce: string;
  settlementTx: string;
  timestamp: number;
}

// ElizaOS Plugin Framework Interfaces
export interface ActionExample {
  user: string;
  content: {
    text: string;
    action?: string;
    [key: string]: any;
  };
}

export type HandlerCallback = (response: {
  text: string;
  action?: string;
  data?: any;
  [key: string]: any;
}) => Promise<any> | any;

export interface Memory {
  id?: string;
  userId?: string;
  agentId?: string;
  content: {
    text: string;
    [key: string]: any;
  };
  roomId?: string;
  createdAt?: number;
}

export interface State {
  [key: string]: any;
}

export interface IAgentRuntime {
  getSetting(key: string): string | undefined;
  [key: string]: any;
}

export interface Action {
  name: string;
  similes: string[];
  description: string;
  validate: (runtime: IAgentRuntime, message: Memory, state?: State) => Promise<boolean>;
  handler: (
    runtime: IAgentRuntime,
    message: Memory,
    state?: State,
    options?: any,
    callback?: HandlerCallback
  ) => Promise<boolean | any>;
  examples: ActionExample[][];
}

export interface Plugin {
  name: string;
  description: string;
  actions?: Action[];
  evaluators?: any[];
  providers?: any[];
  services?: any[];
}
