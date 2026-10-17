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
  riskScore: number; // 0 to 100 (0 = safest, 100 = definite rug/scam)
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
    threatScore: number; // 0 to 100
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
    priceImpactPer1Sol: number; // %
    priceImpactPer5Sol: number; // %
    priceImpactPer20Sol: number; // %
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
  overallSafetyScore: number; // 0 (rugged) to 100 (fully safe)
  canAgentSafelyTrade: boolean;
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

// x402 Protocol Specification Types
export interface X402PaymentRequirement {
  version: "2.0";
  network: string; // CAIP-2 Solana e.g. "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" or "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
  scheme: "exact";
  payTo: string; // Solana public key recipient
  amount: string; // Base units (e.g. "2000" = $0.002 USDC 6-decimals) or USD format "$0.002"
  asset: string; // Mint address or symbol (e.g. USDC: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v)
  assetDecimals: number;
  nonce: string; // Unique cryptographic challenge nonce
  timestamp: number;
  expiresAt: number;
  description: string;
}

export interface X402PaymentSignature {
  version: "2.0";
  network: string;
  scheme: "exact";
  payer: string; // Solana public key of payer
  payTo: string;
  amount: string;
  nonce: string;
  timestamp: number;
  signature: string; // Ed25519 signature of payload: `${nonce}:${payer}:${payTo}:${amount}:${timestamp}`
  txHash?: string; // Optional on-chain transaction hash or simulated facilitator proof
}

export interface X402PaymentReceipt {
  status: "verified" | "settled";
  payer: string;
  amount: string;
  asset: string;
  network: string;
  nonce: string;
  settlementTx?: string;
  timestamp: number;
}
