import dotenv from "dotenv";
dotenv.config();

import { Keypair, PublicKey } from "@solana/web3.js";
import { base58 } from "@scure/base";
import { X402PaymentRequirement, X402PaymentSignature, X402PaymentReceipt, FullSecurityAudit, TokenRiskReport, BundlerAnalysis, MevIntelligence } from "../types/index.js";

export interface AgentClientConfig {
  baseUrl?: string;
  keypair?: Keypair;
  privateKeyBase58?: string;
  debug?: boolean;
}

export class SolanaAgentClient {
  public keypair: Keypair;
  public baseUrl: string;
  public debug: boolean;

  constructor(config: AgentClientConfig = {}) {
    this.baseUrl = (config.baseUrl || process.env.API_BASE_URL || "http://localhost:4020").replace(/\/$/, "");
    this.debug = config.debug ?? true;

    const privateKeyInput = config.privateKeyBase58 || process.env.AGENT_SOLANA_PRIVATE_KEY;
    if (config.keypair) {
      this.keypair = config.keypair;
    } else if (privateKeyInput) {
      try {
        const trimmed = privateKeyInput.trim();
        if (trimmed.startsWith("[")) {
          this.keypair = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(trimmed)));
        } else {
          this.keypair = Keypair.fromSecretKey(base58.decode(trimmed));
        }
      } catch (err) {
        console.warn("Failed to parse provided private key; generating new session keypair.");
        this.keypair = Keypair.generate();
      }
    } else {
      // Generate a new autonomous agent keypair for session
      this.keypair = Keypair.generate();
    }
  }

  public getPublicKey(): string {
    return this.keypair.publicKey.toBase58();
  }

  /**
   * Executes autonomous request with automatic x402 challenge capture and payment signing
   */
  public async fetchWithPayment<T = any>(endpoint: string, options: RequestInit = {}): Promise<{ data: T; receipt?: X402PaymentReceipt }> {
    const url = endpoint.startsWith("http") ? endpoint : `${this.baseUrl}${endpoint.startsWith("/") ? "" : "/"}${endpoint}`;

    if (this.debug) {
      console.log(`\n🤖 [AI Agent] Requesting resource: ${url}`);
    }

    // Step 1: Initial attempt without payment
    const initialResponse = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (initialResponse.ok) {
      if (this.debug) console.log(`🟢 [AI Agent] Free endpoint accessed without payment (${initialResponse.status} OK)`);
      const data = (await initialResponse.json()) as T;
      return { data };
    }

    // Step 2: Handle HTTP 402 Payment Required
    if (initialResponse.status === 402) {
      if (this.debug) {
        console.log(`⚡ [AI Agent] Intercepted HTTP 402 Payment Required challenge!`);
      }

      // Extract requirement from header or body
      let requirement: X402PaymentRequirement;
      const headerReq = initialResponse.headers.get("payment-required");

      if (headerReq) {
        try {
          requirement = headerReq.startsWith("{")
            ? JSON.parse(headerReq)
            : JSON.parse(Buffer.from(headerReq, "base64").toString("utf-8"));
        } catch {
          const body = (await initialResponse.json()) as any;
          if (body && body.x402) {
            requirement = body.x402;
          } else {
            throw new Error("Received 402 status but could not parse x402 payment specifications.");
          }
        }
      } else {
        const body = (await initialResponse.json()) as any;
        if (body && body.x402) {
          requirement = body.x402;
        } else {
          throw new Error("Received 402 status but could not find x402 payment specifications in headers or body.");
        }
      }

      if (this.debug) {
        console.log(`💳 [AI Agent] Payment Terms:`);
        console.log(`   - Network:     ${requirement.network}`);
        console.log(`   - Recipient:   ${requirement.payTo}`);
        console.log(`   - Amount:      ${requirement.amount} base units (USDC)`);
        console.log(`   - Nonce:       ${requirement.nonce}`);
        console.log(`   - Purpose:     ${requirement.description}`);
      }

      // Step 3: Sign payment challenge with agent's Solana keypair
      const paymentPayload = await this.signPaymentChallenge(requirement);

      if (this.debug) {
        console.log(`✍️  [AI Agent] Generated Ed25519 cryptographic payment signature.`);
        console.log(`🚀 [AI Agent] Retrying request with 'PAYMENT-SIGNATURE' header...`);
      }

      // Step 4: Retry request with payment authorization
      const paymentHeaderValue = Buffer.from(JSON.stringify(paymentPayload)).toString("base64");
      const paidResponse = await fetch(url, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          ...options.headers,
          "PAYMENT-SIGNATURE": paymentHeaderValue,
        },
      });

      if (!paidResponse.ok) {
        const errorBody = await paidResponse.text();
        throw new Error(`Payment settlement rejected with status ${paidResponse.status}: ${errorBody}`);
      }

      // Step 5: Read payment receipt and fulfilled data
      const receiptHeader = paidResponse.headers.get("payment-response");
      let receipt: X402PaymentReceipt | undefined;
      if (receiptHeader) {
        try {
          receipt = receiptHeader.startsWith("{")
            ? JSON.parse(receiptHeader)
            : JSON.parse(Buffer.from(receiptHeader, "base64").toString("utf-8"));
        } catch {
          // ignore
        }
      }

      const responseJson = (await paidResponse.json()) as any;
      if (this.debug) {
        console.log(`🎉 [AI Agent] 200 OK Resource Unlocked!`);
        if (receipt) {
          console.log(`🧾 [AI Agent] Receipt TX: ${receipt.settlementTx} (Settled)`);
        }
      }

      return {
        data: responseJson.data !== undefined ? (responseJson.data as T) : (responseJson as T),
        receipt,
      };
    }

    const errText = await initialResponse.text();
    throw new Error(`Request failed with HTTP status ${initialResponse.status}: ${errText}`);
  }

  /**
   * Cryptographically signs the payment challenge
   */
  public async signPaymentChallenge(req: X402PaymentRequirement): Promise<X402PaymentSignature> {
    const payer = this.keypair.publicKey.toBase58();
    const timestamp = Date.now();
    const message = `${req.nonce}:${payer}:${req.payTo}:${req.amount}:${timestamp}`;
    const messageBytes = Buffer.from(message, "utf-8");

    // Dynamic import tweetnacl or use keypair secretKey
    let signatureBase64: string;
    try {
      const tweetnacl = await import("tweetnacl");
      const naclSign = tweetnacl.default?.sign || tweetnacl.sign;
      const sigBytes = naclSign.detached(new Uint8Array(messageBytes), this.keypair.secretKey);
      signatureBase64 = Buffer.from(sigBytes).toString("base64");
    } catch {
      // Fallback signing via node crypto
      const { createPrivateKey, sign } = await import("crypto");
      // Ed25519 PKCS#8 prefix for 32-byte seed
      const ed25519Pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
      const seed = this.keypair.secretKey.subarray(0, 32);
      const pkcs8Key = Buffer.concat([ed25519Pkcs8Prefix, seed]);
      const privateKeyObj = createPrivateKey({ key: pkcs8Key, format: "der", type: "pkcs8" });
      const sigBytes = sign(null, messageBytes, privateKeyObj);
      signatureBase64 = sigBytes.toString("base64");
    }

    return {
      version: "2.0",
      network: req.network,
      scheme: "exact",
      payer,
      payTo: req.payTo,
      amount: req.amount,
      nonce: req.nonce,
      timestamp,
      signature: signatureBase64,
    };
  }

  public async getTokenRisk(mintAddress: string): Promise<TokenRiskReport> {
    const res = await this.fetchWithPayment<TokenRiskReport>(`/api/token/risk/${mintAddress}`);
    return res.data;
  }

  public async getBundlerDetection(mintAddress: string): Promise<BundlerAnalysis> {
    const res = await this.fetchWithPayment<BundlerAnalysis>(`/api/token/bundler/${mintAddress}`);
    return res.data;
  }

  public async getMevIntelligence(mintAddress: string): Promise<MevIntelligence> {
    const res = await this.fetchWithPayment<MevIntelligence>(`/api/token/mev/${mintAddress}`);
    return res.data;
  }

  public async getFullSecurityAudit(mintAddress: string): Promise<FullSecurityAudit> {
    const res = await this.fetchWithPayment<FullSecurityAudit>(`/api/token/full-audit`, {
      method: "POST",
      body: JSON.stringify({ tokenAddress: mintAddress }),
    });
    return res.data;
  }
}

// Standalone CLI runner for demonstrations & tests
async function runDemo() {
  console.log("=================================================================");
  console.log("   Solana Autonomous AI Agent - x402 Micropayment Client Demo   ");
  console.log("=================================================================");

  const agent = new SolanaAgentClient({ baseUrl: "http://localhost:4020", debug: true });
  console.log(`Agent Public Key: ${agent.getPublicKey()}`);

  const testMints = [
    { name: "Legitimate Pump/Raydium Token", mint: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU" },
    { name: "Sniped Cabal & Bundler Token", mint: "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse" },
    { name: "Honeypot Freeze Risk Token", mint: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9" },
  ];

  for (const item of testMints) {
    console.log(`\n-------------------------------------------------------------`);
    console.log(`[TEST CASE] Auditing: ${item.name} (${item.mint})`);
    console.log(`-------------------------------------------------------------`);

    try {
      const fullAudit = await agent.getFullSecurityAudit(item.mint);
      console.log(`\nAudit Results:`);
      console.log(`- Overall Safety Score: ${fullAudit.overallSafetyScore}/100`);
      console.log(`- Can Agent Safely Trade? -> ${fullAudit.canAgentSafelyTrade ? "✅ YES" : "❌ NO"}`);
      console.log(`- Risk Level:           ${fullAudit.riskReport.riskLevel} (Score: ${fullAudit.riskReport.riskScore})`);
      console.log(`- Honeypot Detected:    ${fullAudit.riskReport.flags.isHoneypot}`);
      console.log(`- Bundler Threat Score: ${fullAudit.bundlerReport.summary.threatScore} (${fullAudit.bundlerReport.summary.recommendation})`);
      console.log(`- MEV Sandwich Risk:    ${fullAudit.mevReport.sandwichVulnerability}`);
      console.log(`- Agent Guidance:       ${fullAudit.mevReport.agentExecutionAdvice}`);
    } catch (err: any) {
      console.error(`Error auditing token:`, err.message);
    }
  }
}

const normalizedClientArgv1 = (process.argv[1] || "").replace(/\\/g, "/");
const isAgentClientMain =
  normalizedClientArgv1.endsWith("agent-client.ts") ||
  normalizedClientArgv1.endsWith("agent-client.js") ||
  normalizedClientArgv1.includes("agent-client");

if (isAgentClientMain) {
  runDemo();
}
