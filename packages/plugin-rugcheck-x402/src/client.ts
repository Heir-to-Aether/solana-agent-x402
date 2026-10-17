import { Keypair } from "@solana/web3.js";
import { base58 } from "@scure/base";
import {
  X402PaymentRequirement,
  X402PaymentSignature,
  X402PaymentReceipt,
  TokenRiskReport,
  BundlerAnalysis,
  MevIntelligence,
  FullSecurityAudit,
} from "./types.js";

export interface RugcheckClientConfig {
  baseUrl?: string;
  privateKey?: string;
  keypair?: Keypair;
  debug?: boolean;
}

export class RugcheckX402Client {
  public baseUrl: string;
  public keypair: Keypair;
  public debug: boolean;

  constructor(config: RugcheckClientConfig = {}) {
    this.baseUrl = (
      config.baseUrl ||
      (typeof process !== "undefined" && (process.env.RUGCHECK_API_URL || process.env.API_BASE_URL)) ||
      "http://localhost:4020"
    ).replace(/\/$/, "");

    this.debug = config.debug ?? false;

    if (config.keypair) {
      this.keypair = config.keypair;
    } else if (config.privateKey) {
      try {
        const trimmed = config.privateKey.trim();
        if (trimmed.startsWith("[")) {
          this.keypair = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(trimmed)));
        } else {
          this.keypair = Keypair.fromSecretKey(base58.decode(trimmed));
        }
      } catch (err) {
        this.keypair = Keypair.generate();
      }
    } else if (typeof process !== "undefined" && (process.env.AGENT_SOLANA_PRIVATE_KEY || process.env.SOLANA_PRIVATE_KEY)) {
      const key = process.env.AGENT_SOLANA_PRIVATE_KEY || process.env.SOLANA_PRIVATE_KEY || "";
      try {
        const trimmed = key.trim();
        if (trimmed.startsWith("[")) {
          this.keypair = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(trimmed)));
        } else {
          this.keypair = Keypair.fromSecretKey(base58.decode(trimmed));
        }
      } catch {
        this.keypair = Keypair.generate();
      }
    } else {
      this.keypair = Keypair.generate();
    }
  }

  public getPublicKey(): string {
    return this.keypair.publicKey.toBase58();
  }

  public async fetchWithPayment<T = any>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<{ data: T; receipt?: X402PaymentReceipt }> {
    const url = endpoint.startsWith("http")
      ? endpoint
      : `${this.baseUrl}${endpoint.startsWith("/") ? "" : "/"}${endpoint}`;

    if (this.debug) {
      console.log(`[RugcheckX402Client] Requesting: ${url}`);
    }

    const initialRes = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (initialRes.ok) {
      const data = (await initialRes.json()) as T;
      return { data };
    }

    if (initialRes.status === 402) {
      if (this.debug) {
        console.log(`[RugcheckX402Client] Intercepted HTTP 402 challenge, signing payment...`);
      }

      let requirement: X402PaymentRequirement;
      const headerReq = initialRes.headers.get("payment-required");
      if (headerReq) {
        try {
          requirement = headerReq.startsWith("{")
            ? JSON.parse(headerReq)
            : JSON.parse(Buffer.from(headerReq, "base64").toString("utf-8"));
        } catch {
          const body = (await initialRes.json()) as any;
          if (body && body.x402) requirement = body.x402;
          else throw new Error("Received 402 status but could not parse x402 payment specifications.");
        }
      } else {
        const body = (await initialRes.json()) as any;
        if (body && body.x402) requirement = body.x402;
        else throw new Error("Received 402 status but could not find x402 payment specifications in headers or body.");
      }

      const paymentPayload = await this.signPaymentChallenge(requirement);
      const paymentHeader = Buffer.from(JSON.stringify(paymentPayload)).toString("base64");

      const paidRes = await fetch(url, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          ...options.headers,
          "PAYMENT-SIGNATURE": paymentHeader,
        },
      });

      if (!paidRes.ok) {
        const errText = await paidRes.text();
        throw new Error(`x402 payment settlement failed (${paidRes.status}): ${errText}`);
      }

      const receiptHeader = paidRes.headers.get("payment-response");
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

      const responseJson = (await paidRes.json()) as any;
      return {
        data: responseJson.data !== undefined ? (responseJson.data as T) : (responseJson as T),
        receipt,
      };
    }

    const errText = await initialRes.text();
    throw new Error(`Request failed with status ${initialRes.status}: ${errText}`);
  }

  public async signPaymentChallenge(req: X402PaymentRequirement): Promise<X402PaymentSignature> {
    const payer = this.keypair.publicKey.toBase58();
    const timestamp = Date.now();
    const message = `${req.nonce}:${payer}:${req.payTo}:${req.amount}:${timestamp}`;
    const messageBytes = Buffer.from(message, "utf-8");

    let signatureBase64: string;
    try {
      const tweetnacl = await import("tweetnacl");
      const naclSign = (tweetnacl as any).default?.sign || (tweetnacl as any).sign;
      const sigBytes = naclSign.detached(new Uint8Array(messageBytes), this.keypair.secretKey);
      signatureBase64 = Buffer.from(sigBytes).toString("base64");
    } catch {
      const { createPrivateKey, sign } = await import("crypto");
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

  public async auditToken(mintAddress: string): Promise<TokenRiskReport> {
    const res = await this.fetchWithPayment<TokenRiskReport>(`/api/token/risk/${mintAddress}`);
    return res.data;
  }

  public async detectBundlers(mintAddress: string): Promise<BundlerAnalysis> {
    const res = await this.fetchWithPayment<BundlerAnalysis>(`/api/token/bundler/${mintAddress}`);
    return res.data;
  }

  public async getMevIntel(mintAddress: string): Promise<MevIntelligence> {
    const res = await this.fetchWithPayment<MevIntelligence>(`/api/token/mev/${mintAddress}`);
    return res.data;
  }

  public async fullSecurityAudit(mintAddress: string): Promise<FullSecurityAudit> {
    const res = await this.fetchWithPayment<FullSecurityAudit>(`/api/token/full-audit`, {
      method: "POST",
      body: JSON.stringify({ tokenAddress: mintAddress }),
    });
    if (!res.data.paymentReceipt && res.receipt) {
      res.data.paymentReceipt = {
        payer: res.receipt.payer,
        amountUsd: "$0.005",
        settlementNetwork: res.receipt.network,
        signature: res.receipt.settlementTx || res.receipt.nonce,
      };
    }
    return res.data;
  }
}
