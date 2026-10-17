import { Request, Response, NextFunction } from "express";
import { PublicKey } from "@solana/web3.js";
import { randomBytes } from "crypto";
import { X402PaymentRequirement, X402PaymentSignature, X402PaymentReceipt } from "../types/index.js";

export interface X402RouteConfig {
  priceUsd: string; // e.g. "$0.002"
  amountBaseUnits: string; // 2000 (0.002 USDC with 6 decimals)
  description: string;
}

export interface X402MiddlewareOptions {
  recipientAddress?: string;
  network?: string;
  facilitatorUrl?: string;
  allowSimulatedDevnet?: boolean;
}

// In-memory nonce cache for replay protection (with TTL and in-flight concurrency locks)
const activeChallenges = new Map<string, { requirement: X402PaymentRequirement; createdAt: number }>();
const usedNonces = new Map<string, number>(); // Nonce -> expiresAt ms
const inFlightNonces = new Set<string>();

// Cleanup stale nonces every 10 minutes
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [nonce, data] of activeChallenges.entries()) {
    if (now > data.requirement.expiresAt) {
      activeChallenges.delete(nonce);
    }
  }
  for (const [nonce, expiresAt] of usedNonces.entries()) {
    if (now > expiresAt) {
      usedNonces.delete(nonce);
    }
  }
}, 600000);
// Ensure timer does not prevent process exit
cleanupTimer.unref();

export function clearNonceCache(): void {
  activeChallenges.clear();
  usedNonces.clear();
  inFlightNonces.clear();
}

export function createX402Middleware(
  routeConfigs: Record<string, X402RouteConfig>,
  options: X402MiddlewareOptions = {}
) {
  const recipientAddress =
    options.recipientAddress ||
    process.env.SOLANA_RECIPIENT_WALLET ||
    process.env.SOLANA_RECIPIENT_ADDRESS ||
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
  const rawNetwork =
    options.network ||
    process.env.SOLANA_NETWORK ||
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"; // Solana Devnet CAIP-2
  const allowSimulatedDevnet = options.allowSimulatedDevnet ?? true;

  // Resolve network CAIP-2 identifier
  const isDevnet = rawNetwork.toLowerCase().includes("devnet") || rawNetwork.toLowerCase().includes("etwtrabzayq6imfeykouru166vu2xqa1");
  const network = rawNetwork.startsWith("solana:")
    ? rawNetwork
    : isDevnet
    ? "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    : "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

  // Resolve USDC mint address according to network
  const usdcAssetAddress = isDevnet
    ? "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" // Devnet USDC
    : "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // Mainnet USDC

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Route matching key: "METHOD PATH" or path pattern (normalized without trailing slashes)
    const rawPath = req.path || "/";
    const normalizedPath = rawPath.replace(/\/+/g, "/").replace(/(.+)\/+$/, "$1");
    const methodUpper = req.method.toUpperCase();
    const routeKey = `${methodUpper} ${normalizedPath}`;

    const matchingConfig =
      routeConfigs[routeKey] ||
      routeConfigs[normalizedPath] ||
      Object.entries(routeConfigs).find(([pattern]) => {
        const [method, p] = pattern.includes(" ") ? pattern.split(" ") : [methodUpper, pattern];
        if (method.toUpperCase() !== methodUpper) return false;
        const normalizedPattern = p.replace(/\/+/g, "/").replace(/(.+)\/+$/, "$1");
        // Convert express style :param to wildcard regex, matching both raw and normalized paths
        const regex = new RegExp(`^${normalizedPattern.replace(/:[^\s/]+/g, "[^/]+")}/?$`);
        return regex.test(rawPath) || regex.test(normalizedPath);
      })?.[1];

    if (!matchingConfig) {
      // Endpoint is not gated by x402
      return next();
    }

    // Check for payment signature in headers
    const paymentHeader =
      req.header("payment-signature") ||
      req.header("x-payment-signature") ||
      req.header("x402") ||
      (req.header("authorization")?.toLowerCase().startsWith("x402 ")
        ? req.header("authorization")?.slice(5).trim()
        : null);

    if (!paymentHeader) {
      // No payment provided -> Issue HTTP 402 challenge
      const nonce = randomBytes(16).toString("hex");
      const timestamp = Date.now();
      const expiresAt = timestamp + 300000; // 5 minutes TTL

      const requirement: X402PaymentRequirement = {
        version: "2.0",
        network,
        scheme: "exact",
        payTo: recipientAddress,
        amount: matchingConfig.amountBaseUnits,
        asset: usdcAssetAddress,
        assetDecimals: 6,
        nonce,
        timestamp,
        expiresAt,
        description: matchingConfig.description,
      };

      activeChallenges.set(nonce, { requirement, createdAt: timestamp });

      res.status(402);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("PAYMENT-REQUIRED", JSON.stringify(requirement));
      res.setHeader("x402-network", requirement.network);
      res.setHeader("x402-pay-to", requirement.payTo);
      res.setHeader("x402-amount", requirement.amount);
      res.setHeader("x402-nonce", requirement.nonce);

      res.json({
        error: "Payment Required",
        message: `Endpoint requires micro-payment of ${matchingConfig.priceUsd} (${matchingConfig.amountBaseUnits} USDC base units). Sign payment challenge to proceed.`,
        x402: requirement,
        instructions: {
          step1: "Extract payment specifications from PAYMENT-REQUIRED header or x402 payload.",
          step2: "Construct payload string: `${nonce}:${payerPublicKey}:${payTo}:${amount}:${timestamp}`.",
          step3: "Sign message using your agent's Solana keypair (Ed25519 signature).",
          step4: "Re-send request with 'PAYMENT-SIGNATURE' header containing base64 JSON payload.",
        },
      });
      return;
    }

    // Payment header present -> parse and verify
    try {
      let parsedPayment: X402PaymentSignature;
      try {
        const decodedString = paymentHeader.startsWith("{")
          ? paymentHeader
          : Buffer.from(paymentHeader, "base64").toString("utf-8");
        parsedPayment = JSON.parse(decodedString);
      } catch {
        res.status(400).json({ error: "Invalid payment header encoding. Must be JSON or base64-encoded JSON." });
        return;
      }

      // Validate parsed format is a non-null object
      if (!parsedPayment || typeof parsedPayment !== "object" || Array.isArray(parsedPayment)) {
        res.status(400).json({ error: "Invalid payment signature format: expected a JSON object payload." });
        return;
      }

      // Validate required fields
      if (!parsedPayment.payer || !parsedPayment.nonce || !parsedPayment.signature || !parsedPayment.amount) {
        res.status(400).json({ error: "Incomplete payment signature payload: missing payer, nonce, signature, or amount." });
        return;
      }

      // Validate amount format (must be integer string base units)
      if (typeof parsedPayment.amount !== "string" || !/^\d+$/.test(parsedPayment.amount)) {
        res.status(400).json({ error: "Invalid payment amount: must be positive integer string in base units." });
        return;
      }

      // Check replay attack protection and in-flight lock
      if (usedNonces.has(parsedPayment.nonce) || inFlightNonces.has(parsedPayment.nonce)) {
        res.status(402).json({ error: "Replay detected: payment nonce has already been consumed or is currently processing." });
        return;
      }

      // Check if nonce was issued by this server
      const challenge = activeChallenges.get(parsedPayment.nonce);
      if (!challenge && !allowSimulatedDevnet) {
        res.status(402).json({ error: "Unknown or expired payment nonce." });
        return;
      }

      if (challenge && Date.now() > challenge.requirement.expiresAt) {
        activeChallenges.delete(parsedPayment.nonce);
        res.status(402).json({ error: "Payment challenge has expired. Please re-query to obtain a fresh nonce." });
        return;
      }

      // Verify recipient matches
      if (parsedPayment.payTo !== recipientAddress) {
        res.status(402).json({ error: `Payment recipient mismatch: expected ${recipientAddress}` });
        return;
      }

      // Verify network matches
      if (parsedPayment.network && parsedPayment.network !== network) {
        res.status(402).json({ error: `Payment network mismatch: expected ${network}` });
        return;
      }

      // Verify payment amount satisfies requirement
      const paidAmount = BigInt(parsedPayment.amount);
      const requiredAmount = BigInt(matchingConfig.amountBaseUnits);
      if (paidAmount < requiredAmount) {
        res.status(402).json({
          error: `Insufficient payment: required ${requiredAmount.toString()} base units, received ${paidAmount.toString()}`,
        });
        return;
      }

      // Mark nonce as in-flight to prevent race condition replay
      inFlightNonces.add(parsedPayment.nonce);
      let isValidSignature = false;
      try {
        isValidSignature = await verifySolanaPaymentSignature(parsedPayment);
      } finally {
        inFlightNonces.delete(parsedPayment.nonce);
      }

      if (!isValidSignature) {
        res.status(402).json({ error: "Cryptographic signature verification failed for payer." });
        return;
      }

      // Mark nonce as consumed with expiration TTL
      const nonceExpiresAt = challenge ? challenge.requirement.expiresAt : Date.now() + 600000;
      usedNonces.set(parsedPayment.nonce, nonceExpiresAt);
      activeChallenges.delete(parsedPayment.nonce);

      // Generate settlement receipt
      const receipt: X402PaymentReceipt = {
        status: "settled",
        payer: parsedPayment.payer,
        amount: parsedPayment.amount,
        asset: usdcAssetAddress,
        network,
        nonce: parsedPayment.nonce,
        settlementTx: parsedPayment.txHash || `sim_${randomBytes(16).toString("hex")}`,
        timestamp: Date.now(),
      };

      res.setHeader("PAYMENT-RESPONSE", JSON.stringify(receipt));
      (req as any).paymentReceipt = receipt;

      return next();
    } catch (err: any) {
      res.status(500).json({ error: "Failed to process payment authorization", details: err.message });
      return;
    }
  };
}

/**
 * Verifies Ed25519 signature of message payload:
 * `${nonce}:${payer}:${payTo}:${amount}:${timestamp}`
 */
export async function verifySolanaPaymentSignature(payment: X402PaymentSignature): Promise<boolean> {
  try {
    const payerPubkey = new PublicKey(payment.payer);
    const message = `${payment.nonce}:${payment.payer}:${payment.payTo}:${payment.amount}:${payment.timestamp}`;
    const messageBytes = Buffer.from(message, "utf-8");

    // Support both base64 and hex signature formats
    let sigBytes: Uint8Array;
    if (payment.signature.length === 128) {
      sigBytes = new Uint8Array(Buffer.from(payment.signature, "hex"));
    } else {
      sigBytes = new Uint8Array(Buffer.from(payment.signature, "base64"));
    }

    // Try tweetnacl if installed
    try {
      const tweetnacl = await import("tweetnacl");
      const naclSign = tweetnacl.default?.sign || tweetnacl.sign;
      if (naclSign?.detached?.verify) {
        return naclSign.detached.verify(
          new Uint8Array(messageBytes),
          sigBytes,
          payerPubkey.toBytes()
        );
      }
    } catch {
      // tweetnacl not directly resolvable, fallback to ed25519 DER verification
    }

    // Native Node crypto verification with Ed25519 DER header
    const { createPublicKey, verify } = await import("crypto");
    const ed25519DerPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const derKey = Buffer.concat([ed25519DerPrefix, payerPubkey.toBuffer()]);
    const publicKeyObject = createPublicKey({
      key: derKey,
      format: "der",
      type: "spki",
    });

    return verify(null, messageBytes, publicKeyObject, sigBytes);
  } catch (err) {
    return false;
  }
}
