import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Server } from "http";
import { createApp } from "../src/server/index.js";
import { SolanaAgentClient } from "../src/client/agent-client.js";
import { Keypair } from "@solana/web3.js";
import { X402PaymentRequirement, X402PaymentSignature } from "../src/types/index.js";

describe("x402 Payment Protocol & Autonomous Agent Flow", () => {
  let server: Server;
  let baseUrl: string;
  const testPort = 4029;

  beforeAll(async () => {
    const { app } = createApp();
    await new Promise<void>((resolve) => {
      server = app.listen(testPort, () => {
        baseUrl = `http://localhost:${testPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it("should allow public access to /api/health without requiring 402 payment", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.status).toBe("ok");
    expect(body.protocol).toContain("x402");
  });

  it("should return HTTP 402 Payment Required challenge on protected endpoint", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const res = await fetch(`${baseUrl}/api/token/risk/${mint}`);

    expect(res.status).toBe(402);
    expect(res.headers.get("payment-required")).toBeTruthy();
    expect(res.headers.get("x402-network")).toContain("solana");
    expect(res.headers.get("x402-pay-to")).toBeTruthy();
    expect(res.headers.get("x402-amount")).toBe("2000");

    const body = (await res.json()) as any;
    expect(body.error).toBe("Payment Required");
    expect(body.x402).toBeTruthy();
    expect(body.x402.nonce).toBeTruthy();
  });

  it("should reject tampered or invalid payment signature with 402", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    // 1. Get challenge
    const challengeRes = await fetch(`${baseUrl}/api/token/risk/${mint}`);
    const requirement: X402PaymentRequirement = JSON.parse(challengeRes.headers.get("payment-required")!);

    // 2. Craft invalid / forged signature
    const fakeKeypair = Keypair.generate();
    const forgedPayment: X402PaymentSignature = {
      version: "2.0",
      network: requirement.network,
      scheme: "exact",
      payer: fakeKeypair.publicKey.toBase58(),
      payTo: requirement.payTo,
      amount: requirement.amount,
      nonce: requirement.nonce,
      timestamp: Date.now(),
      signature: Buffer.from(new Uint8Array(64).fill(1)).toString("base64"), // Invalid garbage signature
    };

    const retryRes = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: {
        "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(forgedPayment)).toString("base64"),
      },
    });

    expect(retryRes.status).toBe(402);
    const errBody = (await retryRes.json()) as any;
    expect(errBody.error).toContain("Cryptographic signature verification failed");
  });

  it("should execute full autonomous payment flow using SolanaAgentClient and unlock 200 OK", async () => {
    const agent = new SolanaAgentClient({ baseUrl, debug: false });
    const testMint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

    // Autonomous call to token risk
    const riskReport = await agent.getTokenRisk(testMint);
    expect(riskReport).toBeTruthy();
    expect(riskReport.tokenAddress).toBe(testMint);
    expect(riskReport.riskLevel).toBe("LOW");

    // Autonomous call to bundler detection
    const bundlerReport = await agent.getBundlerDetection(testMint);
    expect(bundlerReport).toBeTruthy();
    expect(bundlerReport.tokenAddress).toBe(testMint);
    expect(bundlerReport.summary.recommendation).toBe("PROCEED_SAFE");

    // Autonomous call to MEV intelligence
    const mevReport = await agent.getMevIntelligence(testMint);
    expect(mevReport).toBeTruthy();
    expect(mevReport.tokenAddress).toBe(testMint);
    expect(mevReport.sandwichVulnerability).toBe("LOW");

    // Autonomous call to POST full audit
    const fullAudit = await agent.getFullSecurityAudit(testMint);
    expect(fullAudit).toBeTruthy();
    expect(fullAudit.overallSafetyScore).toBeGreaterThanOrEqual(60);
    expect(fullAudit.canAgentSafelyTrade).toBe(true);
    expect(fullAudit.paymentReceipt).toBeTruthy();
    expect(fullAudit.paymentReceipt?.amountUsd).toBe("$0.005");
  });

  it("should prevent replay attacks by rejecting a reused payment nonce", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const agent = new SolanaAgentClient({ baseUrl, debug: false });

    // Step 1: Get challenge nonce
    const challengeRes = await fetch(`${baseUrl}/api/token/risk/${mint}`);
    const requirement: X402PaymentRequirement = JSON.parse(challengeRes.headers.get("payment-required")!);

    // Step 2: Sign valid payload
    const payment = await agent.signPaymentChallenge(requirement);
    const paymentHeader = Buffer.from(JSON.stringify(payment)).toString("base64");

    // Step 3: First consumption -> success 200
    const res1 = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: { "PAYMENT-SIGNATURE": paymentHeader },
    });
    expect(res1.status).toBe(200);

    // Step 4: Replay exact same payload -> must fail with 402 replay error
    const res2 = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: { "PAYMENT-SIGNATURE": paymentHeader },
    });
    expect(res2.status).toBe(402);
    const errBody = (await res2.json()) as any;
    expect(errBody.error).toContain("Replay detected");
  });

  it("should return HTTP 400 Bad Request for malformed payment headers (null, non-object, invalid encoding) instead of 500", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

    // Case A: Base64-encoded "null"
    const nullHeader = Buffer.from("null").toString("base64");
    const resA = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: { "PAYMENT-SIGNATURE": nullHeader },
    });
    expect(resA.status).toBe(400);
    const bodyA = (await resA.json()) as any;
    expect(bodyA.error).toContain("Invalid payment signature format");

    // Case B: Base64-encoded array "[]"
    const arrayHeader = Buffer.from("[]").toString("base64");
    const resB = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: { "PAYMENT-SIGNATURE": arrayHeader },
    });
    expect(resB.status).toBe(400);

    // Case C: Invalid non-JSON string
    const garbageHeader = Buffer.from("{not valid json:").toString("base64");
    const resC = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: { "PAYMENT-SIGNATURE": garbageHeader },
    });
    expect(resC.status).toBe(400);
    const bodyC = (await resC.json()) as any;
    expect(bodyC.error).toContain("Invalid payment header encoding");
  });

  it("should return HTTP 400 Bad Request for non-numeric or invalid amount payloads", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const invalidAmountPayload = {
      payer: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
      payTo: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
      nonce: "fake_nonce_123",
      amount: "abc_not_a_number",
      signature: Buffer.from(new Uint8Array(64)).toString("base64"),
    };

    const res = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: { "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(invalidAmountPayload)).toString("base64") },
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.error).toContain("Invalid payment amount");
  });

  it("should reject payments with mismatched network specifications", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const challengeRes = await fetch(`${baseUrl}/api/token/risk/${mint}`);
    const requirement: X402PaymentRequirement = JSON.parse(challengeRes.headers.get("payment-required")!);

    const agent = new SolanaAgentClient({ baseUrl, debug: false });
    const payment = await agent.signPaymentChallenge(requirement);
    // Tamper with network
    payment.network = "ethereum:1";

    const res = await fetch(`${baseUrl}/api/token/risk/${mint}`, {
      headers: { "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(payment)).toString("base64") },
    });
    expect(res.status).toBe(402);
    const body = (await res.json()) as any;
    expect(body.error).toContain("network mismatch");
  });

  it("should protect against concurrent race-condition replay attacks with in-flight lock", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const agent = new SolanaAgentClient({ baseUrl, debug: false });

    // Obtain single challenge nonce
    const challengeRes = await fetch(`${baseUrl}/api/token/risk/${mint}`);
    const requirement: X402PaymentRequirement = JSON.parse(challengeRes.headers.get("payment-required")!);
    const payment = await agent.signPaymentChallenge(requirement);
    const paymentHeader = Buffer.from(JSON.stringify(payment)).toString("base64");

    // Fire 4 rapid concurrent requests with identical payment payload
    const responses = await Promise.all([
      fetch(`${baseUrl}/api/token/risk/${mint}`, { headers: { "PAYMENT-SIGNATURE": paymentHeader } }),
      fetch(`${baseUrl}/api/token/risk/${mint}`, { headers: { "PAYMENT-SIGNATURE": paymentHeader } }),
      fetch(`${baseUrl}/api/token/risk/${mint}`, { headers: { "PAYMENT-SIGNATURE": paymentHeader } }),
      fetch(`${baseUrl}/api/token/risk/${mint}`, { headers: { "PAYMENT-SIGNATURE": paymentHeader } }),
    ]);

    const statuses = responses.map((r) => r.status);
    const successCount = statuses.filter((s) => s === 200).length;
    const replayRejections = statuses.filter((s) => s === 402).length;

    // Exactly one request MUST succeed (200), and all other concurrent attempts MUST be rejected (402)
    expect(successCount).toBe(1);
    expect(replayRejections).toBe(3);
  });

  it("should correctly configure SolanaAgentClient with a pre-existing base58 private key", async () => {
    const originalKeypair = Keypair.generate();
    const { base58 } = await import("@scure/base");
    const base58Secret = base58.encode(originalKeypair.secretKey);

    const agent = new SolanaAgentClient({
      baseUrl,
      debug: false,
      privateKeyBase58: base58Secret,
    });

    expect(agent.getPublicKey()).toBe(originalKeypair.publicKey.toBase58());
  });

  it("should serve machine-readable x402 discovery manifest at /.well-known/x402.json", async () => {
    const res = await fetch(`${baseUrl}/.well-known/x402.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");

    const manifest = (await res.json()) as any;
    expect(manifest.x402Version).toBe(2);
    expect(manifest.name).toBe("solana-agent-x402-intelligence");
    expect(manifest.paymentProtocol.name).toBe("x402");
    expect(manifest.endpoints.length).toBeGreaterThanOrEqual(4);
    expect(manifest.resources.length).toBeGreaterThanOrEqual(4);

    const riskEndpoint = manifest.endpoints.find((e: any) => e.path.includes("risk"));
    expect(riskEndpoint).toBeDefined();
    expect(riskEndpoint.priceBaseUnits).toBe("2000");
    expect(riskEndpoint.asset).toBe("USDC");
  });

  it("should serve agent documentation at /llms.txt in Markdown text format", async () => {
    const res = await fetch(`${baseUrl}/llms.txt`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/plain");

    const text = await res.text();
    expect(text).toContain("# Solana Token Risk, Bundler Detection & MEV Intelligence API (x402)");
    expect(text).toContain("/api/token/risk/:address");
    expect(text).toContain("PAYMENT-REQUIRED");
    expect(text).toContain("PAYMENT-SIGNATURE");
    expect(text).toContain("/.well-known/x402.json");
  });

  it("should serve canonical OpenAPI 3.1.0 specification at /openapi.json and /.well-known/x402", async () => {
    // 1. Check /openapi.json
    const res = await fetch(`${baseUrl}/openapi.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");

    const spec = (await res.json()) as any;
    expect(spec.openapi).toBe("3.1.0");
    expect(spec.info.title).toContain("Solana Token Risk");
    expect(spec.info.contact.email).toBe("merchants@merit.systems");
    expect(spec.info["x-guidance"]).toBeTruthy();
    expect(spec.components.securitySchemes.x402).toBeDefined();
    expect(spec.components.securitySchemes.siwx).toBeDefined();

    // Verify free routes have security: []
    expect(spec.paths["/"].get.security).toEqual([]);
    expect(spec.paths["/api/health"].get.security).toEqual([]);
    expect(spec.paths["/llms.txt"].get.security).toEqual([]);
    expect(spec.paths["/.well-known/x402.json"].get.security).toEqual([]);
    expect(spec.paths["/openapi.json"].get.security).toEqual([]);

    // Verify paid routes declare x-payment-info and 402 responses
    const riskOp = spec.paths["/api/token/risk/{address}"].get;
    expect(riskOp["x-payment-info"].price.amount).toBe("0.002000");
    expect(riskOp.responses["402"]).toBeDefined();
    expect(riskOp.security).toEqual([{ x402: [] }]);

    const auditOp = spec.paths["/api/token/full-audit"].post;
    expect(auditOp["x-payment-info"].price.amount).toBe("0.005000");
    expect(auditOp.requestBody.content["application/json"].schema).toBeDefined();
    expect(auditOp.responses["402"]).toBeDefined();

    // 2. Check /.well-known/x402 alias
    const aliasRes = await fetch(`${baseUrl}/.well-known/x402`);
    expect(aliasRes.status).toBe(200);
    const aliasSpec = (await aliasRes.json()) as any;
    expect(aliasSpec.openapi).toBe("3.1.0");
  });

  it("should strictly protect against paywall bypass via trailing slash on GET and POST endpoints", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

    // 1. GET with trailing slash MUST return 402, NOT 200
    const getRes = await fetch(`${baseUrl}/api/token/risk/${mint}/`);
    expect(getRes.status).toBe(402);
    expect(getRes.headers.get("payment-required")).toBeTruthy();

    // 2. POST with trailing slash MUST return 402, NOT 200
    const postRes = await fetch(`${baseUrl}/api/token/full-audit/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tokenAddress: mint }),
    });
    expect(postRes.status).toBe(402);
    expect(postRes.headers.get("payment-required")).toBeTruthy();
  });

  it("should successfully unlock resources requested with trailing slash when valid payment is provided", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const agent = new SolanaAgentClient({ baseUrl, debug: false });

    // Initial challenge with trailing slash
    const challengeRes = await fetch(`${baseUrl}/api/token/risk/${mint}/`);
    expect(challengeRes.status).toBe(402);
    const reqSpec: X402PaymentRequirement = JSON.parse(challengeRes.headers.get("payment-required")!);

    // Sign challenge
    const payment = await agent.signPaymentChallenge(reqSpec);
    const paymentHeader = Buffer.from(JSON.stringify(payment)).toString("base64");

    // Retry with payment on trailing slash path -> must unlock 200 OK
    const unlockRes = await fetch(`${baseUrl}/api/token/risk/${mint}/`, {
      headers: { "PAYMENT-SIGNATURE": paymentHeader },
    });
    expect(unlockRes.status).toBe(200);
    const body = (await unlockRes.json()) as any;
    expect(body.success).toBe(true);
    expect(body.data.tokenAddress).toBe(mint);
  });
});
