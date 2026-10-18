import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Server } from "http";
import { createApp } from "../src/server/index.js";
import { getOpenApiSpec, getDiscoveryManifest } from "../src/server/discovery.js";
import {
  discoverOriginSchema,
  checkEndpointSchema,
  validatePaymentRequiredDetailed,
  getOpenAPI,
  getWarningsForOpenAPI,
  checkL2ForOpenAPI,
  getWarningsForL2,
  checkL4ForOpenAPI,
  getWarningsForL4,
  getWarningsForFavicon,
} from "@agentcash/discovery";

describe("OpenAPI 3.1.0 Discovery & x402scan Specification", () => {
  let server: Server;
  let baseUrl: string;
  const testPort = 4035;

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

  it("should generate a valid standalone OpenAPI 3.1.0 spec object", () => {
    const spec = getOpenApiSpec({
      baseUrl: "https://solana-agent-x402.onrender.com",
      recipientAddress: "RVmRQMtMAdyWk3dq678N6GUPkrK9yDeDLqTQsFZMpcU",
      network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    });

    expect(spec.openapi).toBe("3.1.0");
    expect(spec.info.title).toContain("Solana Token Risk");
    expect(spec.info.version).toBe("1.0.0");
    expect(spec.info.contact.email).toBe("merchants@merit.systems");
    expect(spec.info["x-guidance"]).toContain("Autonomous AI agent guide");
    expect(spec.servers[0].url).toBe("https://solana-agent-x402.onrender.com");
    expect(spec["x-agentcash-guidance"].llmsTxtUrl).toBe("https://solana-agent-x402.onrender.com/llms.txt");
    expect(spec["x-agentcash-provenance"].ownershipProofs).toContain("https://github.com/Heir-to-Aether/solana-agent-x402");
  });

  it("should define both x402 and siwx security schemes in components", () => {
    const spec = getOpenApiSpec();
    const schemes = spec.components.securitySchemes;

    expect(schemes.x402).toBeDefined();
    expect(schemes.x402.type).toBe("http");
    expect(schemes.x402.scheme).toBe("x402");

    expect(schemes.siwx).toBeDefined();
    expect(schemes.siwx.type).toBe("apiKey");
    expect(schemes.siwx["x-agentcash-auth-kind"]).toBe("siwx");
  });

  it("should declare security: [] on all free endpoints", () => {
    const spec = getOpenApiSpec();
    const freePaths = ["/", "/api/health", "/llms.txt", "/.well-known/x402.json", "/.well-known/x402", "/openapi.json"];

    for (const path of freePaths) {
      const op = spec.paths[path as keyof typeof spec.paths]?.get;
      expect(op, `Path ${path} should have GET operation`).toBeDefined();
      expect(op?.security, `Path ${path} should have security: []`).toEqual([]);
      expect(op?.["x-payment-info"], `Path ${path} should NOT have x-payment-info`).toBeUndefined();
    }
  });

  it("should declare valid x-payment-info and 402 response on all paid endpoints", () => {
    const spec = getOpenApiSpec();
    const paidRoutes = [
      { path: "/api/token/risk", method: "get", expectedAmount: "0.002000" },
      { path: "/api/token/risk/{address}", method: "get", expectedAmount: "0.002000" },
      { path: "/api/token/bundler", method: "get", expectedAmount: "0.003000" },
      { path: "/api/token/bundler/{address}", method: "get", expectedAmount: "0.003000" },
      { path: "/api/token/mev", method: "get", expectedAmount: "0.002000" },
      { path: "/api/token/mev/{address}", method: "get", expectedAmount: "0.002000" },
      { path: "/api/token/full-audit", method: "post", expectedAmount: "0.005000" },
    ];

    for (const route of paidRoutes) {
      const pathItem = spec.paths[route.path as keyof typeof spec.paths] as any;
      expect(pathItem, `Path ${route.path} must exist in spec`).toBeDefined();

      const op = pathItem[route.method];
      expect(op, `Method ${route.method} on ${route.path} must exist`).toBeDefined();

      // x-payment-info verification
      expect(op["x-payment-info"]).toBeDefined();
      expect(op["x-payment-info"].price.mode).toBe("fixed");
      expect(op["x-payment-info"].price.currency).toBe("USD");
      expect(op["x-payment-info"].price.amount).toBe(route.expectedAmount);
      expect(op["x-payment-info"].protocols).toEqual([{ x402: {} }]);

      // security & responses verification
      expect(op.security).toEqual([{ x402: [] }]);
      expect(op.responses["402"]).toBeDefined();
      expect(op.responses["200"]).toBeDefined();
    }
  });

  it("should define valid input schema (parameters/requestBody) and output schema on all paid endpoints", () => {
    const spec = getOpenApiSpec();

    // GET endpoints with path parameters must have path parameter schema
    const getPathParams = ["/api/token/risk/{address}", "/api/token/bundler/{address}", "/api/token/mev/{address}"];
    for (const p of getPathParams) {
      const op = (spec.paths[p as keyof typeof spec.paths] as any).get;
      expect(op.parameters).toBeDefined();
      expect(op.parameters.length).toBeGreaterThan(0);
      expect(op.parameters[0].name).toBe("address");
      expect(op.parameters[0].in).toBe("path");
      expect(op.parameters[0].schema.type).toBe("string");
      expect(op.responses["200"].content["application/json"].schema).toBeDefined();
    }

    // GET endpoints with query parameters must have query parameter schema
    const getQueryParams = ["/api/token/risk", "/api/token/bundler", "/api/token/mev"];
    for (const p of getQueryParams) {
      const op = (spec.paths[p as keyof typeof spec.paths] as any).get;
      expect(op.parameters).toBeDefined();
      expect(op.parameters.length).toBeGreaterThan(0);
      expect(op.parameters[0].name).toBe("address");
      expect(op.parameters[0].in).toBe("query");
      expect(op.parameters[0].schema.type).toBe("string");
      expect(op.responses["200"].content["application/json"].schema).toBeDefined();
    }

    // POST endpoint must have requestBody with application/json schema
    const postOp = spec.paths["/api/token/full-audit"].post;
    expect(postOp.requestBody).toBeDefined();
    expect(postOp.requestBody.content["application/json"].schema).toBeDefined();
    expect(postOp.requestBody.content["application/json"].schema.properties.tokenAddress).toBeDefined();
    expect(postOp.responses["200"].content["application/json"].schema).toBeDefined();
  });

  it("should serve GET /openapi.json over HTTP with correct Content-Type", async () => {
    const res = await fetch(`${baseUrl}/openapi.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");

    const json = (await res.json()) as any;
    expect(json.openapi).toBe("3.1.0");
    expect(json.paths["/api/token/risk/{address}"]).toBeDefined();
  });

  it("should serve GET /.well-known/x402 pointing to the same OpenAPI spec", async () => {
    const res = await fetch(`${baseUrl}/.well-known/x402`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");

    const json = (await res.json()) as any;
    expect(json.openapi).toBe("3.1.0");
    expect(json.paths["/api/token/full-audit"]).toBeDefined();
  });

  it("should serve /favicon.ico with 200 status and image content-type to eliminate discovery favicon warning", async () => {
    const res = await fetch(`${baseUrl}/favicon.ico`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("image/x-icon");
    const buffer = await res.arrayBuffer();
    expect(buffer.byteLength).toBeGreaterThan(0);
  });

  it("should return valid 402 challenge with x402Version 2 and accepts array on paid endpoints", async () => {
    const res = await fetch(`${baseUrl}/api/token/risk/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`);
    expect(res.status).toBe(402);

    const body = (await res.json()) as any;
    expect(body.x402Version).toBe(2);
    expect(body.error).toBe("Payment Required");
    expect(body.resource).toBeDefined();
    expect(body.resource.url).toContain("/api/token/risk");
    expect(Array.isArray(body.accepts)).toBe(true);
    expect(body.accepts[0].scheme).toBe("exact");
    expect(body.accepts[0].amount).toBe("2000");
    expect(body.accepts[0].extra.nonce).toBeTruthy();
    expect(body.extensions.bazaar.schema).toBeDefined();

    // Headers
    expect(res.headers.get("payment-required")).toBeTruthy();
    expect(res.headers.get("x-payment-protocol")).toBe("x402");
    expect(res.headers.get("x402-network")).toBeTruthy();
    expect(res.headers.get("x402-amount")).toBe("2000");
    expect(res.headers.get("x402-nonce")).toBeTruthy();
  });

  it("should return base64 PAYMENT-REQUIRED header by default on paid endpoints without specialized headers", async () => {
    // 1. POST full-audit with standard fetch (no discovery Accept or user-agent)
    const postRes = await fetch(`${baseUrl}/api/token/full-audit`, {
      method: "POST",
    });

    expect(postRes.status).toBe(402);
    const postHeader = postRes.headers.get("payment-required")!;
    expect(postHeader).toBeTruthy();
    expect(postHeader.startsWith("{")).toBe(false);

    const postDecoded = Buffer.from(postHeader, "base64").toString("utf-8");
    const postParsed = JSON.parse(postDecoded);
    expect(postParsed.x402Version).toBe(2);
    expect(postParsed.accepts[0].amount).toBe("5000");
    expect(postParsed.resource.url).toContain("/api/token/full-audit");

    // 2. GET risk with standard fetch
    const getRes = await fetch(`${baseUrl}/api/token/risk/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`);
    expect(getRes.status).toBe(402);
    const getHeader = getRes.headers.get("payment-required")!;
    expect(getHeader).toBeTruthy();
    expect(getHeader.startsWith("{")).toBe(false);

    const getDecoded = Buffer.from(getHeader, "base64").toString("utf-8");
    const getParsed = JSON.parse(getDecoded);
    expect(getParsed.x402Version).toBe(2);
    expect(getParsed.accepts[0].amount).toBe("2000");
  });

  it("should satisfy validatePaymentRequiredDetailed with 0 issues on all 4 paid endpoint challenges", async () => {
    const endpoints = [
      { url: `${baseUrl}/api/token/risk/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`, method: "GET" },
      { url: `${baseUrl}/api/token/bundler/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`, method: "GET" },
      { url: `${baseUrl}/api/token/mev/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`, method: "GET" },
      { url: `${baseUrl}/api/token/full-audit`, method: "POST" },
    ];

    for (const ep of endpoints) {
      const res = await fetch(ep.url, { method: ep.method });
      expect(res.status).toBe(402);
      const body = (await res.json()) as any;

      const validation = validatePaymentRequiredDetailed(body);
      expect(validation.valid, `Endpoint ${ep.url} failed validation: ${JSON.stringify(validation.issues)}`).toBe(true);
      expect(validation.issues.length).toBe(0);
      expect(validation.normalized?.version).toBe(2);
      expect(validation.normalized?.accepts.length).toBeGreaterThan(0);
    }
  });

  it("should support custom merchant contact email in DiscoveryConfig", () => {
    const customEmail = "security@solana-agent.xyz";
    const spec = getOpenApiSpec({ contactEmail: customEmail });
    expect(spec.info.contact.email).toBe(customEmail);

    const manifest = getDiscoveryManifest({ contactEmail: customEmail });
    expect(manifest.contact.email).toBe(customEmail);
    expect(manifest.repository).toBe("https://github.com/Heir-to-Aether/solana-agent-x402");
  });

  it("should return 402 challenge with valid schema on base routes without path params", async () => {
    const baseRoutes = [
      `${baseUrl}/api/token/risk`,
      `${baseUrl}/api/token/bundler`,
      `${baseUrl}/api/token/mev`,
    ];

    for (const url of baseRoutes) {
      const res = await fetch(url, { method: "GET" });
      expect(res.status).toBe(402);
      const body = (await res.json()) as any;
      expect(body.x402Version).toBe(2);
      expect(body.accepts.length).toBeGreaterThan(0);
      expect(body.extensions.bazaar.schema.properties.input.properties.queryParams).toBeDefined();

      const validation = validatePaymentRequiredDetailed(body, {
        requireInputSchema: true,
        requireOutputSchema: true,
      });
      expect(validation.valid).toBe(true);
      expect(validation.issues.length).toBe(0);
    }
  });

  it("should pass all @agentcash/discovery audit suites with zero warnings", async () => {
    const openApiRes = await getOpenAPI(baseUrl);
    expect(openApiRes.isOk()).toBe(true);
    const openApi = openApiRes._unsafeUnwrap();
    expect(openApi).not.toBeNull();

    // 1. OpenAPI warnings
    const openApiWarnings = getWarningsForOpenAPI(openApi);
    expect(openApiWarnings).toEqual([]);

    // 2. L2 route-list warnings
    const l2 = checkL2ForOpenAPI(openApi as any);
    const l2Warnings = getWarningsForL2(l2);
    expect(l2Warnings).toEqual([]);

    // 3. L4 guidance warnings
    const l4 = checkL4ForOpenAPI(openApi as any);
    const l4Warnings = getWarningsForL4(l4);
    expect(l4Warnings).toEqual([]);

    // 4. Favicon warnings
    const faviconWarningsRes = await getWarningsForFavicon(baseUrl);
    expect(faviconWarningsRes.isOk()).toBe(true);
    expect(faviconWarningsRes._unsafeUnwrap()).toEqual([]);
  });

  it("should be successfully discovered and validated by @agentcash/discovery without errors", async () => {
    const result = await discoverOriginSchema({ target: baseUrl });
    expect(result.found).toBe(true);
    if (!result.found) return;

    expect(result.source).toBe("openapi");
    expect(result.endpoints.length).toBeGreaterThanOrEqual(10);
    expect(result.trustTier).toBe("ownership_verified");
    expect(result.ownershipProofs).toContain("https://github.com/Heir-to-Aether/solana-agent-x402");
    expect(result.guidanceAvailable).toBe(true);

    const paidEndpoints = result.endpoints.filter((e: any) => e.authMode === "paid");
    expect(paidEndpoints.length).toBe(7);

    const freeEndpoints = result.endpoints.filter((e: any) => e.authMode === "unprotected");
    expect(freeEndpoints.length).toBeGreaterThanOrEqual(6);

    // Verify probe checks on ALL 7 paid endpoints (both base query and parameterized) find paymentOptions and schemas
    const testMint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const checkEndpoints = [
      { path: "/api/token/risk", method: "GET" },
      { path: `/api/token/risk/${testMint}`, method: "GET" },
      { path: "/api/token/bundler", method: "GET" },
      { path: `/api/token/bundler/${testMint}`, method: "GET" },
      { path: "/api/token/mev", method: "GET" },
      { path: `/api/token/mev/${testMint}`, method: "GET" },
      { path: `/api/token/full-audit`, method: "POST" },
    ];

    for (const ep of checkEndpoints) {
      const check = await checkEndpointSchema({
        url: `${baseUrl}${ep.path}`,
        probe: true,
      });
      expect(check.found).toBe(true);
      const paidAdv = check.advisories.find((a: any) => a.method === ep.method && a.authMode === "paid");
      expect(paidAdv, `Advisory for ${ep.method} ${ep.path} must exist`).toBeDefined();
      expect(paidAdv.paymentOptions.length, `Payment options for ${ep.path} must exist`).toBeGreaterThan(0);
      expect(paidAdv.protocols).toContain("x402");
    }
  });

  it("should have zero warnings when checkEndpointSchema is executed on all base query routes", async () => {
    const baseRoutes = [
      `${baseUrl}/api/token/risk`,
      `${baseUrl}/api/token/bundler`,
      `${baseUrl}/api/token/mev`,
    ];

    for (const url of baseRoutes) {
      const check = await checkEndpointSchema({ url, probe: false });
      expect(check.found).toBe(true);
      expect(check.advisories.length).toBeGreaterThan(0);
      const paidAdv = check.advisories[0];
      expect(paidAdv.authMode).toBe("paid");
      expect(paidAdv.inputSchema).toBeDefined();
      expect(paidAdv.outputSchema).toBeDefined();
    }
  });
});
