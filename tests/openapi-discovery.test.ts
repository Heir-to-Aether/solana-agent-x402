import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Server } from "http";
import { createApp } from "../src/server/index.js";
import { getOpenApiSpec } from "../src/server/discovery.js";
import { discoverOriginSchema, checkEndpointSchema } from "@agentcash/discovery";

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
    const freePaths = ["/", "/api/health", "/llms.txt", "/.well-known/x402.json", "/openapi.json"];

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
      { path: "/api/token/risk/{address}", method: "get", expectedAmount: "0.002000" },
      { path: "/api/token/bundler/{address}", method: "get", expectedAmount: "0.003000" },
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

    // GET endpoints must have path parameters with schema
    const getPaths = ["/api/token/risk/{address}", "/api/token/bundler/{address}", "/api/token/mev/{address}"];
    for (const p of getPaths) {
      const op = (spec.paths[p as keyof typeof spec.paths] as any).get;
      expect(op.parameters).toBeDefined();
      expect(op.parameters.length).toBeGreaterThan(0);
      expect(op.parameters[0].name).toBe("address");
      expect(op.parameters[0].in).toBe("path");
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

  it("should serve /favicon.ico with 204 status to eliminate discovery favicon warning", async () => {
    const res = await fetch(`${baseUrl}/favicon.ico`);
    expect(res.status).toBe(204);
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

  it("should return base64 PAYMENT-REQUIRED header when probed with discovery accept header", async () => {
    const res = await fetch(`${baseUrl}/api/token/full-audit`, {
      method: "POST",
      headers: {
        Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
      },
    });

    expect(res.status).toBe(402);
    const headerVal = res.headers.get("payment-required")!;
    expect(headerVal).toBeTruthy();

    // Verify it is base64-encoded JSON with x402Version: 2
    const decoded = Buffer.from(headerVal, "base64").toString("utf-8");
    const parsed = JSON.parse(decoded);
    expect(parsed.x402Version).toBe(2);
    expect(parsed.accepts[0].amount).toBe("5000");
    expect(parsed.resource.url).toContain("/api/token/full-audit");
  });

  it("should be successfully discovered and validated by @agentcash/discovery without errors", async () => {
    const result = await discoverOriginSchema({ target: baseUrl });
    expect(result.found).toBe(true);
    expect(result.source).toBe("openapi");
    expect(result.endpoints.length).toBeGreaterThanOrEqual(9);

    const paidEndpoints = result.endpoints.filter((e: any) => e.authMode === "paid");
    expect(paidEndpoints.length).toBe(4);

    const freeEndpoints = result.endpoints.filter((e: any) => e.authMode === "unprotected");
    expect(freeEndpoints.length).toBe(5);

    // Verify probe checks on paid endpoints find paymentOptions and schemas
    const checkRisk = await checkEndpointSchema({
      url: `${baseUrl}/api/token/risk/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`,
      probe: true,
    });
    expect(checkRisk.found).toBe(true);
    const paidRiskAdv = checkRisk.advisories.find((a: any) => a.method === "GET" && a.authMode === "paid");
    expect(paidRiskAdv).toBeDefined();
    expect(paidRiskAdv.paymentOptions.length).toBeGreaterThan(0);
    expect(paidRiskAdv.protocols).toContain("x402");

    const checkAudit = await checkEndpointSchema({
      url: `${baseUrl}/api/token/full-audit`,
      probe: true,
    });
    expect(checkAudit.found).toBe(true);
    const paidAuditAdv = checkAudit.advisories.find((a: any) => a.method === "POST" && a.authMode === "paid");
    expect(paidAuditAdv).toBeDefined();
    expect(paidAuditAdv.paymentOptions.length).toBeGreaterThan(0);
    expect(paidAuditAdv.protocols).toContain("x402");
  });
});
