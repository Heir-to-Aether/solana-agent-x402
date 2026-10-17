import { describe, it, expect } from "vitest";
import { createMcpServer } from "../src/mcp/index.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { KNOWN_FIXTURES } from "../src/services/solana-rpc.js";

describe("Model Context Protocol (MCP) Server", () => {
  const mcpServer = createMcpServer({ embedded: true });

  it("should expose all four Solana security & MEV intelligence tools", async () => {
    // Access the list tools handler
    const handler = (mcpServer as any)._requestHandlers.get(ListToolsRequestSchema.shape.method.value);
    expect(handler).toBeDefined();

    const result = await handler({ method: "tools/list", params: {} });
    expect(result.tools).toBeDefined();
    expect(result.tools.length).toBe(4);

    const toolNames = result.tools.map((t: any) => t.name);
    expect(toolNames).toContain("solana_token_risk_audit");
    expect(toolNames).toContain("solana_detect_bundlers");
    expect(toolNames).toContain("solana_mev_intel");
    expect(toolNames).toContain("solana_full_security_scan");
  });

  it("should execute solana_token_risk_audit via MCP tool handler", async () => {
    const handler = (mcpServer as any)._requestHandlers.get(CallToolRequestSchema.shape.method.value);
    expect(handler).toBeDefined();

    const mint = KNOWN_FIXTURES.SAFE_TOKEN;
    const response = await handler({
      method: "tools/call",
      params: {
        name: "solana_token_risk_audit",
        arguments: { tokenAddress: mint },
      },
    });

    expect(response.isError).toBeFalsy();
    expect(response.content[0].type).toBe("text");
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.tokenAddress).toBe(mint);
    expect(parsed.riskScore).toBeDefined();
    expect(parsed.verdict).toBeDefined();
  });

  it("should execute solana_detect_bundlers via MCP tool handler", async () => {
    const handler = (mcpServer as any)._requestHandlers.get(CallToolRequestSchema.shape.method.value);
    const mint = KNOWN_FIXTURES.SNIPED_BUNDLER;
    const response = await handler({
      method: "tools/call",
      params: {
        name: "solana_detect_bundlers",
        arguments: { tokenAddress: mint },
      },
    });

    expect(response.isError).toBeFalsy();
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.bundleDetected).toBe(true);
    expect(parsed.summary.recommendation).toBe("SNIPED_CABAL");
  });

  it("should execute solana_mev_intel via MCP tool handler", async () => {
    const handler = (mcpServer as any)._requestHandlers.get(CallToolRequestSchema.shape.method.value);
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const response = await handler({
      method: "tools/call",
      params: {
        name: "solana_mev_intel",
        arguments: { tokenAddress: mint },
      },
    });

    expect(response.isError).toBeFalsy();
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.sandwichVulnerability).toBe("LOW");
    expect(parsed.recommendedGasAndFees).toBeDefined();
  });

  it("should execute solana_full_security_scan via MCP tool handler", async () => {
    const handler = (mcpServer as any)._requestHandlers.get(CallToolRequestSchema.shape.method.value);
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const response = await handler({
      method: "tools/call",
      params: {
        name: "solana_full_security_scan",
        arguments: { tokenAddress: mint },
      },
    });

    expect(response.isError).toBeFalsy();
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.overallSafetyScore).toBeGreaterThanOrEqual(60);
    expect(parsed.canAgentSafelyTrade).toBe(true);
  });

  it("should return error if tokenAddress is missing in tool call", async () => {
    const handler = (mcpServer as any)._requestHandlers.get(CallToolRequestSchema.shape.method.value);
    const response = await handler({
      method: "tools/call",
      params: {
        name: "solana_token_risk_audit",
        arguments: {},
      },
    });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Missing required parameter 'tokenAddress'");
  });

  it("should support parameter aliases ('address' or 'mint') in MCP tool calls", async () => {
    const handler = (mcpServer as any)._requestHandlers.get(CallToolRequestSchema.shape.method.value);
    const mint = KNOWN_FIXTURES.SAFE_TOKEN;

    const response = await handler({
      method: "tools/call",
      params: {
        name: "solana_token_risk_audit",
        arguments: { address: mint },
      },
    });

    expect(response.isError).toBeFalsy();
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.tokenAddress).toBe(mint);
  });
});
