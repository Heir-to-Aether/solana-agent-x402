import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Server } from "http";
import { createApp } from "../src/server/index.js";
import {
  rugcheckX402Plugin,
  rugcheckAction,
  extractValidSolanaAddresses,
  createRugcheckTool,
  RugcheckX402Client,
  IAgentRuntime,
  Memory,
} from "../packages/plugin-rugcheck-x402/src/index.js";

describe("ElizaOS & Solana Agent Kit Plugin (@elizaos/plugin-rugcheck-x402)", () => {
  let server: Server;
  let baseUrl: string;
  const testPort = 4031;

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

  it("should export valid ElizaOS plugin metadata and action definitions", () => {
    expect(rugcheckX402Plugin.name).toBe("rugcheck-x402");
    expect(rugcheckX402Plugin.description).toContain("ElizaOS");
    expect(rugcheckX402Plugin.actions).toBeDefined();
    expect(rugcheckX402Plugin.actions!.length).toBeGreaterThanOrEqual(1);

    const action = rugcheckX402Plugin.actions![0];
    expect(action.name).toBe("SOLANA_RUGCHECK_X402");
    expect(action.similes).toContain("RUGCHECK_TOKEN");
    expect(action.similes).toContain("CHECK_HONEYPOT");
    expect(action.examples.length).toBeGreaterThanOrEqual(1);
  });

  it("should validate messages containing a Solana base58 address and reject invalid messages", async () => {
    const mockRuntime: IAgentRuntime = {
      getSetting: () => undefined,
    };

    const validMsg: Memory = {
      content: { text: "Can you audit 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU for honeypot?" },
    };
    const invalidMsg: Memory = {
      content: { text: "What is the price of Bitcoin today?" },
    };
    const invalidBase58Msg: Memory = {
      content: { text: "Check this random 32-char word: zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" },
    };

    const isValid = await rugcheckAction.validate(mockRuntime, validMsg);
    const isInvalid = await rugcheckAction.validate(mockRuntime, invalidMsg);
    const isInvalidBase58 = await rugcheckAction.validate(mockRuntime, invalidBase58Msg);

    expect(isValid).toBe(true);
    expect(isInvalid).toBe(false);
    expect(isInvalidBase58).toBe(false);
  });

  it("should correctly extract multiple valid Solana addresses from a complex message", () => {
    const multiMsg = "Compare 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU with GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse and fake zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    const addresses = extractValidSolanaAddresses(multiMsg);
    expect(addresses.length).toBe(2);
    expect(addresses).toContain("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
    expect(addresses).toContain("GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse");
  });

  it("should execute rugcheckAction and deliver formatted markdown audit via callback", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const mockRuntime: IAgentRuntime = {
      getSetting: (key: string) => {
        if (key === "RUGCHECK_API_URL") return baseUrl;
        return undefined;
      },
    };

    const msg: Memory = {
      content: { text: `Please check risk on ${mint}` },
    };

    const callbackResponses: any[] = [];
    const callback = async (response: any) => {
      callbackResponses.push(response);
    };

    const result = await rugcheckAction.handler(mockRuntime, msg, undefined, undefined, callback);
    expect(result).toBe(true);
    expect(callbackResponses.length).toBeGreaterThanOrEqual(1);

    const finalResponse = callbackResponses[callbackResponses.length - 1];
    expect(finalResponse.text).toContain("Solana Token Security Audit (x402 Verified)");
    expect(finalResponse.text).toContain("Verdict");
    expect(finalResponse.text).toContain(mint);
    expect(finalResponse.data).toBeDefined();
    expect(finalResponse.data.tokenAddress).toBe(mint);
    expect(finalResponse.data.canAgentSafelyTrade).toBe(true);
    expect(finalResponse.data.overallSafetyScore).toBeGreaterThanOrEqual(80);
  });

  it("should execute Solana Agent Kit tool definition", async () => {
    const mint = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const tool = createRugcheckTool({ baseUrl });

    expect(tool.name).toBe("solana_rugcheck_x402");
    expect(tool.parameters.required).toContain("tokenAddress");

    const audit = await tool.execute(null, { tokenAddress: mint });
    expect(audit).toBeDefined();
    expect(audit.tokenAddress).toBe(mint);
    expect(audit.overallSafetyScore).toBeGreaterThanOrEqual(80);
    expect(audit.riskReport).toBeDefined();
    expect(audit.bundlerReport).toBeDefined();
    expect(audit.mevReport).toBeDefined();
  });

  it("should allow direct standalone use of RugcheckX402Client", async () => {
    const client = new RugcheckX402Client({ baseUrl });
    const mint = "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse";

    const bundlers = await client.detectBundlers(mint);
    expect(bundlers.tokenAddress).toBe(mint);
    expect(bundlers.summary).toBeDefined();
    expect(bundlers.clusters.length).toBeGreaterThan(0);

    const mev = await client.getMevIntel(mint);
    expect(mev.tokenAddress).toBe(mint);
    expect(mev.recommendedGasAndFees.priorityFeeMicroLamports.fast).toBeGreaterThan(0);
  });
});
