import { Plugin } from "./types.js";
import { rugcheckAction } from "./actions/rugcheckAction.js";
import { RugcheckX402Client } from "./client.js";
import { createRugcheckTool } from "./solanaAgentKit.js";

export * from "./types.js";
export * from "./client.js";
export * from "./actions/rugcheckAction.js";
export * from "./solanaAgentKit.js";

export const rugcheckX402Plugin: Plugin = {
  name: "rugcheck-x402",
  description:
    "ElizaOS plugin for autonomous Solana token risk analysis, honeypot detection, bundler sniping identification, and MEV telemetry gated by x402 micropayments.",
  actions: [rugcheckAction],
};

export default rugcheckX402Plugin;
