#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { startHttp } from "./http.js";
import { MailClient, loadConfig } from "./mail.js";
import { createServer } from "./server.js";

const mail = new MailClient(loadConfig());
const transport = (process.env.MCP_TRANSPORT ?? "stdio").toLowerCase();

async function main() {
  if (transport === "http") {
    const authToken = process.env.MCP_AUTH_TOKEN;
    if (!authToken || authToken.length < 16) {
      throw new Error("MCP_AUTH_TOKEN (min 16 chars) is required when MCP_TRANSPORT=http");
    }
    startHttp({
      host: process.env.HOST ?? "127.0.0.1",
      port: Number(process.env.PORT ?? 3000),
      authToken,
      makeServer: () => createServer(mail),
    });
  } else if (transport === "stdio") {
    await createServer(mail).connect(new StdioServerTransport());
    // stdout is reserved for the MCP protocol; log to stderr only.
    console.error("mailmcp running on stdio");
  } else {
    throw new Error(`Unknown MCP_TRANSPORT "${transport}" (use "stdio" or "http")`);
  }
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
