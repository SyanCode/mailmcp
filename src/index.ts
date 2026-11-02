#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createAdminHandler } from "./admin.js";
import { startHttp } from "./http.js";
import { MailClient, loadAccounts, loadConfig } from "./mail.js";
import { createServer } from "./server.js";
import { AccountStore } from "./store.js";

const env = process.env;
const transport = (env.MCP_TRANSPORT ?? "stdio").toLowerCase();
// The admin UI is on as soon as MAILMCP_DATA_DIR is set, unless ADMIN_ACCESS=off.
const adminEnabled = Boolean(env.MAILMCP_DATA_DIR) && (env.ADMIN_ACCESS ?? "on").toLowerCase() !== "off";

async function main() {
  if (!["stdio", "http"].includes(transport)) {
    throw new Error(`Unknown MCP_TRANSPORT "${transport}" (use "stdio" or "http")`);
  }
  const authToken = env.MCP_AUTH_TOKEN;
  if (transport === "http" && (!authToken || authToken.length < 16)) {
    throw new Error("MCP_AUTH_TOKEN (min 16 chars) is required when MCP_TRANSPORT=http");
  }
  const registry = loadAccounts(env);

  // Accounts added from the admin UI live in an encrypted file in a persistent folder.
  let store: AccountStore | undefined;
  if (env.MAILMCP_DATA_DIR) {
    const secret = env.MAILMCP_ENCRYPTION_KEY ?? authToken;
    if (!secret) throw new Error("MAILMCP_ENCRYPTION_KEY (or MCP_AUTH_TOKEN) is required with MAILMCP_DATA_DIR");
    store = new AccountStore(env.MAILMCP_DATA_DIR, secret);
    if (env.ADMIN_RESET_TOTP === "true") {
      // Lost authenticator: clear TOTP and public access, then remove this variable.
      store.updateSettings({ totpSecret: undefined, adminPublic: false });
      console.error("TOTP reset: admin is local-only again. Remove ADMIN_RESET_TOTP.");
    }
    for (const [name, acc] of store.list()) {
      if (registry.has(name)) {
        console.error(`Stored account "${name}" ignored: same name defined by environment variables`);
        continue;
      }
      registry.add(name, new MailClient(loadConfig(acc as NodeJS.ProcessEnv, "", name)));
    }
  }

  if (!registry.names().length) {
    console.error("Warning: no mail account configured yet");
  }

  if (transport === "http") {
    startHttp({
      host: env.HOST ?? "127.0.0.1",
      port: Number(env.PORT ?? 3000),
      authToken: authToken!,
      makeServer: () => createServer(registry),
      admin:
        adminEnabled && store
          ? {
              handler: createAdminHandler({
                registry,
                store,
                token: authToken!,
                envTotpSecret: env.ADMIN_TOTP_SECRET || undefined,
              }),
              localPort: Number(env.ADMIN_PORT ?? 3001),
            }
          : undefined,
    });
  } else {
    await createServer(registry).connect(new StdioServerTransport());
    // stdout is reserved for the MCP protocol; log to stderr only.
    console.error("mailmcp running on stdio");
  }
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
