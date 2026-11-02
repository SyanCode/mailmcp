import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readJson, safeEqual, sendJson } from "./util.js";

type AdminHandler = (req: IncomingMessage, res: ServerResponse, path: string, isPublic: boolean) => Promise<boolean>;

function bearerMatches(header: string | undefined, token: string): boolean {
  const m = /^Bearer (.+)$/.exec(header ?? "");
  return Boolean(m) && safeEqual(m![1], token);
}

export interface HttpOptions {
  host: string;
  port: number;
  authToken: string;
  /** Factory: stateless mode, one server + transport per request. */
  makeServer: () => McpServer;
  /**
   * Admin UI. Always served on a loopback listener; also on the main (public) listener,
   * but the handler answers 404 there until TOTP is configured and public access enabled.
   */
  admin?: {
    handler: AdminHandler;
    localPort: number;
  };
}

export function startHttp({ host, port, authToken, makeServer, admin }: HttpOptions): Server[] {
  const main = createHttpServer(async (req, res) => {
    const path = (req.url ?? "/").split("?")[0];

    // Unauthenticated health check for the deployer (Mas).
    if (req.method === "GET" && (path === "/" || path === "/health")) {
      return sendJson(res, 200, { status: "ok", name: "mailmcp" });
    }

    if (admin && (path === "/admin" || path.startsWith("/admin/"))) {
      await admin.handler(req, res, path, true);
      return;
    }

    if (path !== "/mcp") return sendJson(res, 404, { error: "Not found" });

    if (!bearerMatches(req.headers.authorization, authToken)) {
      return sendJson(res, 401, { error: "Unauthorized" }, { "WWW-Authenticate": "Bearer" });
    }

    if (req.method !== "POST") {
      return sendJson(res, 405, {
        jsonrpc: "2.0",
        error: { code: -32000, message: "Method not allowed" },
        id: null,
      });
    }

    try {
      const body = await readJson(req);
      const server = makeServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (e) {
      console.error("Request error:", e);
      if (!res.headersSent) {
        sendJson(res, 500, {
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  main.listen(port, host, () => {
    console.error(`mailmcp listening on http://${host}:${port}/mcp`);
  });
  const servers = [main];

  if (admin) {
    const local = createHttpServer(async (req, res) => {
      const path = (req.url ?? "/").split("?")[0];
      if (path === "/") {
        res.writeHead(302, { Location: "/admin" });
        return void res.end();
      }
      await admin.handler(req, res, path, false);
    });
    // Loopback only, never reachable from outside (use an SSH tunnel).
    local.listen(admin.localPort, "127.0.0.1", () => {
      console.error(`mailmcp admin on http://127.0.0.1:${admin.localPort}/admin (local only)`);
    });
    servers.push(local);
  }
  return servers;
}
