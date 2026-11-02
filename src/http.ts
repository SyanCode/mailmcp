import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const MAX_BODY = 1_000_000;

function tokenMatches(header: string | undefined, token: string): boolean {
  const m = /^Bearer (.+)$/.exec(header ?? "");
  if (!m) return false;
  const a = Buffer.from(m[1]);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("Body too large");
    chunks.push(chunk as Buffer);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
}

export interface HttpOptions {
  host: string;
  port: number;
  authToken: string;
  /** Factory: stateless mode, one server + transport per request. */
  makeServer: () => McpServer;
}

export function startHttp({ host, port, authToken, makeServer }: HttpOptions) {
  const http = createHttpServer(async (req, res) => {
    const path = (req.url ?? "/").split("?")[0];

    // Unauthenticated health check for the deployer (Mas).
    if (req.method === "GET" && (path === "/" || path === "/health")) {
      return send(res, 200, { status: "ok", name: "mailmcp" });
    }

    if (path !== "/mcp") return send(res, 404, { error: "Not found" });

    if (!tokenMatches(req.headers.authorization, authToken)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      return send(res, 401, { error: "Unauthorized" });
    }

    if (req.method !== "POST") {
      return send(res, 405, {
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
        send(res, 500, {
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  http.listen(port, host, () => {
    console.error(`mailmcp listening on http://${host}:${port}/mcp`);
  });
  return http;
}
