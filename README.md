# mailmcp

MCP server connecting a self-hosted mailbox (IMAP + SMTP) to Claude. Two transports: `stdio` (local) and Streamable `http` (remote, e.g. deployed with [Mas](https://github.com/SyanCode/Mas)).

## Tools

| Tool | Description |
|------|-------------|
| `mail_list_folders` | List folders with message/unread counts |
| `mail_search` | Search by folder, unread, text, sender, subject, date |
| `mail_read` | Read a message by UID |
| `mail_send` | Send a message via SMTP |

## Configuration

See `.env.example`. `SMTP_USER`/`SMTP_PASS` fall back to the IMAP credentials.

| Variable | Notes |
|----------|-------|
| `MCP_TRANSPORT` | `stdio` (default) or `http` |
| `MCP_AUTH_TOKEN` | Required for `http`, min 16 chars. Sent as `Authorization: Bearer <token>` |
| `HOST` / `PORT` | `http` only. Defaults `127.0.0.1` / `3000` |

HTTP endpoints: `POST /mcp` (authenticated), `GET /health` and `GET /` (public, for health checks).

## Local run

```sh
npm install
npm run build
npm start          # stdio
```

## Deploy with Mas

1. Push this repo to GitHub, then **Apps → New app** in Mas (detected as Node).
2. Build command: `npm ci && npm run build`. Start command: `npm start`.
3. Environment variables: `MCP_TRANSPORT=http`, `MCP_AUTH_TOKEN`, `IMAP_*`, `SMTP_*`, and `PORT` matching the port Mas assigns (the app must listen on `127.0.0.1:<port>`).
4. Set a domain so Mas provisions nginx + HTTPS. Never expose the endpoint over plain HTTP: it can read and send your mail.

Then add it to Claude as a remote MCP server (`https://your-domain/mcp` with the Bearer token), or use `claude_desktop_config.example.json`.

## License

MIT
