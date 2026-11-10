# mailmcp

MCP server connecting a self-hosted mailbox (IMAP + SMTP) to Claude. Two transports: `stdio` (local) and Streamable `http` (remote, e.g. deployed with [Mas](https://github.com/SyanCode/Mas)).

## Tools

| Tool | Description |
|------|-------------|
| `mail_list_accounts` | List mailboxes with their email address and description (what each is for) |
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

### Several mailboxes

Set `MAIL_ACCOUNTS=perso,pro` (letters and digits only) and prefix every IMAP/SMTP variable with the upper-cased name: `PERSO_IMAP_HOST`, `PERSO_IMAP_USER`, `PERSO_IMAP_PASS`, `PERSO_SMTP_HOST`, `PRO_IMAP_HOST`, ... The first account is the default, override it with `MAIL_DEFAULT_ACCOUNT`. Add `<NAME>_MAIL_DESCRIPTION` (e.g. `PRO_MAIL_DESCRIPTION="Work mailbox: clients and invoices"`) so Claude knows what each mailbox is for. Every tool takes an optional `account` argument, and `mail_list_accounts` returns each mailbox's address and description. Without `MAIL_ACCOUNTS`, the unprefixed variables define a single account.

### Admin UI

Add and remove mailboxes from a browser instead of editing env vars. Each new account is tested (IMAP login + SMTP) before it is saved, and takes effect immediately, without restart. Accounts defined by env vars are listed but read-only.

Adding a mailbox only needs the **email address**, the **password** and a **description**: the name is derived from the address and the IMAP/SMTP host defaults to `mail.<domain>` (override under *Advanced settings*). The description can be edited later from the account list and is what `mail_list_accounts` shows to Claude.

| Variable | Notes |
|----------|-------|
| `MAILMCP_DATA_DIR` | Enables the admin UI. Persistent folder outside the Mas releases (a redeploy wipes the release folder) and writable by the app's user |
| `ADMIN_ACCESS` | Set to `off` to disable the admin UI even with `MAILMCP_DATA_DIR` |
| `ADMIN_PORT` | Loopback port of the local admin, default `3001` |
| `MAILMCP_ENCRYPTION_KEY` | Encrypts `accounts.enc.json` (AES-256-GCM). Defaults to `MCP_AUTH_TOKEN`: set a dedicated key before rotating the token, or the file becomes unreadable |
| `ADMIN_TOTP_SECRET` | Optional. Fixes the authenticator secret from the environment instead of the UI. Generate with `node dist/totp-secret.js` |
| `ADMIN_RESET_TOTP` | Set to `true` for one start if you lose your authenticator, then remove it |

**Access model.** The admin always listens on `127.0.0.1:ADMIN_PORT`, never exposed by the proxy. Reach it through an SSH tunnel: `ssh -L 3001:127.0.0.1:3001 user@server`, then open `http://127.0.0.1:3001/admin`.

- Until an authenticator (TOTP, e.g. Google Authenticator) is configured, `/admin` on the public domain answers 404: the admin is **local only**.
- In the local admin, **Security → Set up authenticator** shows a key to enter in the app and asks for a code to confirm.
- Once TOTP is active, you choose from the local admin: stay local-only, or **Allow access from the public domain** (`https://your-domain/admin`). Public login then needs the token **and** an authenticator code. Public access can be switched off from either side, but only switched on from the local admin.

Login uses `MCP_AUTH_TOKEN` (plus the authenticator code once configured). 5 failed attempts lock the login for a minute. This page can add mailboxes that Claude can read, so prefer local-only unless you need remote access.

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
3. Environment variables: `MCP_TRANSPORT=http`, `MCP_AUTH_TOKEN`, `IMAP_*`, `SMTP_*`. Do **not** set `PORT` or `HOST`: Mas injects them in the systemd unit, and a value in the app's variables would override Mas's port and break the health check.
4. Set a domain so Mas provisions nginx + HTTPS. Never expose the endpoint over plain HTTP: it can read and send your mail.

## Connect to Claude

The endpoint is `https://your-domain/mcp` and expects `Authorization: Bearer <MCP_AUTH_TOKEN>`.

**Claude Code**
```sh
claude mcp add --transport http mailmcp https://your-domain/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```
Add `--scope user` to make it available in every project. Check with `claude mcp list`, then ask Claude to run `mail_list_accounts`.

**Claude Desktop** (`claude_desktop_config.json`): use the `mailmcp-remote` entry of `claude_desktop_config.example.json`. It goes through `mcp-remote`, which sends the Bearer header.

**claude.ai custom connectors**: these authenticate with OAuth (or nothing), not with a static Bearer header, so they cannot use this token as is. Use Claude Code or Desktop until OAuth support is added.

## License

MIT
