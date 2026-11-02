import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { ACCOUNT_NAME, MailClient, Registry, loadConfig } from "./mail.js";
import type { AccountStore, StoredAccount } from "./store.js";
import { generateSecret, otpauthUrl, verifyTotp } from "./totp.js";
import { readJson, safeEqual, sendJson } from "./util.js";

export interface AdminDeps {
  registry: Registry;
  store: AccountStore;
  /** Login secret (MCP_AUTH_TOKEN). */
  token: string;
  /** Base32 secret from ADMIN_TOTP_SECRET. Overrides the one set from the UI, which is then read-only. */
  envTotpSecret?: string;
}

const SESSION_TTL = 60 * 60 * 1000;
const MAX_FAILS = 5;
const LOCK_MS = 60 * 1000;

const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

function cookieValue(req: IncomingMessage, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return undefined;
}

const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");

export function createAdminHandler({ registry, store, token, envTotpSecret }: AdminDeps) {
  // A session is bound to the listener it was created on (public domain vs local port).
  const sessions = new Map<string, { exp: number; pub: boolean }>();
  let pendingTotp: string | undefined;
  let fails = 0;
  let lockedUntil = 0;

  const totpSecret = (): string | undefined => envTotpSecret || store.getSettings().totpSecret;
  const publicAllowed = (): boolean => Boolean(totpSecret()) && store.getSettings().adminPublic === true;

  const valid = (req: IncomingMessage, pub: boolean): boolean => {
    const id = cookieValue(req, "mailmcp_admin");
    const s = id ? sessions.get(id) : undefined;
    if (!id || !s || s.exp < Date.now() || s.pub !== pub) {
      if (id && s && s.exp < Date.now()) sessions.delete(id);
      return false;
    }
    s.exp = Date.now() + SESSION_TTL;
    return true;
  };

  const page = (res: ServerResponse, type: string, body: string) => {
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Security-Policy": CSP,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
    });
    res.end(body);
  };

  const listAccounts = () =>
    registry.names().map((name) => ({
      name,
      source: registry.isFromEnv(name) ? "env" : "admin",
      imap_host: store.list().find(([n]) => n.toLowerCase() === name)?.[1].IMAP_HOST ?? null,
      imap_user: store.list().find(([n]) => n.toLowerCase() === name)?.[1].IMAP_USER ?? null,
      default: name === registry.defaultName,
    }));

  /**
   * Returns true when the request was handled.
   * isPublic: request came through the public listener (behind the proxy), not the loopback one.
   */
  return async function handle(req: IncomingMessage, res: ServerResponse, path: string, isPublic = false): Promise<boolean> {
    // Until TOTP is configured and public access enabled, the admin only exists locally.
    if (isPublic && !publicAllowed()) {
      sendJson(res, 404, { error: "Not found" });
      return true;
    }
    if (path === "/admin" || path === "/admin/") {
      page(res, "text/html; charset=utf-8", ADMIN_HTML);
      return true;
    }
    if (path === "/admin/app.js") {
      page(res, "text/javascript; charset=utf-8", ADMIN_JS);
      return true;
    }
    if (!path.startsWith("/admin/api/")) {
      sendJson(res, 404, { error: "Not found" });
      return true;
    }

    // Cross-site requests cannot set this header without a CORS preflight.
    if (req.method !== "GET" && req.headers["x-requested-with"] !== "mailmcp") {
      sendJson(res, 403, { error: "Forbidden" });
      return true;
    }

    try {
      if (path === "/admin/api/login" && req.method === "POST") {
        if (Date.now() < lockedUntil) {
          sendJson(res, 429, { error: "Too many attempts, retry in a minute" });
          return true;
        }
        const body = (await readJson(req)) as Record<string, unknown> | undefined;
        const okToken = safeEqual(str(body?.token), token);
        const secret = totpSecret();
        const okTotp = !secret || verifyTotp(secret, str(body?.code));
        if (!okToken || !okTotp) {
          if (++fails >= MAX_FAILS) {
            lockedUntil = Date.now() + LOCK_MS;
            fails = 0;
          }
          sendJson(res, 401, { error: "Invalid credentials" });
          return true;
        }
        fails = 0;
        const id = randomBytes(32).toString("hex");
        sessions.set(id, { exp: Date.now() + SESSION_TTL, pub: isPublic });
        const secure = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
        sendJson(res, 200, { ok: true }, {
          "Set-Cookie": `mailmcp_admin=${id}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=3600${secure}`,
        });
        return true;
      }

      const status = () => ({
        totp: Boolean(totpSecret()),
        totp_from_env: Boolean(envTotpSecret),
        public_access: store.getSettings().adminPublic === true,
        is_public: isPublic,
      });

      if (path === "/admin/api/session" && req.method === "GET") {
        sendJson(res, 200, { authenticated: valid(req, isPublic), ...status() });
        return true;
      }

      if (!valid(req, isPublic)) {
        sendJson(res, 401, { error: "Not authenticated" });
        return true;
      }

      // Security settings can only be changed from the local listener, except turning public access off.
      if (path === "/admin/api/totp/setup" && req.method === "POST") {
        if (isPublic || envTotpSecret || totpSecret()) {
          sendJson(res, 400, { error: "TOTP is already configured or managed by ADMIN_TOTP_SECRET" });
          return true;
        }
        pendingTotp = generateSecret();
        sendJson(res, 200, { secret: pendingTotp, otpauth: otpauthUrl(pendingTotp) });
        return true;
      }

      if (path === "/admin/api/totp/confirm" && req.method === "POST") {
        const body = (await readJson(req)) as Record<string, unknown> | undefined;
        if (isPublic || !pendingTotp || !verifyTotp(pendingTotp, str(body?.code))) {
          sendJson(res, 400, { error: "Invalid code. Start the setup again if the problem persists" });
          return true;
        }
        store.updateSettings({ totpSecret: pendingTotp });
        pendingTotp = undefined;
        sendJson(res, 200, { ok: true, ...status() });
        return true;
      }

      if (path === "/admin/api/settings" && req.method === "POST") {
        const body = (await readJson(req)) as Record<string, unknown> | undefined;
        const wantPublic = body?.public_access === true;
        if (wantPublic && (isPublic || !totpSecret())) {
          sendJson(res, 400, { error: "Public access needs TOTP configured and must be enabled from the local admin" });
          return true;
        }
        store.updateSettings({ adminPublic: wantPublic });
        sendJson(res, 200, { ok: true, ...status() });
        return true;
      }

      if (path === "/admin/api/logout" && req.method === "POST") {
        const id = cookieValue(req, "mailmcp_admin");
        if (id) sessions.delete(id);
        sendJson(res, 200, { ok: true });
        return true;
      }

      if (path === "/admin/api/accounts" && req.method === "GET") {
        sendJson(res, 200, { accounts: listAccounts() });
        return true;
      }

      if (path === "/admin/api/accounts" && req.method === "POST") {
        const b = (await readJson(req)) as Record<string, unknown> | undefined;
        const name = str(b?.name);
        if (!ACCOUNT_NAME.test(name)) {
          sendJson(res, 400, { error: "Name: letters and digits only" });
          return true;
        }
        if (registry.has(name)) {
          sendJson(res, 409, { error: `Account "${name}" already exists` });
          return true;
        }
        const acc: StoredAccount = {
          IMAP_HOST: str(b?.imap_host),
          IMAP_PORT: str(b?.imap_port) || "993",
          IMAP_USER: str(b?.imap_user),
          IMAP_PASS: typeof b?.imap_pass === "string" ? b.imap_pass : "",
          SMTP_HOST: str(b?.smtp_host) || str(b?.imap_host),
          SMTP_PORT: str(b?.smtp_port) || "465",
        };
        for (const [k, v] of [
          ["SMTP_USER", str(b?.smtp_user)],
          ["SMTP_PASS", typeof b?.smtp_pass === "string" ? b.smtp_pass : ""],
          ["SMTP_FROM", str(b?.smtp_from)],
        ] as const) {
          if (v) acc[k] = v;
        }
        if (b?.allow_self_signed === true) acc.MAIL_TLS_REJECT_UNAUTHORIZED = "false";

        let client: MailClient;
        try {
          client = new MailClient(loadConfig(acc as NodeJS.ProcessEnv, "", name));
        } catch (e) {
          sendJson(res, 400, { error: e instanceof Error ? e.message : String(e) });
          return true;
        }
        try {
          await client.verify();
        } catch (e) {
          sendJson(res, 400, { error: `Connection test failed. ${e instanceof Error ? e.message : String(e)}` });
          return true;
        }
        store.set(name.toLowerCase(), acc);
        registry.add(name, client);
        sendJson(res, 201, { ok: true, accounts: listAccounts() });
        return true;
      }

      const m = /^\/admin\/api\/accounts\/([A-Za-z0-9]+)$/.exec(path);
      if (m && req.method === "DELETE") {
        const name = m[1].toLowerCase();
        if (registry.isFromEnv(name)) {
          sendJson(res, 400, { error: "This account is defined by environment variables" });
          return true;
        }
        if (!registry.remove(name) || !store.remove(name)) {
          sendJson(res, 404, { error: "Unknown account" });
          return true;
        }
        sendJson(res, 200, { ok: true, accounts: listAccounts() });
        return true;
      }

      sendJson(res, 404, { error: "Not found" });
    } catch (e) {
      console.error("Admin error:", e);
      sendJson(res, 500, { error: "Internal error" });
    }
    return true;
  };
}

const ADMIN_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>mailmcp admin</title>
<style>
body{font:15px system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.4rem} input{display:block;width:100%;box-sizing:border-box;padding:.5rem;margin:.25rem 0 .75rem;border:1px solid #bbb;border-radius:4px}
label{font-size:.85rem;color:#444} button{padding:.5rem 1rem;border:0;border-radius:4px;background:#2f5bea;color:#fff;cursor:pointer}
button.danger{background:#c62828} button.link{background:none;color:#2f5bea;padding:0}
table{width:100%;border-collapse:collapse;margin:1rem 0} td,th{text-align:left;padding:.4rem;border-bottom:1px solid #ddd}
.row{display:grid;grid-template-columns:1fr 1fr;gap:0 1rem} .err{color:#c62828;min-height:1.2em} .muted{color:#777}
fieldset{border:1px solid #ddd;border-radius:4px;margin:1rem 0;padding:.5rem 1rem} [hidden]{display:none}
</style></head><body>
<h1>mailmcp admin</h1>
<form id="login" hidden>
  <label>Access token<input type="password" id="token" autocomplete="current-password" required></label>
  <label id="codeWrap" hidden>Authenticator code<input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label>
  <button>Sign in</button>
</form>
<section id="app" hidden>
  <p><button class="link" id="logout">Sign out</button></p>
  <h2>Accounts</h2>
  <table><thead><tr><th>Name</th><th>Source</th><th>Login</th><th></th></tr></thead><tbody id="list"></tbody></table>
  <h2>Security</h2>
  <div id="security">
    <p id="secState"></p>
    <div id="totpSetup" hidden>
      <p>Add this key in Google Authenticator (<em>Enter a setup key</em>, type <em>Time based</em>), then type the code it shows.</p>
      <p><code id="totpKey"></code></p>
      <label>Code<input id="totpCode" inputmode="numeric" maxlength="6" autocomplete="off"></label>
      <button id="totpConfirm" type="button">Confirm</button>
    </div>
    <button id="totpStart" type="button" hidden>Set up authenticator</button>
    <button id="pubToggle" type="button" hidden></button>
  </div>
  <h2>Add an account</h2>
  <form id="add">
    <label>Name (letters and digits)<input id="name" required pattern="[A-Za-z0-9]+"></label>
    <fieldset><legend>IMAP</legend>
      <div class="row"><label>Host<input id="imap_host" required></label><label>Port<input id="imap_port" value="993"></label></div>
      <div class="row"><label>User<input id="imap_user" required></label><label>Password<input id="imap_pass" type="password" required autocomplete="new-password"></label></div>
    </fieldset>
    <fieldset><legend>SMTP (defaults to IMAP host and credentials)</legend>
      <div class="row"><label>Host<input id="smtp_host"></label><label>Port<input id="smtp_port" value="465"></label></div>
      <div class="row"><label>User<input id="smtp_user"></label><label>Password<input id="smtp_pass" type="password" autocomplete="new-password"></label></div>
      <label>From address<input id="smtp_from" placeholder="You &lt;you@example.com&gt;"></label>
    </fieldset>
    <label><input type="checkbox" id="allow_self_signed" style="display:inline;width:auto"> Accept self-signed certificate</label>
    <p><button>Test and save</button></p>
  </form>
</section>
<p class="err" id="err"></p>
<script src="/admin/app.js"></script>
</body></html>`;

const ADMIN_JS = `(() => {
const $ = (id) => document.getElementById(id);
const err = (m) => { $('err').textContent = m || ''; };
async function api(method, path, body) {
  const r = await fetch('/admin/api/' + path, {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'mailmcp' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(data.error || 'Request failed'), { status: r.status });
  return data;
}
function render(accounts) {
  const tb = $('list'); tb.replaceChildren();
  if (!accounts.length) {
    const tr = document.createElement('tr'); const td = document.createElement('td');
    td.colSpan = 4; td.className = 'muted'; td.textContent = 'No account yet'; tr.append(td); tb.append(tr); return;
  }
  for (const a of accounts) {
    const tr = document.createElement('tr');
    const cells = [a.name + (a.default ? ' (default)' : ''), a.source, a.imap_user || '-'];
    for (const c of cells) { const td = document.createElement('td'); td.textContent = c; tr.append(td); }
    const last = document.createElement('td');
    if (a.source === 'admin') {
      const b = document.createElement('button'); b.className = 'danger'; b.textContent = 'Remove';
      b.onclick = async () => {
        if (!confirm('Remove account ' + a.name + '?')) return;
        try { render((await api('DELETE', 'accounts/' + encodeURIComponent(a.name))).accounts); err(); } catch (e) { err(e.message); }
      };
      last.append(b);
    }
    tr.append(last); tb.append(tr);
  }
}
function renderSecurity(s) {
  $('codeWrap').hidden = !s.totp;
  $('totpSetup').hidden = true;
  $('totpStart').hidden = s.totp || s.is_public;
  $('pubToggle').hidden = !s.totp || (s.is_public && !s.public_access);
  $('pubToggle').textContent = s.public_access ? 'Disable public access' : 'Allow access from the public domain';
  $('pubToggle').dataset.next = s.public_access ? 'false' : 'true';
  $('secState').textContent = !s.totp
    ? 'Authenticator not configured: this page is reachable only locally (127.0.0.1).'
    : 'Authenticator active. Public access is ' + (s.public_access ? 'enabled' : 'disabled (local only)') + '.';
}
async function show() {
  const s = await api('GET', 'session');
  renderSecurity(s);
  $('login').hidden = s.authenticated; $('app').hidden = !s.authenticated;
  if (s.authenticated) render((await api('GET', 'accounts')).accounts);
}
$('totpStart').onclick = async () => {
  try { const d = await api('POST', 'totp/setup'); $('totpKey').textContent = d.secret; $('totpSetup').hidden = false; $('totpStart').hidden = true; err(); }
  catch (x) { err(x.message); }
};
$('totpConfirm').onclick = async () => {
  try { await api('POST', 'totp/confirm', { code: $('totpCode').value }); $('totpCode').value = ''; $('totpKey').textContent = ''; err(); await show(); }
  catch (x) { err(x.message); }
};
$('pubToggle').onclick = async () => {
  const next = $('pubToggle').dataset.next === 'true';
  if (next && !confirm('Expose this admin page on the public domain? Login needs the token and an authenticator code.')) return;
  try { await api('POST', 'settings', { public_access: next }); err(); await show(); }
  catch (x) { err(x.message); }
};
$('login').onsubmit = async (e) => {
  e.preventDefault();
  try { await api('POST', 'login', { token: $('token').value, code: $('code').value }); $('token').value = ''; $('code').value = ''; err(); await show(); }
  catch (x) { err(x.message); }
};
$('logout').onclick = async () => { await api('POST', 'logout').catch(() => {}); await show(); };
$('add').onsubmit = async (e) => {
  e.preventDefault();
  const ids = ['name','imap_host','imap_port','imap_user','imap_pass','smtp_host','smtp_port','smtp_user','smtp_pass','smtp_from'];
  const body = Object.fromEntries(ids.map((i) => [i, $(i).value]));
  body.allow_self_signed = $('allow_self_signed').checked;
  err('Testing connection...');
  try { const d = await api('POST', 'accounts', body); render(d.accounts); $('add').reset(); err(); }
  catch (x) { err(x.message); }
};
show().catch((x) => err(x.message));
})();`;
