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
    registry.names().map((name) => {
      const info = registry.get(name).info;
      return {
        name,
        description: info.description,
        source: registry.isFromEnv(name) ? "env" : "admin",
        imap_host: info.imap_host,
        imap_user: info.imap_user,
        smtp_host: info.smtp_host,
        from: info.from,
        default: name === registry.defaultName,
      };
    });

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
        const imapUser = str(b?.imap_user);
        const domain = imapUser.split("@")[1] ?? "";
        // Simple form: only the address and password are needed, the rest is derived.
        let name = str(b?.name);
        if (!name) {
          const local = imapUser.split("@")[0].replace(/[^A-Za-z0-9]/g, "");
          name = local || "mailbox";
          if (registry.has(name)) name += domain.replace(/[^A-Za-z0-9]/g, "");
          for (let i = 2; registry.has(name); i++) name = `${local || "mailbox"}${i}`;
        }
        if (!ACCOUNT_NAME.test(name)) {
          sendJson(res, 400, { error: "Name: letters and digits only" });
          return true;
        }
        if (registry.has(name)) {
          sendJson(res, 409, { error: `Account "${name}" already exists` });
          return true;
        }
        const acc: StoredAccount = {
          IMAP_HOST: str(b?.imap_host) || (domain ? `mail.${domain}` : ""),
          IMAP_PORT: str(b?.imap_port) || "993",
          IMAP_USER: imapUser,
          IMAP_PASS: typeof b?.imap_pass === "string" ? b.imap_pass : "",
          SMTP_HOST: str(b?.smtp_host) || str(b?.imap_host) || (domain ? `mail.${domain}` : ""),
          SMTP_PORT: str(b?.smtp_port) || "465",
        };
        for (const [k, v] of [
          ["SMTP_USER", str(b?.smtp_user)],
          ["SMTP_PASS", typeof b?.smtp_pass === "string" ? b.smtp_pass : ""],
          ["SMTP_FROM", str(b?.smtp_from)],
          ["MAIL_DESCRIPTION", str(b?.description)],
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
      if (m && req.method === "PATCH") {
        const name = m[1].toLowerCase();
        if (registry.isFromEnv(name) || !registry.has(name)) {
          sendJson(res, 400, { error: "Unknown account, or defined by environment variables (use <NAME>_MAIL_DESCRIPTION)" });
          return true;
        }
        const b = (await readJson(req)) as Record<string, unknown> | undefined;
        const description = str(b?.description);
        const acc = store.list().find(([n]) => n === name)?.[1];
        if (!acc) {
          sendJson(res, 404, { error: "Unknown account" });
          return true;
        }
        const next = { ...acc };
        if (description) next.MAIL_DESCRIPTION = description;
        else delete next.MAIL_DESCRIPTION;
        store.set(name, next);
        registry.get(name).setDescription(description);
        sendJson(res, 200, { ok: true, accounts: listAccounts() });
        return true;
      }
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
:root{--bg:#f5f6f8;--card:#fff;--fg:#17191c;--muted:#6b7280;--line:#e3e5e9;--accent:#3b5bdb;--accent-fg:#fff;--danger:#d92d20;--ok:#12805c;--ok-bg:#e3f6ee;--env-bg:#eceefe;--field:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--fg:#e8eaed;--muted:#9aa1ad;--line:#272b33;--accent:#7b93ff;--accent-fg:#0f1115;--danger:#ff6b5e;--ok:#4ade9f;--ok-bg:#12332a;--env-bg:#242a48;--field:#0f1115}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:780px;margin:0 auto;padding:1.5rem 1rem 3rem}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.25rem}
h1{font-size:1.25rem;margin:0} h2{font-size:1rem;margin:0 0 .75rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.25rem;margin-bottom:1rem}
label{display:block;font-size:.8rem;font-weight:500;color:var(--muted);margin-bottom:.75rem}
input:not([type=checkbox]){display:block;width:100%;margin-top:.3rem;padding:.55rem .7rem;font:inherit;color:var(--fg);background:var(--field);border:1px solid var(--line);border-radius:8px}
input:focus{outline:2px solid var(--accent);outline-offset:-1px}
button{font:inherit;font-weight:500;padding:.5rem 1rem;border:0;border-radius:8px;background:var(--accent);color:var(--accent-fg);cursor:pointer}
button:hover{filter:brightness(1.08)}
button.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
button.danger{background:transparent;color:var(--danger);border:1px solid var(--line);padding:.3rem .7rem;font-size:.85rem}
.acc{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.75rem 0;border-top:1px solid var(--line)}
.acc:first-of-type{border-top:0;padding-top:0}
.acc b{font-weight:600} .acc small{display:block;color:var(--muted);word-break:break-all}
.badge{display:inline-block;margin-left:.4rem;padding:.05rem .5rem;border-radius:99px;font-size:.7rem;font-weight:600;vertical-align:middle;background:var(--env-bg);color:var(--accent)}
.badge.def{background:var(--ok-bg);color:var(--ok)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:0 1rem}
@media(max-width:560px){.row{grid-template-columns:1fr}}
fieldset{border:1px solid var(--line);border-radius:8px;margin:0 0 1rem;padding:.75rem 1rem .25rem}
legend{padding:0 .4rem;font-size:.8rem;font-weight:600}
.check{display:flex;align-items:center;gap:.5rem;font-size:.85rem}
.err{color:var(--danger);min-height:1.2em;margin:.5rem 0 0} .muted{color:var(--muted)}
code{display:block;padding:.6rem .8rem;background:var(--bg);border-radius:8px;word-break:break-all;user-select:all}
#login{max-width:380px;margin:3rem auto}
summary{cursor:pointer;margin:.25rem 0 1rem}
.desc{display:block;color:var(--fg);margin:.15rem 0}
.link{background:none;border:0;padding:0;color:var(--accent);font-size:.8rem;cursor:pointer}
[hidden]{display:none!important}
</style></head><body>
<main>
<header><h1>mailmcp admin</h1><button class="ghost" id="logout" hidden>Sign out</button></header>
<form id="login" class="card" hidden>
  <h2>Sign in</h2>
  <label>Access token<input type="password" id="token" autocomplete="current-password" required></label>
  <label id="codeWrap" hidden>Authenticator code<input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label>
  <button>Sign in</button>
</form>
<section id="app" hidden>
  <div class="card">
    <h2>Accounts</h2>
    <div id="list"></div>
  </div>
  <div class="card">
    <h2>Security</h2>
    <p id="secState" class="muted"></p>
    <div id="totpSetup" hidden>
      <p>Add this key in Google Authenticator (<em>Enter a setup key</em>, type <em>Time based</em>), then type the code it shows.</p>
      <code id="totpKey"></code>
      <label style="margin-top:.75rem">Code<input id="totpCode" inputmode="numeric" maxlength="6" autocomplete="off"></label>
      <button id="totpConfirm" type="button">Confirm</button>
    </div>
    <button id="totpStart" type="button" hidden>Set up authenticator</button>
    <button id="pubToggle" class="ghost" type="button" hidden></button>
  </div>
  <form id="add" class="card">
    <h2>Add an account</h2>
    <div class="row"><label>Email address<input id="imap_user" type="email" required placeholder="you@example.com"></label><label>Password<input id="imap_pass" type="password" required autocomplete="new-password"></label></div>
    <label>Description (what this mailbox is for, shown to Claude)<input id="description" placeholder="Work mailbox: clients and invoices"></label>
    <details><summary class="muted">Advanced settings (servers, ports, name)</summary>
    <label>Name (letters and digits, derived from the address if empty)<input id="name" pattern="[A-Za-z0-9]*"></label>
    <fieldset><legend>IMAP (host defaults to mail.&lt;domain&gt;)</legend>
      <div class="row"><label>Host<input id="imap_host"></label><label>Port<input id="imap_port" value="993"></label></div>
    </fieldset>
    <fieldset><legend>SMTP (defaults to IMAP host and credentials)</legend>
      <div class="row"><label>Host<input id="smtp_host"></label><label>Port<input id="smtp_port" value="465"></label></div>
      <div class="row"><label>User<input id="smtp_user"></label><label>Password<input id="smtp_pass" type="password" autocomplete="new-password"></label></div>
      <label>From address<input id="smtp_from" placeholder="You &lt;you@example.com&gt;"></label>
    </fieldset>
    <label class="check"><input type="checkbox" id="allow_self_signed"> Accept self-signed certificate</label>
    </details>
    <button style="margin-top:1rem">Test and save</button>
  </form>
</section>
<p class="err" id="err"></p>
</main>
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
function badge(text, cls) {
  const s = document.createElement('span'); s.className = 'badge' + (cls ? ' ' + cls : ''); s.textContent = text; return s;
}
function render(accounts) {
  const box = $('list'); box.replaceChildren();
  if (!accounts.length) {
    const p = document.createElement('p'); p.className = 'muted'; p.textContent = 'No account yet'; box.append(p); return;
  }
  for (const a of accounts) {
    const row = document.createElement('div'); row.className = 'acc';
    const info = document.createElement('div');
    const title = document.createElement('b'); title.textContent = a.name;
    info.append(title, badge(a.source === 'env' ? 'env' : 'admin'));
    if (a.default) info.append(badge('default', 'def'));
    const detail = document.createElement('small');
    detail.textContent = (a.imap_user || '-') + ' \\u00b7 IMAP ' + (a.imap_host || '-') + ' \\u00b7 SMTP ' + (a.smtp_host || '-');
    const desc = document.createElement('span'); desc.className = 'desc'; desc.textContent = a.description || 'No description';
    if (!a.description) desc.classList.add('muted');
    info.append(desc, detail);
    row.append(info);
    if (a.source === 'admin') {
      const ed = document.createElement('button'); ed.className = 'link'; ed.textContent = 'Edit description';
      ed.onclick = async () => {
        const v = prompt('Description of ' + a.name, a.description || '');
        if (v === null) return;
        try { render((await api('PATCH', 'accounts/' + encodeURIComponent(a.name), { description: v })).accounts); err(); } catch (e) { err(e.message); }
      };
      info.append(ed);
      const b = document.createElement('button'); b.className = 'danger'; b.textContent = 'Remove';
      b.onclick = async () => {
        if (!confirm('Remove account ' + a.name + '?')) return;
        try { render((await api('DELETE', 'accounts/' + encodeURIComponent(a.name))).accounts); err(); } catch (e) { err(e.message); }
      };
      row.append(b);
    }
    box.append(row);
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
  $('login').hidden = s.authenticated; $('app').hidden = !s.authenticated; $('logout').hidden = !s.authenticated;
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
  const ids = ['name','description','imap_host','imap_port','imap_user','imap_pass','smtp_host','smtp_port','smtp_user','smtp_pass','smtp_from'];
  const body = Object.fromEntries(ids.map((i) => [i, $(i).value]));
  body.allow_self_signed = $('allow_self_signed').checked;
  err('Testing connection...');
  try { const d = await api('POST', 'accounts', body); render(d.accounts); $('add').reset(); err(); }
  catch (x) { err(x.message); }
};
show().catch((x) => err(x.message));
})();`;
