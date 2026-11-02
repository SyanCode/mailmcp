import { ImapFlow, type SearchObject } from "imapflow";
import { simpleParser } from "mailparser";
import nodemailer from "nodemailer";
import { z } from "zod";

const bool = (v: string | undefined, def: boolean): boolean =>
  v === undefined || v === "" ? def : ["1", "true", "yes"].includes(v.toLowerCase());

const EnvSchema = z.object({
  IMAP_HOST: z.string().min(1),
  IMAP_PORT: z.coerce.number().int().positive().default(993),
  IMAP_USER: z.string().min(1),
  IMAP_PASS: z.string().min(1),
  IMAP_SECURE: z.string().optional(),
  SMTP_HOST: z.string().min(1),
  SMTP_PORT: z.coerce.number().int().positive().default(465),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_SECURE: z.string().optional(),
  SMTP_FROM: z.string().optional(),
  MAIL_TLS_REJECT_UNAUTHORIZED: z.string().optional(),
});

export type MailConfig = ReturnType<typeof loadConfig>;

export const ACCOUNT_NAME = /^[A-Za-z0-9]+$/;

/** Live set of mailbox accounts. Env accounts are read-only, admin ones can change. */
export class Registry {
  private readonly clients = new Map<string, MailClient>();
  private readonly fixed = new Set<string>();

  constructor(private readonly preferredDefault?: string) {}

  add(name: string, client: MailClient, fromEnv = false) {
    const key = name.toLowerCase();
    this.clients.set(key, client);
    if (fromEnv) this.fixed.add(key);
  }

  remove(name: string): boolean {
    return this.clients.delete(name.toLowerCase());
  }

  has(name: string): boolean {
    return this.clients.has(name.toLowerCase());
  }

  isFromEnv(name: string): boolean {
    return this.fixed.has(name.toLowerCase());
  }

  names(): string[] {
    return [...this.clients.keys()];
  }

  get defaultName(): string {
    if (this.preferredDefault && this.clients.has(this.preferredDefault)) return this.preferredDefault;
    return this.names()[0] ?? "";
  }

  get(name?: string): MailClient {
    if (!this.clients.size) throw new Error("No mail account configured");
    const key = (name ?? this.defaultName).toLowerCase();
    const client = this.clients.get(key);
    if (!client) throw new Error(`Unknown account "${name}". Available: ${this.names().join(", ")}`);
    return client;
  }
}

/**
 * Accounts come from MAIL_ACCOUNTS=perso,pro with prefixed vars (PERSO_IMAP_HOST, ...).
 * Without MAIL_ACCOUNTS, unprefixed IMAP_* / SMTP_* define one "default" account
 * (only if IMAP_HOST is set, so a pure admin-UI setup can start empty).
 */
export function loadAccounts(env: NodeJS.ProcessEnv = process.env): Registry {
  const names = (env.MAIL_ACCOUNTS ?? "")
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);

  const registry = new Registry(env.MAIL_DEFAULT_ACCOUNT?.toLowerCase());

  if (!names.length) {
    if (env.IMAP_HOST) registry.add("default", new MailClient(loadConfig(env)), true);
    return registry;
  }

  for (const name of names) {
    if (!ACCOUNT_NAME.test(name)) {
      throw new Error(`Invalid account name "${name}" (letters and digits only)`);
    }
    if (registry.has(name)) throw new Error(`Duplicate account "${name}"`);
    registry.add(name, new MailClient(loadConfig(env, `${name.toUpperCase()}_`, name)), true);
  }

  if (env.MAIL_DEFAULT_ACCOUNT && !registry.has(env.MAIL_DEFAULT_ACCOUNT)) {
    throw new Error(`MAIL_DEFAULT_ACCOUNT "${env.MAIL_DEFAULT_ACCOUNT}" is not in MAIL_ACCOUNTS`);
  }
  return registry;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env, prefix = "", label = "default") {
  const scoped: Record<string, string | undefined> = {};
  for (const key of Object.keys(EnvSchema.shape)) {
    scoped[key] = env[prefix + key];
  }
  // TLS strictness may be set once globally.
  scoped.MAIL_TLS_REJECT_UNAUTHORIZED ??= env.MAIL_TLS_REJECT_UNAUTHORIZED;

  const parsed = EnvSchema.safeParse(scoped);
  if (!parsed.success) {
    const missing = parsed.error.issues.map((i) => prefix + i.path.join(".")).join(", ");
    throw new Error(`Invalid configuration for account "${label}", check env vars: ${missing}`);
  }
  const e = parsed.data;
  const rejectUnauthorized = bool(e.MAIL_TLS_REJECT_UNAUTHORIZED, true);
  return {
    imap: {
      host: e.IMAP_HOST,
      port: e.IMAP_PORT,
      secure: bool(e.IMAP_SECURE, e.IMAP_PORT === 993),
      user: e.IMAP_USER,
      pass: e.IMAP_PASS,
      rejectUnauthorized,
    },
    smtp: {
      host: e.SMTP_HOST,
      port: e.SMTP_PORT,
      secure: bool(e.SMTP_SECURE, e.SMTP_PORT === 465),
      user: e.SMTP_USER ?? e.IMAP_USER,
      pass: e.SMTP_PASS ?? e.IMAP_PASS,
      from: e.SMTP_FROM ?? e.SMTP_USER ?? e.IMAP_USER,
      rejectUnauthorized,
    },
  };
}

export interface FolderInfo {
  path: string;
  name: string;
  specialUse?: string;
  messages?: number;
  unseen?: number;
}

export interface MessageSummary {
  uid: number;
  from: string;
  subject: string;
  date: string | null;
  unread: boolean;
}

export interface SearchParams {
  folder?: string;
  unread?: boolean;
  text?: string;
  from?: string;
  subject?: string;
  since?: string;
  limit?: number;
}

export interface ReadResult {
  uid: number;
  folder: string;
  from: string;
  to: string;
  cc: string;
  subject: string;
  date: string | null;
  messageId?: string;
  text: string;
  attachments: { filename?: string; contentType: string; size: number }[];
}

export interface SendParams {
  to: string[];
  subject: string;
  text: string;
  cc?: string[];
  bcc?: string[];
  html?: string;
  inReplyTo?: string;
}

const addr = (a: unknown): string => {
  if (!a) return "";
  const list = Array.isArray(a) ? a : [a];
  return list.map((x) => (x as { text?: string }).text ?? "").filter(Boolean).join(", ");
};

export class MailClient {
  constructor(private readonly cfg: MailConfig) {}

  /** Non-secret connection details, for display in the admin. */
  get info() {
    return {
      imap_host: this.cfg.imap.host,
      imap_user: this.cfg.imap.user,
      smtp_host: this.cfg.smtp.host,
      from: this.cfg.smtp.from,
    };
  }

  private newImap(): ImapFlow {
    const { imap } = this.cfg;
    return new ImapFlow({
      host: imap.host,
      port: imap.port,
      secure: imap.secure,
      auth: { user: imap.user, pass: imap.pass },
      tls: { rejectUnauthorized: imap.rejectUnauthorized },
      logger: false,
    });
  }

  /** Open a short-lived IMAP connection for one operation. */
  private async withImap<T>(fn: (c: ImapFlow) => Promise<T>): Promise<T> {
    const client = this.newImap();
    await client.connect();
    try {
      return await fn(client);
    } finally {
      await client.logout().catch(() => client.close());
    }
  }

  /** Check that IMAP login and SMTP connection both work. Throws a readable error. */
  async verify(): Promise<void> {
    try {
      await this.withImap(async () => undefined);
    } catch (e) {
      throw new Error(`IMAP: ${e instanceof Error ? e.message : String(e)}`);
    }
    const { smtp } = this.cfg;
    const transport = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth: { user: smtp.user, pass: smtp.pass },
      tls: { rejectUnauthorized: smtp.rejectUnauthorized },
    });
    try {
      await transport.verify();
    } catch (e) {
      throw new Error(`SMTP: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      transport.close();
    }
  }

  async listFolders(): Promise<FolderInfo[]> {
    return this.withImap(async (c) => {
      const boxes = await c.list({ statusQuery: { messages: true, unseen: true } });
      return boxes.map((b) => ({
        path: b.path,
        name: b.name,
        specialUse: b.specialUse,
        messages: b.status?.messages,
        unseen: b.status?.unseen,
      }));
    });
  }

  async search(p: SearchParams): Promise<MessageSummary[]> {
    const folder = p.folder ?? "INBOX";
    const limit = p.limit ?? 20;
    return this.withImap(async (c) => {
      const lock = await c.getMailboxLock(folder, { readOnly: true });
      try {
        const query: SearchObject = {};
        if (p.unread) query.seen = false;
        if (p.text) query.text = p.text;
        if (p.from) query.from = p.from;
        if (p.subject) query.subject = p.subject;
        if (p.since) query.since = new Date(p.since);
        const found = await c.search(Object.keys(query).length ? query : { all: true }, { uid: true });
        const uids = (found || []).sort((a, b) => b - a).slice(0, limit);
        if (!uids.length) return [];
        const out: MessageSummary[] = [];
        for await (const m of c.fetch(uids, { uid: true, envelope: true, flags: true }, { uid: true })) {
          out.push({
            uid: m.uid,
            from: m.envelope?.from?.map((f) => f.name ? `${f.name} <${f.address}>` : f.address).join(", ") ?? "",
            subject: m.envelope?.subject ?? "",
            date: m.envelope?.date ? new Date(m.envelope.date).toISOString() : null,
            unread: !m.flags?.has("\\Seen"),
          });
        }
        return out.sort((a, b) => b.uid - a.uid);
      } finally {
        lock.release();
      }
    });
  }

  async read(uid: number, folder = "INBOX", markRead = false, maxChars = 20000): Promise<ReadResult> {
    return this.withImap(async (c) => {
      const lock = await c.getMailboxLock(folder, { readOnly: !markRead });
      try {
        const msg = await c.fetchOne(String(uid), { source: true, uid: true }, { uid: true });
        if (!msg || !msg.source) throw new Error(`Message UID ${uid} not found in ${folder}`);
        const mail = await simpleParser(msg.source);
        if (markRead) await c.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true });
        const body = mail.text ?? (mail.html ? String(mail.html).replace(/<[^>]+>/g, " ") : "");
        return {
          uid,
          folder,
          from: addr(mail.from),
          to: addr(mail.to),
          cc: addr(mail.cc),
          subject: mail.subject ?? "",
          date: mail.date ? mail.date.toISOString() : null,
          messageId: mail.messageId,
          text: body.length > maxChars ? body.slice(0, maxChars) + "\n[truncated]" : body,
          attachments: mail.attachments.map((a) => ({
            filename: a.filename,
            contentType: a.contentType,
            size: a.size,
          })),
        };
      } finally {
        lock.release();
      }
    });
  }

  async send(p: SendParams): Promise<{ messageId: string; accepted: string[]; rejected: string[] }> {
    const { smtp } = this.cfg;
    const transport = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth: { user: smtp.user, pass: smtp.pass },
      tls: { rejectUnauthorized: smtp.rejectUnauthorized },
    });
    try {
      const info = await transport.sendMail({
        from: smtp.from,
        to: p.to,
        cc: p.cc,
        bcc: p.bcc,
        subject: p.subject,
        text: p.text,
        html: p.html,
        inReplyTo: p.inReplyTo,
        references: p.inReplyTo,
      });
      return {
        messageId: info.messageId,
        accepted: info.accepted.map(String),
        rejected: info.rejected.map(String),
      };
    } finally {
      transport.close();
    }
  }
}
