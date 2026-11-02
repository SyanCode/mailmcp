import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Env-style keys without account prefix: IMAP_HOST, IMAP_USER, ... */
export type StoredAccount = Record<string, string>;

/** Admin UI settings, encrypted together with the accounts. */
export interface AdminSettings {
  /** Base32 TOTP secret, set once the admin confirmed a code from the authenticator. */
  totpSecret?: string;
  /** Allow the admin UI on the public domain (only honoured when TOTP is configured). */
  adminPublic?: boolean;
}

interface FileFormat {
  v: 1 | 2;
  salt: string;
  iv: string;
  tag: string;
  data: string;
}

/** Accounts and settings added from the admin UI, kept in an AES-256-GCM encrypted file. */
export class AccountStore {
  private readonly accounts = new Map<string, StoredAccount>();
  private settings: AdminSettings = {};
  private readonly file: string;

  constructor(dir: string, private readonly secret: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = join(dir, "accounts.enc.json");
    this.load();
  }

  private key(salt: Buffer): Buffer {
    return scryptSync(this.secret, salt, 32);
  }

  private load() {
    if (!existsSync(this.file)) return;
    const f = JSON.parse(readFileSync(this.file, "utf8")) as FileFormat;
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.key(Buffer.from(f.salt, "base64")), Buffer.from(f.iv, "base64"));
      decipher.setAuthTag(Buffer.from(f.tag, "base64"));
      const plain = Buffer.concat([decipher.update(Buffer.from(f.data, "base64")), decipher.final()]);
      const obj = JSON.parse(plain.toString("utf8"));
      const accounts = (f.v === 2 ? obj.accounts : obj) as Record<string, StoredAccount>;
      for (const [name, acc] of Object.entries(accounts)) this.accounts.set(name, acc);
      if (f.v === 2) this.settings = obj.settings ?? {};
    } catch {
      throw new Error(`Cannot decrypt ${this.file}: wrong MAILMCP_ENCRYPTION_KEY/MCP_AUTH_TOKEN or corrupted file`);
    }
  }

  private persist() {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key(salt), iv);
    const payload = JSON.stringify({ accounts: Object.fromEntries(this.accounts), settings: this.settings });
    const data = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
    const out: FileFormat = {
      v: 2,
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      data: data.toString("base64"),
    };
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify(out), { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  list(): [string, StoredAccount][] {
    return [...this.accounts.entries()];
  }

  set(name: string, acc: StoredAccount) {
    this.accounts.set(name, acc);
    this.persist();
  }

  remove(name: string): boolean {
    const had = this.accounts.delete(name);
    if (had) this.persist();
    return had;
  }

  getSettings(): AdminSettings {
    return { ...this.settings };
  }

  updateSettings(patch: Partial<AdminSettings>) {
    this.settings = { ...this.settings, ...patch };
    for (const k of Object.keys(this.settings) as (keyof AdminSettings)[]) {
      if (this.settings[k] === undefined) delete this.settings[k];
    }
    this.persist();
  }
}
