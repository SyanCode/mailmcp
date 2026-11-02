import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP = 30;

export function generateSecret(): string {
  const bytes = randomBytes(20);
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

function decode(secret: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of secret.replace(/[\s=]/g, "").toUpperCase()) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error("ADMIN_TOTP_SECRET is not valid base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function code(key: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", key).update(buf).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, "0");
}

let lastUsed = -1;

/** Verify a 6-digit code (±1 step). A code can be used only once. */
export function verifyTotp(secret: string, token: string, now = Date.now()): boolean {
  const key = decode(secret);
  const current = Math.floor(now / 1000 / STEP);
  for (const d of [-1, 0, 1]) {
    const counter = current + d;
    const expected = Buffer.from(code(key, counter));
    const given = Buffer.from(token.trim());
    if (expected.length === given.length && timingSafeEqual(expected, given) && counter > lastUsed) {
      lastUsed = counter;
      return true;
    }
  }
  return false;
}

export function otpauthUrl(secret: string, label = "mailmcp"): string {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=mailmcp`;
}
