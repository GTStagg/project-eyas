import "server-only";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

// Column-level encryption for credentials at rest.
//
// Why: settings.json was plaintext mode-0600 on disk. That protected against
// other Unix users on the same box, but left credentials exposed to backup
// hygiene mistakes (a synced data/ folder shipped Falcon API + Anthropic
// keys in cleartext). The Keychain/keytar path was reverted on the macOS
// fleet (`anthropic_gateway_only_standalone`-adjacent revert 2026-05-11),
// so app-level AES-256-GCM is the path that doesn't reintroduce the native
// binary problem.
//
// Key derivation: HKDF-SHA256 from AUTH_SESSION_SECRET. That secret is
// already required, already 32+ bytes, already rotated by deleting the
// .env line. Reusing it means we don't introduce a second secret-rotation
// surface — at the cost that rotating AUTH_SESSION_SECRET also invalidates
// all encrypted credentials. Decryption failures surface as null + a
// warning; the operator re-enters via /config. This is intentional — a
// secret rotation is meant to invalidate sessions, and ciphertext that
// outlived the secret it was encrypted against shouldn't be silently
// trusted.
//
// Wire format per column: nonce(12) || ciphertext || tag(16), one BLOB.
// AAD is the column tag string supplied by the caller (e.g. "settings.anthropic_api_key")
// so a swapped ciphertext from a different column fails to authenticate.

const KEY_LEN = 32;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const HKDF_SALT = Buffer.from("falcon-eyas-db-v1");
const HKDF_INFO = Buffer.from("column-encryption-key");

let cachedKey: Buffer | null = null;
let cachedFromSecret: string | null = null;

function masterKey(): Buffer {
  const secret = process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      "AUTH_SESSION_SECRET missing or too short — cannot derive DB encryption key. " +
        "start.sh auto-generates this on first run; check .env.",
    );
  }
  if (cachedKey && cachedFromSecret === secret) return cachedKey;
  const derived = hkdfSync("sha256", Buffer.from(secret, "utf8"), HKDF_SALT, HKDF_INFO, KEY_LEN);
  cachedKey = Buffer.from(derived);
  cachedFromSecret = secret;
  return cachedKey;
}

/** Encrypt a UTF-8 string for storage. Returns null for null/empty input
 *  so callers can pass through unset credentials without branching. */
export function encryptColumn(plaintext: string | null | undefined, aad: string): Buffer | null {
  if (plaintext == null || plaintext === "") return null;
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", masterKey(), nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]);
}

/** Decrypt to a UTF-8 string. Returns null for null input or any decrypt
 *  failure (corrupt blob, rotated AUTH_SESSION_SECRET, wrong AAD). */
export function decryptColumn(blob: Buffer | Uint8Array | null | undefined, aad: string): string | null {
  if (!blob || blob.length < NONCE_LEN + TAG_LEN) return null;
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  try {
    const nonce = buf.subarray(0, NONCE_LEN);
    const tag = buf.subarray(buf.length - TAG_LEN);
    const ct = buf.subarray(NONCE_LEN, buf.length - TAG_LEN);
    const decipher = createDecipheriv("aes-256-gcm", masterKey(), nonce);
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString("utf8");
  } catch (err) {
    // Most likely cause: AUTH_SESSION_SECRET rotated. Don't crash — surface
    // as a missing credential and let /config re-collection fix it.
    console.warn(`[db/crypto] decrypt failed for column "${aad}":`, (err as Error).message);
    return null;
  }
}
