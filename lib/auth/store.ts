import "server-only";
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { eq } from "drizzle-orm";
import { db } from "../db/client";
import { auth } from "../db/schema";

// Single-user auth, SQLite-backed. password_hash format is
// `scrypt$<saltB64>$<hashB64>`. Set once via /register on first boot.

const scrypt = promisify(scryptCb) as (
  password: string | Buffer,
  salt: Buffer,
  keylen: number,
) => Promise<Buffer>;

export const MIN_PASSWORD_LENGTH = 12;

const SCRYPT_KEYLEN = 64;
const SCRYPT_SALT_BYTES = 16;

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SCRYPT_SALT_BYTES);
  const derived = await scrypt(password, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString("base64")}$${derived.toString("base64")}`;
}

async function verifyPassword(stored: string, password: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "base64");
  const expected = Buffer.from(parts[2], "base64");
  const derived = await scrypt(password, salt, expected.length);
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

function getAuthRow(): { passwordHash: string; createdAt: string } | null {
  const row = db().select().from(auth).where(eq(auth.id, 1)).get();
  if (!row) return null;
  return { passwordHash: row.passwordHash, createdAt: row.createdAt };
}

export async function isRegistered(): Promise<boolean> {
  return getAuthRow() !== null;
}

/**
 * First-run registration: claim the single auth row, then run `persist`
 * (saving the operator's credentials). The row insert is the atomic claim, so
 * of two concurrent first-run submissions only the winner ever writes
 * configuration; the loser gets "Already registered." before touching it. If
 * `persist` throws, the claim is released so registration can be retried.
 */
export async function registerWith(password: string, persist: () => Promise<void>): Promise<void> {
  await register(password);
  try {
    await persist();
  } catch (err) {
    db().delete(auth).where(eq(auth.id, 1)).run();
    throw err;
  }
}

/** Exclusive create — throws if the auth row already exists. */
export async function register(password: string): Promise<void> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
  if (getAuthRow()) {
    throw new Error("Already registered.");
  }
  const passwordHash = await hashPassword(password);
  const createdAt = new Date().toISOString();
  try {
    db().insert(auth).values({ id: 1, passwordHash, createdAt }).run();
  } catch (err) {
    // PRIMARY KEY collision — concurrent register attempt won the race.
    // Preserve the EEXIST-style semantic the old `wx` flag gave us.
    if (/UNIQUE|PRIMARY KEY/i.test((err as Error).message)) {
      throw new Error("Already registered.");
    }
    throw err;
  }
}

export async function verify(password: string): Promise<boolean> {
  const row = getAuthRow();
  if (!row) return false;
  try {
    return await verifyPassword(row.passwordHash, password);
  } catch {
    return false;
  }
}
