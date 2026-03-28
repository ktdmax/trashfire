import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import {
  TFBM_MAGIC,
  TFBM_VERSION,
  SALT_LENGTH,
  IV_LENGTH,
  TAG_LENGTH,
  PBKDF2_ITERATIONS,
  KEY_LENGTH,
} from "./types.js";

// ─── Key Derivation ──────────────────────────────────────────────────────────

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
}

// ─── Encrypt ─────────────────────────────────────────────────────────────────

export function encrypt(plaintext: Buffer, passphrase: string): Buffer {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(passphrase, salt);

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Build TFBM binary format:
  // [TFBM(4)] [version(2)] [salt(32)] [iv(12)] [plaintext_length(4)] [tag(16)] [ciphertext(...)]
  const header = Buffer.alloc(4 + 2 + SALT_LENGTH + IV_LENGTH + 4 + TAG_LENGTH);
  let offset = 0;

  TFBM_MAGIC.copy(header, offset);
  offset += 4;

  header.writeUInt16BE(TFBM_VERSION, offset);
  offset += 2;

  salt.copy(header, offset);
  offset += SALT_LENGTH;

  iv.copy(header, offset);
  offset += IV_LENGTH;

  header.writeUInt32BE(plaintext.length, offset);
  offset += 4;

  tag.copy(header, offset);

  return Buffer.concat([header, ciphertext]);
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

export function decrypt(data: Buffer, passphrase: string): Buffer {
  let offset = 0;

  // Verify magic
  const magic = data.subarray(offset, offset + 4);
  if (!magic.equals(TFBM_MAGIC)) {
    throw new Error("Invalid file: missing TFBM magic header");
  }
  offset += 4;

  // Read version
  const version = data.readUInt16BE(offset);
  if (version !== TFBM_VERSION) {
    throw new Error(`Unsupported TFBM version: ${version}`);
  }
  offset += 2;

  // Read salt
  const salt = data.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;

  // Read IV
  const iv = data.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;

  // Read plaintext length (for verification)
  const plaintextLength = data.readUInt32BE(offset);
  offset += 4;

  // Read auth tag
  const tag = data.subarray(offset, offset + TAG_LENGTH);
  offset += TAG_LENGTH;

  // Rest is ciphertext
  const ciphertext = data.subarray(offset);

  // Derive key and decrypt
  const key = deriveKey(passphrase, Buffer.from(salt));
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv));
  decipher.setAuthTag(Buffer.from(tag));

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  if (plaintext.length !== plaintextLength) {
    throw new Error(`Length mismatch: expected ${plaintextLength}, got ${plaintext.length}`);
  }

  return plaintext;
}

// ─── Encrypt Manifest (JSON → .enc) ─────────────────────────────────────────

export function encryptManifest(jsonPath: string, encPath: string, passphrase: string): void {
  const plaintext = readFileSync(jsonPath);
  const encrypted = encrypt(plaintext, passphrase);
  writeFileSync(encPath, encrypted);
}

// ─── Decrypt Manifest (.enc → JSON in memory) ───────────────────────────────

export function decryptManifest(encPath: string, passphrase: string): string {
  const data = readFileSync(encPath);
  const plaintext = decrypt(data, passphrase);
  return plaintext.toString("utf-8");
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

async function promptPassphrase(prompt: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const fileIndex = args.indexOf("--file");

  if (!command || fileIndex === -1 || !args[fileIndex + 1]) {
    console.error("Usage: tsx crypto.ts <encrypt|decrypt> --file <path> [--out <path>]");
    console.error("  encrypt: reads JSON, writes .enc");
    console.error("  decrypt: reads .enc, writes JSON to stdout");
    process.exit(1);
  }

  const filePath = args[fileIndex + 1];
  const outIndex = args.indexOf("--out");
  const passphrase = await promptPassphrase("Passphrase: ");

  if (command === "encrypt") {
    const outPath = outIndex !== -1 ? args[outIndex + 1] : filePath.replace(/\.json$/, ".enc");
    encryptManifest(filePath, outPath, passphrase);
    console.error(`Encrypted: ${filePath} → ${outPath}`);
  } else if (command === "decrypt") {
    const json = decryptManifest(filePath, passphrase);
    if (outIndex !== -1) {
      writeFileSync(args[outIndex + 1], json);
      console.error(`Decrypted: ${filePath} → ${args[outIndex + 1]}`);
    } else {
      process.stdout.write(json);
    }
  } else {
    console.error(`Unknown command: ${command}`);
    process.exit(1);
  }
}

// Run CLI if executed directly
const isDirectRun = process.argv[1]?.endsWith("crypto.ts");
if (isDirectRun) {
  main().catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
}
