#!/usr/bin/env npx tsx
/**
 * encrypt-all.ts
 *
 * Encrypts all .json manifest files in _manifests/ to .enc files.
 * Usage: npx tsx encrypt-all.ts <passphrase>
 */

import { readdirSync } from "node:fs";
import { join } from "node:path";
import { encryptManifest } from "./crypto.js";

const args = process.argv.slice(2);
const passphrase = args[0];

if (!passphrase) {
  console.error("Usage: npx tsx encrypt-all.ts <passphrase>");
  process.exit(1);
}

const manifestDir = join(import.meta.dirname ?? ".", "..", "_manifests");
const files = readdirSync(manifestDir).filter(f => f.endsWith(".json")).sort();

let count = 0;
for (const file of files) {
  const jsonPath = join(manifestDir, file);
  const encPath = join(manifestDir, file.replace(/\.json$/, ".enc"));
  encryptManifest(jsonPath, encPath, passphrase);
  count++;
  console.log(`  ${file} → ${file.replace(".json", ".enc")}`);
}

console.log(`\nEncrypted ${count} manifests.`);
