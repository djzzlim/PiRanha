#!/usr/bin/env bun

/**
 * credential-vault.ts — Secure credential manager for bug bounty hunting
 *
 * Stores credentials base64-encoded in ~/.claude/MEMORY/BugBounty/Vault/credentials.enc
 * Supports CLI usage and programmatic import via getCredentials().
 *
 * Usage:
 *   bun credential-vault.ts --store --target "hackerone-target" --username "user" --password "pass"
 *   bun credential-vault.ts --get --target "hackerone-target"
 *   bun credential-vault.ts --list
 *   bun credential-vault.ts --delete --target "hackerone-target"
 *   bun credential-vault.ts --redact --file "./report.md"
 *   bun credential-vault.ts --store --target "target" --op-item "1password-item-name"
 */

import { parseArgs } from "util";
import { existsSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Credential {
  username?: string;
  password?: string;
  cookie?: string;
  apiKey?: string;
  jwt?: string;
  otpSeed?: string;
  creditCard?: string;
  updatedAt: string;
}

type VaultData = Record<string, Credential>;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const VAULT_DIR = join(homedir(), ".claude", "MEMORY", "BugBounty", "Vault");
const VAULT_FILE = join(VAULT_DIR, "credentials.enc");

// ---------------------------------------------------------------------------
// Encoding helpers (base64 — prevents casual exposure, not crypto)
// ---------------------------------------------------------------------------

function encode(data: VaultData): string {
  return Buffer.from(JSON.stringify(data, null, 2), "utf-8").toString("base64");
}

function decode(raw: string): VaultData {
  return JSON.parse(Buffer.from(raw, "base64").toString("utf-8")) as VaultData;
}

// ---------------------------------------------------------------------------
// Vault I/O
// ---------------------------------------------------------------------------

function ensureVaultDir(): void {
  if (!existsSync(VAULT_DIR)) {
    mkdirSync(VAULT_DIR, { recursive: true });
  }
}

async function readVault(): Promise<VaultData> {
  ensureVaultDir();
  const file = Bun.file(VAULT_FILE);
  if (!(await file.exists())) return {};
  const raw = await file.text();
  if (!raw.trim()) return {};
  try {
    return decode(raw.trim());
  } catch {
    console.error("[vault] WARNING: corrupt vault file, starting fresh");
    return {};
  }
}

async function writeVault(data: VaultData): Promise<void> {
  ensureVaultDir();
  await Bun.write(VAULT_FILE, encode(data));
}

// ---------------------------------------------------------------------------
// 1Password CLI integration
// ---------------------------------------------------------------------------

async function pull1PasswordItem(itemName: string): Promise<Partial<Credential>> {
  // Check if `op` binary is available
  const which = Bun.spawnSync(["which", "op"]);
  if (which.exitCode !== 0) {
    throw new Error("`op` CLI not found. Install 1Password CLI to use --op-item.");
  }

  const proc = Bun.spawnSync(["op", "item", "get", itemName, "--format", "json"]);
  if (proc.exitCode !== 0) {
    const stderr = proc.stderr.toString().trim();
    throw new Error(`1Password lookup failed: ${stderr || "unknown error"}`);
  }

  const item = JSON.parse(proc.stdout.toString());
  const cred: Partial<Credential> = {};

  // Extract fields from 1Password item
  for (const field of item.fields ?? []) {
    const label = (field.label ?? "").toLowerCase();
    const value = field.value ?? "";
    if (!value) continue;

    if (label === "username") cred.username = value;
    else if (label === "password") cred.password = value;
    else if (label === "cookie") cred.cookie = value;
    else if (label.includes("api") && label.includes("key")) cred.apiKey = value;
    else if (label === "jwt" || label === "token") cred.jwt = value;
    else if (label.includes("otp") || label.includes("totp")) cred.otpSeed = value;
    else if (label.includes("credit") || label.includes("card")) cred.creditCard = value;
  }

  return cred;
}

// ---------------------------------------------------------------------------
// Environment variable overrides
// ---------------------------------------------------------------------------

function applyEnvOverrides(cred: Credential): Credential {
  const env = process.env;
  return {
    ...cred,
    username: env.HUNT_USER ?? cred.username,
    password: env.HUNT_PASS ?? cred.password,
    cookie: env.HUNT_COOKIE ?? cred.cookie,
    apiKey: env.HUNT_API_KEY ?? cred.apiKey,
  };
}

// ---------------------------------------------------------------------------
// Auto-redact warning
// ---------------------------------------------------------------------------

function warnIfExposed(cred: Credential): void {
  const secrets = [
    cred.password,
    cred.cookie,
    cred.apiKey,
    cred.jwt,
    cred.otpSeed,
    cred.creditCard,
  ].filter(Boolean) as string[];

  if (secrets.length > 0) {
    console.error(
      "[vault] WARNING: Credential values returned. Ensure they do not leak into logs, prompts, or reports. Use --redact to sanitize files."
    );
  }
}

// ---------------------------------------------------------------------------
// Exported: getCredentials (for programmatic import)
// ---------------------------------------------------------------------------

export async function getCredentials(targetSlug: string): Promise<Credential | null> {
  const vault = await readVault();
  const cred = vault[targetSlug];
  if (!cred) return null;

  const resolved = applyEnvOverrides(cred);
  warnIfExposed(resolved);
  return resolved;
}

// ---------------------------------------------------------------------------
// CLI actions
// ---------------------------------------------------------------------------

async function actionStore(
  target: string,
  fields: Partial<Credential>,
  opItem?: string
): Promise<void> {
  const vault = await readVault();

  let opCreds: Partial<Credential> = {};
  if (opItem) {
    opCreds = await pull1PasswordItem(opItem);
  }

  // Merge: explicit flags > 1Password > existing
  const existing = vault[target] ?? ({} as Credential);
  vault[target] = {
    username: fields.username ?? opCreds.username ?? existing.username,
    password: fields.password ?? opCreds.password ?? existing.password,
    cookie: fields.cookie ?? opCreds.cookie ?? existing.cookie,
    apiKey: fields.apiKey ?? opCreds.apiKey ?? existing.apiKey,
    jwt: fields.jwt ?? opCreds.jwt ?? existing.jwt,
    otpSeed: fields.otpSeed ?? opCreds.otpSeed ?? existing.otpSeed,
    creditCard: fields.creditCard ?? opCreds.creditCard ?? existing.creditCard,
    updatedAt: new Date().toISOString(),
  };

  await writeVault(vault);
  console.log(`[vault] Stored credentials for "${target}"`);
}

async function actionGet(target: string): Promise<void> {
  const cred = await getCredentials(target);
  if (!cred) {
    console.error(`[vault] No credentials found for "${target}"`);
    process.exit(1);
  }
  console.log(JSON.stringify(cred, null, 2));
}

async function actionList(): Promise<void> {
  const vault = await readVault();
  const targets = Object.keys(vault);
  if (targets.length === 0) {
    console.log("[vault] No stored targets.");
    return;
  }
  console.log("[vault] Stored targets:");
  for (const t of targets) {
    console.log(`  - ${t}  (updated: ${vault[t].updatedAt})`);
  }
}

async function actionDelete(target: string): Promise<void> {
  const vault = await readVault();
  if (!(target in vault)) {
    console.error(`[vault] Target "${target}" not found.`);
    process.exit(1);
  }
  delete vault[target];
  await writeVault(vault);
  console.log(`[vault] Deleted credentials for "${target}"`);
}

async function actionRedact(filePath: string): Promise<void> {
  const vault = await readVault();
  const file = Bun.file(filePath);
  if (!(await file.exists())) {
    console.error(`[vault] File not found: ${filePath}`);
    process.exit(1);
  }

  let content = await file.text();
  let replacements = 0;

  for (const [_target, cred] of Object.entries(vault)) {
    const secrets = [
      cred.password,
      cred.cookie,
      cred.apiKey,
      cred.jwt,
      cred.otpSeed,
      cred.creditCard,
    ].filter(Boolean) as string[];

    for (const secret of secrets) {
      // Only redact secrets that are at least 4 chars to avoid false positives
      if (secret.length < 4) continue;
      const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(escaped, "g");
      const matches = content.match(regex);
      if (matches) {
        replacements += matches.length;
        content = content.replace(regex, "[REDACTED]");
      }
    }
  }

  await Bun.write(filePath, content);
  console.log(`[vault] Redacted ${replacements} secret(s) in ${filePath}`);
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

export async function runCli(argv: string[] = Bun.argv.slice(2)): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      store: { type: "boolean", default: false },
      get: { type: "boolean", default: false },
      list: { type: "boolean", default: false },
      delete: { type: "boolean", default: false },
      redact: { type: "boolean", default: false },
      target: { type: "string" },
      username: { type: "string" },
      password: { type: "string" },
      cookie: { type: "string" },
      "api-key": { type: "string" },
      jwt: { type: "string" },
      "otp-seed": { type: "string" },
      "credit-card": { type: "string" },
      "op-item": { type: "string" },
      file: { type: "string" },
    },
    strict: true,
  });

  // Determine action
  if (values.store) {
    if (!values.target) {
      console.error("[vault] --target is required for --store");
      process.exit(1);
    }
    await actionStore(
      values.target,
      {
        username: values.username,
        password: values.password,
        cookie: values.cookie,
        apiKey: values["api-key"],
        jwt: values.jwt,
        otpSeed: values["otp-seed"],
        creditCard: values["credit-card"],
      },
      values["op-item"]
    );
  } else if (values.get) {
    if (!values.target) {
      console.error("[vault] --target is required for --get");
      process.exit(1);
    }
    await actionGet(values.target);
  } else if (values.list) {
    await actionList();
  } else if (values.delete) {
    if (!values.target) {
      console.error("[vault] --target is required for --delete");
      process.exit(1);
    }
    await actionDelete(values.target);
  } else if (values.redact) {
    if (!values.file) {
      console.error("[vault] --file is required for --redact");
      process.exit(1);
    }
    await actionRedact(values.file);
  } else {
    console.log(`credential-vault — Bug Bounty Credential Manager

Usage:
  --store   --target <name> [--username <u>] [--password <p>] [--cookie <c>]
            [--api-key <k>] [--jwt <j>] [--otp-seed <s>] [--credit-card <cc>]
            [--op-item <item>]
  --get     --target <name>
  --list
  --delete  --target <name>
  --redact  --file <path>

Environment overrides: HUNT_USER, HUNT_PASS, HUNT_COOKIE, HUNT_API_KEY`);
  }
}

if (import.meta.main) {
  runCli().catch((err) => {
    console.error(`[vault] Fatal: ${err.message}`);
    process.exit(1);
  });
}
