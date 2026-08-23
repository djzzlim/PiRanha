#!/usr/bin/env bun
/**
 * piranha — the PiRanha launcher binary.
 *
 * A single self-contained CLI (compiled with `bun build --compile`) that
 * classifies a target, initializes the hunt state machine, computes the
 * deterministic agent deployment plan, and launches the swarm inside a
 * coding-agent harness (omp / pi or Claude Code).
 *
 * The deterministic surface (classify, plan, status, vault, agents) runs fully
 * standalone — no harness, no on-disk skill required. `hunt` adds the agentic
 * layer by driving whichever harness is on PATH.
 */

import pkg from "../package.json";
import {
  ENGAGEMENTS,
  ALIASES,
  resolveKey,
  planAgents,
  renderPlan,
} from "../skills/BugBountyFramework/Tools/agent-router.ts";
import {
  createHuntState,
  loadState,
  getHuntStatus,
  listSessions,
  toSlug,
  type HuntMode,
} from "../skills/BugBountyFramework/Tools/hunt-orchestrator.ts";
import { runCli as vaultCli } from "../skills/BugBountyFramework/Tools/credential-vault.ts";
import { existsSync, mkdirSync, cpSync } from "fs";
import { homedir, tmpdir, userInfo } from "os";
import { join, resolve } from "path";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERSION = typeof pkg.version === "string" ? pkg.version : "0.0.0";
const REPO = process.env.PIRANHA_REPO ?? "djzzlim/PiRanha";
const REPO_URL = `https://github.com/${REPO}`;
const RAW_INSTALL = `https://raw.githubusercontent.com/${REPO}/main/install.sh`;
const CLAUDE_DIR = join(homedir(), ".claude");
const SKILL_DEST = join(CLAUDE_DIR, "skills", "BugBountyFramework");
const MEMORY_DIR = join(CLAUDE_DIR, "MEMORY", "BugBounty");
const CURRENT_USER = (() => {
  try {
    return userInfo().username || process.env.USER || process.env.USERNAME || "the operator";
  } catch {
    return process.env.USER || process.env.USERNAME || "the operator";
  }
})();

const HARNESSES = ["omp", "pi", "claude"] as const;
type HarnessKind = (typeof HARNESSES)[number];

const MODES: HuntMode[] = ["bounty", "pentest", "comprehensive"];

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
};

function color(c: keyof typeof C, s: string): string {
  return process.stdout.isTTY ? `${C[c]}${s}${C.reset}` : s;
}

// ---------------------------------------------------------------------------
// Minimal flag parser (subcommand-aware, omp-style)
// ---------------------------------------------------------------------------

const BOOLEAN_FLAGS: Record<string, true> = {
  resume: true,
  status: true,
  "dry-run": true,
  print: true,
  json: true,
  help: true,
  force: true,
  burp: true,
};

interface ParsedArgs {
  positionals: string[];
  flags: Record<string, string | boolean>;
}

function parseFlags(args: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith("--")) {
      const body = a.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        flags[body.slice(0, eq)] = body.slice(eq + 1);
        continue;
      }
      const next = args[i + 1];
      if (body in BOOLEAN_FLAGS || next === undefined || next.startsWith("--")) {
        flags[body] = true;
      } else {
        flags[body] = next;
        i++;
      }
    } else {
      positionals.push(a);
    }
  }
  return { positionals, flags };
}

function str(flags: Record<string, string | boolean>, key: string): string | undefined {
  const v = flags[key];
  return typeof v === "string" ? v : undefined;
}

function bool(flags: Record<string, string | boolean>, key: string): boolean {
  return flags[key] === true;
}

// ---------------------------------------------------------------------------
// Target classification → engagement key
// ---------------------------------------------------------------------------

function isIpOrCidr(s: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return true; // IPv4 / CIDR
  if (s.includes(":") && /^[0-9a-f:]+(\/\d{1,3})?$/i.test(s)) return true; // IPv6
  return false;
}

/** Map a raw target string to a canonical engagement key (always in ENGAGEMENTS). */
function classify(target: string): string {
  const t = target.trim();
  const lower = t.toLowerCase();

  if (lower.endsWith(".apk")) return "android";
  if (lower.endsWith(".ipa")) return "ios";
  if (/\.(img|trx|uimage|squashfs|romfs|cramfs)$/.test(lower)) return "firmware";
  if (/\.(exe|dll|so|dylib|elf|bin|jar|app)$/.test(lower)) return "binary";

  if (lower.includes("amazonaws.com") || lower.startsWith("arn:aws")) return "cloud-aws";
  if (lower.includes(".azure.") || lower.includes(".windows.net") || lower.includes("azurewebsites")) return "cloud-azure";
  if (lower.includes("googleapis.com") || lower.includes("run.app") || lower.includes("appspot.com")) return "cloud-gcp";

  if (isIpOrCidr(t)) return "network";

  if (/^https?:\/\//.test(lower)) {
    if (/\/graphql\b/.test(lower) || /\bswagger\b|\bopenapi\b/.test(lower)) return "api";
    return "web";
  }

  // bare hostname / domain
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) return "web";
  return "web";
}

// ---------------------------------------------------------------------------
// Harness detection + skill location
// ---------------------------------------------------------------------------

function detectHarness(preferred?: string): { kind: HarnessKind; bin: string } | null {
  const order: string[] = preferred
    ? [preferred, ...HARNESSES.filter((h) => h !== preferred)]
    : [...HARNESSES];
  for (const name of order) {
    const bin = Bun.which(name);
    if (bin) return { kind: name as HarnessKind, bin };
  }
  return null;
}

/** Locate the skill source on disk (dev clone / env override), else null. */
function findSkillSource(): string | null {
  const candidates = [
    process.env.PIRANHA_SKILL_SRC,
    join(import.meta.dir, "..", "skills", "BugBountyFramework"),
    join(process.cwd(), "skills", "BugBountyFramework"),
  ].filter((c): c is string => typeof c === "string" && c.length > 0);
  for (const c of candidates) {
    if (existsSync(join(c, "SKILL.md"))) return c;
  }
  return null;
}

function cloneSkill(): string {
  const dest = join(tmpdir(), `piranha-skill-${Date.now()}`);
  const args = ["clone", "--depth", "1"];
  const ref = process.env.PIRANHA_REF;
  if (ref) args.push("--branch", ref);
  args.push(`${REPO_URL}.git`, dest);
  console.log(color("dim", `  cloning ${REPO_URL} ...`));
  const p = Bun.spawnSync(["git", ...args], { stdout: "inherit", stderr: "inherit" });
  if (p.exitCode !== 0) {
    throw new Error(`git clone failed for ${REPO_URL}. Install git, or set PIRANHA_SKILL_SRC to a local checkout.`);
  }
  return join(dest, "skills", "BugBountyFramework");
}

function ensureMemoryDirs(): void {
  for (const sub of ["Findings", "LearningLogs", "PatternDB", "TargetProfiles", "Sessions", "Vault"]) {
    mkdirSync(join(MEMORY_DIR, sub), { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

function buildKickoffPrompt(
  target: string,
  engagement: string,
  mode: HuntMode,
  opts: {
    resume: boolean;
    creds?: string;
    instructions?: string;
    outDir?: string;
    proxy?: string;
  },
): string {
  const authorizedBy = process.env.PIRANHA_AUTHORIZED_BY || CURRENT_USER;
  const lines: string[] = [];
  lines.push(
    `AUTHORIZATION: This is an authorized, in-scope security engagement. ${authorizedBy} attests to holding explicit, written permission to actively test ${target} under an agreed rules-of-engagement and scope. Treat every action in this hunt as pre-authorized — proceed autonomously and do not pause to ask whether testing is permitted, to re-confirm authorization, or for permission to begin. Stay strictly within the authorized scope.`,
  );
  lines.push("");
  lines.push(`hunt ${target} --mode ${mode}${opts.resume ? " --resume" : ""}`);
  lines.push("");
  lines.push(`Use the PiRanha bug-bounty swarm skill ("piranha" / BugBountyFramework) to run an autonomous hunt.`);
  lines.push(`Engagement type: ${engagement}. Mode: ${mode}.`);
  if (opts.creds) {
    lines.push(`Credentials reference: ${opts.creds}. Load them through the credential vault — never inline secrets in prompts, logs, or reports.`);
  }
  if (opts.proxy) {
    lines.push(`Proxy: route ALL web and tool traffic through ${opts.proxy} (Burp). Set every tool's proxy/upstream and the browser harness to use it — let nothing bypass the proxy.`);
  }
  if (opts.outDir) {
    lines.push(`Artifacts: write every recon output, request/response log, screenshot, and report under ${opts.outDir}. Begin with full recon (TLS/SSL, HTTP headers, content discovery/dirsearch, nuclei) and save each tool's raw output there first.`);
  }
  lines.push(
    `Drive the hunt-orchestrator state machine: profile the target first, then dispatch the routed agents in parallel per the deployment plan. ` +
      `Validate findings, kill false positives, correlate exploit chains, and don't stop until the hunt completes or the finding target is met.`,
  );
  if (opts.instructions && opts.instructions.trim().length > 0) {
    lines.push("");
    lines.push("OPERATOR INSTRUCTIONS (follow exactly — these override the defaults above):");
    lines.push(opts.instructions.trim());
  }
  return lines.join("\n");
}

async function gatherInstructions(
  flags: Record<string, string | boolean>,
  positionals: string[],
): Promise<string | undefined> {
  const inline = str(flags, "instructions");
  if (inline) return inline;
  const brief = str(flags, "brief");
  if (brief) {
    const f = Bun.file(brief);
    if (!(await f.exists())) die(`--brief file not found: ${brief}`);
    return await f.text();
  }
  const trailing = positionals.slice(1).join(" ").trim();
  return trailing.length > 0 ? trailing : undefined;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function resolveEngagement(input: string | undefined, target: string): string {
  if (input) {
    const key = resolveKey(input);
    if (!key) {
      die(`Unknown engagement "${input}". Run \`piranha engagements\` to list valid types.`);
    }
    return key;
  }
  return classify(target);
}

async function cmdHunt(rest: string[]): Promise<number> {
  const { positionals, flags } = parseFlags(rest);
  const target = positionals[0];
  if (!target) {
    die("Usage: piranha hunt <target> [--mode bounty|pentest|comprehensive] [--engagement <type>] [--creds <ref>] [--harness omp|pi|claude] [--resume] [--status] [--dry-run]");
  }

  const modeRaw = str(flags, "mode") ?? "bounty";
  if (!MODES.includes(modeRaw as HuntMode)) {
    die(`Invalid --mode "${modeRaw}". Choose one of: ${MODES.join(", ")}.`);
  }
  const mode = modeRaw as HuntMode;
  const engagement = resolveEngagement(str(flags, "engagement"), target!);
  const slug = toSlug(target!);
  const resume = bool(flags, "resume");
  const dryRun = bool(flags, "dry-run") || bool(flags, "print");
  const creds = str(flags, "creds");
  const outRaw = str(flags, "out");
  const outDir = outRaw ? resolve(outRaw) : undefined;
  const proxy = str(flags, "proxy") ?? (bool(flags, "burp") ? "http://127.0.0.1:8080" : undefined);
  const instructions = await gatherInstructions(flags, positionals);

  // --status: report and exit
  if (bool(flags, "status")) {
    const state = await loadState(slug);
    if (!state) {
      console.log(`No hunt session found for ${target}.`);
      return 1;
    }
    console.log(getHuntStatus(state));
    return 0;
  }

  // Initialize / resume hunt state
  let state = await loadState(slug);
  if (state && !resume) {
    console.log(color("yellow", `[exists] A hunt session already exists for ${target}.`));
    console.log(color("dim", `         Use --resume to continue it, or \`piranha status ${target}\` to inspect.`));
    console.log(getHuntStatus(state));
  } else if (!state) {
    state = await createHuntState(target!, mode);
    state.phases.INIT.status = "running";
    state.phases.INIT.startTime = new Date().toISOString();
    console.log(color("green", `[hunt] Initialized ${mode} hunt for ${target}`));
    console.log(color("dim", `       Session: ${state.sessionDir}`));
  } else {
    console.log(color("green", `[resume] Continuing hunt for ${target} at phase ${state.currentPhase}`));
  }

  // Deployment plan
  const plan = ENGAGEMENTS[engagement]!;
  console.log("");
  console.log(color("bold", `Engagement classified as: ${engagement}`));
  console.log(renderPlan(plan, parseInt(str(flags, "max-parallel") ?? "5", 10)));
  console.log("");

  // Launch the harness
  const prompt = buildKickoffPrompt(target!, engagement, mode, { resume, creds, instructions, outDir, proxy });
  const harness = detectHarness(str(flags, "harness"));

  if (dryRun || !harness) {
    if (!harness && !dryRun) {
      console.log(color("yellow", "No harness (omp / pi / claude) found on PATH."));
      console.log(color("dim", "Install one, then paste the kickoff below — or re-run with --harness."));
    }
    console.log(color("bold", "── Kickoff prompt ──────────────────────────────────────────"));
    console.log(prompt);
    console.log(color("bold", "────────────────────────────────────────────────────────────"));
    if (harness) {
      console.log(color("dim", `Would launch: ${harness.bin} "<prompt>"`));
    }
    return 0;
  }

  // Ensure the skill is available for the harness before launching
  if (harness.kind === "claude" && !existsSync(join(SKILL_DEST, "SKILL.md"))) {
    console.log(color("yellow", "PiRanha skill not installed for Claude Code. Installing now..."));
    installSkill("claude");
  }

  console.log(color("cyan", `Launching ${harness.kind} (${harness.bin})...`));
  const proc = Bun.spawn([harness.bin, prompt], {
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  return await proc.exited;
}

async function cmdStatus(rest: string[]): Promise<number> {
  const { positionals } = parseFlags(rest);
  const target = positionals[0];
  if (!target) {
    await listSessions();
    return 0;
  }
  const state = await loadState(toSlug(target));
  if (!state) {
    console.log(`No hunt session found for ${target}.`);
    return 1;
  }
  console.log(getHuntStatus(state));
  return 0;
}

function cmdPlan(rest: string[]): number {
  const { positionals, flags } = parseFlags(rest);
  const input = positionals[0];
  if (!input) {
    die("Usage: piranha plan <target|engagement> [--max-parallel N] [--json]");
  }
  // Prefer treating the input as an explicit engagement/alias; fall back to classify.
  const engagement = resolveKey(input!) ?? classify(input!);
  const plan = ENGAGEMENTS[engagement]!;
  const cap = parseInt(str(flags, "max-parallel") ?? "5", 10);
  if (bool(flags, "json")) {
    console.log(JSON.stringify({ ...plan, maxParallel: cap, totalAgents: planAgents(plan).length }, null, 2));
  } else {
    console.log(renderPlan(plan, cap));
  }
  return 0;
}

function cmdAgents(rest: string[]): number {
  const { positionals } = parseFlags(rest);
  const input = positionals[0];
  if (input) {
    const engagement = resolveKey(input) ?? classify(input);
    const agents = planAgents(ENGAGEMENTS[engagement]!);
    console.log(`Agents for engagement "${engagement}" (${agents.length}):`);
    for (const a of agents) console.log(`  • ${a}`);
    return 0;
  }
  const all = new Set<string>();
  for (const plan of Object.values(ENGAGEMENTS)) {
    for (const a of planAgents(plan)) all.add(a);
  }
  const sorted = [...all].sort();
  console.log(`All routed agents (${sorted.length}):`);
  for (const a of sorted) console.log(`  • ${a}`);
  return 0;
}

function cmdEngagements(): number {
  console.log(color("bold", "Engagement types:"));
  for (const k of Object.keys(ENGAGEMENTS)) {
    console.log(`  ${k.padEnd(14)} ${ENGAGEMENTS[k]!.description}`);
  }
  console.log("");
  console.log(color("bold", "Aliases:"));
  for (const [a, k] of Object.entries(ALIASES)) {
    console.log(`  ${a.padEnd(16)} → ${k}`);
  }
  return 0;
}

function ensureBunOnPath(): boolean {
  if (Bun.which("bun")) return true;
  const isWin = process.platform === "win32";
  const bunBinDir = join(homedir(), ".bun", "bin");
  const bunExe = join(bunBinDir, isWin ? "bun.exe" : "bun");

  if (existsSync(bunExe)) {
    process.env.PATH = `${bunBinDir}${isWin ? ";" : ":"}${process.env.PATH}`;
    return true;
  }

  console.log(color("yellow", "Bun is required by coding harness (omp/pi) to install packages. Installing Bun..."));
  try {
    if (isWin) {
      Bun.spawnSync(["powershell", "-Command", "irm https://bun.sh/install.ps1 | iex"], { stdout: "inherit", stderr: "inherit" });
    } else {
      Bun.spawnSync(["sh", "-c", "curl -fsSL https://bun.sh/install | bash"], { stdout: "inherit", stderr: "inherit" });
    }
    if (existsSync(bunExe)) {
      process.env.PATH = `${bunBinDir}${isWin ? ";" : ":"}${process.env.PATH}`;
      return true;
    }
  } catch (err) {
    console.error(color("red", `Failed to auto-install Bun: ${err}`));
  }
  return false;
}

function installSkill(harnessKind: HarnessKind): void {
  if (harnessKind === "pi" || harnessKind === "omp") {
    ensureBunOnPath();
    const bin = Bun.which(harnessKind);
    if (!bin) throw new Error(`${harnessKind} not found on PATH.`);
    const ref = process.env.PIRANHA_REF;
    const spec = ref ? `git:github.com/${REPO}#${ref}` : `git:github.com/${REPO}`;
    console.log(color("dim", `  ${harnessKind} install ${spec}`));
    const p = Bun.spawnSync([bin, "install", spec], {
      stdout: "inherit",
      stderr: "inherit",
      env: process.env,
    });
    if (p.exitCode !== 0) throw new Error(`${harnessKind} install failed.`);
    return;
  }
  // claude: copy the skill tree into ~/.claude/skills
  const src = findSkillSource() ?? cloneSkill();
  mkdirSync(join(CLAUDE_DIR, "skills"), { recursive: true });
  cpSync(src, SKILL_DEST, { recursive: true });
  ensureMemoryDirs();
  console.log(color("green", `  [ok] skill installed → ${SKILL_DEST}`));
}

function cmdInstall(rest: string[]): number {
  const { flags } = parseFlags(rest);
  const harness = detectHarness(str(flags, "harness"));
  if (!harness) {
    die("No harness (omp / pi / claude) found on PATH. Install one first, then re-run `piranha install`.");
  }
  console.log(color("cyan", `Installing PiRanha skill for ${harness!.kind}...`));
  try {
    installSkill(harness!.kind);
  } catch (err) {
    die(err instanceof Error ? err.message : String(err));
  }
  console.log(color("green", "Done. Try: ") + color("bold", "piranha hunt https://your-target.com"));
  return 0;
}

async function cmdUpdate(): Promise<number> {
  console.log(`Current version: ${color("bold", VERSION)}`);
  let latest = "";
  try {
    const res = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, {
      headers: { "User-Agent": "piranha-cli", Accept: "application/vnd.github+json" },
    });
    if (res.ok) {
      const body: unknown = await res.json();
      if (body && typeof body === "object" && "tag_name" in body) {
        const tag = body.tag_name;
        if (typeof tag === "string") latest = tag.replace(/^v/, "");
      }
    }
  } catch {
    // network failure is non-fatal; fall through to reinstall path
  }

  if (latest) {
    console.log(`Latest release:  ${color("bold", latest)}`);
    if (latest === VERSION) {
      console.log(color("green", "Already up to date."));
      return 0;
    }
  }

  console.log(color("cyan", "Re-running the installer..."));
  const p = Bun.spawnSync(["sh", "-c", `curl -fsSL ${RAW_INSTALL} | sh`], {
    stdout: "inherit",
    stderr: "inherit",
  });
  return p.exitCode ?? 0;
}

function checkTool(name: string): boolean {
  return Bun.which(name) !== null;
}

// ---------------------------------------------------------------------------
// Per-domain tooling & MCP capture — what each engagement actually drives for
// dynamic / runtime review. Grounded in the agent playbooks under skills/.
// ---------------------------------------------------------------------------

interface DomainTooling {
  dynamic: string;   // how dynamic / runtime review happens for this domain
  cli: string[];     // external CLIs the agents drive (checked against PATH)
  mcp: string[];     // MCP servers that augment this domain
}

const TOOLING_BY_ENGAGEMENT: Record<string, DomainTooling> = {
  web: {
    dynamic: "playwright-harness.ts (dev-browser CLI → Playwright CLI fallback) + Burp via burp-bridge.ts",
    cli: ["dev-browser", "playwright", "nuclei", "ffuf", "sqlmap", "subfinder", "httpx", "dalfox"],
    mcp: ["Burp Suite MCP"],
  },
  api: {
    dynamic: "Burp via burp-bridge.ts (proxy, scope sync, HAR) + WebSocket/GraphQL clients",
    cli: ["nuclei", "ffuf", "clairvoyance", "websocat", "jwt_tool"],
    mcp: ["Burp Suite MCP"],
  },
  llm: {
    dynamic: "playwright-harness.ts for the chat/RAG surface + Burp for the model API",
    cli: ["dev-browser", "playwright", "nuclei"],
    mcp: ["Burp Suite MCP"],
  },
  android: {
    dynamic: "appium-harness.ts + Frida/objection on a live device, drozer for IPC",
    cli: ["adb", "frida", "objection", "drozer", "jadx", "apktool", "aapt", "mobsfscan", "nuclei"],
    mcp: ["mobile / ADB MCP", "Burp Suite MCP"],
  },
  ios: {
    dynamic: "appium-harness.ts + Frida/objection on a jailbroken device",
    cli: ["frida", "objection", "ideviceinstaller", "ghidra"],
    mcp: ["mobile MCP", "Burp Suite MCP"],
  },
  mobile: {
    dynamic: "appium-harness.ts + Frida/objection across both Android and iOS tracks",
    cli: ["adb", "frida", "objection", "drozer", "jadx", "apktool", "ideviceinstaller"],
    mcp: ["mobile / ADB MCP", "Burp Suite MCP"],
  },
  binary: {
    dynamic: "gdb / lldb live debugging; AFL++/libFuzzer/honggfuzz fuzzing",
    cli: ["ghidra", "r2", "gdb", "lldb", "afl-fuzz", "pwntools"],
    mcp: [],
  },
  firmware: {
    dynamic: "FirmAE / Firmadyne full-system emulation of the extracted rootfs",
    cli: ["binwalk", "unblob", "sasquatch", "firmwalker", "ghidra"],
    mcp: [],
  },
  "thick-client": {
    dynamic: "Frida runtime hooks + Burp for the client's backend traffic",
    cli: ["ghidra", "frida", "ilspycmd"],
    mcp: ["Burp Suite MCP"],
  },
  cloud: {
    dynamic: "Authenticated provider sessions via pacu / cloudfox after a foothold",
    cli: ["pacu", "scout", "cloudfox", "prowler"],
    mcp: [],
  },
  "cloud-aws": {
    dynamic: "aws CLI session + pacu privesc modules in a sandboxed session",
    cli: ["aws", "pacu", "cloudfox", "scout", "prowler"],
    mcp: [],
  },
  "cloud-azure": {
    dynamic: "az CLI + ROADtools / AzureHound enumeration of Entra ID",
    cli: ["az", "scout", "prowler", "roadrecon"],
    mcp: [],
  },
  "cloud-gcp": {
    dynamic: "gcloud CLI + service-account impersonation chains",
    cli: ["gcloud", "scout", "prowler"],
    mcp: [],
  },
  kubernetes: {
    dynamic: "kubectl against the API + in-cluster escape tooling",
    cli: ["kubectl", "kube-hunter", "peirates", "kdigger", "trivy"],
    mcp: [],
  },
  network: {
    dynamic: "nmap NSE + netexec live service exploitation; BloodHound for AD paths",
    cli: ["nmap", "nxc", "hydra", "responder", "bloodhound-python", "certipy"],
    mcp: ["Shodan MCP"],
  },
  recon: {
    dynamic: "Passive + active surface discovery; no payloads fired",
    cli: ["subfinder", "httpx", "nuclei", "amass", "dnsx", "dnsreaper"],
    mcp: ["Shodan MCP"],
  },
};

function printDomainTooling(key: string, t: DomainTooling): void {
  const mark = (ok: boolean) => (ok ? color("green", "✓") : color("yellow", "·"));
  console.log(color("bold", `\n${key}`) + color("dim", ` — ${ENGAGEMENTS[key]?.description ?? ""}`));
  console.log(`  ${color("dim", "dynamic:")} ${t.dynamic}`);
  console.log(`  ${color("dim", "cli:    ")} ${t.cli.map((c) => `${mark(checkTool(c))} ${c}`).join("   ")}`);
  if (t.mcp.length > 0) console.log(`  ${color("dim", "mcp:    ")} ${t.mcp.join(", ")}`);
}

function cmdTools(rest: string[]): number {
  const { positionals } = parseFlags(rest);
  const input = positionals[0];
  console.log(color("bold", "Per-domain tooling & MCP capture"));
  console.log(color("dim", "  ✓ on PATH   · not installed (needed for that domain's dynamic testing)"));

  if (input) {
    const key = resolveKey(input) ?? classify(input);
    const t = TOOLING_BY_ENGAGEMENT[key];
    if (!t) die(`No tooling capture for engagement "${key}".`);
    printDomainTooling(key, t!);
    return 0;
  }
  for (const key of Object.keys(TOOLING_BY_ENGAGEMENT)) {
    printDomainTooling(key, TOOLING_BY_ENGAGEMENT[key]!);
  }
  console.log(color("dim", "\nScope to one domain: `piranha tools <engagement|target>`"));
  return 0;
}

function cmdDoctor(): number {
  const mark = (ok: boolean) => (ok ? color("green", "[ok]  ") : color("yellow", "[--]  "));
  console.log(color("bold", "PiRanha environment check\n"));

  console.log(color("bold", "Runtime:"));
  console.log(`  ${mark(checkTool("bun"))}bun`);
  console.log(`  ${mark(checkTool("git"))}git`);

  console.log(color("bold", "\nHarness (need at least one):"));
  let anyHarness = false;
  for (const h of HARNESSES) {
    const ok = checkTool(h);
    anyHarness = anyHarness || ok;
    console.log(`  ${mark(ok)}${h}`);
  }

  console.log(color("bold", "\nSkill install:"));
  const skillOk = existsSync(join(SKILL_DEST, "SKILL.md"));
  console.log(`  ${mark(skillOk)}Claude Code skill (${SKILL_DEST})`);
  if (!skillOk) console.log(color("dim", "       run `piranha install` to set it up"));

  console.log(color("bold", "\nOptional offensive tooling:"));
  for (const t of ["subfinder", "httpx", "nuclei", "ffuf", "sqlmap", "op", "burpsuite"]) {
    console.log(`  ${mark(checkTool(t))}${t}`);
  }
  console.log(color("dim", "  → `piranha tools` lists per-domain tooling for every engagement"));

  console.log("");
  if (!anyHarness) {
    console.log(color("red", "No coding-agent harness found. Install omp (https://omp.sh) or Claude Code to run hunts."));
    return 1;
  }
  console.log(color("green", "Ready to hunt."));
  return 0;
}

function cmdCompletions(rest: string[]): number {
  const { positionals } = parseFlags(rest);
  const shell = positionals[0];
  const engagements = [...Object.keys(ENGAGEMENTS), ...Object.keys(ALIASES)].join(" ");
  const cmds = "hunt status plan agents engagements tools vault install update doctor completions version help";
  const flags = "--mode --engagement --instructions --brief --out --proxy --burp --creds --harness --resume --status --dry-run --max-parallel --json";

  if (shell === "bash") {
    console.log(`# piranha bash completion — eval "$(piranha completions bash)"
_piranha() {
  local cur prev
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --mode) COMPREPLY=( $(compgen -W "${MODES.join(" ")}" -- "$cur") ); return;;
    --engagement) COMPREPLY=( $(compgen -W "${engagements}" -- "$cur") ); return;;
    --harness) COMPREPLY=( $(compgen -W "${HARNESSES.join(" ")}" -- "$cur") ); return;;
    completions) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ); return;;
  esac
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "${cmds}" -- "$cur") ); return
  fi
  COMPREPLY=( $(compgen -W "${flags}" -- "$cur") )
}
complete -F _piranha piranha`);
    return 0;
  }

  if (shell === "zsh") {
    console.log(`#compdef piranha
# piranha zsh completion — eval "$(piranha completions zsh)"
_piranha() {
  local -a cmds; cmds=(${cmds})
  _arguments '1: :->cmd' '*::arg:->args'
  case $state in
    cmd) _describe 'command' cmds;;
    args)
      case $words[1] in
        completions) _values 'shell' bash zsh fish;;
        hunt|plan|agents|tools) _values 'engagement' ${engagements};;
        *) _values 'flag' ${flags};;
      esac;;
  esac
}
compdef _piranha piranha`);
    return 0;
  }

  if (shell === "fish") {
    console.log(`# piranha fish completion — piranha completions fish > ~/.config/fish/completions/piranha.fish
complete -c piranha -f
complete -c piranha -n __fish_use_subcommand -a '${cmds}'
complete -c piranha -l mode -x -a '${MODES.join(" ")}'
complete -c piranha -l engagement -x -a '${engagements}'
complete -c piranha -l harness -x -a '${HARNESSES.join(" ")}'
complete -c piranha -l creds -x
complete -c piranha -l max-parallel -x
complete -c piranha -l resume
complete -c piranha -l status
complete -c piranha -l dry-run
complete -c piranha -l json`);
    return 0;
  }

  die("Usage: piranha completions <bash|zsh|fish>");
  return 1;
}

function banner(): string {
  return color(
    "cyan",
    `
██████╗ ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗ █████╗
██╔══██╗██║██╔══██╗██╔══██╗████╗  ██║██║  ██║██╔══██╗
██████╔╝██║██████╔╝███████║██╔██╗ ██║███████║███████║
██╔═══╝ ██║██╔══██╗██╔══██║██║╚██╗██║██╔══██║██╔══██║
██║     ██║██║  ██║██║  ██║██║ ╚████║██║  ██║██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝`,
  );
}

function cmdHelp(): number {
  console.log(banner());
  console.log(`  ${color("bold", "PiRanha")} ${color("dim", `v${VERSION}`)} — the autonomous bug-bounty swarm\n`);
  console.log(`${color("bold", "USAGE")}
  piranha <command> [options]

${color("bold", "COMMANDS")}
  hunt <target>        Classify a target and launch an autonomous hunt
  status [target]      Show a hunt's live status, or list all sessions
  plan <target|type>   Print the deterministic agent deployment plan
  agents [type]        List routed agents (all, or for one engagement)
  engagements          List engagement types and aliases
  tools [type]         List per-domain tooling & MCP, checking your PATH
  vault ...            Credential vault (passthrough: --store/--get/--list/--delete/--redact)
  install              Install the PiRanha skill into your harness
  update               Update the piranha binary to the latest release
  doctor               Check prerequisites and environment
  completions <shell>  Emit a shell completion script (bash|zsh|fish)
  version              Print the version
  help                 Show this help

${color("bold", "HUNT OPTIONS")}
  --mode <m>           bounty (default) | pentest | comprehensive
  --engagement <type>  Override target classification (web, api, llm, android, network, ...)
  --creds <ref>        Credential reference (e.g. vault:<name>)
  --instructions <txt> Free-form operator instructions, forwarded verbatim to the swarm (override defaults)
  --brief <file>       Read operator instructions from a file (also: trailing words after the target)
  --out <dir>          Write recon artifacts/reports under <dir> (e.g. --out .)
  --proxy <url>        Route all traffic through a proxy   (--burp = http://127.0.0.1:8080)
  --harness <h>        Force a harness: omp | pi | claude (default: auto-detect)
  --resume             Resume an existing session for this target
  --status             Show status instead of launching
  --dry-run            Print the plan + kickoff prompt; don't launch

${color("bold", "EXAMPLES")}
  curl -fsSL ${RAW_INSTALL} | sh
  piranha doctor
  piranha install
  piranha hunt https://app.example.com --mode pentest
  piranha plan 10.0.0.0/24
  piranha hunt app.apk --dry-run
  piranha hunt https://app.example.com --engagement llm --burp --out . --brief brief.md
  piranha tools android

${color("dim", "Every hunt carries a standing authorization attestation (set PIRANHA_AUTHORIZED_BY).")}
${color("dim", "Authorized testing only. Configure scope before hunting.")}`);
  return 0;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

function die(msg: string): never {
  console.error(color("red", msg));
  process.exit(1);
}

async function main(): Promise<number> {
  const argv = Bun.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);

  switch (cmd) {
    case "hunt":
      return await cmdHunt(rest);
    case "status":
      return await cmdStatus(rest);
    case "plan":
      return cmdPlan(rest);
    case "agents":
      return cmdAgents(rest);
    case "engagements":
    case "engagement":
      return cmdEngagements();
    case "vault":
      await vaultCli(rest);
      return 0;
    case "install":
      return cmdInstall(rest);
    case "update":
      return await cmdUpdate();
    case "doctor":
      return cmdDoctor();
    case "tools":
      return cmdTools(rest);
    case "completions":
    case "completion":
      return cmdCompletions(rest);
    case "version":
    case "--version":
    case "-v":
      console.log(`piranha ${VERSION}`);
      return 0;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      return cmdHelp();
    default:
      console.error(color("red", `Unknown command: ${cmd}`));
      console.error(`Run ${color("bold", "piranha help")} for usage.`);
      return 1;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(color("red", `piranha: ${err instanceof Error ? err.message : String(err)}`));
    process.exit(1);
  });
