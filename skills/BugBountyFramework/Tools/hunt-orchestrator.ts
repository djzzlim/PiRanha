#!/usr/bin/env bun
/**
 * BugBountyFramework — Hunt Orchestrator (ENH-1, ENH-3, ENH-10)
 * State machine for hunt phase management, session persistence, and progress tracking.
 */

import { parseArgs } from "util";
import { homedir } from "os";

// --- Types ---

export type PhaseStatus = "pending" | "running" | "completed" | "failed" | "skipped";

export type HuntMode = "bounty" | "pentest" | "comprehensive";

export const PHASES = [
  "INIT",
  "MEMORY_LOAD",
  "TARGET_INGEST",
  "APP_UNDERSTANDING",
  "RECON",
  "AGENT_DEPLOY",
  "DYNAMIC_TEST",
  "VULN_ASSESS",
  "LEARNING",
  "REPORT",
] as const;

export type PhaseName = (typeof PHASES)[number];

export interface PhaseState {
  name: PhaseName;
  status: PhaseStatus;
  startTime: string | null;
  endTime: string | null;
  findingsCount: number;
  error: string | null;
  retryCount: number;
}

export interface HuntState {
  target: string;
  targetSlug: string;
  mode: HuntMode;
  sessionDir: string;
  startedAt: string;
  lastUpdated: string;
  currentPhase: PhaseName;
  phases: Record<PhaseName, PhaseState>;
  totalFindings: number;
  findings: Array<{ id: string; severity: string; type: string; title: string; timestamp: string }>;
  config: {
    minCvss: number;
    maxRetries: number;
    targetFindingCount: number;
  };
}

// --- Helpers ---

export function toSlug(url: string): string {
  return url
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]/gi, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();
}

function getSessionDir(slug: string): string {
  return `${homedir()}/.claude/MEMORY/BugBounty/Sessions/${slug}`;
}

function getStatePath(slug: string): string {
  return `${getSessionDir(slug)}/hunt-state.json`;
}

function getLogPath(slug: string): string {
  return `${getSessionDir(slug)}/hunt-events.jsonl`;
}

function modeToConfig(mode: HuntMode) {
  switch (mode) {
    case "bounty":
      return { minCvss: 8.0, maxRetries: 1, targetFindingCount: 10 };
    case "pentest":
      return { minCvss: 4.0, maxRetries: 2, targetFindingCount: 20 };
    case "comprehensive":
      return { minCvss: 0.0, maxRetries: 2, targetFindingCount: 50 };
  }
}

async function logEvent(slug: string, event: Record<string, unknown>) {
  const logPath = getLogPath(slug);
  const entry = JSON.stringify({ ...event, timestamp: new Date().toISOString() }) + "\n";
  const file = Bun.file(logPath);
  const existing = (await file.exists()) ? await file.text() : "";
  await Bun.write(logPath, existing + entry);
}

// --- State Management ---

export async function createHuntState(target: string, mode: HuntMode): Promise<HuntState> {
  const slug = toSlug(target);
  const sessionDir = getSessionDir(slug);

  // Create directory structure
  const dirs = [sessionDir, `${sessionDir}/findings`, `${sessionDir}/screenshots`, `${sessionDir}/artifacts`];
  for (const dir of dirs) {
    await Bun.write(`${dir}/.gitkeep`, "");
  }

  const phases: Record<string, PhaseState> = {};
  for (const name of PHASES) {
    phases[name] = {
      name,
      status: "pending",
      startTime: null,
      endTime: null,
      findingsCount: 0,
      error: null,
      retryCount: 0,
    };
  }

  const state: HuntState = {
    target,
    targetSlug: slug,
    mode,
    sessionDir,
    startedAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    currentPhase: "INIT",
    phases: phases as Record<PhaseName, PhaseState>,
    totalFindings: 0,
    findings: [],
    config: modeToConfig(mode),
  };

  await saveState(state);
  await logEvent(slug, { event: "HUNT_CREATED", target, mode });
  return state;
}

export async function loadState(slug: string): Promise<HuntState | null> {
  const path = getStatePath(slug);
  const file = Bun.file(path);
  if (!(await file.exists())) return null;
  return JSON.parse(await file.text());
}

export async function saveState(state: HuntState): Promise<void> {
  state.lastUpdated = new Date().toISOString();
  await Bun.write(getStatePath(state.targetSlug), JSON.stringify(state, null, 2));
}

export async function advancePhase(state: HuntState): Promise<HuntState> {
  const currentIdx = PHASES.indexOf(state.currentPhase);
  const currentPhaseState = state.phases[state.currentPhase];

  // Mark current as completed
  currentPhaseState.status = "completed";
  currentPhaseState.endTime = new Date().toISOString();

  // Find next non-skipped phase
  let nextIdx = currentIdx + 1;
  while (nextIdx < PHASES.length && state.phases[PHASES[nextIdx]].status === "skipped") {
    nextIdx++;
  }

  if (nextIdx >= PHASES.length) {
    await logEvent(state.targetSlug, { event: "HUNT_COMPLETE", totalFindings: state.totalFindings });
    console.log(`\n[HUNT COMPLETE] ${state.target} — ${state.totalFindings} findings in ${state.mode} mode`);
    await saveState(state);
    return state;
  }

  const nextPhase = PHASES[nextIdx];
  state.currentPhase = nextPhase;
  state.phases[nextPhase].status = "running";
  state.phases[nextPhase].startTime = new Date().toISOString();

  await logEvent(state.targetSlug, { event: "PHASE_ADVANCE", from: PHASES[currentIdx], to: nextPhase });
  await saveState(state);
  return state;
}

export async function failPhase(state: HuntState, error: string): Promise<HuntState> {
  const phase = state.phases[state.currentPhase];
  phase.retryCount++;

  if (phase.retryCount <= state.config.maxRetries) {
    // Retry
    phase.status = "running";
    phase.error = `Retry ${phase.retryCount}: ${error}`;
    await logEvent(state.targetSlug, { event: "PHASE_RETRY", phase: state.currentPhase, error, attempt: phase.retryCount });
    console.log(`[RETRY] Phase ${state.currentPhase} — attempt ${phase.retryCount}/${state.config.maxRetries}: ${error}`);
  } else {
    // Skip after max retries
    phase.status = "failed";
    phase.endTime = new Date().toISOString();
    phase.error = error;
    await logEvent(state.targetSlug, { event: "PHASE_FAILED", phase: state.currentPhase, error });
    console.log(`[FAILED] Phase ${state.currentPhase} — skipping after ${phase.retryCount} retries: ${error}`);

    // Advance to next phase
    state = await advancePhase(state);
  }

  await saveState(state);
  return state;
}

export async function addFinding(state: HuntState, finding: { severity: string; type: string; title: string }): Promise<HuntState> {
  const id = `F-${String(state.totalFindings + 1).padStart(3, "0")}`;
  state.findings.push({ id, ...finding, timestamp: new Date().toISOString() });
  state.totalFindings++;
  state.phases[state.currentPhase].findingsCount++;

  await logEvent(state.targetSlug, { event: "FINDING_ADDED", id, ...finding });
  await saveState(state);
  console.log(`[FINDING ${id}] [${finding.severity}] ${finding.type}: ${finding.title}`);
  return state;
}

// --- Status Display ---

export function getHuntStatus(state: HuntState): string {
  const elapsed = Date.now() - new Date(state.startedAt).getTime();
  const elapsedMin = Math.floor(elapsed / 60000);

  const lines: string[] = [];
  lines.push(`\n${"=".repeat(70)}`);
  lines.push(`  HUNT STATUS: ${state.target}`);
  lines.push(`  Mode: ${state.mode.toUpperCase()} | Elapsed: ${elapsedMin}m | Findings: ${state.totalFindings}`);
  lines.push(`  Min CVSS: ${state.config.minCvss} | Target: ${state.config.targetFindingCount} findings`);
  lines.push(`${"=".repeat(70)}`);

  for (const name of PHASES) {
    const p = state.phases[name];
    const icon = p.status === "completed" ? "[OK]"
      : p.status === "running" ? "[>>]"
      : p.status === "failed" ? "[!!]"
      : p.status === "skipped" ? "[--]"
      : "[  ]";

    const time = p.startTime && p.endTime
      ? `${Math.round((new Date(p.endTime).getTime() - new Date(p.startTime).getTime()) / 1000)}s`
      : p.startTime ? "running..." : "";

    const findings = p.findingsCount > 0 ? ` (${p.findingsCount} findings)` : "";
    const error = p.error ? ` ERR: ${p.error.slice(0, 50)}` : "";

    lines.push(`  ${icon} ${name.padEnd(20)} ${time.padEnd(12)} ${findings}${error}`);
  }

  if (state.findings.length > 0) {
    lines.push(`\n  FINDINGS:`);
    for (const f of state.findings.slice(-10)) {
      lines.push(`    ${f.id} [${f.severity}] ${f.type}: ${f.title}`);
    }
  }

  lines.push(`${"=".repeat(70)}\n`);
  return lines.join("\n");
}

// --- Session Listing ---

export async function listSessions(): Promise<void> {
  const sessionsDir = `${homedir()}/.claude/MEMORY/BugBounty/Sessions`;
  const glob = new Bun.Glob("*/hunt-state.json");
  const matches: string[] = [];

  for await (const path of glob.scan({ cwd: sessionsDir })) {
    matches.push(path);
  }

  if (matches.length === 0) {
    console.log("No hunt sessions found.");
    return;
  }

  console.log(`\nHunt Sessions (${matches.length}):\n`);
  for (const path of matches) {
    const state: HuntState = JSON.parse(await Bun.file(`${sessionsDir}/${path}`).text());
    const age = Math.floor((Date.now() - new Date(state.lastUpdated).getTime()) / 86400000);
    const completedPhases = PHASES.filter(p => state.phases[p].status === "completed").length;
    console.log(`  ${state.targetSlug.padEnd(40)} ${state.mode.padEnd(14)} ${completedPhases}/${PHASES.length} phases  ${state.totalFindings} findings  ${age}d ago`);
  }
}

// --- CLI ---

async function main() {
  const { values: args } = parseArgs({
    args: Bun.argv.slice(2),
    options: {
      target: { type: "string" },
      mode: { type: "string", default: "bounty" }, // bounty | pentest | comprehensive
      resume: { type: "boolean", default: false },
      status: { type: "boolean", default: false },
      advance: { type: "string" },     // advance to next phase or specific phase
      fail: { type: "string" },        // mark a phase as failed
      "add-finding": { type: "string" }, // JSON finding to add
      reset: { type: "boolean", default: false },
    },
  });

  if (!args.target && !args.status) {
    console.log("Usage:");
    console.log("  hunt-orchestrator --target URL [--mode bounty|pentest|comprehensive]");
    console.log("  hunt-orchestrator --target URL --resume");
    console.log("  hunt-orchestrator --target URL --status");
    console.log("  hunt-orchestrator --target URL --advance");
    console.log("  hunt-orchestrator --target URL --fail 'error message'");
    console.log("  hunt-orchestrator --target URL --add-finding '{\"severity\":\"critical\",\"type\":\"SSRF\",\"title\":\"...\"}'");
    console.log("  hunt-orchestrator --status  (list all sessions)");
    return;
  }

  // List all sessions
  if (args.status && !args.target) {
    await listSessions();
    return;
  }

  const target = args.target!;
  const slug = toSlug(target);

  // Show status for specific target
  if (args.status) {
    const state = await loadState(slug);
    if (!state) {
      console.log(`No hunt session found for ${target}`);
      return;
    }
    console.log(getHuntStatus(state));
    return;
  }

  // Resume existing session
  if (args.resume) {
    const state = await loadState(slug);
    if (!state) {
      console.log(`No session to resume for ${target}. Starting new hunt.`);
    } else {
      console.log(`[RESUME] Resuming hunt for ${target} at phase ${state.currentPhase}`);
      console.log(getHuntStatus(state));
      console.log(JSON.stringify(state, null, 2));
      return;
    }
  }

  // Reset
  if (args.reset) {
    const mode = (args.mode || "bounty") as HuntMode;
    const state = await createHuntState(target, mode);
    console.log(`[RESET] Hunt reset for ${target}`);
    console.log(JSON.stringify(state, null, 2));
    return;
  }

  // Advance phase
  if (args.advance !== undefined) {
    const state = await loadState(slug);
    if (!state) { console.log("No active hunt."); return; }
    const updated = await advancePhase(state);
    console.log(`[ADVANCE] Now at phase: ${updated.currentPhase}`);
    return;
  }

  // Fail phase
  if (args.fail) {
    const state = await loadState(slug);
    if (!state) { console.log("No active hunt."); return; }
    await failPhase(state, args.fail);
    return;
  }

  // Add finding
  if (args["add-finding"]) {
    const state = await loadState(slug);
    if (!state) { console.log("No active hunt."); return; }
    const finding = JSON.parse(args["add-finding"]);
    await addFinding(state, finding);
    return;
  }

  // Create new hunt
  const mode = (args.mode || "bounty") as HuntMode;
  const existing = await loadState(slug);
  if (existing && !args.reset) {
    console.log(`[EXISTS] Hunt session already exists for ${target}. Use --resume or --reset.`);
    console.log(getHuntStatus(existing));
    return;
  }

  const state = await createHuntState(target, mode);
  state.phases.INIT.status = "running";
  state.phases.INIT.startTime = new Date().toISOString();
  await saveState(state);

  console.log(`[HUNT STARTED] ${target} in ${mode} mode`);
  console.log(`  Session: ${state.sessionDir}`);
  console.log(`  Min CVSS: ${state.config.minCvss}`);
  console.log(`  Target findings: ${state.config.targetFindingCount}`);
  console.log(JSON.stringify(state, null, 2));
}

if (import.meta.main) main().catch(console.error);
