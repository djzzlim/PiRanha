#!/usr/bin/env bun
/**
 * BugBountyFramework — Agent Router (ENH-12)
 *
 * Deterministic engagement-type → ordered agent deployment plan.
 * The Hunt Orchestrator calls this at Phase 5 (AGENT_DEPLOY) to learn WHICH
 * agents to deploy, in WHAT order, with WHAT parallelism and dependencies, for
 * a given engagement type — instead of agents being chosen by hand each run.
 *
 * Design (PAI principle: code before prompts):
 *   - Single source of truth: ENGAGEMENTS map below.
 *   - Each plan is an ordered list of GROUPS. Agents inside a group run in
 *     PARALLEL (Agent tool, run_in_background). Groups run SEQUENTIALLY — a
 *     group only starts once the previous group's agents have reported. This
 *     encodes the real dependencies (profile → auth → hunters → validate → chain).
 *   - ValidatorAgent then ExploitChainAgent are appended to every finding-
 *     producing engagement as post-processing (META).
 *
 * Usage:
 *   bun agent-router.ts --list
 *   bun agent-router.ts --engagement web
 *   bun agent-router.ts --engagement cloud-aws --json
 *   bun agent-router.ts --validate                 # all engagements resolve to real agent files
 *   bun agent-router.ts --engagement android --validate
 */

import { parseArgs } from "util";
import { readdirSync } from "fs";

const { values: args } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    engagement: { type: "string" },   // engagement type or alias (see --list)
    json: { type: "boolean", default: false },
    validate: { type: "boolean", default: false },
    list: { type: "boolean", default: false },
    "max-parallel": { type: "string", default: "5" }, // concurrency cap hint
  },
});

const AGENTS_DIR = `${import.meta.dir}/../Agents`;

// A group of agents that run in parallel, after all earlier groups complete.
export interface AgentGroup {
  phase: string;          // short label for the deployment phase
  parallel: string[];     // agent names deployed concurrently
  note?: string;          // why / dependency rationale
}

export interface DeploymentPlan {
  engagement: string;
  description: string;
  skills: string[];       // companion skills the orchestrator auto-invokes
  groups: AgentGroup[];
}

// Post-processing appended to every finding-producing engagement.
const META: AgentGroup[] = [
  { phase: "VALIDATE", parallel: ["ValidatorAgent"], note: "reproduce, kill false positives, de-dup by root cause, score CVSS 3.1/4.0, apply hunt-mode gate" },
  { phase: "CHAIN", parallel: ["ExploitChainAgent"], note: "correlate validated findings into MITRE ATT&CK kill chains; elevate combined CVSS" },
];

// Engagement aliases → canonical key.
const ALIASES: Record<string, string> = {
  ai: "llm", chatbot: "llm", rag: "llm",
  apk: "android",
  ipa: "ios",
  native: "binary", binexp: "binary",
  iot: "firmware", embedded: "firmware",
  desktop: "thick-client", electron: "thick-client", dotnet: "thick-client", java: "thick-client",
  aws: "cloud-aws", azure: "cloud-azure", gcp: "cloud-gcp",
  k8s: "kubernetes", container: "kubernetes",
  internal: "network", ad: "network", "active-directory": "network",
};

// --- Single source of truth: engagement → ordered deployment groups ---
const ENGAGEMENTS: Record<string, DeploymentPlan> = {
  web: {
    engagement: "web",
    description: "Web application (HTTP/HTTPS URL)",
    skills: ["WebAssessment", "Recon"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["AppReviewAgent"], note: "produce AppProfile before any payload fires" },
      { phase: "AUTH", parallel: ["AuthAgent", "OAuthAgent"], note: "establish auth model first — IDOR/BFLA depend on it" },
      { phase: "HUNT", parallel: [
        "XSSAgent", "SQLiAgent", "NoSQLiAgent", "SSRFAgent", "IDORAgent", "CORSAgent",
        "FileUploadAgent", "XXEAgent", "RCEAgent", "SSTIAgent", "CommandInjectionAgent",
        "DeserializationAgent", "PathTraversalAgent", "OpenRedirectAgent", "CRLFAgent",
        "SecretsExposureAgent", "BusinessLogicAgent", "CSRFAgent", "CachePoisoningAgent",
        "HTTPSmugglingAgent", "RaceConditionAgent", "PrototypePollutionAgent",
        "GraphQLAgent", "WebSocketAgent",
      ], note: "hypothesis-driven parallel hunters (orchestrator caps concurrency, see --max-parallel)" },
      ...META,
    ],
  },
  api: {
    engagement: "api",
    description: "REST / GraphQL / gRPC / WebSocket API",
    skills: ["APISecurityTesting"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["AppReviewAgent"] },
      { phase: "AUTH", parallel: ["AuthAgent", "OAuthAgent"] },
      { phase: "HUNT", parallel: [
        "APIAgent", "GraphQLAgent", "WebSocketAgent", "IDORAgent", "SQLiAgent", "NoSQLiAgent",
        "RCEAgent", "CommandInjectionAgent", "DeserializationAgent", "SSRFAgent", "CRLFAgent",
        "RaceConditionAgent", "BusinessLogicAgent",
      ] },
      ...META,
    ],
  },
  llm: {
    engagement: "llm",
    description: "AI/LLM application (chatbot, RAG, copilot, agent)",
    skills: ["PromptInjection", "WebAssessment"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["AppReviewAgent"], note: "detect chat/RAG vs tool-using agent surface" },
      { phase: "AUTH", parallel: ["AuthAgent"] },
      { phase: "HUNT", parallel: [
        "LLMSecurityAgent", "AIAgentExploitationAgent", "IDORAgent", "SSRFAgent",
        "XSSAgent", "APIAgent", "FileUploadAgent",
      ], note: "LLMSecurity owns OWASP-LLM text/RAG; AIAgentExploitation owns tool-calling/MCP action surface" },
      ...META,
    ],
  },
  android: {
    engagement: "android",
    description: "Android application (.apk)",
    skills: ["MobileSecurity"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["AppReviewAgent"] },
      { phase: "PLATFORM", parallel: ["AndroidAgent"], note: "decompile, components, storage, pinning bypass" },
      { phase: "BACKEND", parallel: ["APIAgent", "AuthAgent", "OAuthAgent", "IDORAgent", "SSRFAgent", "SecretsExposureAgent"], note: "the app's server-side is where most bounties land" },
      { phase: "NATIVE", parallel: ["ReverseEngineeringAgent"], note: "only if native .so / packed logic present" },
      ...META,
    ],
  },
  ios: {
    engagement: "ios",
    description: "iOS application (.ipa)",
    skills: ["MobileSecurity"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["AppReviewAgent"] },
      { phase: "PLATFORM", parallel: ["iOSAgent"], note: "Mach-O, keychain, URL schemes, pinning/jailbreak bypass" },
      { phase: "BACKEND", parallel: ["APIAgent", "AuthAgent", "OAuthAgent", "IDORAgent", "SSRFAgent", "SecretsExposureAgent"] },
      { phase: "NATIVE", parallel: ["ReverseEngineeringAgent"] },
      ...META,
    ],
  },
  mobile: {
    engagement: "mobile",
    description: "Mobile app, platform unknown (routes both Android + iOS)",
    skills: ["MobileSecurity"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["AppReviewAgent"] },
      { phase: "PLATFORM", parallel: ["AndroidAgent", "iOSAgent"] },
      { phase: "BACKEND", parallel: ["APIAgent", "AuthAgent", "OAuthAgent", "IDORAgent", "SSRFAgent", "SecretsExposureAgent"] },
      { phase: "NATIVE", parallel: ["ReverseEngineeringAgent"] },
      ...META,
    ],
  },
  binary: {
    engagement: "binary",
    description: "Native binary / executable target",
    skills: ["ReverseEngineering", "ExploitDev"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["ReverseEngineeringAgent"], note: "static + dynamic understanding before fuzzing" },
      { phase: "DISCOVER", parallel: ["MemoryCorruptionAgent"], note: "fuzz, sanitize, triage to a controllable primitive" },
      { phase: "WEAPONIZE", parallel: ["ExploitDevAgent"], note: "build the working exploit under mitigations" },
      ...META,
    ],
  },
  firmware: {
    engagement: "firmware",
    description: "Firmware / embedded / IoT image or device",
    skills: ["ReverseEngineering", "ExploitDev"],
    groups: [
      { phase: "EXTRACT", parallel: ["FirmwareAgent"], note: "acquire, unpack, analyze filesystem + config" },
      { phase: "UNDERSTAND", parallel: ["ReverseEngineeringAgent", "SecretsExposureAgent"] },
      { phase: "DISCOVER", parallel: ["MemoryCorruptionAgent", "NetworkServiceAgent"], note: "native bugs + emulated network services" },
      { phase: "WEAPONIZE", parallel: ["ExploitDevAgent"] },
      ...META,
    ],
  },
  "thick-client": {
    engagement: "thick-client",
    description: "Desktop / Electron / .NET / Java thick client",
    skills: ["ReverseEngineering"],
    groups: [
      { phase: "UNDERSTAND", parallel: ["AppReviewAgent", "DesktopAppAgent", "ReverseEngineeringAgent"] },
      { phase: "HUNT", parallel: ["AuthAgent", "APIAgent", "SQLiAgent", "RCEAgent", "DeserializationAgent", "CommandInjectionAgent"] },
      ...META,
    ],
  },
  cloud: {
    engagement: "cloud",
    description: "Cloud environment, provider unknown (specify cloud-aws|cloud-azure|cloud-gcp|kubernetes for provider-deep testing)",
    skills: ["CloudSecurity"],
    groups: [
      { phase: "RECON", parallel: ["ReconAgent"] },
      { phase: "PIVOT", parallel: ["CloudExploitationAgent"], note: "turn foothold (SSRF/leaked cred/file read) into a cloud session, detect provider" },
      { phase: "EXPOSURE", parallel: ["SecretsExposureAgent", "SupplyChainAgent"] },
      ...META,
    ],
  },
  "cloud-aws": {
    engagement: "cloud-aws",
    description: "AWS account / AWS-hosted target",
    skills: ["CloudSecurity"],
    groups: [
      { phase: "RECON", parallel: ["ReconAgent"] },
      { phase: "PIVOT", parallel: ["CloudExploitationAgent"], note: "entry: SSRF→IMDS / leaked key → AWS session" },
      { phase: "PROVIDER", parallel: ["AWSAgent"], note: "IAM priv-esc paths, S3/Lambda/Cognito/Secrets" },
      { phase: "CLUSTER", parallel: ["KubernetesAgent"], note: "only if EKS present" },
      { phase: "EXPOSURE", parallel: ["SecretsExposureAgent", "SupplyChainAgent"] },
      ...META,
    ],
  },
  "cloud-azure": {
    engagement: "cloud-azure",
    description: "Azure subscription / Entra ID tenant",
    skills: ["CloudSecurity"],
    groups: [
      { phase: "RECON", parallel: ["ReconAgent"] },
      { phase: "PIVOT", parallel: ["CloudExploitationAgent"], note: "entry: managed-identity IMDS / leaked cred → Azure session" },
      { phase: "PROVIDER", parallel: ["AzureAgent"], note: "Entra ID, managed identities, Key Vault, Storage, Automation" },
      { phase: "CLUSTER", parallel: ["KubernetesAgent"], note: "only if AKS present" },
      { phase: "EXPOSURE", parallel: ["SecretsExposureAgent", "SupplyChainAgent"] },
      ...META,
    ],
  },
  "cloud-gcp": {
    engagement: "cloud-gcp",
    description: "GCP project / organization",
    skills: ["CloudSecurity"],
    groups: [
      { phase: "RECON", parallel: ["ReconAgent"] },
      { phase: "PIVOT", parallel: ["CloudExploitationAgent"], note: "entry: metadata SA token / leaked key → GCP session" },
      { phase: "PROVIDER", parallel: ["GCPAgent"], note: "SA impersonation, IAM priv-esc, GCS, Functions/Run" },
      { phase: "CLUSTER", parallel: ["KubernetesAgent"], note: "only if GKE present" },
      { phase: "EXPOSURE", parallel: ["SecretsExposureAgent", "SupplyChainAgent"] },
      ...META,
    ],
  },
  kubernetes: {
    engagement: "kubernetes",
    description: "Kubernetes cluster / container platform",
    skills: ["CloudSecurity"],
    groups: [
      { phase: "PIVOT", parallel: ["CloudExploitationAgent"], note: "entry: exposed control plane / SSRF / pod foothold" },
      { phase: "CLUSTER", parallel: ["KubernetesAgent"], note: "RBAC priv-esc, node escape, service-account abuse" },
      { phase: "EXPOSURE", parallel: ["SecretsExposureAgent"] },
      ...META,
    ],
  },
  network: {
    engagement: "network",
    description: "Internal network / IP range / Active Directory",
    skills: ["NetworkSecurity"],
    groups: [
      { phase: "RECON", parallel: ["ReconAgent"] },
      { phase: "SERVICES", parallel: ["NetworkServiceAgent"], note: "enumerate + exploit exposed services, weak/default creds" },
      { phase: "DIRECTORY", parallel: ["ActiveDirectoryAgent"], note: "Kerberos, ADCS, delegation, NTLM relay, BloodHound paths" },
      { phase: "HOST", parallel: ["WindowsAgent"], note: "single-host Windows privilege escalation" },
      { phase: "MOVE", parallel: ["LateralMovementAgent"], note: "PtH/PtT, pivoting, credential harvesting, domain compromise" },
      { phase: "WEAPONIZE", parallel: ["ExploitDevAgent"], note: "only for service CVEs needing a custom exploit" },
      ...META,
    ],
  },
  recon: {
    engagement: "recon",
    description: "Standalone reconnaissance / attack-surface discovery",
    skills: ["Recon", "OSINT"],
    groups: [
      { phase: "DISCOVER", parallel: ["ReconAgent", "SubdomainTakeoverAgent"] },
      { phase: "EXPOSURE", parallel: ["SecretsExposureAgent"] },
      ...META,
    ],
  },
};

// --- Helpers ---

function resolveKey(input: string): string | null {
  const k = input.trim().toLowerCase();
  if (ENGAGEMENTS[k]) return k;
  if (ALIASES[k]) return ALIASES[k];
  return null;
}

function planAgents(plan: DeploymentPlan): string[] {
  return [...new Set(plan.groups.flatMap((g) => g.parallel))];
}

function renderPlan(plan: DeploymentPlan, cap: number): string {
  const lines: string[] = [];
  lines.push(`ENGAGEMENT: ${plan.engagement} — ${plan.description}`);
  lines.push(`SKILLS:     ${plan.skills.join(", ")}`);
  lines.push(`AGENTS:     ${planAgents(plan).length} total | max ${cap} concurrent per group`);
  lines.push("");
  plan.groups.forEach((g, i) => {
    const arrow = i === 0 ? "  " : "→ ";
    lines.push(`${arrow}[${g.phase}] (parallel: ${g.parallel.length})`);
    g.parallel.forEach((a) => lines.push(`     • ${a}`));
    if (g.note) lines.push(`     ↳ ${g.note}`);
  });
  return lines.join("\n");
}

// --- CLI ---

function main() {
  const cap = parseInt(args["max-parallel"] || "5", 10);

  if (args.list || (!args.engagement && !args.validate)) {
    console.log("Engagement types (alias → canonical):");
    for (const k of Object.keys(ENGAGEMENTS)) {
      console.log(`  ${k.padEnd(14)} ${ENGAGEMENTS[k].description}`);
    }
    console.log("\nAliases:");
    for (const [a, k] of Object.entries(ALIASES)) console.log(`  ${a.padEnd(16)} → ${k}`);
    console.log("\nUsage: bun agent-router.ts --engagement <type> [--json] [--validate] [--max-parallel N]");
    if (!args.validate) return;
  }

  // Validate: every routed agent resolves to a real Agents/*.md file.
  if (args.validate) {
    const have = new Set(readdirSync(AGENTS_DIR).filter((f) => f.endsWith(".md")).map((f) => f.replace(/\.md$/, "")));
    const scope = args.engagement ? [resolveKey(args.engagement)].filter(Boolean) as string[] : Object.keys(ENGAGEMENTS);
    const missing: { engagement: string; agent: string }[] = [];
    for (const key of scope) {
      for (const a of planAgents(ENGAGEMENTS[key])) {
        if (!have.has(a)) missing.push({ engagement: key, agent: a });
      }
    }
    if (missing.length) {
      console.error(`[FAIL] ${missing.length} dangling agent reference(s):`);
      for (const m of missing) console.error(`  ${m.engagement} → ${m.agent} (no Agents/${m.agent}.md)`);
      process.exit(1);
    }
    const total = new Set(Object.values(ENGAGEMENTS).flatMap((p) => planAgents(p))).size;
    console.log(`[OK] All routed agents resolve to files. ${Object.keys(ENGAGEMENTS).length} engagements, ${total} distinct agents referenced.`);
    return;
  }

  const key = resolveKey(args.engagement!);
  if (!key) {
    console.error(`Unknown engagement: "${args.engagement}". Run --list to see valid types.`);
    process.exit(1);
  }
  const plan = ENGAGEMENTS[key];

  if (args.json) {
    console.log(JSON.stringify({ ...plan, maxParallel: cap, totalAgents: planAgents(plan).length }, null, 2));
    return;
  }
  console.log(renderPlan(plan, cap));
}

main();
