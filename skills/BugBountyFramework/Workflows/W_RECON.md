---
name: W_RECON
description: Comprehensive attack surface discovery and reconnaissance
trigger: Standalone recon request or first phase of any hunt
agents: [ReconAgent, SubdomainTakeoverAgent, SecretsExposureAgent, ValidatorAgent, ExploitChainAgent]
tools: [dev-browser, burp-bridge]
skills_invoked: [Recon, OSINT]
---

# W_RECON — Standalone Reconnaissance Workflow

Maps the full external attack surface of a target organization before any exploitation. The output is a single deliverable: a deduplicated, normalized, prioritized attack-surface inventory with explicit hand-off notes to the web, API, LLM, network, and cloud workflows. Recon is the foundation every other hunt stands on — breadth here decides whether the deep-dive workflows ever see the vulnerable asset at all.

This file is self-contained. A senior recon lead can run it top to bottom and miss nothing material: scope and seed expansion, passive intelligence, subdomain enumeration, DNS intelligence, live host and port/service mapping, content and endpoint discovery, JavaScript analysis, technology fingerprinting, cloud and third-party/SaaS asset discovery, subdomain takeover, code and leak recon, visual recon, and attack-surface prioritization — then hand-off.

---

## Operating Doctrine

The recon mindset, in priority order. Every technique below obeys these.

1. **Map before you touch.** Discovery is a map-making exercise, not an attack. You are inventorying doors and windows, not opening them. The deep-dive workflows (W_WEB, W_API, W_NETWORK, etc.) do the opening. Conflating the two leaks scope and burns the engagement.
2. **Passive-first discipline.** Exhaust passive sources (CT logs, archives, third-party APIs, search indexes) before sending a single packet to target infrastructure. Passive sources are free, silent, and historical — they reveal decommissioned and forgotten assets that active scanning never will. Phase 1 makes zero direct contact with the target.
3. **Hypothesis-driven enumeration.** Every active step answers a question: "Does this org own this CIDR?" "Is this CNAME dangling?" "Does this host serve a different app on a vhost?" Random scanning is noise; targeted enumeration is signal. Seed expansion (ASNs, acquisitions) multiplies surface far more than brute force does.
4. **Proxy everything that touches the target.** Once you go active, route target-bound traffic through Burp (`http://127.0.0.1:8080`) so every request/response is captured, searchable, and replayable. Passive third-party lookups (crt.sh, Shodan, GitHub) stay OUT of the proxy to keep the Burp sitemap clean and in-scope.
5. **Evidence capture is non-negotiable.** Every finding lands as a file in the run output dir: the raw tool output, the resolving DNS record, the screenshot, the response delta. An asset you cannot point to on disk does not exist for reporting or hand-off.
6. **Scope discipline is a hard gate, not a guideline.** Maintain a scope allowlist and a hard out-of-scope denylist. Every resolved host passes the scope guard before any active touch. A spectacular finding on an out-of-scope host is worthless and may be a contract or legal violation. Acquisitions and ASN-derived ranges are confirmed in-scope before active work.
7. **Depth vs. breadth is a deliberate call.** Early phases prize breadth (find every asset). Late phases prize depth (which of these assets is most likely to hold a bug, and why). Prioritization is the whole point — an inventory of 4,000 hosts with no ranking is a liability, not a deliverable.
8. **Normalize and dedup continuously.** The same host appears across a dozen sources with different casings, ports, and schemes. Collapse to a canonical form early and keep one source of truth so downstream counts and hand-offs are trustworthy.

---

## Pre-Flight

Run once before Phase 0. Establishes proxy wiring, scope guard, identities, output structure, and tool discovery.

### 1. Variables and output directory

```bash
# --- Engagement identity ---
export TARGET="target.com"                 # primary seed root domain
export ORG="Target Inc"                    # legal org name for reverse-whois / ASN intel
export SLUG="$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/-/g')"

# --- Run output dir (every artifact lands here) — under the framework-canonical
#     session dir (~/.claude/MEMORY/BugBounty/Sessions/<slug>/, per hunt-orchestrator.ts). ---
export OUT="$HOME/.claude/MEMORY/BugBounty/Sessions/$SLUG/recon"
mkdir -p "$OUT"/{scope,passive,subdomains,dns,hosts,ports,content,js,tech,cloud,takeover,leaks,screenshots,reports}

# --- Bundled framework tooling ---
export TOOLS="$HOME/.claude/skills/BugBountyFramework/Tools"

# --- Browser User-Agent for ALL active requests (never a default curl/tool UA) ---
export UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# --- Burp proxy ---
export BURP="http://127.0.0.1:8080"

# --- Wordlists (SecLists) and resolvers ---
export WL_SUB="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
export WL_SUB_SMALL="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
export WL_CONTENT="/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
export WL_FILES="/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt"
export WL_PERM="/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
export RESOLVERS="$OUT/resolvers.txt"
```

### 2. Trusted resolvers (active DNS needs known-good resolvers)

```bash
# Build a validated resolver list so brute/permutation results are not poisoned
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 50 -o "$RESOLVERS" 2>/dev/null \
  || printf '1.1.1.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n208.67.222.222\n' > "$RESOLVERS"
echo "[*] Resolvers: $(wc -l < "$RESOLVERS")"
```

### 3. Burp proxy wiring + scope sync (hard scope guard)

```bash
# Confirm Burp proxy + REST API are alive before any active work
bun "$TOOLS/burp-bridge.ts" --health

# Push the engagement scope INTO Burp so target traffic is in-scope and recorded.
# Comma-separated patterns; include every confirmed root + acquisition root.
bun "$TOOLS/burp-bridge.ts" --sync-scope --scope "*.target.com,*.target-acq.com,api.target.io"

# Persist the human-readable scope allow/deny as the run's source of truth
cat > "$OUT/scope/in-scope.txt"  <<'EOF'
*.target.com
*.target-acq.com
api.target.io
EOF
cat > "$OUT/scope/out-of-scope.txt" <<'EOF'
# Explicit denylist — these NEVER receive an active packet
blog.target.com
*.zendesk.com
*.statuspage.io
third-party-saas.com
EOF
```

```bash
# Hard scope guard — every active phase pipes candidate hosts through this.
# Keeps in-scope wildcard matches, drops anything matching the denylist.
inscope () {
  grep -vF -f <(grep -v '^#' "$OUT/scope/out-of-scope.txt") \
  | grep -E -f <(grep -v '^#' "$OUT/scope/in-scope.txt" | sed 's/\./\\./g; s/\*/[a-z0-9_-]*/g; s/$/$/')
}
# Usage:  cat candidates.txt | inscope > active-targets.txt
```

### 4. Vault-loaded credentials + multi-identity (for authenticated crawl in later phases)

```bash
# Never inline secrets. Pull engagement creds from the vault when an authenticated
# crawl is in scope (recon usually authenticates ONLY to map the post-login surface).
bun "$TOOLS/credential-vault.ts" --get --target "$SLUG"

# Two identities so authenticated content discovery can later contrast surfaces:
#   low-priv (standard user) vs admin/elevated. Exported for the harness, never echoed.
export HUNT_USER="$(bun "$TOOLS/credential-vault.ts" --get --target "$SLUG" | jq -r '.username // empty')"
export HUNT_PASS="$(bun "$TOOLS/credential-vault.ts" --get --target "$SLUG" | jq -r '.password // empty')"
export HUNT_COOKIE="$(bun "$TOOLS/credential-vault.ts" --get --target "$SLUG-lowpriv" | jq -r '.cookie // empty')"
export ADMIN_COOKIE="$(bun "$TOOLS/credential-vault.ts" --get --target "$SLUG-admin"  | jq -r '.cookie // empty')"
```

### 5. Per-domain tooling surfaced by PiRanha

```bash
# Surface external recon tooling configured for this engagement
piranha tools recon
```

### 6. Active-request convention (reuse everywhere)

Every command that touches the target uses the proxy and the browser UA. Define one wrapper and reuse it:

```bash
# Proxy-aware, browser-UA curl for ANY target-direct request
fetch () { curl -sk -x "$BURP" -A "$UA" "$@"; }
# Passive third-party lookups deliberately DO NOT use $BURP (keep sitemap clean):
pfetch () { curl -sk -A "$UA" "$@"; }
```

---

## Coverage Matrix

Authoritative attack-surface discovery checklist mapped to the phase and technique that covers it. Nothing on this list is left to chance.

| # | Checklist item (authoritative recon surface) | Phase | Technique |
|---|----------------------------------------------|-------|-----------|
| 1 | Root domain / seed identification | 0 | Seed inventory |
| 2 | ASN discovery (org → AS numbers) | 0 | ASN mapping (asnmap, amass intel) |
| 3 | CIDR / netblock expansion + PTR sweep | 0 | CIDR expansion (mapcidr, dnsx -ptr) |
| 4 | Acquisitions / sibling brands / related orgs | 0 | Acquisition & org graph |
| 5 | Reverse WHOIS (registrant email/org → domains) | 0 | Reverse-whois (amass intel -whois) |
| 6 | WHOIS / registration intelligence | 1 | WHOIS & domain intel |
| 7 | Certificate Transparency (crt.sh, certspotter, Censys) | 1 | CT logs |
| 8 | Passive infra intel (Shodan, Censys, FOFA) | 1 | Internet-scan engines |
| 9 | SecurityTrails / passive DNS history | 1 | Passive DNS history |
| 10 | Wayback / archive URL + asset mining | 1 | Web archives |
| 11 | Passive subdomain enum (subfinder, chaos, amass passive) | 2 | Passive subdomain enum |
| 12 | Active DNS resolution (dnsx / puredns) | 2 | Resolution & wildcard filter |
| 13 | DNS brute-force with wordlists | 2 | DNS brute-force |
| 14 | Permutation / alteration (gotator, altdns, dnsgen) | 2 | Permutation scanning |
| 15 | Virtual host (vhost) discovery | 2 | VHOST discovery |
| 16 | DNS records (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV) | 3 | Record enumeration |
| 17 | Zone transfer (AXFR) | 3 | Zone transfer |
| 18 | SPF / DKIM / DMARC / DNSSEC posture | 3 | Mail & DNSSEC posture |
| 19 | Wildcard DNS detection + false-positive control | 2,3 | Wildcard handling |
| 20 | Live host probing (httpx) | 4 | HTTP probing |
| 21 | Port scanning (naabu) | 4 | Port discovery |
| 22 | Service / version detection (nmap -sV) | 4 | Service mapping |
| 23 | Technology fingerprinting (httpx, whatweb, wappalyzer, nuclei) | 7 | Tech detection |
| 24 | CMS identification (WordPress/Joomla/Drupal) | 7 | CMS detection |
| 25 | Historical URLs (gau, waybackurls) | 5 | Historical URL mining |
| 26 | Crawling / spidering (katana, hakrawler) | 5 | Active crawl |
| 27 | robots.txt / sitemap.xml / security.txt / .well-known | 5 | Policy & sitemap files |
| 28 | Directory / file brute-force (ffuf, feroxbuster) | 5 | Content brute-force |
| 29 | Parameter discovery (arjun, x8, paramspider) | 5 | Parameter mining |
| 30 | API schema discovery (swagger/openapi/graphql) | 5 | API surface discovery |
| 31 | JS endpoint extraction (linkfinder, katana -jc) | 6 | JS route mining |
| 32 | JS secret extraction (secretfinder, trufflehog, nuclei exposures) | 6 | JS secret mining |
| 33 | JS source-map reconstruction | 6 | Source-map recovery |
| 34 | Cloud bucket discovery (S3/GCS/Azure) | 8 | Bucket enumeration |
| 35 | Cloud app domains (azurewebsites, herokuapp, *.web.app) | 8 | Cloud app discovery |
| 36 | Third-party / SaaS footprint (Zendesk, Atlassian, Slack, etc.) | 8 | SaaS footprinting |
| 37 | Dangling DNS / CNAME takeover (dnsreaper, subjack, nuclei) | 9 | Takeover scanning |
| 38 | NS / MX record takeover | 9 | Delegation takeover |
| 39 | GitHub/GitLab/Bitbucket dorking | 10 | Code-platform dorking |
| 40 | Secret scanning of public repos (trufflehog, gitleaks) | 10 | Repo secret scanning |
| 41 | Paste sites / leak dumps / credential breaches | 10 | Paste & breach recon |
| 42 | Employee / email OSINT (spray seeds for W_NETWORK) | 10 | People & email OSINT |
| 43 | Visual recon / screenshots (gowitness, aquatone) | 11 | Screenshot gallery |
| 44 | Attack-surface scoring & prioritization | 11 | Prioritization engine |
| 45 | Dedup / normalize into canonical inventory | 11,12 | Inventory normalization |
| 46 | Validation, de-dup by root cause, CVSS gate | 12 | ValidatorAgent hand-off |
| 47 | Kill-chain correlation across discovered assets | 12 | ExploitChainAgent hand-off |
| 48 | Per-workflow hand-off (web/api/llm/network/cloud) | 12 | Reporting & hand-off |

---

## Phase 0: SCOPE & SEED EXPANSION

**Objective:** Convert the handful of given seeds into the org's true root-asset graph — every root domain, ASN, CIDR, and acquisition the organization actually owns.

**Expert rationale:** The single highest-leverage recon activity. Bug bounty scopes are written by humans who forget assets; the org owns far more than the seed list says. Expanding from `target.com` to three acquisition roots and two ASNs can multiply the eventual attack surface 10x. Every subsequent phase operates on the seed graph this phase produces, so an incomplete Phase 0 caps the entire engagement.

**Gate-in:** Pre-Flight complete; `$TARGET`, `$ORG`, scope files populated; Burp healthy.

> All Phase 0 work is passive (third-party APIs, WHOIS, registries). No target contact. Sub-techniques are parallelizable.

### 0.1 Seed inventory

- **Objective / hypothesis:** Establish the canonical seed set; the program scope plus any obviously-related apex domains are the roots from which everything expands.
- **Procedure:**
  ```bash
  # Record provided + obvious seeds (program brief, marketing footers, app stores)
  printf '%s\n' target.com target.io target.net target-app.com > "$OUT/scope/seed-roots.txt"
  sort -u "$OUT/scope/seed-roots.txt" -o "$OUT/scope/seed-roots.txt"
  ```
- **Indicators:** A confirmed list of apex domains the org publicly operates.
- **Validation:** Each root resolves and its WHOIS/registrant or hosting ties back to `$ORG` (confirmed in 0.4).
- **Evasion / edge cases:** Country-code TLD variants (`target.co.uk`, `target.de`) and brand typo-domains the org defensively registered are real assets — include them.
- **Severity:** N/A (enabling step). Business impact: completeness of the entire engagement.
- **Dispatch:** -> ReconAgent

### 0.2 ASN mapping (org → autonomous systems)

- **Objective / hypothesis:** If the org runs its own netblocks, its AS numbers reveal IP ranges hosting assets DNS never names.
- **Procedure:**
  ```bash
  # asnmap: domain/org -> ASN(s)
  asnmap -d target.com -silent | tee "$OUT/scope/asn-from-domain.txt"
  asnmap -org "$ORG" -silent   | tee -a "$OUT/scope/asns.txt"
  # amass intel cross-check
  amass intel -org "$ORG" 2>/dev/null | tee -a "$OUT/scope/asns.txt"
  sort -u "$OUT/scope/asns.txt" -o "$OUT/scope/asns.txt"
  ```
- **Indicators:** One or more `ASxxxxx` entries whose registrant string matches `$ORG`.
- **Validation:** Cross-check the AS registrant via `whois -h whois.radb.net AS12345` and bgp.he.net; only owned ASNs proceed.
- **Evasion / edge cases:** Shared-hosting/cloud ASNs (AWS, Cloudflare) are NOT org-owned — exclude them, or you will scan the whole cloud. Owned ASNs are usually colo/datacenter ranges.
- **Severity:** N/A. Business impact: exposes self-hosted infra (the highest-value, least-tested surface).
- **Dispatch:** -> ReconAgent

### 0.3 CIDR expansion + PTR sweep

- **Objective / hypothesis:** Owned ASNs decompose into CIDRs; reverse DNS over those CIDRs names hosts that forward DNS hides.
- **Procedure:**
  ```bash
  # ASN -> CIDR ranges
  for asn in $(cat "$OUT/scope/asns.txt"); do asnmap -a "$asn" -silent; done \
    | sort -u | tee "$OUT/scope/cidrs.txt"
  # Expand CIDRs to IPs, then PTR-resolve to surface hostnames (proxy not needed: DNS)
  mapcidr -cl "$OUT/scope/cidrs.txt" -silent \
    | dnsx -ptr -resp-only -silent -r "$RESOLVERS" \
    | sort -u | tee "$OUT/scope/ptr-hostnames.txt"
  ```
- **Indicators:** PTR records returning `*.target.com` or org-branded hostnames inside owned CIDRs.
- **Validation:** Forward-resolve each PTR name and confirm it lands back in an owned CIDR (rules out stale PTRs).
- **Evasion / edge cases:** Large CIDRs from cloud ASNs explode into millions of IPs — only sweep CONFIRMED org-owned ranges. Rate-limit PTR queries to avoid resolver bans.
- **Severity:** N/A. Business impact: finds un-DNS'd management interfaces, jump hosts, legacy boxes.
- **Dispatch:** -> ReconAgent

### 0.4 Acquisition & organization graph

- **Objective / hypothesis:** Acquired companies retain their own domains/infra that the parent now owns and is responsible for — and rarely re-secures.
- **Procedure:**
  ```bash
  # WHOIS registrant + org-string pivots
  whois target.com | grep -iE "registrant|org|email" | tee "$OUT/scope/whois-pivots.txt"
  # Crunchbase/Wikipedia acquisition lists (manual review), plus amass intel org pivot
  amass intel -org "$ORG" -whois 2>/dev/null | tee "$OUT/scope/acquisitions-amass.txt"
  # Record confirmed acquisitions as new roots
  printf '%s\n' target-acq.com sibling-brand.io >> "$OUT/scope/seed-roots.txt"
  sort -u "$OUT/scope/seed-roots.txt" -o "$OUT/scope/seed-roots.txt"
  ```
- **Indicators:** Domains sharing registrant org/email, or named in public M&A records, tied to `$ORG`.
- **Validation:** Confirm the acquisition is in program scope before any active touch; add confirmed roots to `in-scope.txt` and re-sync Burp scope.
- **Evasion / edge cases:** Recently divested brands are OUT of scope even if WHOIS still shows the parent — verify the current relationship.
- **Severity:** N/A. Business impact: acquisition infra is the classic source of forgotten, unpatched assets.
- **Dispatch:** -> ReconAgent

### 0.5 Reverse WHOIS

- **Objective / hypothesis:** Domains registered under the same email/org/phone are likely owned by the target.
- **Procedure:**
  ```bash
  amass intel -d target.com -whois 2>/dev/null | sort -u | tee "$OUT/scope/reverse-whois.txt"
  # ViewDNS / WhoisXML reverse-whois (API) cross-check
  pfetch "https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=<KEY>&mode=purchase&searchType=current&basicSearchTerms[include][]=$ORG" \
    | jq -r '.domainsList[]?' | sort -u >> "$OUT/scope/reverse-whois.txt"
  sort -u "$OUT/scope/reverse-whois.txt" -o "$OUT/scope/reverse-whois.txt"
  ```
- **Indicators:** Additional apex domains whose registration record matches the org's registrant identity.
- **Validation:** WHOIS-confirm registrant match and program scope before promoting to a root.
- **Evasion / edge cases:** WHOIS privacy/redaction hides registrant strings — pivot on historical (pre-GDPR) records and on shared name servers / hosting IPs instead.
- **Severity:** N/A. Business impact: widens the root graph beyond the obvious brand.
- **Dispatch:** -> ReconAgent

**Phase artifacts:** `scope/seed-roots.txt`, `scope/asns.txt`, `scope/cidrs.txt`, `scope/ptr-hostnames.txt`, `scope/acquisitions-amass.txt`, `scope/reverse-whois.txt`, updated `scope/in-scope.txt` + re-synced Burp scope.

**Gate-out:** A confirmed, scope-validated root graph (all apex domains + owned ASNs/CIDRs) exists and is the input to Phase 1/2. Proceed only once acquisitions/ASNs are scope-confirmed.

---

## Phase 1: PASSIVE INTELLIGENCE

**Objective:** Gather maximum intelligence about the root graph without sending a single packet to target infrastructure.

**Expert rationale:** Passive sources are silent, free, and historical. They surface decommissioned hosts, rotated keys in old assets, and infra relationships that active scanning can never reconstruct. Doing this first also seeds Phase 2 so brute-force/permutation start from a rich base rather than a cold wordlist.

**Gate-in:** Phase 0 root graph exists.

> Entire phase is passive third-party lookups — `pfetch`/APIs only, NOT proxied through Burp (keeps the sitemap in-scope-only). All sub-techniques parallelizable.

### 1.1 WHOIS & domain intelligence

- **Objective / hypothesis:** Registration data exposes registrant identity, name servers, and historical ownership useful for further pivots.
- **Procedure:**
  ```bash
  for root in $(cat "$OUT/scope/seed-roots.txt"); do
    whois "$root" > "$OUT/passive/whois-$root.txt"
  done
  # SecurityTrails current + historical WHOIS (API)
  pfetch "https://api.securitytrails.com/v1/domain/target.com/whois" -H "APIKEY: <ST_API_KEY>" \
    | jq > "$OUT/passive/st-whois.json"
  ```
- **Indicators:** Registrant org/email, NS records, historical registrants enabling more reverse-whois pivots.
- **Validation:** Cross-reference registrant strings against `$ORG`.
- **Evasion / edge cases:** Privacy-protected WHOIS — fall back to historical records and NS/hosting pivots.
- **Severity:** Informational. Business impact: pivot fuel; occasionally exposes admin contact emails for OSINT.
- **Dispatch:** -> ReconAgent

### 1.2 Certificate Transparency logs

- **Objective / hypothesis:** Every TLS cert the org issued is publicly logged; CT is the single richest passive subdomain source.
- **Procedure:**
  ```bash
  # crt.sh (JSON) — handle wildcard + SAN entries
  pfetch "https://crt.sh/?q=%25.target.com&output=json" \
    | jq -r '.[].name_value' | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u \
    > "$OUT/passive/crtsh.txt"
  # certspotter
  pfetch "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" \
    | jq -r '.[].dns_names[]' | sort -u >> "$OUT/passive/crtsh.txt"
  # Censys cert search
  censys search "names: target.com" --index-type certificates 2>/dev/null \
    | jq -r '.[].names[]?' | sort -u >> "$OUT/passive/crtsh.txt"
  sort -u "$OUT/passive/crtsh.txt" -o "$OUT/passive/crtsh.txt"
  ```
- **Indicators:** Subdomains (incl. internal-looking `dev/stg/internal`) and sibling roots appearing in SAN fields.
- **Validation:** Names from CT are candidates only — resolution happens in Phase 2.
- **Evasion / edge cases:** Wildcard certs (`*.target.com`) hide specific names; pre-cert and leaf entries differ — query both. Internal hostnames in CT (from internal CAs that leaked) are gold.
- **Severity:** Informational. Business impact: largest single passive subdomain yield.
- **Dispatch:** -> ReconAgent

### 1.3 Internet-scan engines (Shodan / Censys / FOFA)

- **Objective / hypothesis:** Internet-wide scanners already fingerprinted the org's hosts, ports, banners, and certs — read their index instead of scanning yourself.
- **Procedure:**
  ```bash
  shodan search --fields ip_str,port,org,product "ssl.cert.subject.cn:target.com" > "$OUT/passive/shodan.txt"
  shodan search --fields ip_str,port,hostnames "hostname:target.com" >> "$OUT/passive/shodan.txt"
  shodan domain target.com > "$OUT/passive/shodan-domain.txt"
  censys search "services.tls.certificates.leaf_data.subject.common_name: target.com" 2>/dev/null \
    > "$OUT/passive/censys-hosts.json"
  ```
- **Indicators:** Live IPs, exposed ports/products, expired certs, banners revealing version strings and internal IPs.
- **Validation:** Treat banners as leads; confirm in Phase 4. Cross-check IPs against owned CIDRs.
- **Evasion / edge cases:** Shodan data can be stale — note `last_seen`. CDN-fronted hosts show the CDN, not origin; pivot on `ssl.cert` to find origin IPs that bypass the CDN/WAF.
- **Severity:** Informational, but exposed-service banners can be high. Business impact: pre-maps open ports for free; origin-IP discovery enables WAF bypass.
- **Dispatch:** -> ReconAgent

### 1.4 Passive DNS history

- **Objective / hypothesis:** Historical DNS reveals subdomains and IPs no longer in current records but still pointing at live, forgotten infra.
- **Procedure:**
  ```bash
  pfetch "https://api.securitytrails.com/v1/domain/target.com/subdomains" -H "APIKEY: <ST_API_KEY>" \
    | jq -r '.subdomains[]' | sed "s/$/.target.com/" | sort -u > "$OUT/passive/st-subs.txt"
  pfetch "https://api.securitytrails.com/v1/history/target.com/dns/a" -H "APIKEY: <ST_API_KEY>" \
    | jq > "$OUT/passive/st-dns-history.json"
  pfetch "https://api.securitytrails.com/v1/domain/target.com/associated" -H "APIKEY: <ST_API_KEY>" \
    | jq -r '.records[].hostname?' >> "$OUT/passive/st-subs.txt"
  ```
- **Indicators:** Old A records pointing to still-claimable IPs; subdomains absent from CT.
- **Validation:** Resolve in Phase 2; dangling historical records feed Phase 9 takeover.
- **Evasion / edge cases:** Historical IPs in cloud ranges may now belong to a different tenant — a classic dangling-A takeover lead.
- **Severity:** Informational; historical dangling records can be high (takeover). Business impact: surfaces abandoned infra.
- **Dispatch:** -> ReconAgent

### 1.5 Web archives (Wayback / CommonCrawl)

- **Objective / hypothesis:** Archives hold years of URLs, parameters, and JS assets — including endpoints and keys removed from the live site but still functional.
- **Procedure:**
  ```bash
  pfetch "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" \
    | sort -u > "$OUT/passive/wayback-urls.txt"
  # Archived sensitive paths
  pfetch "http://web.archive.org/cdx/search/cdx?url=target.com/admin*&output=text&fl=original,timestamp" \
    | sort -u > "$OUT/passive/wayback-admin.txt"
  # BuiltWith tech history (third-party SaaS fingerprint seed)
  pfetch "https://api.builtwith.com/v21/api.json?KEY=<KEY>&LOOKUP=target.com" | jq > "$OUT/passive/builtwith.json"
  ```
- **Indicators:** Archived `/api/`, `?param=` patterns, `.js`/`.json`/`.env` assets, old admin URLs.
- **Validation:** Live-check interesting archived URLs in Phase 5 (proxied); rotated keys in old JS validated in Phase 6/10.
- **Evasion / edge cases:** Archives capture pre-WAF, pre-auth states — old endpoints often still work. Diff archived JS versions to find rotated-but-live keys.
- **Severity:** Informational; archived secrets/endpoints can be critical. Business impact: free historical endpoint + secret corpus.
- **Dispatch:** -> ReconAgent (secrets in archived assets -> SecretsExposureAgent)

**Phase artifacts:** `passive/crtsh.txt`, `passive/shodan*.txt`, `passive/censys-hosts.json`, `passive/st-subs.txt`, `passive/st-dns-history.json`, `passive/wayback-urls.txt`, `passive/builtwith.json`.

**Gate-out:** A rich passive corpus of candidate subdomains, IPs, banners, and historical URLs exists to seed active enumeration. No target was contacted.

---

## Phase 2: SUBDOMAIN ENUMERATION

**Objective:** Discover every subdomain across the root graph via passive aggregation, active resolution, brute-force, permutation, and virtual-host discovery — then resolve and dedup into a canonical live-name set.

**Expert rationale:** Subdomains are the primary unit of web/API attack surface. Coverage here directly determines what the deep-dive workflows ever see. Passive aggregation gives breadth cheaply; brute and permutation catch the predictable internal names (`dev`, `staging`, `jira-internal`); vhost discovery catches names that exist only behind a shared IP and never resolve publicly.

**Gate-in:** Phase 1 passive corpus exists; resolvers built; scope guard ready.

> 2.1 is passive. 2.2–2.4 are active (DNS resolution touches resolvers, not the target app, but vhost discovery in 2.5 touches target IPs — proxy + UA there). 2.1–2.4 parallelizable per root.

### 2.1 Passive subdomain aggregation

- **Objective / hypothesis:** Aggregate every passive source into one candidate pool before spending a single active query.
- **Procedure:**
  ```bash
  cd "$OUT/subdomains"
  for root in $(cat "$OUT/scope/seed-roots.txt"); do
    subfinder -d "$root" -all -silent      >> subs-passive.txt
    amass enum -passive -d "$root" -silent >> subs-passive.txt 2>/dev/null
    assetfinder --subs-only "$root"        >> subs-passive.txt
    findomain -t "$root" -q                >> subs-passive.txt 2>/dev/null
    chaos -d "$root" -silent               >> subs-passive.txt 2>/dev/null
  done
  cat subs-passive.txt "$OUT/passive/crtsh.txt" "$OUT/passive/st-subs.txt" \
      "$OUT/scope/ptr-hostnames.txt" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' | sort -u > subs-candidates.txt
  echo "[*] Passive candidates: $(wc -l < subs-candidates.txt)"
  ```
- **Indicators:** Thousands of candidate names merged from CT, passive DNS, and source aggregators.
- **Validation:** Candidates are unresolved until 2.2.
- **Evasion / edge cases:** Configure subfinder/amass with API keys (Shodan, Censys, VirusTotal, etc.) for far deeper passive yield; recursive subfinder (`-recursive`) finds sub-subdomains.
- **Severity:** Informational. Business impact: breadth of the entire web surface.
- **Dispatch:** -> ReconAgent

### 2.2 Resolution & wildcard filtering

- **Objective / hypothesis:** Only resolving names are real; wildcard DNS poisons brute results and must be filtered.
- **Procedure:**
  ```bash
  cd "$OUT/subdomains"
  # Detect wildcard: random labels that resolve = wildcard in play
  for i in 1 2 3; do echo "zzz-$RANDOM-$RANDOM.target.com"; done \
    | dnsx -silent -a -resp -r "$RESOLVERS" | tee ../dns/wildcard-probe.txt
  # Resolve candidates with wildcard filtering (puredns handles wildcard roots)
  puredns resolve subs-candidates.txt -r "$RESOLVERS" --wildcard-batch 100000 \
    -w subs-resolved.txt 2>/dev/null
  # dnsx enrichment (A/CNAME) for the resolved set
  dnsx -l subs-resolved.txt -a -cname -resp -silent -r "$RESOLVERS" -json -o ../dns/dnsx-resolved.json
  ```
- **Indicators:** A subset of candidates returning real A/CNAME records; wildcard probe reveals catch-all behavior.
- **Validation:** Names that survive wildcard filtering and resolve are real; pass them through the scope guard.
- **Evasion / edge cases:** Wildcard DNS returns the same IP for everything — use response-content comparison (httpx body hash in Phase 4) to separate real apps from the wildcard default page.
- **Severity:** Informational. Business impact: the canonical live-name set.
- **Dispatch:** -> ReconAgent

### 2.3 DNS brute-force

- **Objective / hypothesis:** Predictable internal names (`dev`, `vpn`, `git`, `admin`) often resolve but never appear in passive sources.
- **Procedure:**
  ```bash
  cd "$OUT/subdomains"
  for root in $(cat "$OUT/scope/seed-roots.txt"); do
    puredns bruteforce "$WL_SUB" "$root" -r "$RESOLVERS" -q >> subs-brute.txt 2>/dev/null
  done
  sort -u subs-brute.txt -o subs-brute.txt
  echo "[*] Brute hits: $(wc -l < subs-brute.txt)"
  ```
- **Indicators:** New resolving names absent from passive aggregation.
- **Validation:** Re-resolve with puredns wildcard filtering before trusting.
- **Evasion / edge cases:** Use a large, curated wordlist (`$WL_SUB`); rate-limit via puredns to avoid resolver bans; on wildcard roots, brute yields are dominated by the wildcard — rely on response-diff later.
- **Severity:** Informational. Business impact: surfaces internal/dev environments (high-value, low-defense).
- **Dispatch:** -> ReconAgent

### 2.4 Permutation scanning

- **Objective / hypothesis:** Variations on known names (`api-dev`, `staging-api`, `api2`) frequently exist; generate and resolve them from the already-known set.
- **Procedure:**
  ```bash
  cd "$OUT/subdomains"
  cat subs-resolved.txt subs-brute.txt | sort -u > subs-known.txt
  # gotator — permutations from known names + wordlist
  gotator -sub subs-known.txt -perm "$WL_PERM" -depth 1 -numbers 5 -mindup -adv -md 2>/dev/null \
    | puredns resolve -r "$RESOLVERS" -q > subs-gotator.txt 2>/dev/null
  # altdns / dnsgen alternates
  dnsgen subs-known.txt 2>/dev/null | puredns resolve -r "$RESOLVERS" -q >> subs-gotator.txt 2>/dev/null
  altdns -i subs-known.txt -w "$WL_PERM" -r -s /dev/stdout 2>/dev/null >> subs-gotator.txt
  sort -u subs-gotator.txt -o subs-gotator.txt
  ```
- **Indicators:** Newly resolving permuted names (env/number/region variants).
- **Validation:** puredns resolution + wildcard filter on the generated set.
- **Evasion / edge cases:** Permutation explodes combinatorially — cap `-depth`/`-numbers`. Region/cloud-tier suffixes (`-eu`, `-prod`, `-blue`) are productive permutation tokens.
- **Severity:** Informational. Business impact: catches the env-variant hosts everyone else misses.
- **Dispatch:** -> ReconAgent

### 2.5 Virtual host (vhost) discovery

- **Objective / hypothesis:** A single IP may serve multiple apps keyed only by the `Host` header — vhosts that never resolve in DNS.
- **Procedure:**
  ```bash
  cd "$OUT/subdomains"
  # For each live IP, brute Host headers (proxied + browser UA). Baseline-filter by size.
  for ip in $(cat "$OUT/hosts/live-ips.txt" 2>/dev/null); do
    ffuf -x "$BURP" -H "User-Agent: $UA" -H "Host: FUZZ.target.com" \
         -u "https://$ip" -w "$WL_SUB_SMALL" -ac -mc 200,301,302,401,403 \
         -o "../content/vhost-$ip.json" -of json 2>/dev/null
  done
  ```
- **Indicators:** A response whose size/status/title differs from the IP's default vhost — a hidden app keyed to a Host value.
- **Validation:** Re-request the differing Host directly through Burp; confirm a distinct application (not the default/404 page).
- **Evasion / edge cases:** Auto-calibrate (`-ac`) against wildcard/catch-all responses; some vhosts require the exact case or a port; test both 80 and 443. Internal-only vhosts (admin panels) are the prize.
- **Severity:** Can be high — hidden admin/staging apps. Business impact: surfaces apps invisible to DNS-based recon.
- **Dispatch:** -> ReconAgent (discovered app -> W_WEB / W_API)

### 2.6 Merge, normalize & dedup

- **Objective / hypothesis:** Collapse all sources into one canonical, scope-filtered subdomain set.
- **Procedure:**
  ```bash
  cd "$OUT/subdomains"
  cat subs-resolved.txt subs-brute.txt subs-gotator.txt 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' | sort -u \
    | inscope > all-subdomains.txt
  echo "[*] Canonical in-scope subdomains: $(wc -l < all-subdomains.txt)"
  ```
- **Indicators:** A single deduped file feeding every later phase.
- **Validation:** Scope guard applied; counts logged.
- **Evasion / edge cases:** Strip trailing dots and normalize case to avoid duplicate counting.
- **Severity:** N/A. Business impact: the trustworthy source of truth for the whole run.
- **Dispatch:** -> ReconAgent

**Phase artifacts:** `subdomains/all-subdomains.txt` (canonical), `subdomains/subs-*.txt` (per-source), `dns/dnsx-resolved.json`, `content/vhost-*.json`.

**Gate-out:** `all-subdomains.txt` exists, deduped, normalized, scope-filtered, with ≥1 resolving host. If <5 resolved on a known-large org, return to 2.3/2.4 with deeper wordlists or check for wildcard masking.

---

## Phase 3: DNS INTELLIGENCE & RESOLUTION

**Objective:** Enrich the resolved set with full DNS records, attempt zone transfers, assess mail/DNSSEC posture, and flag dangling records that feed the takeover phase.

**Expert rationale:** DNS is the connective tissue of the attack surface. CNAME chains reveal third-party/SaaS dependencies and takeover candidates; MX/NS reveal mail and delegation takeover paths; TXT/SPF expose included third parties and sometimes internal IPs; a successful AXFR is a full map handed over for free.

**Gate-in:** `all-subdomains.txt` exists.

> Record queries and AXFR hit name servers, not the target app — proxy not required (DNS). Parallelizable per subdomain.

### 3.1 Record enumeration

- **Objective / hypothesis:** Full per-host records expose hosting providers, CDNs, mail, and SaaS dependencies.
- **Procedure:**
  ```bash
  dnsx -l "$OUT/subdomains/all-subdomains.txt" -a -aaaa -cname -mx -ns -txt -soa -caa -srv \
    -resp -silent -r "$RESOLVERS" -json -o "$OUT/dns/records.json"
  # Extract CNAME map (takeover + SaaS dependency signal)
  jq -r 'select(.cname) | "\(.host) -> \(.cname[])"' "$OUT/dns/records.json" \
    | sort -u > "$OUT/dns/cname-map.txt"
  ```
- **Indicators:** CNAMEs to cloud/SaaS providers, multiple A records (load-balanced), CAA pinning a CA, SRV revealing services.
- **Validation:** Records are factual; interpretation (takeover) happens in Phase 9.
- **Evasion / edge cases:** CNAME chains (`a -> b -> c`) — follow the whole chain; any claimable link is a takeover. CDN A records mask origin (note for Phase 4 origin discovery).
- **Severity:** Informational; CNAME map seeds high-severity takeover. Business impact: dependency + takeover graph.
- **Dispatch:** -> ReconAgent (CNAME map -> SubdomainTakeoverAgent)

### 3.2 Zone transfer (AXFR)

- **Objective / hypothesis:** A misconfigured name server may dump its entire zone — every record at once.
- **Procedure:**
  ```bash
  for ns in $(dig +short NS target.com); do
    echo "=== AXFR via $ns ==="
    dig @"$ns" target.com AXFR +noall +answer
  done | tee "$OUT/dns/axfr.txt"
  # Try AXFR on every NS of every in-scope root
  for root in $(cat "$OUT/scope/seed-roots.txt"); do
    for ns in $(dig +short NS "$root"); do dig @"$ns" "$root" AXFR +noall +answer; done
  done >> "$OUT/dns/axfr.txt"
  ```
- **Indicators:** AXFR returns actual records (not `Transfer failed`) — the full zone, including internal hosts.
- **Validation:** Real records returned = confirmed misconfiguration; cross-check the dumped names into `all-subdomains.txt`.
- **Evasion / edge cases:** Most NS refuse AXFR; try every NS (one may be misconfigured), try TCP explicitly, and try internal/legacy NS found via PTR.
- **Severity:** Medium-High (CVSS ~5–7) — full internal zone disclosure. Business impact: complete DNS map, often internal hostnames.
- **Dispatch:** -> ReconAgent

### 3.3 Mail & DNSSEC posture

- **Objective / hypothesis:** SPF/DKIM/DMARC and DNSSEC posture expose included third parties, spoofability, and sometimes internal IPs in SPF.
- **Procedure:**
  ```bash
  {
    echo "== SPF =="; dig target.com TXT +short | grep -i "v=spf1"
    echo "== DMARC =="; dig _dmarc.target.com TXT +short
    echo "== DKIM (common selectors) =="
    for sel in default google selector1 selector2 k1 mail smtp; do
      dig "$sel._domainkey.target.com" TXT +short | grep -q . && echo "$sel: present"
    done
    echo "== DNSSEC =="; dig target.com DNSKEY +dnssec +short
    echo "== CAA =="; dig target.com CAA +short
  } | tee "$OUT/dns/mail-dnssec.txt"
  ```
- **Indicators:** SPF `include:` of third-party senders (SaaS footprint), `~all`/`?all` (weak), missing/`p=none` DMARC (spoofable), no DNSSEC, SPF embedding `ip4:` internal ranges.
- **Validation:** Confirm policy strings directly; spoofability is a real low/medium finding for the org.
- **Evasion / edge cases:** SPF `include` chains expand recursively — follow them for the full third-party sender list; >10 DNS lookups in SPF is itself a misconfig.
- **Severity:** Low-Medium (email spoofing, CVSS ~4–6). Business impact: phishing enablement; SPF includes feed SaaS footprint (Phase 8).
- **Dispatch:** -> ReconAgent

**Phase artifacts:** `dns/records.json`, `dns/cname-map.txt`, `dns/axfr.txt`, `dns/mail-dnssec.txt`.

**Gate-out:** Full DNS record set captured; CNAME map produced (feeds Phase 9); any AXFR results folded back into the subdomain set.

---

## Phase 4: LIVE HOST, PORT & SERVICE MAPPING

**Objective:** Determine which subdomains/IPs are alive over HTTP(S) and other ports, and map services and versions on open ports.

**Expert rationale:** Of thousands of names, only a fraction serve live apps — those are the real attack surface. Port scanning beyond 80/443 surfaces dev servers (3000/8080), databases, admin panels, and management interfaces that are the softest targets. Service/version detection turns "port open" into "exploitable software X.Y".

**Gate-in:** `all-subdomains.txt` and DNS records exist.

> All active. Probing and scanning touch the target — proxy HTTP probing through Burp, set the browser UA. Port scanning is direct (TCP). Profile (probe) before any deep service interaction. Parallelizable with concurrency caps.

### 4.1 HTTP probing

- **Objective / hypothesis:** Identify live web services with status, title, tech, CDN, and IP — the core web inventory.
- **Procedure:**
  ```bash
  cd "$OUT/hosts"
  # Probe through Burp so every live host enters the proxied sitemap; browser UA.
  httpx -l "$OUT/subdomains/all-subdomains.txt" \
    -http-proxy "$BURP" -H "User-Agent: $UA" \
    -status-code -title -tech-detect -web-server -cdn -ip -cname -location \
    -content-length -favicon -jarm -follow-redirects -threads 40 \
    -json -o httpx.json
  jq -r '.url' httpx.json | sort -u > live-hosts.txt
  jq -r '.a[]?'  httpx.json | sort -u > live-ips.txt
  # Body-hash to separate real apps from wildcard/default pages
  jq -r '[.url,(.hash.body_mmh3 // "-"),(.status_code|tostring)] | @tsv' httpx.json \
    | sort -u > body-hashes.tsv
  echo "[*] Live hosts: $(wc -l < live-hosts.txt)"
  ```
- **Indicators:** `200/301/302/401/403` responses, distinct titles, tech stacks, favicon hashes clustering related apps.
- **Validation:** Group by body hash — identical hashes across many hosts = wildcard/parked default, not real apps. Investigate distinct hashes.
- **Evasion / edge cases:** Proxy capture lets you replay any host later. `403`s may be WAF/path-gated — keep them (often bypassable). Favicon mmh3 hash pivots to find more org assets on Shodan.
- **Severity:** Informational; the inventory drives everything. Business impact: the definitive live web map.
- **Dispatch:** -> ReconAgent

### 4.2 Port discovery

- **Objective / hypothesis:** Non-web and non-standard ports host the least-defended services.
- **Procedure:**
  ```bash
  cd "$OUT/ports"
  # Fast top-ports across resolved IPs (direct TCP — not via Burp)
  naabu -l "$OUT/hosts/live-ips.txt" -top-ports 1000 -silent -rate 1000 -o naabu-top.txt
  # Targeted web-adjacent + admin ports across all subdomains
  naabu -l "$OUT/subdomains/all-subdomains.txt" \
    -p 80,443,8080,8443,8000,8888,3000,5000,9090,9200,5601,15672,2375,6379,27017,5432,3306 \
    -silent -o naabu-web-admin.txt
  ```
- **Indicators:** Open ports beyond 80/443 — `3000` (Node dev), `9200` (Elasticsearch), `6379` (Redis), `27017` (Mongo), `2375` (Docker), `15672` (RabbitMQ).
- **Validation:** Re-probe each open port with httpx/nc to confirm a live service (not a stale filtered port).
- **Evasion / edge cases:** Behind a CDN, scanning the CDN IP is pointless — scan origin IPs from owned CIDRs (Phase 0) and Shodan-found origins. Rate-limit to avoid IPS triggers.
- **Severity:** Open data stores/management ports are often High-Critical. Business impact: exposed infra services = direct compromise candidates.
- **Dispatch:** -> ReconAgent (exposed services -> W_NETWORK)

### 4.3 Service & version mapping

- **Objective / hypothesis:** Turn open ports into named, versioned services for targeted exploitation.
- **Procedure:**
  ```bash
  cd "$OUT/ports"
  # Build ip:port list, then nmap -sV with safe scripts
  awk -F: '{print $1}' naabu-web-admin.txt | sort -u > nmap-targets.txt
  nmap -sV -sC --version-intensity 5 -iL nmap-targets.txt \
    -oA nmap-services 2>/dev/null
  # HTTP-specific NSE on web ports
  nmap -sV --script=http-title,http-headers,http-methods,http-auth \
    -p 80,443,8080,8443 -iL nmap-targets.txt -oA nmap-http 2>/dev/null
  ```
- **Indicators:** Service banners with versions (e.g., `nginx 1.18`, `OpenSSH 7.4`, `Jenkins`), supported HTTP methods (PUT/DELETE), auth realms.
- **Validation:** Confirm version strings; map to known CVEs only as leads (exploitation is for the deep-dive workflows).
- **Evasion / edge cases:** Aggressive scanning trips IDS — pace it. Some services lie in banners; corroborate with behavior. Tarpits inflate scan time — set host timeouts.
- **Severity:** Version-dependent (vulnerable service = High-Critical). Business impact: pinpoints exploitable software.
- **Dispatch:** -> ReconAgent (CVE-bearing services -> W_NETWORK / ExploitDevAgent via that workflow)

**Phase artifacts:** `hosts/httpx.json`, `hosts/live-hosts.txt`, `hosts/live-ips.txt`, `hosts/body-hashes.tsv`, `ports/naabu-*.txt`, `ports/nmap-services.*`, `ports/nmap-http.*`.

**Gate-out:** Live web host list + open-port/service map exist. If no live hosts, verify connectivity, CDN/WAF blocking, and that resolution actually returned IPs.

---

## Phase 5: CONTENT & ENDPOINT DISCOVERY

**Objective:** Enumerate URLs, endpoints, parameters, directories, policy files, and API schemas across live hosts.

**Expert rationale:** Subdomains are doors; endpoints are the locks you actually pick. Historical URL mining + crawling + brute-force together produce the parameterized endpoints the injection/IDOR/SSRF hunters need. robots/sitemaps/security.txt and exposed API schemas frequently hand you the sensitive paths directly.

**Gate-in:** `live-hosts.txt` exists.

> All active — proxy everything through Burp (`-http-proxy`/`-x`/`--proxy`), browser UA. Authenticated crawl uses the harness with vault creds. Parallelizable per host with concurrency caps.

### 5.1 Historical URL mining

- **Objective / hypothesis:** Archives and indexes already hold the URL/parameter corpus; harvest it before crawling.
- **Procedure:**
  ```bash
  cd "$OUT/content"
  cat "$OUT/hosts/live-hosts.txt" | unfurl -u domains | sort -u > live-domains.txt
  # gau + waybackurls (passive corpora; aggregate, then proxy when re-fetching)
  cat live-domains.txt | gau --threads 5 2>/dev/null            > urls-gau.txt
  cat live-domains.txt | waybackurls 2>/dev/null                > urls-wayback.txt
  cat "$OUT/passive/wayback-urls.txt" urls-gau.txt urls-wayback.txt 2>/dev/null \
    | sort -u > urls-historical.txt
  ```
- **Indicators:** Parameterized endpoints (`?id=`, `?url=`, `?file=`), API paths, archived admin/debug URLs.
- **Validation:** Live-check interesting URLs via httpx through Burp before treating them as current.
- **Evasion / edge cases:** Historical URLs may 404 now but reveal the routing scheme; many old endpoints are still live pre-WAF. Filter static noise (images/fonts) to keep signal.
- **Severity:** Informational; archived endpoints seed high-severity bugs. Business impact: free endpoint + parameter corpus.
- **Dispatch:** -> ReconAgent

### 5.2 Active crawl

- **Objective / hypothesis:** Crawling discovers live, JS-rendered routes that archives miss, including post-login surface.
- **Procedure:**
  ```bash
  cd "$OUT/content"
  # Unauthenticated crawl through Burp with JS parsing
  katana -list "$OUT/hosts/live-hosts.txt" -proxy "$BURP" -H "User-Agent: $UA" \
    -jc -kf all -d 4 -c 15 -silent -o urls-katana.txt
  # Authenticated crawl of the post-login surface via the bundled harness
  # (real/headed session via dev-browser, traffic through Burp; uses vault cookie)
  bun "$TOOLS/playwright-harness.ts" --target "https://app.target.com" \
    --proxy "$BURP" --auth-cookie "$HUNT_COOKIE" --mode map-flows \
    --crawl-depth 4 --screenshots "$OUT/screenshots" --output "$OUT/content/app-profile-lowpriv.json"
  # Repeat as admin to contrast surfaces (admin-only routes)
  bun "$TOOLS/playwright-harness.ts" --target "https://app.target.com" \
    --proxy "$BURP" --auth-cookie "$ADMIN_COOKIE" --mode map-flows \
    --crawl-depth 4 --screenshots "$OUT/screenshots" --output "$OUT/content/app-profile-admin.json"
  ```
- **Indicators:** SPA routes, XHR/fetch endpoints, forms, admin-only routes present in the admin profile but absent in low-priv.
- **Validation:** Burp sitemap captures every crawled request; confirm capture with `burp-bridge --history`.
- **Evasion / edge cases:** Use the harness (real session) for JS-heavy apps — raw curl misses client-rendered routes. The low-priv vs admin diff is itself an IDOR/BFLA lead for W_API.
- **Severity:** Informational; route diffs seed access-control bugs. Business impact: the live, authenticated endpoint map.
- **Dispatch:** -> ReconAgent (authenticated route diffs -> W_API / W_WEB)

### 5.3 Policy & sitemap files

- **Objective / hypothesis:** robots/sitemap/security.txt and `.well-known` often name sensitive paths and disclose intent.
- **Procedure:**
  ```bash
  cd "$OUT/content"
  for h in $(cat "$OUT/hosts/live-hosts.txt"); do
    for p in robots.txt sitemap.xml security.txt .well-known/security.txt \
             .well-known/openid-configuration .well-known/assetlinks.json \
             .well-known/apple-app-site-association crossdomain.xml; do
      code=$(fetch -o "/tmp/pf.out" -w "%{http_code}" "$h/$p")
      [ "$code" = "200" ] && { echo "[$code] $h/$p"; cat /tmp/pf.out >> "policy-$p.dump"; }
    done
  done | tee policy-files.txt
  # Pull Disallow paths out of robots (often the juicy ones)
  grep -rhiE "Disallow|Sitemap" policy-robots.txt.dump 2>/dev/null | sort -u > robots-paths.txt
  ```
- **Indicators:** `Disallow:` paths pointing at admin/backups, OIDC config exposing endpoints/issuer, assetlinks/AASA naming mobile-linked domains.
- **Validation:** Live-check each disclosed path through Burp.
- **Evasion / edge cases:** OIDC `.well-known` reveals the full auth surface for W_API/OAuth; AASA/assetlinks tie mobile apps to web domains (hand-off to mobile).
- **Severity:** Informational; disclosed paths can lead to High. Business impact: hands you sensitive routes directly.
- **Dispatch:** -> ReconAgent (OIDC config -> W_API/OAuthAgent; app-link files -> mobile)

### 5.4 Content brute-force

- **Objective / hypothesis:** Unlinked directories/files (admin, backups, configs) exist but are not crawlable.
- **Procedure:**
  ```bash
  cd "$OUT/content"
  # Directory brute-force, proxied, auto-calibrated, recursive on smart hits
  ffuf -x "$BURP" -H "User-Agent: $UA" \
    -u "https://app.target.com/FUZZ" -w "$WL_CONTENT" \
    -mc 200,201,204,301,302,307,401,403 -ac -recursion -recursion-depth 2 \
    -o ffuf-dirs.json -of json 2>/dev/null
  # File brute-force with high-signal extensions
  ffuf -x "$BURP" -H "User-Agent: $UA" \
    -u "https://app.target.com/FUZZ" -w "$WL_FILES" \
    -e .php,.asp,.aspx,.jsp,.json,.xml,.bak,.old,.zip,.sql,.env,.config,.log,.txt,.swp \
    -mc 200,301,302,401,403 -ac -o ffuf-files.json -of json 2>/dev/null
  # feroxbuster for fast recursive coverage on priority hosts
  feroxbuster -u "https://app.target.com" --proxy "$BURP" -A \
    -w "$WL_CONTENT" -x php,html,js,json,bak,zip,env -d 2 --smart \
    -o ferox.txt 2>/dev/null
  ```
- **Indicators:** `200/403` on `admin/`, `backup.zip`, `.env`, `config.json`, `/.git/`, swap files.
- **Validation:** Confirm content (not a soft-404); `403` may be bypassable (note for W_WEB). Backup/config files with secrets -> SecretsExposureAgent.
- **Evasion / edge cases:** Auto-calibrate against soft-404s; vary case and add trailing slashes; rotate UA already browser-like; WAF rate-limits — throttle and split wordlists.
- **Severity:** Exposed backups/`.git`/`.env` are High-Critical. Business impact: direct source/secret disclosure candidates.
- **Dispatch:** -> ReconAgent; exposed VCS/backup/config -> SecretsExposureAgent

### 5.5 Parameter mining

- **Objective / hypothesis:** Hidden/undocumented parameters expand the injectable surface for every server-side hunter.
- **Procedure:**
  ```bash
  cd "$OUT/content"
  # From the URL corpus
  cat urls-historical.txt urls-katana.txt | grep "?" \
    | unfurl --unique keys 2>/dev/null | sort -u > params-from-urls.txt
  # paramspider over archives
  paramspider -d target.com 2>/dev/null | sort -u >> params-from-urls.txt
  # arjun — active hidden-parameter discovery (proxied)
  arjun -i "$OUT/hosts/live-hosts.txt" --proxy "$BURP" -oJ arjun.json 2>/dev/null
  # x8 — high-confidence brute of a key endpoint
  x8 -u "https://app.target.com/api/endpoint" -w params-from-urls.txt \
     -x "$BURP" -o x8.txt 2>/dev/null
  sort -u params-from-urls.txt -o params-from-urls.txt
  ```
- **Indicators:** Parameters that change response size/behavior or are reflected — leads for XSS/SQLi/SSRF/IDOR.
- **Validation:** A discovered param is a lead; the deep-dive workflows confirm exploitability.
- **Evasion / edge cases:** arjun/x8 baseline against the endpoint to avoid noise; some params only activate with specific values/methods.
- **Severity:** Informational; expands injectable surface. Business impact: more parameters = more bug candidates.
- **Dispatch:** -> ReconAgent (params -> W_WEB/W_API)

### 5.6 API surface discovery

- **Objective / hypothesis:** Exposed API schemas/consoles enumerate the entire API for free.
- **Procedure:**
  ```bash
  cd "$OUT/content"
  for h in $(cat "$OUT/hosts/live-hosts.txt"); do
    for p in swagger.json openapi.json swagger-ui.html api-docs v2/api-docs v3/api-docs \
             graphql graphiql v1/graphql .well-known/openapi redoc api/swagger.json; do
      code=$(fetch -o "/tmp/api.out" -w "%{http_code}" "$h/$p")
      [ "$code" = "200" ] && echo "[$code] $h/$p"
    done
  done | tee api-surface.txt
  # If GraphQL present, attempt introspection through Burp
  fetch -X POST "https://app.target.com/graphql" -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name fields{name}}}}"}' -o graphql-introspection.json
  ```
- **Indicators:** Reachable Swagger/OpenAPI JSON, GraphQL introspection returning the schema, GraphiQL console.
- **Validation:** Parse the schema into an endpoint list; confirm endpoints respond.
- **Evasion / edge cases:** Introspection may be disabled — try field suggestions / `__type` probing (hand-off to GraphQLAgent via W_API). Versioned schemas (`v1/v2/v3`) — check all.
- **Severity:** Schema exposure is Low-Medium; the enumerated API is the real prize. Business impact: full API map -> W_API.
- **Dispatch:** -> ReconAgent (schema/endpoints -> W_API / GraphQLAgent)

**Phase artifacts:** `content/urls-historical.txt`, `content/urls-katana.txt`, `content/app-profile-{lowpriv,admin}.json`, `content/policy-files.txt`, `content/robots-paths.txt`, `content/ffuf-*.json`, `content/ferox.txt`, `content/params-from-urls.txt`, `content/arjun.json`, `content/api-surface.txt`, `content/graphql-introspection.json`.

**Gate-out:** Consolidated URL/endpoint/parameter corpus + API surface exists. If thin, deepen the crawl (auth state) and JS analysis (Phase 6).

---

## Phase 6: JAVASCRIPT & CLIENT-SIDE ANALYSIS

**Objective:** Mine JavaScript for routes, API endpoints, and secrets, and reconstruct source from maps.

**Expert rationale:** Modern apps ship their entire client logic in JS — including undocumented API routes, feature flags, internal hostnames, and (carelessly) live keys. JS analysis routinely yields endpoints no crawler finds and credentials no scanner flags. Source maps hand back original source.

**Gate-in:** URL corpus exists with JS assets.

> JS collection is active (fetch the assets through Burp); analysis is local. Parallelizable.

### 6.1 JS asset collection

- **Objective / hypothesis:** Build the complete JS corpus (current + historical) before mining.
- **Procedure:**
  ```bash
  cd "$OUT/js"
  cat "$OUT/content/urls-historical.txt" "$OUT/content/urls-katana.txt" \
    | grep -iE "\.js(\?|$)" | sort -u > js-urls.txt
  # JS-focused crawl through Burp to catch dynamically loaded chunks
  katana -list "$OUT/hosts/live-hosts.txt" -proxy "$BURP" -H "User-Agent: $UA" \
    -jc -d 3 -ef css,png,jpg,gif,svg,woff,woff2,ttf -silent | grep -iE "\.js" >> js-urls.txt
  sort -u js-urls.txt -o js-urls.txt
  # Download (proxied, browser UA), content-addressed filenames
  mkdir -p files
  while read -r u; do
    fn="files/$(printf '%s' "$u" | md5sum | cut -d' ' -f1).js"
    fetch "$u" -o "$fn" 2>/dev/null
  done < js-urls.txt
  echo "[*] JS files: $(ls files | wc -l)"
  ```
- **Indicators:** Dozens-to-hundreds of bundles incl. vendor + app chunks.
- **Validation:** Non-empty, JS-content files (not 404 HTML).
- **Evasion / edge cases:** Webpack chunk-loading hides lazy bundles — the katana JS crawl forces them; include historical bundle versions (rotated keys).
- **Severity:** Informational. Business impact: the corpus for endpoint + secret mining.
- **Dispatch:** -> ReconAgent

### 6.2 JS route/endpoint mining

- **Objective / hypothesis:** JS embeds API routes and internal paths absent from the crawl.
- **Procedure:**
  ```bash
  cd "$OUT/js"
  # linkfinder per-asset
  for f in files/*.js; do python3 linkfinder.py -i "$f" -o cli 2>/dev/null; done \
    | sort -u > js-endpoints.txt
  # Raw regex sweep for API-ish paths and absolute URLs
  grep -rhoE "(https?://[a-zA-Z0-9./?=_%:-]+|/api/[a-zA-Z0-9./?=_%-]+|/v[0-9]+/[a-zA-Z0-9./?=_%-]+)" files/ \
    | sort -u >> js-endpoints.txt
  sort -u js-endpoints.txt -o js-endpoints.txt
  # Fold new internal hosts back into the surface
  grep -oE "https?://[a-zA-Z0-9.-]+" js-endpoints.txt | unfurl -u domains \
    | sort -u | inscope >> "$OUT/subdomains/all-subdomains.txt"
  sort -u "$OUT/subdomains/all-subdomains.txt" -o "$OUT/subdomains/all-subdomains.txt"
  ```
- **Indicators:** New `/api/...` routes, internal hostnames, feature-flag/admin endpoints.
- **Validation:** Live-check new endpoints/hosts through Burp; new hosts re-enter Phase 4.
- **Evasion / edge cases:** Beautify minified JS first for better regex hits; relative paths need a base URL to resolve.
- **Severity:** Informational; new endpoints seed bugs. Business impact: endpoints no crawler finds.
- **Dispatch:** -> ReconAgent (endpoints -> W_WEB/W_API)

### 6.3 JS secret mining

- **Objective / hypothesis:** Bundles leak live API keys, tokens, and cloud credentials.
- **Procedure:**
  ```bash
  cd "$OUT/js"
  # secretfinder + trufflehog + nuclei exposure templates
  for f in files/*.js; do python3 SecretFinder.py -i "$f" -o cli 2>/dev/null; done \
    | sort -u > js-secrets-raw.txt
  trufflehog filesystem files/ --json 2>/dev/null > trufflehog-js.json
  nuclei -l js-urls.txt -http-proxy "$BURP" -H "User-Agent: $UA" \
    -t http/exposures/ -t http/exposures/tokens/ -silent -o nuclei-js-exposures.txt
  # High-signal key patterns
  grep -rhoE "AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]+|sk_live_[0-9a-zA-Z]{24,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\." files/ \
    | sort -u > js-keys.txt
  ```
- **Indicators:** AWS keys, Google API keys, GitHub PATs, Slack/Stripe tokens, JWTs, Firebase configs.
- **Validation:** A string is NOT a finding — SecretsExposureAgent must authenticate each key against its provider. Unverified keys are dropped.
- **Evasion / edge cases:** Public/anon keys (Firebase web config, Stripe publishable) are usually noise — check scope/privilege. Rotated-but-live keys hide in historical bundles (compare versions).
- **Severity:** Validated live cloud creds = Critical (CVSS ~9.8). Business impact: potential account/cloud compromise.
- **Dispatch:** -> SecretsExposureAgent (validate + escalate)

### 6.4 Source-map reconstruction

- **Objective / hypothesis:** A reachable `.js.map` reconstructs original source — comments, internal endpoints, and keys the minifier hid.
- **Procedure:**
  ```bash
  cd "$OUT/js"
  for u in $(cat js-urls.txt); do
    fetch -o /dev/null -w "%{http_code} ${u}.map\n" "${u}.map"
  done | grep "^200" | awk '{print $2}' > js-maps.txt
  while read -r m; do
    npx sourcemapper -url "$m" -output "srcmap/$(echo "$m" | md5sum | cut -d' ' -f1)" 2>/dev/null
  done < js-maps.txt
  grep -rEn "apiKey|secret|token|/api/|/internal/|Authorization|password" srcmap/ 2>/dev/null \
    | sort -u > srcmap-findings.txt
  ```
- **Indicators:** `.map` returns 200; reconstructed tree exposes endpoints/comments/keys.
- **Validation:** Re-feed reconstructed source for endpoint mining; secrets -> SecretsExposureAgent for validation.
- **Evasion / edge cases:** Maps may be at a different path or inline (`//# sourceMappingURL=data:`); some are behind auth — fetch with the vault cookie.
- **Severity:** Source disclosure Medium; embedded live keys escalate to Critical. Business impact: full client source + hidden secrets.
- **Dispatch:** -> SecretsExposureAgent (source -> feeds W_WEB review)

**Phase artifacts:** `js/js-urls.txt`, `js/files/*.js`, `js/js-endpoints.txt`, `js/js-secrets-raw.txt`, `js/trufflehog-js.json`, `js/nuclei-js-exposures.txt`, `js/js-keys.txt`, `js/js-maps.txt`, `js/srcmap/`, `js/srcmap-findings.txt`.

**Gate-out:** JS endpoints folded into the surface; candidate secrets queued for SecretsExposureAgent validation.

---

## Phase 7: TECHNOLOGY FINGERPRINTING & CMS

**Objective:** Identify frameworks, languages, servers, CDNs/WAFs, and CMS platforms per host.

**Expert rationale:** Tech identity routes the deep-dive workflows: a Spring app gets actuator probing, WordPress gets wpscan, a known-version component gets a CVE check. Fingerprinting converts a flat host list into a prioritized, technology-targeted plan.

**Gate-in:** `live-hosts.txt` exists.

> Active — proxy + browser UA. Parallelizable.

### 7.1 Technology detection

- **Objective / hypothesis:** Per-host tech stacks reveal the framework/server and seed CVE leads.
- **Procedure:**
  ```bash
  cd "$OUT/tech"
  whatweb -i "$OUT/hosts/live-hosts.txt" --log-json whatweb.json -a 3 \
    --user-agent "$UA" 2>/dev/null
  # httpx tech + nuclei tech/CVE templates, proxied
  httpx -l "$OUT/hosts/live-hosts.txt" -http-proxy "$BURP" -H "User-Agent: $UA" \
    -tech-detect -json -o httpx-tech.json
  nuclei -l "$OUT/hosts/live-hosts.txt" -http-proxy "$BURP" -H "User-Agent: $UA" \
    -t http/technologies/ -silent -o nuclei-tech.txt
  # Aggregate a stack frequency table to prioritize
  jq -r '.tech[]?' httpx-tech.json 2>/dev/null | sort | uniq -c | sort -rn > tech-summary.txt
  ```
- **Indicators:** Named frameworks/servers/versions; CDN/WAF identity; clustering of a shared stack across hosts.
- **Validation:** Corroborate via headers + error pages; treat versions as CVE leads.
- **Evasion / edge cases:** CDN/WAF masks origin tech — confirm against origin IPs (Phase 0/4). `X-Powered-By` is often stripped; fingerprint via error pages, cookies, and default paths.
- **Severity:** Informational; vulnerable versions escalate. Business impact: routes targeted testing.
- **Dispatch:** -> ReconAgent

### 7.2 CMS identification & enumeration

- **Objective / hypothesis:** CMS platforms have known plugin/theme attack surface and dedicated scanners.
- **Procedure:**
  ```bash
  cd "$OUT/tech"
  # Detect CMS hosts from tech summary, then targeted scans (proxied)
  wpscan --url https://blog.target.com --enumerate vp,vt,u,dbe \
    --proxy "$BURP" --user-agent "$UA" --api-token <WPSCAN_TOKEN> \
    -f json -o wpscan.json 2>/dev/null
  droopescan scan drupal -u https://cms.target.com 2>/dev/null > droopescan.txt
  joomscan -u https://portal.target.com 2>/dev/null > joomscan.txt
  ```
- **Indicators:** CMS version, vulnerable plugins/themes, enumerated users, exposed `wp-config` backups.
- **Validation:** Confirm plugin/version presence directly; user enumeration via login/REST.
- **Evasion / edge cases:** Throttle wpscan to dodge bans; the WordPress REST API (`/wp-json/wp/v2/users`) enumerates users even when XML-RPC is closed.
- **Severity:** Vulnerable plugin = High-Critical. Business impact: CMS plugins are a top real-world entry point.
- **Dispatch:** -> ReconAgent (CMS bugs -> W_WEB)

### 7.3 Framework debug & default-path probing

- **Objective / hypothesis:** Frameworks expose default debug/admin paths that confirm the stack and often leak data.
- **Procedure:**
  ```bash
  cd "$OUT/tech"
  for h in $(cat "$OUT/hosts/live-hosts.txt"); do
    for p in actuator actuator/env actuator/health _profiler/phpinfo elmah.axd \
             rails/info/routes telescope/requests _ignition/health-check \
             swagger-ui.html graphql server-status phpinfo.php; do
      code=$(fetch -o /dev/null -w "%{http_code}" "$h/$p")
      [ "$code" = "200" ] && echo "[$code] $h/$p"
    done
  done | tee framework-paths.txt
  ```
- **Indicators:** `200` on Spring `/actuator/*`, Laravel `/telescope`/`/_ignition`, Rails `/rails/info`, `phpinfo`, ELMAH.
- **Validation:** Confirm content (actual env/debug data), then hand to SecretsExposureAgent for exploitation (heapdump/env mining).
- **Evasion / edge cases:** Actuator may be under a base path or alt port; `/_ignition` is CVE-2021-3129 RCE territory — flag, do not exploit here.
- **Severity:** Exposed actuator/env/heapdump = High-Critical. Business impact: direct creds/source/RCE leads.
- **Dispatch:** -> SecretsExposureAgent

**Phase artifacts:** `tech/whatweb.json`, `tech/httpx-tech.json`, `tech/nuclei-tech.txt`, `tech/tech-summary.txt`, `tech/wpscan.json`, `tech/droopescan.txt`, `tech/joomscan.txt`, `tech/framework-paths.txt`.

**Gate-out:** Per-host tech identity + CMS map + debug-path hits exist, ready to route deep-dive testing.

---

## Phase 8: CLOUD & THIRD-PARTY / SaaS ASSET DISCOVERY

**Objective:** Find cloud storage buckets, cloud-hosted app domains, and third-party/SaaS assets the org depends on.

**Expert rationale:** Orgs sprawl across S3/GCS/Azure buckets, serverless app domains, and dozens of SaaS vendors. Public buckets leak data directly; cloud app domains and SaaS subdomains are takeover and misconfig candidates. This surface is invisible to classic subdomain enum yet routinely holds the worst exposures.

**Gate-in:** Root graph + CNAME map + SPF includes exist (Phases 0/1/3).

> Bucket probing touches cloud endpoints (use UA; proxy optional). SaaS footprinting is mostly passive. Parallelizable.

### 8.1 Cloud bucket enumeration

- **Objective / hypothesis:** Predictably-named buckets across providers are public or listable.
- **Procedure:**
  ```bash
  cd "$OUT/cloud"
  # Generate candidate bucket names from org/brand tokens
  BASE="${TARGET%%.*}"
  for n in "$BASE" "$BASE-dev" "$BASE-staging" "$BASE-prod" "$BASE-backup" "$BASE-assets" \
           "$BASE-media" "$BASE-data" "$BASE-uploads" "$BASE-logs" "backup-$BASE" "dev-$BASE"; do
    echo "$n"
  done | sort -u > bucket-candidates.txt
  # cloud_enum across AWS/Azure/GCP
  cloud_enum -k "$BASE" -k "$ORG" -l cloud-enum.txt 2>/dev/null
  # s3scanner over candidates
  s3scanner scan -f bucket-candidates.txt 2>/dev/null | tee s3scanner.txt
  # Direct probes (browser UA)
  while read -r n; do
    pfetch "https://$n.s3.amazonaws.com/"            | grep -q "ListBucketResult" && echo "PUBLIC S3: $n"
    pfetch "https://storage.googleapis.com/$n/"      | grep -q "<Contents>"       && echo "PUBLIC GCS: $n"
    pfetch "https://$n.blob.core.windows.net/?comp=list" | grep -q "EnumerationResults" && echo "PUBLIC AZURE: $n"
  done < bucket-candidates.txt | tee buckets-public.txt
  ```
- **Indicators:** `ListBucketResult`/`<Contents>`/`EnumerationResults` (listable), or accessible objects.
- **Validation:** List, then sample-read an object to confirm sensitivity; SecretsExposureAgent validates any creds found.
- **Evasion / edge cases:** Region-specific S3 endpoints; some buckets deny LIST but allow GET of known keys (try keys from JS/source); writable buckets are Critical.
- **Severity:** Public sensitive bucket = High-Critical (CVSS ~7–9.8). Business impact: direct data exposure / asset tampering.
- **Dispatch:** -> ReconAgent; bucket contents/creds -> SecretsExposureAgent; cloud config -> W_CLOUD

### 8.2 Cloud-hosted app discovery

- **Objective / hypothesis:** Serverless/PaaS app domains (azurewebsites, herokuapp, *.web.app, *.run.app) belong to the org and are takeover/misconfig candidates.
- **Procedure:**
  ```bash
  cd "$OUT/cloud"
  # From CNAME map, extract cloud app endpoints
  grep -iE "azurewebsites\.net|herokuapp\.com|web\.app|firebaseapp\.com|run\.app|amplifyapp\.com|pages\.dev|netlify\.app|vercel\.app|cloudfront\.net" \
    "$OUT/dns/cname-map.txt" | sort -u > cloud-app-domains.txt
  # Firebase DB open-read check
  for fb in $(grep -oE "[a-z0-9-]+\.firebaseio\.com" "$OUT/js/files/"*.js 2>/dev/null | sort -u); do
    pfetch "https://$fb/.json" | head -c 200 | grep -qv "Permission denied" && echo "OPEN FIREBASE: $fb"
  done | tee firebase-open.txt
  ```
- **Indicators:** CNAMEs to PaaS providers; Firebase `/.json` returning data (open DB).
- **Validation:** Confirm ownership (in-scope) and whether the endpoint is misconfigured/claimable (claimable -> Phase 9).
- **Evasion / edge cases:** Some PaaS endpoints are shared — confirm tenancy; open Firebase is a direct data leak.
- **Severity:** Open Firebase/misconfig = High-Critical. Business impact: data exposure; takeover candidates.
- **Dispatch:** -> ReconAgent; claimable -> SubdomainTakeoverAgent; misconfig -> W_CLOUD

### 8.3 Third-party / SaaS footprinting

- **Objective / hypothesis:** Vendor-hosted subdomains (Zendesk, Atlassian, Slack, statuspage) are part of the org's surface and have their own misconfig/takeover risks.
- **Procedure:**
  ```bash
  cd "$OUT/cloud"
  # SaaS CNAME signatures
  grep -iE "zendesk\.com|atlassian\.net|statuspage\.io|myshopify\.com|github\.io|gitbook\.io|readme\.io|helpscout|freshdesk|intercom|discourse|wpengine|pantheonsite\.io|surge\.sh|bigcartel" \
    "$OUT/dns/cname-map.txt" | sort -u > saas-footprint.txt
  # SPF includes reveal mail/SaaS senders
  grep -oE "include:[a-zA-Z0-9._-]+" "$OUT/dns/mail-dnssec.txt" | sort -u >> saas-footprint.txt
  # BuiltWith history corroboration
  jq -r '.. | .Name? // empty' "$OUT/passive/builtwith.json" 2>/dev/null | sort -u > saas-builtwith.txt
  ```
- **Indicators:** Subdomains delegated to SaaS vendors; SPF includes naming senders; BuiltWith vendor list.
- **Validation:** Each SaaS subdomain is a takeover candidate (Phase 9) and an OAuth/SSO trust to map (W_API).
- **Evasion / edge cases:** SaaS tenants with default/guest access (open Atlassian, public Zendesk admin) are real findings; SSO trust to a SaaS expands the auth surface.
- **Severity:** Misconfigured SaaS tenant = Medium-High; takeover = High. Business impact: third-party trust and data exposure.
- **Dispatch:** -> ReconAgent; takeover-prone -> SubdomainTakeoverAgent

**Phase artifacts:** `cloud/bucket-candidates.txt`, `cloud/buckets-public.txt`, `cloud/cloud-enum.txt`, `cloud/s3scanner.txt`, `cloud/cloud-app-domains.txt`, `cloud/firebase-open.txt`, `cloud/saas-footprint.txt`, `cloud/saas-builtwith.txt`.

**Gate-out:** Cloud + SaaS asset map exists; public buckets and open cloud apps flagged; SaaS subdomains queued for takeover assessment.

---

## Phase 9: SUBDOMAIN TAKEOVER & DANGLING DNS

**Objective:** Identify subdomains whose DNS points to deprovisioned/claimable services (CNAME/A/NS/MX) — confirm claimability without claiming.

**Expert rationale:** Dangling records are high-impact, low-effort wins. A taken-over subdomain inside parent cookie scope or CSP yields cookie theft, CSP-bypass XSS, or OAuth-redirect hijack. NS/MX takeover escalates to full DNS/email control. This phase consumes the CNAME map + SaaS footprint from earlier phases.

**Gate-in:** `dns/cname-map.txt`, `cloud/saas-footprint.txt`, and `all-subdomains.txt` exist.

> Active fingerprinting touches target subdomains (browser UA; proxy optional for evidence). This is the SubdomainTakeoverAgent's core surface. Parallelizable.

### 9.1 Automated takeover scanning

- **Objective / hypothesis:** Known service signatures expose claimable dangling subdomains at scale.
- **Procedure:**
  ```bash
  cd "$OUT/takeover"
  subjack -w "$OUT/subdomains/all-subdomains.txt" -t 100 -timeout 30 -ssl -v -o subjack.txt 2>/dev/null
  nuclei -l "$OUT/subdomains/all-subdomains.txt" -H "User-Agent: $UA" \
    -t http/takeovers/ -silent -o nuclei-takeover.txt
  dnsreaper file --filename "$OUT/subdomains/all-subdomains.txt" --out dnsreaper.json 2>/dev/null
  subzy run --targets "$OUT/subdomains/all-subdomains.txt" --output subzy.txt 2>/dev/null
  ```
- **Indicators:** Tool flags a claimable service + matching error fingerprint (e.g., "There isn't a GitHub Pages site here", "NoSuchBucket").
- **Validation:** Cross-confirm with a manual fingerprint (9.2); scanners produce false positives.
- **Evasion / edge cases:** Wildcard DNS causes false positives — confirm the specific dangling record; multiple tools reduce misses (each covers different services).
- **Severity:** Confirmed takeover High-Critical (CVSS ~7–9.5). Business impact: phishing, cookie/CSP/OAuth abuse.
- **Dispatch:** -> SubdomainTakeoverAgent

### 9.2 Dangling CNAME / A confirmation

- **Objective / hypothesis:** A CNAME/A to a service that returns NXDOMAIN or a "not configured" page is claimable.
- **Procedure:**
  ```bash
  cd "$OUT/takeover"
  # Dangling CNAME (target of CNAME does not resolve)
  while read -r line; do
    sub="${line%% ->*}"; cname="${line##*-> }"
    [ -n "$cname" ] && [ -z "$(dig +short "$cname" 2>/dev/null)" ] \
      && echo "[DANGLING-CNAME] $sub -> $cname (NXDOMAIN)"
  done < "$OUT/dns/cname-map.txt" | tee dangling-cnames.txt
  # Service-error fingerprints on live subdomains
  while read -r sub; do
    body=$(pfetch "http://$sub" | head -c 4000)
    echo "$body" | grep -qiE "NoSuchBucket|There isn't a GitHub Pages|No such app|Fastly error: unknown domain|project not found|Repository not found|Sorry, this shop is currently unavailable|The thing you were looking for is no longer here|Do you want to register" \
      && echo "[TAKEOVER-CANDIDATE] $sub"
  done < "$OUT/subdomains/all-subdomains.txt" | tee takeover-fingerprints.txt
  ```
- **Indicators:** CNAME resolving to a provider with no backing resource; service-specific "claim me" error body.
- **Validation:** Verify claimability per provider WITHOUT claiming (e.g., S3 `aws s3 ls s3://BUCKET` returns `NoSuchBucket`; GitHub Pages repo unconfigured). Document, never claim.
- **Evasion / edge cases:** CNAME chains — any claimable link is a takeover; some providers need a specific region/name available; check can-i-take-over-xyz for current claimability.
- **Severity:** High-Critical; impact depends on cookie/CSP/OAuth scope (assessed by the agent). Business impact: subdomain control.
- **Dispatch:** -> SubdomainTakeoverAgent

### 9.3 NS / MX delegation takeover

- **Objective / hypothesis:** Dangling NS (full DNS control) or MX (email interception) on an expired/claimable domain is the most severe takeover.
- **Procedure:**
  ```bash
  cd "$OUT/takeover"
  for sub in $(cat "$OUT/subdomains/all-subdomains.txt"); do
    for ns in $(dig +short NS "$sub" 2>/dev/null); do
      whois "$ns" 2>/dev/null | grep -qiE "no match|not found|is available|no entries" \
        && echo "[NS-TAKEOVER] $sub -> $ns (registrable)"
    done
  done | tee ns-takeover.txt
  for root in $(cat "$OUT/scope/seed-roots.txt"); do
    for mx in $(dig +short MX "$root" | awk '{print $2}'); do
      whois "${mx%.}" 2>/dev/null | grep -qiE "no match|not found|is available" \
        && echo "[MX-TAKEOVER] $root -> $mx (registrable)"
    done
  done | tee -a ns-takeover.txt
  ```
- **Indicators:** NS/MX target on a domain that WHOIS reports as unregistered/available.
- **Validation:** Confirm the target domain is genuinely registrable (registrar lookup); do NOT register it.
- **Evasion / edge cases:** Some NS appear available but are reserved/premium; confirm before reporting. NS takeover = full subtree DNS control (highest severity).
- **Severity:** NS takeover ~9.5; MX takeover ~7–8. Business impact: full DNS/email control of the subtree.
- **Dispatch:** -> SubdomainTakeoverAgent

**Phase artifacts:** `takeover/subjack.txt`, `takeover/nuclei-takeover.txt`, `takeover/dnsreaper.json`, `takeover/subzy.txt`, `takeover/dangling-cnames.txt`, `takeover/takeover-fingerprints.txt`, `takeover/ns-takeover.txt`.

**Gate-out:** All takeover candidates confirmed-or-dropped by fingerprint; confirmed candidates handed to SubdomainTakeoverAgent for impact assessment (cookie/CSP/OAuth scope) and reporting.

---

## Phase 10: CODE & LEAK RECON

**Objective:** Find leaked source, credentials, and sensitive data in public code platforms, paste sites, and breach corpora; gather employee/email OSINT to seed network engagements.

**Expert rationale:** Developers leak. Public repos, gists, CI configs, and pastes routinely contain live keys, internal hostnames, and DB strings. A single valid CI/cloud token can outweigh the entire web surface. Employee email lists seed credential-spray for W_NETWORK.

**Gate-in:** Org name, GitHub org handle, and root graph known.

> Mostly passive (third-party platforms — `pfetch`/APIs, not proxied). Validation of any live secret is the SecretsExposureAgent's job. Parallelizable.

### 10.1 Code-platform dorking

- **Objective / hypothesis:** The org's GitHub/GitLab/Bitbucket presence (and employees') leaks secrets and internal code.
- **Procedure:**
  ```bash
  cd "$OUT/leaks"
  # Enumerate org repos + members (requires GITHUB_TOKEN)
  pfetch -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/orgs/<ORG>/repos?per_page=100&type=all" | jq -r '.[].full_name' > gh-repos.txt
  pfetch -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/orgs/<ORG>/members" | jq -r '.[].login' > gh-members.txt
  # Code search dorks
  for q in "org:<ORG>+password" "org:<ORG>+filename:.env" "org:<ORG>+extension:pem" \
           "org:<ORG>+AWS_ACCESS_KEY_ID" "org:<ORG>+jdbc:mysql" "\"target.com\"+api_key"; do
    pfetch -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/search/code?q=$q" | jq -r '.items[]? | "\(.repository.full_name)  \(.path)"'
  done | sort -u | tee gh-dorks.txt
  # gitdorker for breadth
  python3 gitdorker.py -t "$GITHUB_TOKEN" -d dorks/alldorks.txt -q target.com -o gitdorker.txt 2>/dev/null
  ```
- **Indicators:** Repos/paths matching credential dorks; org/employee repos referencing internal infra.
- **Validation:** Each hit reviewed; secrets handed to SecretsExposureAgent to authenticate.
- **Evasion / edge cases:** Search forks and employee personal repos (members list), not just the org; deleted-but-cached commits still leak (clone full history).
- **Severity:** Validated leaked creds = Critical. Business impact: source/secret exposure, potential CI/cloud compromise.
- **Dispatch:** -> SecretsExposureAgent

### 10.2 Repo secret scanning

- **Objective / hypothesis:** Full-history scans of public repos surface secrets that grep on HEAD misses.
- **Procedure:**
  ```bash
  cd "$OUT/leaks"
  # Whole-org scan
  trufflehog github --org=<ORG> --json 2>/dev/null > trufflehog-org.json
  # Per-repo deep history scan (clone + gitleaks)
  while read -r repo; do
    git clone --quiet "https://github.com/$repo" "/tmp/$(basename "$repo")" 2>/dev/null
    gitleaks detect --source "/tmp/$(basename "$repo")" --report-format json \
      --report-path "gitleaks-$(basename "$repo").json" --no-banner 2>/dev/null
  done < gh-repos.txt
  ```
- **Indicators:** trufflehog/gitleaks flag verified or high-entropy secrets in commit history.
- **Validation:** trufflehog `--only-verified` and SecretsExposureAgent provider checks confirm liveness.
- **Evasion / edge cases:** Secrets removed in later commits persist in history — scan all refs; CI YAML (`.github/workflows`) leaks tokens/registry creds.
- **Severity:** Validated live secret = Critical. Business impact: direct compromise vector.
- **Dispatch:** -> SecretsExposureAgent

### 10.3 Paste, breach & people OSINT

- **Objective / hypothesis:** Paste sites, breach corpora, and employee email lists seed credential attacks and reveal internal naming.
- **Procedure:**
  ```bash
  cd "$OUT/leaks"
  # Paste-site search
  pfetch "https://psbdmp.ws/api/search/target.com" | jq -r '.data[]?.id' > pastes.txt
  # Email harvesting for spray seeds (hand-off to W_NETWORK)
  theHarvester -d target.com -b all -f theharvester.json 2>/dev/null
  jq -r '.emails[]?' theharvester.json 2>/dev/null | sort -u > emails.txt
  # Breach exposure check (HIBP API for org domain)
  pfetch -H "hibp-api-key: <HIBP_KEY>" \
    "https://haveibeenpwned.com/api/v3/breaches?domain=target.com" | jq '.[].Name' > breaches.txt
  ```
- **Indicators:** Pastes referencing the org; harvested employee emails; domain appearing in known breaches.
- **Validation:** Treat breach creds as spray candidates for W_NETWORK (never reuse without authorization); confirm email format.
- **Evasion / edge cases:** Email naming convention (`first.last@`) inferred from harvested set fuels username enumeration; some breach data is stale.
- **Severity:** Informational here; seeds High via spray. Business impact: credential-attack groundwork for network/AD.
- **Dispatch:** -> ReconAgent (emails/creds -> W_NETWORK); leaked secrets -> SecretsExposureAgent

**Phase artifacts:** `leaks/gh-repos.txt`, `leaks/gh-members.txt`, `leaks/gh-dorks.txt`, `leaks/gitdorker.txt`, `leaks/trufflehog-org.json`, `leaks/gitleaks-*.json`, `leaks/pastes.txt`, `leaks/emails.txt`, `leaks/breaches.txt`.

**Gate-out:** Code/leak corpus collected; candidate secrets queued for SecretsExposureAgent; email/spray seeds queued for W_NETWORK.

---

## Phase 11: VISUAL RECON & ATTACK-SURFACE PRIORITIZATION

**Objective:** Screenshot the live surface for rapid triage, then score and rank every asset into a prioritized target list.

**Expert rationale:** At scale, the eye triages faster than any tool — a screenshot grid instantly surfaces login portals, admin panels, default installs, error pages, and dev environments. Prioritization is the deliverable's whole value: a ranked list tells the deep-dive workflows exactly where to spend effort and why.

**Gate-in:** `live-hosts.txt` and per-host metadata (status/title/tech) exist.

> Screenshots touch the target (browser UA). Prioritization is local. Parallelizable.

### 11.1 Screenshot gallery

- **Objective / hypothesis:** Visual triage clusters the surface and surfaces obvious high-value targets.
- **Procedure:**
  ```bash
  cd "$OUT/screenshots"
  gowitness scan file -f "$OUT/hosts/live-hosts.txt" --threads 10 \
    --screenshot-path . --user-agent "$UA" 2>/dev/null
  # Fallback / supplement
  cat "$OUT/hosts/live-hosts.txt" | aquatone -out aquatone -threads 5 \
    -screenshot-timeout 30000 2>/dev/null
  # For auth-gated apps, the harness captures post-login state through Burp
  bun "$TOOLS/playwright-harness.ts" --target "https://app.target.com" \
    --proxy "$BURP" --auth-cookie "$HUNT_COOKIE" --mode test \
    --screenshots "$OUT/screenshots" --output /tmp/recon-shots.json 2>/dev/null
  ```
- **Indicators:** Login portals, admin/dashboard UIs, default/install pages, stack traces, "it works" defaults, dev/staging banners.
- **Validation:** Eyeball the grid; tag each host with a visual category for scoring.
- **Evasion / edge cases:** Auth-gated apps need the harness session for meaningful shots; many `403`/blank shots still matter (path-gated apps).
- **Severity:** Informational; accelerates targeting. Business impact: fast human triage of large surfaces.
- **Dispatch:** -> ReconAgent

### 11.2 Attack-surface scoring & prioritization

- **Objective / hypothesis:** A weighted score ranks assets by likelihood of holding a bug, so deep-dive effort is spent where it pays.
- **Procedure:**
  ```bash
  cd "$OUT/reports"
  # Score each live host: env (dev/stg/internal), function (admin/api/login),
  # tech risk (known-vuln stack), exposure (open non-web ports), and recency.
  jq -r '
    .url as $u
    | ([.url, (.title//""), ((.tech//[])|join(","))] | join(" ")) as $blob
    | ( (if ($blob|test("dev|stg|stag|test|internal|uat|qa";"i")) then 30 else 0 end)
      + (if ($blob|test("admin|dashboard|portal|console|manage";"i")) then 25 else 0 end)
      + (if ($blob|test("api|graphql|swagger|v[0-9]";"i")) then 20 else 0 end)
      + (if ($blob|test("login|sso|oauth|auth";"i")) then 15 else 0 end)
      + (if ((.status_code//0)==200) then 10 else 0 end) ) as $score
    | [$score, $u, (.title//""|gsub("[\\t\\n]";" "))] | @tsv
  ' "$OUT/hosts/httpx.json" | sort -rn > priority-scored.tsv

  # Boost hosts with exposed admin/data ports
  awk -F'\t' 'NR==FNR{p[$1]=1; next}{split($2,a,"//"); split(a[2],b,"/"); print ($0 (b[1] in p ? "\tOPEN-PORT" : ""))}' \
    <(awk -F: '{print $1}' "$OUT/ports/naabu-web-admin.txt" 2>/dev/null) priority-scored.tsv \
    > priority-final.tsv
  head -40 priority-final.tsv | tee high-priority-targets.txt
  ```
- **Indicators:** Top of the list = dev/admin/API/login hosts on vulnerable stacks with extra open ports.
- **Validation:** Spot-check the top entries against screenshots; adjust weights if a class is mis-ranked.
- **Evasion / edge cases:** Score is a heuristic — manually promote any host with a known-vuln version or exposed datastore regardless of score.
- **Severity:** N/A. Business impact: directs the entire downstream effort to the highest-yield assets.
- **Dispatch:** -> ReconAgent

**Phase artifacts:** `screenshots/` (gallery), `reports/priority-scored.tsv`, `reports/priority-final.tsv`, `reports/high-priority-targets.txt`.

**Gate-out:** Every live asset is categorized and ranked; the prioritized target list exists and is ready for normalization + hand-off.

---

## Phase 12: REPORTING & HAND-OFF

**Objective:** Normalize all phase outputs into one deduplicated attack-surface inventory, route findings through ValidatorAgent then ExploitChainAgent, and emit explicit per-workflow hand-off notes plus a concise N-point summary.

**Expert rationale:** Recon's value is realized only when it is consumable. A normalized inventory + targeted hand-off lets each deep-dive workflow start at the right asset immediately, and the Validator/Chain pass ensures any findings recon itself produced (takeovers, live secrets, exposed services) are reproduced, de-duped, scored, and correlated before reporting.

**Gate-in:** All prior phases complete; artifacts present in `$OUT`.

### 12.1 Inventory normalization & dedup

- **Objective / hypothesis:** Collapse all sources into one canonical, deduped, scope-filtered inventory keyed per asset.
- **Procedure:**
  ```bash
  cd "$OUT/reports"
  jq -s '
    {
      generated: (now|todate),
      target: "'"$TARGET"'",
      roots: '"$(jq -R . "$OUT/scope/seed-roots.txt" | jq -s .)"',
      counts: {
        subdomains: ('"$(wc -l < "$OUT/subdomains/all-subdomains.txt")"'),
        live_hosts: ('"$(wc -l < "$OUT/hosts/live-hosts.txt")"'),
        urls:       ('"$(cat "$OUT/content/urls-historical.txt" "$OUT/content/urls-katana.txt" 2>/dev/null | sort -u | wc -l)"'),
        js_files:   ('"$(ls "$OUT/js/files" 2>/dev/null | wc -l)"'),
        params:     ('"$(wc -l < "$OUT/content/params-from-urls.txt" 2>/dev/null || echo 0)"'),
        takeovers:  ('"$(cat "$OUT/takeover/takeover-fingerprints.txt" "$OUT/takeover/ns-takeover.txt" 2>/dev/null | wc -l)"'),
        buckets:    ('"$(wc -l < "$OUT/cloud/buckets-public.txt" 2>/dev/null || echo 0)"')
      }
    }' <<< '{}' > attack-surface-inventory.json
  cat attack-surface-inventory.json
  ```
- **Indicators:** A single inventory JSON with trustworthy per-class counts.
- **Validation:** Counts reconcile against the per-phase artifacts.
- **Severity:** N/A. Business impact: the canonical deliverable.
- **Dispatch:** -> ReconAgent

### 12.2 Findings hand-off — ValidatorAgent then ExploitChainAgent

- **Objective / hypothesis:** Recon-produced findings (takeovers, validated secrets, exposed services/buckets) must be reproduced, de-duped by root cause, scored (CVSS 3.1/4.0), gated by hunt mode, then correlated into kill chains.
- **Procedure:**
  ```bash
  # Aggregate recon findings onto the shared findings bus the agents consume
  cp "$OUT"/takeover/*.txt "$OUT"/cloud/buckets-public.txt /tmp/ 2>/dev/null
  cat "$OUT/takeover/takeover-fingerprints.txt" 2>/dev/null \
    | jq -R '{type:"SUBDOMAIN_TAKEOVER", subtype:"cname_dangling", endpoint:., confirmed:false, agent:"SubdomainTakeoverAgent"}' \
    | jq -s . > /tmp/bb-findings-recon.json
  # Then dispatch the agent pass (recon engagement META):
  #   ValidatorAgent  -> reproduce, kill false positives, de-dup by root cause,
  #                      score CVSS 3.1/4.0, apply hunt-mode gate -> /tmp/bb-findings-validator.json
  #   ExploitChainAgent -> correlate validated findings into MITRE ATT&CK kill chains,
  #                      elevate combined CVSS -> /tmp/bb-findings-chains.json
  bun "$TOOLS/agent-router.ts" --engagement recon
  ```
- **Indicators:** `agent-router --engagement recon` resolves to `DISCOVER[ReconAgent, SubdomainTakeoverAgent] -> EXPOSURE[SecretsExposureAgent] -> VALIDATE[ValidatorAgent] -> CHAIN[ExploitChainAgent]`.
- **Validation:** ValidatorAgent emits only reproduced, in-scope, scored findings; ExploitChainAgent emits only chains with proven transitions to a crown jewel.
- **Severity:** Per validated finding (takeover/secret/bucket commonly High-Critical). Business impact: only true, prioritized findings reach the report.
- **Dispatch:** -> ValidatorAgent -> ExploitChainAgent

### 12.3 Per-workflow hand-off notes

- **Objective / hypothesis:** Each deep-dive workflow should start at the exact assets recon found most promising for its class.
- **Procedure:**
  ```bash
  cd "$OUT/reports"
  cat > handoff-notes.md <<'EOF'
# Recon Hand-off — target.com

## -> W_WEB (web app pentest)
- Top web targets: see high-priority-targets.txt (admin/login/dashboard hosts).
- Params for injection/XSS/IDOR: content/params-from-urls.txt, content/arjun.json.
- JS-discovered routes: js/js-endpoints.txt. Exposed debug paths: tech/framework-paths.txt.
- Exposed VCS/backup/config from content brute-force -> already queued to SecretsExposureAgent.

## -> W_API (API security)
- API schemas/consoles: content/api-surface.txt, content/graphql-introspection.json.
- Authenticated route diff (admin vs low-priv): content/app-profile-admin.json vs app-profile-lowpriv.json (BFLA/IDOR leads).
- OIDC config: content/policy-.well-known-openid-configuration.dump (auth surface).

## -> W_LLM (AI/LLM)
- Chat/RAG/agent endpoints among js/js-endpoints.txt and content/api-surface.txt (filter for chat|completion|assistant|rag|agent).
- Any tool-calling/file-upload surface flagged in app profiles.

## -> W_NETWORK (internal / AD)
- Open non-web/admin ports + services: ports/naabu-web-admin.txt, ports/nmap-services.*.
- Email/spray seeds: leaks/emails.txt; breach exposure: leaks/breaches.txt.
- Origin IPs bypassing CDN/WAF: hosts/live-ips.txt cross-ref scope/cidrs.txt.

## -> W_CLOUD (cloud)
- Public buckets: cloud/buckets-public.txt. Open Firebase: cloud/firebase-open.txt.
- Cloud app domains: cloud/cloud-app-domains.txt. Validated cloud creds: from SecretsExposureAgent.
- SaaS trust footprint: cloud/saas-footprint.txt.

## Confirmed recon findings (already in agent pass)
- Subdomain takeovers: takeover/*.txt -> SubdomainTakeoverAgent.
- Validated secrets/exposed source: js/js-keys.txt, leaks/* -> SecretsExposureAgent.
EOF
  sed -i '' "s/target.com/$TARGET/g" handoff-notes.md 2>/dev/null || sed -i "s/target.com/$TARGET/g" handoff-notes.md
  cat handoff-notes.md
  ```
- **Indicators:** A per-workflow note pointing each consumer at concrete artifact files and the asset classes they care about.
- **Validation:** Each referenced artifact exists; each note names real downstream owners.
- **Severity:** N/A. Business impact: zero-friction continuation into the deep-dive workflows.
- **Dispatch:** -> ReconAgent (notes consumed by W_WEB/W_API/W_LLM/W_NETWORK/W_CLOUD)

### 12.4 Concise N-point update (new tests performed)

- **Objective / hypothesis:** Produce a short, scannable summary of what recon actually did and found, for the operator/report.
- **Procedure:**
  ```bash
  cd "$OUT/reports"
  cat > recon-summary.md <<EOF
# Recon Summary — $TARGET ($(date +%F))

1. Seed expansion: $(wc -l < "$OUT/scope/seed-roots.txt") roots, $(wc -l < "$OUT/scope/asns.txt" 2>/dev/null || echo 0) ASNs, acquisitions + reverse-whois confirmed in scope.
2. Subdomains: $(wc -l < "$OUT/subdomains/all-subdomains.txt") canonical in-scope (passive + brute + permutation + vhost).
3. DNS intel: records captured; AXFR attempted on all NS; SPF/DKIM/DMARC/DNSSEC posture assessed.
4. Live surface: $(wc -l < "$OUT/hosts/live-hosts.txt") live hosts; open ports/services mapped.
5. Content/endpoints: $(cat "$OUT/content/urls-historical.txt" "$OUT/content/urls-katana.txt" 2>/dev/null | sort -u | wc -l) URLs, $(wc -l < "$OUT/content/params-from-urls.txt" 2>/dev/null || echo 0) params, API schemas + policy files enumerated.
6. JS analysis: $(ls "$OUT/js/files" 2>/dev/null | wc -l) bundles mined for routes + secrets; source maps reconstructed where present.
7. Tech/CMS: per-host stack fingerprinted; framework debug paths probed.
8. Cloud/SaaS: $(wc -l < "$OUT/cloud/buckets-public.txt" 2>/dev/null || echo 0) public buckets, cloud apps + SaaS footprint mapped.
9. Takeover: $(cat "$OUT/takeover/takeover-fingerprints.txt" "$OUT/takeover/ns-takeover.txt" 2>/dev/null | wc -l) dangling/takeover candidates (CNAME/A/NS/MX).
10. Code/leak: org repos + history scanned; pastes/breaches/emails harvested for spray seeds.
11. Prioritization: $(wc -l < high-priority-targets.txt 2>/dev/null || echo 0) high-priority targets ranked; screenshots captured.
12. Hand-off: findings -> ValidatorAgent -> ExploitChainAgent; per-workflow notes in handoff-notes.md.
EOF
  cat recon-summary.md
  ```
- **Indicators:** A 12-point recap mapping directly to the phases executed.
- **Validation:** Each line's count reconciles with its artifact.
- **Severity:** N/A. Business impact: operator-readable status and report seed.
- **Dispatch:** -> ReconAgent

**Phase artifacts:** `reports/attack-surface-inventory.json`, `reports/handoff-notes.md`, `reports/recon-summary.md`, `/tmp/bb-findings-recon.json`, `/tmp/bb-findings-validator.json`, `/tmp/bb-findings-chains.json`.

**Gate-out:** Normalized inventory + validated/chained findings + per-workflow hand-off notes + N-point summary all exist. Recon is complete and consumable.

---

## Output Directory Structure

```
$HOME/.claude/MEMORY/BugBounty/Sessions/<slug>/recon/
├── scope/        seed-roots, asns, cidrs, ptr-hostnames, acquisitions, reverse-whois, in/out-scope
├── passive/      whois, crtsh, shodan, censys, securitytrails, wayback, builtwith
├── subdomains/   subs-passive, subs-resolved, subs-brute, subs-gotator, all-subdomains
├── dns/          records.json, cname-map, axfr, mail-dnssec, dnsx-resolved
├── hosts/        httpx.json, live-hosts, live-ips, body-hashes
├── ports/        naabu-*, nmap-services.*, nmap-http.*
├── content/      urls-*, app-profile-{lowpriv,admin}, ffuf-*, ferox, params, api-surface, graphql
├── js/           js-urls, files/, js-endpoints, js-keys, trufflehog, srcmap/
├── tech/         whatweb, httpx-tech, nuclei-tech, wpscan, framework-paths
├── cloud/        buckets-public, cloud-enum, cloud-app-domains, firebase-open, saas-footprint
├── takeover/     subjack, nuclei-takeover, dnsreaper, dangling-cnames, ns-takeover
├── leaks/        gh-repos, gh-dorks, trufflehog-org, gitleaks-*, pastes, emails, breaches
├── screenshots/  gowitness/aquatone galleries
└── reports/      attack-surface-inventory.json, priority-final.tsv, high-priority-targets,
                  handoff-notes.md, recon-summary.md
```

---

## Decision Gates

| Gate | Condition | Action |
|------|-----------|--------|
| Post-Seed (P0) | Only the given root, no ASN/acquisition expansion | Re-run reverse-whois + amass intel; confirm org scope before continuing |
| Post-Passive (P1) | No CT/passive subdomains for a known-large org | Verify root spelling, add API keys to subfinder/amass, re-run |
| Post-Subdomain (P2) | <5 resolved subdomains | Deeper brute wordlist + permutation; check for wildcard DNS masking |
| Wildcard DNS | Random label resolves | Enable puredns wildcard filtering; use httpx body-hash to separate real apps |
| Post-Probe (P4) | No live hosts | Check connectivity, CDN/WAF blocking, that resolution returned IPs; scan origin IPs |
| Post-Content (P5) | Thin URL/param corpus | Authenticated harness crawl + JS analysis; widen content brute-force |
| Post-JS (P6) | Candidate secrets found | Queue to SecretsExposureAgent for live validation — never report unvalidated |
| Post-Cloud (P8) | Public bucket / open Firebase | Document scope of exposure; route to SecretsExposureAgent / W_CLOUD |
| Post-Takeover (P9) | Takeover candidate confirmed | Hand to SubdomainTakeoverAgent for impact (cookie/CSP/OAuth) and reporting |
| Post-Leak (P10) | Live secret / leaked source | Validate via SecretsExposureAgent; emails -> W_NETWORK spray seeds |
| Pre-Handoff (P12) | Findings exist | Run ValidatorAgent then ExploitChainAgent before final report |
| Scope guard | Asset matches out-of-scope denylist | Drop immediately; never send an active packet |

---

## Tool Reference

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Passive subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Attack surface mapping / intel | `go install github.com/owasp-amass/amass/v4/...@master` |
| asnmap | Org/domain -> ASN -> CIDR | `go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest` |
| mapcidr | CIDR expansion | `go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest` |
| dnsx | DNS resolution / PTR / records | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| puredns | DNS resolution / brute + wildcard filter | `go install github.com/d3mondev/puredns/v2@latest` |
| dnsvalidator | Build trusted resolver list | `pip install dnsvalidator` |
| gotator / dnsgen / altdns | Subdomain permutation | `go install github.com/Josue87/gotator@latest` / `pip install dnsgen altdns` |
| httpx | HTTP probing + tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| naabu | Fast port scanner | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| nmap | Service/version detection | `brew install nmap` |
| katana | Crawler/spider (JS-aware) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau / waybackurls | Historical URL mining | `go install github.com/lc/gau/v2/cmd/gau@latest` / `...tomnomnom/waybackurls@latest` |
| ffuf / feroxbuster | Content + vhost brute-force | `go install github.com/ffuf/ffuf/v2@latest` / `cargo install feroxbuster` |
| arjun / x8 / paramspider | Parameter discovery | `pip install arjun` / `cargo install x8` / paramspider repo |
| linkfinder / SecretFinder | JS endpoint + secret extraction | GerbenJavado/LinkFinder, m4ll0k/SecretFinder |
| sourcemapper | JS source-map reconstruction | `go install github.com/denandz/sourcemapper@latest` |
| nuclei | Templated exposure/takeover/tech scan | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| whatweb / webanalyze | Tech fingerprinting | `gem install whatweb` / `go install github.com/rverton/webanalyze/...@latest` |
| wpscan / droopescan / joomscan | CMS enumeration | `gem install wpscan` / `pip install droopescan` / OWASP joomscan |
| subjack / subzy / dnsreaper | Subdomain takeover scanning | repos: haccer/subjack, LukaSikic/subzy, punk-security/dnsReaper |
| cloud_enum / s3scanner | Cloud bucket discovery | `pipx install cloud_enum` / `pip install s3scanner` |
| trufflehog / gitleaks / gitdorker | Repo/secret recon | `go install github.com/trufflesecurity/trufflehog/v3@latest` / gitleaks / GitDorker |
| theHarvester | Email/people OSINT | `pip install theHarvester` |
| gowitness / aquatone | Visual recon screenshots | `go install github.com/sensepost/gowitness@latest` / aquatone |

### Bundled framework tools

| Tool | Use in recon |
|------|--------------|
| `burp-bridge.ts` | `--health` (pre-flight), `--sync-scope --scope` (hard scope guard), `--history`/`--export-har` (evidence), `--collaborator-poll` (OOB during active probing) |
| `playwright-harness.ts` | Authenticated crawl + post-login screenshots through Burp (`--mode map-flows`/`test`, `--auth-cookie`); real dev-browser session for JS-heavy apps |
| `credential-vault.ts` | `--get` low-priv + admin identities for authenticated content discovery; never inline secrets |
| `agent-router.ts` | `--engagement recon` -> deterministic DISCOVER -> EXPOSURE -> VALIDATE -> CHAIN plan |
| `hunt-orchestrator.ts` | RECON phase state, session persistence, progress tracking when run inside a full hunt |

---

## Dispatch Map (engagement: recon)

| Stage | Agent(s) | Responsibility |
|-------|----------|----------------|
| DISCOVER | ReconAgent, SubdomainTakeoverAgent | Asset/endpoint/secret discovery (P0–P11); dangling-DNS/takeover confirmation (P9) |
| EXPOSURE | SecretsExposureAgent | Validate leaked source/creds/keys against their providers; escalate live cloud creds |
| VALIDATE | ValidatorAgent | Reproduce, kill false positives, de-dup by root cause, score CVSS 3.1/4.0, hunt-mode gate |
| CHAIN | ExploitChainAgent | Correlate validated findings into MITRE ATT&CK kill chains; elevate combined CVSS |

**Downstream hand-off (deep-dive workflows):** W_WEB (web targets, params, JS routes, debug paths), W_API (API schemas, auth route diffs, OIDC), W_LLM (chat/RAG/agent + tool/upload surface), W_NETWORK (open services, origin IPs, spray seeds), W_CLOUD (public buckets, open Firebase, cloud apps, SaaS trust). The recon deliverable is the prioritized attack-surface inventory plus `reports/handoff-notes.md`.
