---
name: android_apk_testing
description: Comprehensive Android APK security testing including reverse engineering, permission analysis, component testing, and dynamic analysis
---

# Android APK Security Testing

## Overview
Android security testing involves static analysis (decompilation, code review), dynamic analysis (runtime instrumentation), and component-level testing.

## Tools Available in Sandbox

| Tool | Purpose | Command |
|------|---------|---------|
| **jadx** | DEX to Java decompiler | `jadx -d output/ app.apk` |
| **apktool** | APK reverse engineering | `apktool d app.apk` |
| **androguard** | Android app analysis | `androguard analyze app.apk` |
| **dex2jar** | DEX to JAR conversion | `d2j-dex2jar app.apk` |
| **apkleaks** | Secrets detection | `apkleaks -f app.apk` |
| **quark-engine** | Malware analysis | `quark -a app.apk -r rules.json` |

**Note**: This is a Docker sandbox for static analysis only. Dynamic analysis tools (frida, objection, adb) require physical devices or emulators and are not included.

## Testing Methodology

### 1. APK Decompilation

#### Using jadx (Java Source Recovery)
```bash
# Decompile APK to Java source
jadx -d /tmp/decompiled app.apk

# Decompile with debug info
jadx -d /tmp/decompiled --show-bad-code app.apk

# Decompile specific class
jadx -d /tmp/decompiled --class-name com.example.MainActivity app.apk
```

#### Using apktool (Smali + Resources)
```bash
# Decompile APK to smali and resources
apktool d app.apk -o /tmp/apktool_output

# Rebuild APK after modifications
apktool b /tmp/apktool_output -o modified.apk
```

#### Using dex2jar (JAR for Java Analysis)
```bash
# Convert DEX to JAR
d2j-dex2jar app.apk -o app-dex2jar.jar

# Analyze with jadx-gui
jadx-gui app-dex2jar.jar
```

### 2. Static Analysis

#### Permission Analysis
```bash
# Extract permissions from AndroidManifest.xml
grep -A 100 "<manifest" /tmp/decompiled/AndroidManifest.xml | grep "uses-permission"

# Analyze dangerous permissions
grep "android.permission" /tmp/decompiled/AndroidManifest.xml | grep -E "(SEND_SMS|RECEIVE_SMS|READ_SMS|CALL_PHONE|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|READ_CONTACTS|WRITE_CONTACTS|READ_PHONE_STATE|WRITE_EXTERNAL_STORAGE)"
```

#### Find Hardcoded Secrets
```bash
# Search for API keys, tokens, passwords
grep -rn "api_key\|api_secret\|password\|token\|secret" /tmp/decompiled/ --include="*.java" --include="*.xml"

# Search for AWS credentials
grep -rn "AKIA\|aws_access_key\|aws_secret_key" /tmp/decompiled/

# Search for Firebase URLs
grep -rn "firebaseio.com\|firebase.google.com" /tmp/decompiled/

# Search for hardcoded URLs
grep -rn "http://\|https://" /tmp/decompiled/ --include="*.java" | grep -v "android.com\|google.com\|github.com"
```

#### Find Insecure Configurations
```bash
# Check for debug mode
grep -rn "debuggable\|DEBUG\|BuildConfig.DEBUG" /tmp/decompiled/ --include="*.xml" --include="*.java"

# Check for allowBackup
grep -rn "allowBackup" /tmp/decompiled/AndroidManifest.xml

# Check for exported components
grep -rn "exported=\"true\"" /tmp/decompiled/AndroidManifest.xml

# Check for custom permissions
grep -rn "protectionLevel" /tmp/decompiled/AndroidManifest.xml
```

#### Find Vulnerable Code Patterns
```bash
# SQL Injection
grep -rn "rawQuery\|execSQL\|compileStatement" /tmp/decompiled/ --include="*.java"

# Command Injection
grep -rn "Runtime.getRuntime().exec\|ProcessBuilder" /tmp/decompiled/ --include="*.java"

# Path Traversal
grep -rn "openFileInput\|openFileOutput\|FileInputStream\|FileOutputStream" /tmp/decompiled/ --include="*.java"

# Insecure Crypto
grep -rn "DES\|MD5\|SHA1\|ECB" /tmp/decompiled/ --include="*.java"

# WebView Vulnerabilities
grep -rn "setJavaScriptEnabled\|addJavascriptInterface\|setAllowFileAccess" /tmp/decompiled/ --include="*.java"
```

### 3. Component Testing

#### Activity Testing
```bash
# List all activities
grep -A 5 "<activity" /tmp/decompiled/AndroidManifest.xml

# Export activities (no intent-filter protection)
grep -B 2 -A 10 "exported=\"true\"" /tmp/decompiled/AndroidManifest.xml | grep -A 10 "<activity"

# Launch exported activity
adb shell am start -n com.example/.MainActivity
```

#### Service Testing
```bash
# List all services
grep -A 5 "<service" /tmp/decompiled/AndroidManifest.xml

# Start exported service
adb shell am startservice com.example/.MyService

# Bind to exported service
adb shell am bindservice com.example/.MyService
```

#### Broadcast Receiver Testing
```bash
# List all broadcast receivers
grep -A 5 "<receiver" /tmp/decompiled/AndroidManifest.xml

# Send broadcast to exported receiver
adb shell am broadcast -a com.example.MY_ACTION --es message "test"

# Check for protected broadcasts
grep -rn "android.permission.SEND_SMS\|android.permission.BROADCAST_SMS" /tmp/decompiled/AndroidManifest.xml
```

#### Content Provider Testing
```bash
# List all content providers
grep -A 5 "<provider" /tmp/decompiled/AndroidManifest.xml

# Query exported content provider
adb shell content query --uri content://com.example.provider/users

# Insert data
adb shell content insert --uri content://com.example.provider/users --bind name:s:test

# Check for SQL injection
adb shell content query --uri content://com.example.provider/users --where "id=1 OR 1=1"
```

### 4. Dynamic Analysis

#### Using Frida
```javascript
// frida_script.js - Bypass SSL pinning
Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function() {
        console.log('[+] SSL pinning bypassed');
        return arguments[0];
    };
});

// Hook sensitive methods
Java.perform(function() {
    var MainActivity = Java.use('com.example.MainActivity');
    MainActivity.getLogin.implementation = function() {
        console.log('[+] getLogin called');
        var result = this.getLogin();
        console.log('[+] Credentials: ' + result);
        return result;
    };
});
```

```bash
# Run Frida script
frida -U -l frida_script.js com.example.app

# Spawn app with Frida
frida -U -l frida_script.js -f com.example.app --no-pause
```

#### Using Objection
```bash
# Start objection exploration
objection -g com.example.app explore

# Inside objection console
# Bypass SSL pinning
android sslpinning disable

# Bypass root detection
android root disable

# List activities
android hooking list activities

# List classes
android hooking list classes

# Hook method
android hooking watch class com.example.LoginActivity

# Dump SharedPreferences
android sharedpref dump

# Dump SQLite databases
android sqlite dump
```

#### Using adb
```bash
# Install APK
adb install app.apk

# List packages
adb shell pm list packages

# Get package info
adb shell dumpsys package com.example.app

# Launch activity
adb shell am start -n com.example/.MainActivity

# View logs
adb logcat | grep -i "com.example"

# Capture network traffic
adb shell tcpdump -i any -w /sdcard/capture.pcap

# Pull files from device
adb pull /data/data/com.example/shared_prefs/ ./shared_prefs/
adb pull /data/data/com.example/databases/ ./databases/
```

### 5. Network Analysis

#### Certificate Pinning Bypass
```bash
# Check for certificate pinning
grep -rn "CertificatePinner\|TrustManager\|SSLSocketFactory" /tmp/decompiled/ --include="*.java"

# Bypass with Frida
frida -U -l ssl_pinning_bypass.js com.example.app
```

#### Network Security Config
```bash
# Check network security config
cat /tmp/decompiled/res/xml/network_security_config.xml

# Check for cleartext traffic
grep -rn "cleartextTrafficPermitted\|usesCleartextTraffic" /tmp/decompiled/
```

### 6. Automated Scanning

#### Using apkleaks
```bash
# Scan for secrets
apkleaks -f app.apk -o results.json

# Scan with custom patterns
apkleaks -f app.apk -p patterns.txt
```

#### Using androguard
```python
#!/usr/bin/env python3
"""Automated Android security scanner"""
from androguard.misc import AnalyzeAPK
import json

def scan_apk(apk_path):
    """Scan APK for security issues"""
    a, d, dx = AnalyzeAPK(apk_path)
    
    findings = []
    
    # Check permissions
    dangerous_permissions = [
        "android.permission.SEND_SMS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION"
    ]
    
    permissions = a.get_permissions()
    for perm in permissions:
        if perm in dangerous_permissions:
            findings.append({
                "type": "DANGEROUS_PERMISSION",
                "permission": perm,
                "severity": "MEDIUM"
            })
    
    # Check for debug mode
    if a.get_attribute_value("application", "debuggable") == "true":
        findings.append({
            "type": "DEBUGGABLE",
            "severity": "HIGH"
        })
    
    # Check for allowBackup
    if a.get_attribute_value("application", "allowBackup") == "true":
        findings.append({
            "type": "ALLOW_BACKUP",
            "severity": "MEDIUM"
        })
    
    return findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python android_scanner.py <apk_path>")
        sys.exit(1)
    
    findings = scan_apk(sys.argv[1])
    print(json.dumps(findings, indent=2))
```

### 7. Common Vulnerabilities

| Vulnerability | Detection Method | Severity |
|---------------|------------------|----------|
| Hardcoded secrets | Grep for API keys, tokens | HIGH |
| Debug mode enabled | Check AndroidManifest.xml | HIGH |
| Allow backup | Check AndroidManifest.xml | MEDIUM |
| Exported components | Check AndroidManifest.xml | HIGH |
| SQL injection | grep for rawQuery, execSQL | CRITICAL |
| Command injection | grep for Runtime.exec | CRITICAL |
| Insecure crypto | grep for DES, MD5, ECB | HIGH |
| WebView vulnerabilities | grep for addJavascriptInterface | HIGH |
| Certificate pinning bypass | Dynamic analysis | MEDIUM |
| Root detection bypass | Dynamic analysis | LOW |
| Insecure storage | Check shared_prefs, databases | MEDIUM |
| Insecure logging | Check Log.d, Log.v calls | LOW |
| Weak authentication | Analyze login flows | HIGH |
| Insecure deep links | Check intent-filters | MEDIUM |

### 8. Remediation Guidance

#### Secure AndroidManifest.xml
```xml
<!-- Disable debug mode -->
<application android:debuggable="false" ...>

<!-- Disable backup -->
<application android:allowBackup="false" ...>

<!-- Don't export components unnecessarily -->
<activity android:exported="false" ...>
<service android:exported="false" ...>
<receiver android:exported="false" ...>
```

#### Secure Code Patterns
```java
// GOOD: Parameterized queries
db.rawQuery("SELECT * FROM users WHERE id = ?", new String[]{userId});

// BAD: String concatenation
db.rawQuery("SELECT * FROM users WHERE id = " + userId, null);

// GOOD: Secure crypto
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

// BAD: Weak crypto
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
```

## Validation Checklist

- [ ] APK decompiled successfully
- [ ] Permissions analyzed
- [ ] Hardcoded secrets identified
- [ ] Exported components tested
- [ ] SQL injection tested
- [ ] Command injection tested
- [ ] WebView security tested
- [ ] Certificate pinning tested
- [ ] Dynamic analysis performed
- [ ] Network traffic analyzed
