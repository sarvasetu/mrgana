---
name: ios_testing
description: iOS application security testing including binary analysis, keychain testing, runtime analysis, and certificate pinning bypass
---

# iOS Application Security Testing

## Overview
iOS security testing involves binary analysis, keychain testing, runtime instrumentation, and certificate pinning bypass. iOS apps use Swift/Objective-C compiled to ARM binaries.

## Tools Available in Sandbox

| Tool | Purpose | Command |
|------|---------|---------|
| **strings** | Extract strings | `strings BinaryName` |
| **nm** | Symbol table dump | `nm BinaryName` |
| **file** | Binary type detection | `file BinaryName` |
| **plutil** | Property list parsing | `plutil -p Info.plist` |
| **grep** | Pattern searching | `grep -rn "pattern" .` |

**Note**: This is a Docker sandbox for static analysis of extracted IPA contents only. Dynamic analysis tools (frida, objection, class-dump) and device communication tools (libimobiledevice) require physical devices or macOS and are not included.

## Testing Methodology

### 1. IPA Extraction & Analysis

#### Extract IPA Contents
```bash
# Unzip IPA (IPA is just a zip file)
unzip -d /tmp/ipa_extracted app.ipa

# Find the main binary
find /tmp/ipa_extracted -name "*.app" -type d
ls -la /tmp/ipa_extracted/Payload/*.app/

# Extract Info.plist
plutil -p /tmp/ipa_extracted/Payload/*.app/Info.plist
```

#### Analyze Binary Architecture
```bash
# Check binary architecture
file /tmp/ipa_extracted/Payload/*.app/*

# Check if binary is encrypted
strings /tmp/ipa_extracted/Payload/*.app/* | grep -i "encrypt"

# Extract load commands
otool -l /tmp/ipa_extracted/Payload/*.app/*
```

### 2. Static Analysis

#### Extract Class Information
```bash
# Dump Objective-C class information
class-dump /tmp/ipa_extracted/Payload/*.app/* > classes_dump.txt

# Search for interesting classes
grep -i "login\|auth\|password\|keychain\|token" classes_dump.txt

# Search for sensitive methods
grep -i "password\|secret\|private\|key" classes_dump.txt
```

#### Analyze Info.plist
```bash
# Extract and analyze Info.plist
plutil -p /tmp/ipa_extracted/Payload/*.app/Info.plist

# Check for:
# - ATS (App Transport Security) settings
# - URL schemes
# - Required capabilities
# - Background modes
```

#### Find Hardcoded Secrets
```bash
# Search for API keys, tokens
strings /tmp/ipa_extracted/Payload/*.app/* | grep -iE "(api_key|apikey|secret|token|password|keychain)"

# Search for URLs
strings /tmp/ipa_extracted/Payload/*.app/* | grep -iE "(http://|https://|ftp://)"

# Search for AWS credentials
strings /tmp/ipa_extracted/Payload/*.app/* | grep -iE "(AKIA|aws_access|aws_secret)"

# Search for Firebase
strings /tmp/ipa_extracted/Payload/*.app/* | grep -iE "(firebaseio|firebase)"
```

#### Analyze Entitlements
```bash
# Extract entitlements
codesign -d --entitlements - /tmp/ipa_extracted/Payload/*.app

# Check for:
# - Keychain access groups
# - App groups
# - Network capabilities
# - Push notification entitlements
```

### 3. Keychain Testing

#### Using Frida for Keychain Access
```javascript
// keychain_dump.js
var keychain = ObjC.classes.Security;

keychain.SecItemCopyMatching.implementation = function(query) {
    console.log('[+] Keychain query: ' + query);
    return this.SecItemCopyMatching(query);
};

// Dump all keychain items
var query = ObjC.classes.NSMutableDictionary.alloc().init();
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('kSecClass'), ObjC.classes.NSString.stringWithString_('kSecClassGenericPassword'));

var result = keychain.SecItemCopyMatching(query, NULL);
console.log('[+] Keychain result: ' + result);
```

#### Keychain Item Access Testing
```bash
# Test keychain accessibility
# kSecAttrAccessibleAlways - Always accessible (insecure)
# kSecAttrAccessibleAfterFirstUnlock - Accessible after first unlock
# kSecAttrAccessibleWhenUnlocked - Only when device is unlocked
# kSecAttrAccessibleWhenUnlockedThisDeviceOnly - Only when unlocked, not backed up

# Search for insecure keychain usage
grep -rn "kSecAttrAccessibleAlways\|kSecAttrAccessibleAfterFirstUnlock" /tmp/decompiled/
```

### 4. Runtime Analysis

#### Using Frida
```javascript
// ios_bypass.js - Bypass jailbreak detection
var JailbreakDetection = ObjC.classes.JailbreakDetection;

if (JailbreakDetection) {
    JailbreakDetection.isJailbroken.implementation = function() {
        console.log('[+] Jailbreak detection bypassed');
        return false;
    };
}

// Bypass SSL pinning
var NSURLSession = ObjC.classes.NSURLSession;
NSURLSession.dataTaskWithRequest.implementation = function(request) {
    console.log('[+] SSL pinning bypassed for: ' + request.URL().absoluteString());
    return this.dataTaskWithRequest(request);
};
```

```bash
# Run Frida script on iOS device
frida -U -U -l ios_bypass.js com.example.app

# Spawn app with Frida
frida -U -U -l ios_bypass.js -f com.example.app --no-pause
```

#### Using Objection
```bash
# Start objection exploration
objection -g com.example.app explore

# Inside objection console
# Bypass jailbreak detection
ios jailbreak disable disable

# Bypass SSL pinning
ios sslpinning disable

# Dump keychain
ios keychain dump

# List classes
ios hooking list classes

# Hook method
ios hooking watch method "+[LoginManager authenticateWithPassword:]" --dump-args

# Dump UserDefaults
ios nsuserdefaults dump
```

### 5. URL Scheme Testing

#### Find URL Schemes
```bash
# Extract URL schemes from Info.plist
plutil -p /tmp/ipa_extracted/Payload/*.app/Info.plist | grep -A 5 "CFBundleURLSchemes"

# Search for URL handling in code
grep -rn "openURL\|handleOpenURL\|URLScheme" /tmp/decompiled/ --include="*.swift" --include="*.m"
```

#### Test URL Scheme Injection
```bash
# Test custom URL schemes
open "myapp://callback?token=malicious"
open "myapp://deeplink?param=<script>alert(1)</script>"

# Test universal links
curl -I "https://example.com/app/path"
```

### 6. Network Analysis

#### Certificate Pinning Bypass
```javascript
// ssl_pinning_bypass.js
var TrustManager = ObjC.classes.SSLHandshake;

TrustManager['- SSLHandshake:withTrustedSecCertificates:'].implementation = function(trusted) {
    console.log('[+] SSL pinning bypassed');
    return true;
};
```

#### Analyze Network Security Config
```bash
# Check for ATS configuration
plutil -p /tmp/ipa_extracted/Payload/*.app/Info.plist | grep -A 10 "NSAppTransportSecurity"

# Check for insecure connections
grep -rn "NSAllowsArbitraryLoads\|NSAllowsLocalNetworking" /tmp/ipa_extracted/
```

### 7. Sensitive Data Storage

#### Find Insecure Storage
```bash
# Check for NSUserDefaults usage
grep -rn "NSUserDefaults\|standardUserDefaults" /tmp/decompiled/ --include="*.swift" --include="*.m"

# Check for plist storage
grep -rn "writeToFile\|plistWithContentsOfFile" /tmp/decompiled/ --include="*.swift" --include="*.m"

# Check for SQLite storage
grep -rn "sqlite3_open\|FMDatabase" /tmp/decompiled/ --include="*.swift" --include="*.m"

# Check for Core Data
grep -rn "NSManagedObject\|NSPersistentStore" /tmp/decompiled/ --include="*.swift" --include="*.m"
```

### 8. Automated Scanning

#### iOS Security Scanner Script
```python
#!/usr/bin/env python3
"""iOS security scanner"""
import os
import json
import subprocess
from typing import Dict, List, Any

class iOSScanner:
    def __init__(self, ipa_path: str):
        self.ipa_path = ipa_path
        self.extracted_path = None
        self.findings: List[Dict[str, Any]] = []
    
    def extract_ipa(self):
        """Extract IPA contents"""
        self.extracted_path = "/tmp/ipa_extracted"
        os.makedirs(self.extracted_path, exist_ok=True)
        
        subprocess.run(["unzip", "-d", self.extracted_path, self.ipa_path])
    
    def analyze_info_plist(self):
        """Analyze Info.plist for security issues"""
        plist_path = None
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                if file == "Info.plist":
                    plist_path = os.path.join(root, file)
                    break
        
        if not plist_path:
            return
        
        result = subprocess.run(["plutil", "-p", plist_path], capture_output=True, text=True)
        content = result.stdout
        
        # Check for insecure ATS
        if "NSAllowsArbitraryLoads = true" in content:
            self.findings.append({
                "type": "INSECURE_ATS",
                "severity": "HIGH",
                "description": "App Transport Security disabled"
            })
        
        # Check for URL schemes
        if "CFBundleURLSchemes" in content:
            self.findings.append({
                "type": "URL_SCHEME",
                "severity": "INFO",
                "description": "App registers custom URL schemes"
            })
    
    def analyze_binary(self):
        """Analyze binary for security issues"""
        binary_path = None
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                if not file.endswith(('.app', '.bundle', '.framework')):
                    binary_path = os.path.join(root, file)
                    break
        
        if not binary_path:
            return
        
        # Check for hardcoded secrets
        result = subprocess.run(["strings", binary_path], capture_output=True, text=True)
        strings = result.stdout
        
        secret_patterns = ["api_key", "apikey", "secret", "password", "token"]
        for pattern in secret_patterns:
            if pattern.lower() in strings.lower():
                self.findings.append({
                    "type": "HARDCODED_SECRET",
                    "severity": "HIGH",
                    "description": f"Possible hardcoded {pattern} found"
                })
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all iOS security tests"""
        print("Starting iOS security scan...")
        
        print("1. Extracting IPA...")
        self.extract_ipa()
        
        print("2. Analyzing Info.plist...")
        self.analyze_info_plist()
        
        print("3. Analyzing binary...")
        self.analyze_binary()
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ios_scanner.py <ipa_path>")
        sys.exit(1)
    
    scanner = iOSScanner(sys.argv[1])
    scanner.run_all_tests()
```

### 9. Common Vulnerabilities

| Vulnerability | Detection Method | Severity |
|---------------|------------------|----------|
| Hardcoded secrets | strings, grep | HIGH |
| Insecure ATS | Info.plist analysis | HIGH |
| Jailbreak detection bypass | Frida/objection | LOW |
| Certificate pinning bypass | Dynamic analysis | MEDIUM |
| Insecure keychain storage | Keychain dump | HIGH |
| Insecure URL schemes | Info.plist + code review | MEDIUM |
| Insecure deep links | Code review | MEDIUM |
| Weak crypto | Binary analysis | HIGH |
| Debug mode enabled | Entitlements check | MEDIUM |
| Insecure logging | Code review | LOW |
| Sensitive data in plist | plist analysis | MEDIUM |
| Unencrypted local storage | File system analysis | HIGH |

### 10. Remediation Guidance

#### Secure Keychain Storage
```swift
// GOOD: Accessible only when unlocked
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "username",
    kSecValueData as String: data,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]

SecItemAdd(query as CFDictionary, nil)

// BAD: Always accessible
kSecAttrAccessibleAlways
```

#### Secure ATS Configuration
```xml
<!-- Info.plist - Restrict ATS -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

#### Prevent URL Scheme Attacks
```swift
// Validate URL scheme before processing
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    // Validate URL
    guard url.scheme == "myapp" else { return false }
    
    // Validate host
    guard url.host == "callback" else { return false }
    
    // Validate parameters
    guard let token = url.queryParameters["token"] else { return false }
    
    // Process only validated data
    processToken(token)
    return true
}
```

## Validation Checklist

- [ ] IPA extracted successfully
- [ ] Info.plist analyzed
- [ ] Binary analyzed for secrets
- [ ] Keychain storage tested
- [ ] URL schemes tested
- [ ] Certificate pinning tested
- [ ] Jailbreak detection tested
- [ ] Network security analyzed
- [ ] Sensitive data storage tested
- [ ] Dynamic analysis performed
