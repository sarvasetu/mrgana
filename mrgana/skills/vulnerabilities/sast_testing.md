---
name: sast_testing
description: Comprehensive Static Application Security Testing (SAST) including code analysis, secret detection, dependency vulnerabilities, and custom rules
---

# Static Application Security Testing (SAST)

## Overview
SAST analyzes source code, bytecode, or binary without executing it. Testing must cover vulnerability patterns, secret detection, dependency issues, and framework-specific vulnerabilities.

## Tools Available in Sandbox

| Tool | Purpose | Command |
|------|---------|---------|
| **semgrep** | Multi-language SAST | `semgrep --config auto .` |
| **bandit** | Python security linter | `bandit -r .` |
| **eslint** | JavaScript/TypeScript linter | `eslint --ext .js,.ts .` |
| **jshint** | JavaScript linter | `jshint .` |
| **trufflehog** | Secret detection | `trufflehog git file://. --only-verified` |
| **gitleaks** | Git secret scanning | `gitleaks detect --source .` |
| **trivy** | Dependency CVE scanning | `trivy fs .` |
| **retire.js** | JavaScript vulnerability scanner | `retire --path .` |
| **semgrep** | Custom rule scanning | `semgrep --config custom/ .` |

## Testing Methodology

### 1. Secret Detection

#### Using trufflehog
```bash
# Scan git repository
trufflehog git file://. --only-verified

# Scan specific file
trufflehog filesystem /path/to/file

# Scan GitHub repo
trufflehog github --repo https://github.com/org/repo
```

#### Using gitleaks
```bash
# Scan current directory
gitleaks detect --source . --verbose

# Scan with custom config
gitleaks detect --source . --config .gitleaks.toml

# Generate report
gitleaks detect --source . --report-path gitleaks-report.json
```

#### Manual Secret Detection
```bash
# Search for common secrets
grep -rn "password\|secret\|api_key\|apikey\|token\|private_key" --include="*.py" --include="*.js" --include="*.java" .

# Search for AWS credentials
grep -rn "AKIA\|aws_access_key_id\|aws_secret_access_key" .

# Search for private keys
grep -rn "BEGIN RSA PRIVATE KEY\|BEGIN OPENSSH PRIVATE KEY\|BEGIN EC PRIVATE KEY" .

# Search for connection strings
grep -rn "mongodb://\|mysql://\|postgresql://\|redis://" .

# Search for API keys
grep -rn "sk_live\|pk_live\|sk_test\|pk_test" .
```

### 2. Language-Specific Analysis

#### Python Analysis
```bash
# Bandit security linter
bandit -r . -f json -o bandit-report.json

# Semgrep with Python rules
semgrep --config "p/python" .

# Check for dangerous functions
grep -rn "eval(\|exec(\|os.system(\|subprocess.call" --include="*.py" .

# Check for SQL injection
grep -rn "execute(.*%s\|execute(.*format\|f\"SELECT" --include="*.py" .

# Check for insecure crypto
grep -rn "MD5\|SHA1\|DES\|ECB" --include="*.py" .
```

#### JavaScript/TypeScript Analysis
```bash
# ESLint security plugin
eslint --ext .js,.ts --plugin security .

# Semgrep with JS/TS rules
semgrep --config "p/javascript" --config "p/typescript" .

# Check for eval usage
grep -rn "eval(\|Function(\|setTimeout(.*string\|setInterval(.*string" --include="*.js" --include="*.ts" .

# Check for prototype pollution
grep -rn "__proto__\|constructor\[.*\]\|Object\.assign" --include="*.js" .

# Check for XSS patterns
grep -rn "innerHTML\|outerHTML\|document\.write\|\.html(" --include="*.js" .
```

#### Java Analysis
```bash
# Semgrep with Java rules
semgrep --config "p/java" .

# Check for SQL injection
grep -rn "Statement\|executeQuery\|executeUpdate" --include="*.java" .

# Check for command injection
grep -rn "Runtime\.getRuntime\|ProcessBuilder" --include="*.java" .

# Check for deserialization
grep -rn "ObjectInputStream\|readObject\|Serializable" --include="*.java" .

# Check for XXE
grep -rn "DocumentBuilderFactory\|XMLReader\|SAXParser" --include="*.java" .
```

#### Go Analysis
```bash
# Semgrep with Go rules
semgrep --config "p/go" .

# gosec security scanner
gosec ./...

# Check for SQL injection
grep -rn "db.Query\|db.Exec\|fmt.Sprintf.*SELECT" --include="*.go" .

# Check for command injection
grep -rn "exec.Command\|os/exec" --include="*.go" .
```

#### PHP Analysis
```bash
# Semgrep with PHP rules
semgrep --config "p/php" .

# Check for SQL injection
grep -rn "mysql_query\|mysqli_query\|pg_query" --include="*.php" .

# Check for file inclusion
grep -rn "include\s*\(\|require\s*\(\|include_once\s*\(\|require_once\s*\(" --include="*.php" .

# Check for command injection
grep -rn "exec(\|system(\|passthru(\|shell_exec(" --include="*.php" .
```

### 3. Framework-Specific Analysis

#### Django (Python)
```bash
# Check for SQL injection
grep -rn "raw(\|extra(\|cursor.execute" --include="*.py" .

# Check for XSS
grep -rn "\|safe\|mark_safe\|autoescape off" --include="*.html" --include="*.py" .

# Check for CSRF
grep -rn "@csrf_exempt" --include="*.py" .

# Check for insecure settings
grep -rn "DEBUG\s*=\s*True\|ALLOWED_HOSTS\s*=\s*\['\*'\]" --include="*.py" .
```

#### Express (Node.js)
```bash
# Check for XSS
grep -rn "res\.sendfile\|res\.render.*raw\|dangerouslySetInnerHTML" --include="*.js" .

# Check for SQL injection
grep -rn "query\(.*\+\|query\(.*\`\$\{" --include="*.js" .

# Check for open redirect
grep -rn "res\.redirect\(req\." --include="*.js" .

# Check for insecure CORS
grep -rn "origin.*true\|credentials.*true" --include="*.js" .
```

#### Spring (Java)
```bash
# Check for SQL injection
grep -rn "@Query.*concat\|@Query.*+" --include="*.java" .

# Check for deserialization
grep -rn "@RequestBody.*Serializable\|ObjectInputStream" --include="*.java" .

# Check for XXE
grep -rn "DocumentBuilderFactory\|SAXParser" --include="*.java" .
```

### 4. Vulnerability Pattern Detection

#### Injection Vulnerabilities
```bash
# SQL Injection
grep -rn "execute(.*%\|execute(.*format\|execute(.*+\|execute(.*\`\$" --include="*.py" --include="*.js" --include="*.java" --include="*.php" .

# Command Injection
grep -rn "system(\|exec(\|passthru(\|shell_exec(\|popen(\|ProcessBuilder\|Runtime.getRuntime" --include="*.py" --include="*.js" --include="*.java" --include="*.php" .

# LDAP Injection
grep -rn "ldap_search\|ldap_add\|ldap_modify" --include="*.py" --include="*.java" .

# XPath Injection
grep -rn "xpath\|findall\|findtext" --include="*.py" --include="*.java" .
```

#### Authentication Vulnerabilities
```bash
# Hardcoded credentials
grep -rn "password\s*=\s*[\"']\|secret\s*=\s*[\"']\|api_key\s*=\s*[\"']" --include="*.py" --include="*.js" --include="*.java" .

# Weak hashing
grep -rn "MD5\|SHA1\|hashlib.md5\|hashlib.sha1\|MessageDigest.getInstance(\"MD5\")" --include="*.py" --include="*.java" .

# Insecure session
grep -rn "session\[.*\]\s*=\|localStorage\.setItem\|document\.cookie\s*=" --include="*.js" .
```

#### Authorization Vulnerabilities
```bash
# IDOR patterns
grep -rn "req\.params\.id\|request\.GET\.get\|:id>" --include="*.js" --include="*.py" --include="*.java" .

# Missing authorization
grep -rn "def.*\(request\)\|public.*void\|app\.\(get\|post\|put\|delete\)" --include="*.py" --include="*.js" --include="*.java" .
```

#### Cryptographic Vulnerabilities
```bash
# Weak algorithms
grep -rn "DES\|3DES\|RC4\|MD5\|SHA1\|ECB" --include="*.py" --include="*.java" --include="*.js" .

# Insecure random
grep -rn "Math\.random\|random\.random\|rand()\|srand" --include="*.js" --include="*.php" .

# Hardcoded IV/key
grep -rn "IV\s*=\|key\s*=\s*b\"\|SecretKeySpec" --include="*.java" --include="*.py" .
```

### 5. Dependency Vulnerability Scanning

#### Using trivy
```bash
# Scan filesystem
trivy fs .

# Scan specific file
trivy fs --security-checks vuln,config .

# Scan container image
trivy image nginx:latest

# Scan SBOM
trivy sbom ./sbom.json
```

#### Using retire.js
```bash
# Scan for vulnerable JS libraries
retire --path .

# Scan with output
retire --path . --outputformat json --outputfile retire-report.json
```

#### Manual Dependency Analysis
```bash
# Check for outdated packages (Python)
pip list --outdated

# Check for vulnerable packages (Node.js)
npm audit

# Check for vulnerable packages (Ruby)
bundle audit

# Check for vulnerable packages (Go)
govulncheck ./...
```

### 6. Custom Rule Creation

#### Semgrep Custom Rules
```yaml
# .semgrep/custom-rules.yaml
rules:
  - id: hardcoded-password
    pattern: |
      password = "..."
    message: "Hardcoded password detected"
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      technology: [python]

  - id: sql-injection
    pattern: |
      cursor.execute("..." + ...)
    message: "Potential SQL injection"
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-89"

  - id: command-injection
    pattern: |
      os.system(...)
    message: "Potential command injection"
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-78"
```

#### Gitleaks Custom Config
```toml
# .gitleaks.toml
[[rules]]
id = "custom-api-key"
description = "Custom API Key pattern"
regex = '''(?i)api[_-]?key[_-]?=\s*['"]([a-zA-Z0-9]{32,})['"]'''
tags = ["api-key", "custom"]

[[rules]]
id = "custom-password"
description = "Hardcoded password"
regex = '''(?i)password[_-]?=\s*['"]([^'"]{8,})['"]'''
tags = ["password", "custom"]
```

### 7. Automated SAST Scanner

```python
#!/usr/bin/env python3
"""Comprehensive SAST scanner"""
import os
import subprocess
import json
from typing import Dict, List, Any

class SASTScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.findings: List[Dict[str, Any]] = []
    
    def run_trufflehog(self):
        """Run trufflehog for secret detection"""
        result = subprocess.run(
            ["trufflehog", "git", f"file://{self.project_path}", "--only-verified", "--json"],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    self.findings.append({
                        "type": "SECRET",
                        "tool": "trufflehog",
                        "severity": "CRITICAL",
                        "file": data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                        "description": f"Secret detected: {data.get('DetectorName', 'Unknown')}"
                    })
                except json.JSONDecodeError:
                    pass
    
    def run_bandit(self):
        """Run bandit for Python security"""
        result = subprocess.run(
            ["bandit", "-r", self.project_path, "-f", "json", "-q"],
            capture_output=True,
            text=True
        )
        
        try:
            data = json.loads(result.stdout)
            for result in data.get("results", []):
                self.findings.append({
                    "type": "VULNERABILITY",
                    "tool": "bandit",
                    "severity": result.get("issue_severity", "MEDIUM"),
                    "file": result.get("filename", ""),
                    "line": result.get("line_number", 0),
                    "description": result.get("issue_text", "")
                })
        except json.JSONDecodeError:
            pass
    
    def run_semgrep(self):
        """Run semgrep for multi-language analysis"""
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", self.project_path],
            capture_output=True,
            text=True
        )
        
        try:
            data = json.loads(result.stdout)
            for result in data.get("results", []):
                self.findings.append({
                    "type": "VULNERABILITY",
                    "tool": "semgrep",
                    "severity": result.get("extra", {}).get("severity", "MEDIUM"),
                    "file": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "description": result.get("extra", {}).get("message", "")
                })
        except json.JSONDecodeError:
            pass
    
    def run_trivy(self):
        """Run trivy for dependency vulnerabilities"""
        result = subprocess.run(
            ["trivy", "fs", "--security-checks", "vuln", "--format", "json", self.project_path],
            capture_output=True,
            text=True
        )
        
        try:
            data = json.loads(result.stdout)
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    self.findings.append({
                        "type": "DEPENDENCY_VULNERABILITY",
                        "tool": "trivy",
                        "severity": vuln.get("Severity", "MEDIUM"),
                        "file": result.get("Target", ""),
                        "description": f"{vuln.get('VulnerabilityID', '')}: {vuln.get('Title', '')}"
                    })
        except json.JSONDecodeError:
            pass
    
    def run_all(self) -> List[Dict[str, Any]]:
        """Run all SAST tools"""
        print("Starting SAST scan...")
        
        print("1. Running trufflehog (secrets)...")
        self.run_trufflehog()
        
        print("2. Running bandit (Python)...")
        self.run_bandit()
        
        print("3. Running semgrep (multi-language)...")
        self.run_semgrep()
        
        print("4. Running trivy (dependencies)...")
        self.run_trivy()
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python sast_scanner.py <project_path>")
        sys.exit(1)
    
    scanner = SASTScanner(sys.argv[1])
    findings = scanner.run_all()
    
    for f in findings:
        print(f"[{f['severity']}] {f['description']} in {f.get('file', 'N/A')}")
```

### 8. Remediation Guidance

#### SQL Injection Prevention
```python
# BAD: String concatenation
query = f"SELECT * FROM users WHERE id = {user_id}"

# GOOD: Parameterized query
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

#### Command Injection Prevention
```python
# BAD: os.system
os.system(f"ping {host}")

# GOOD: subprocess with list
subprocess.run(["ping", host], check=True)
```

#### XSS Prevention
```javascript
// BAD: innerHTML
element.innerHTML = userInput;

// GOOD: textContent
element.textContent = userInput;

// GOOD: React (auto-escaped)
<div>{userInput}</div>
```

#### Hardcoded Secrets Prevention
```python
# BAD: Hardcoded key
API_KEY = "sk_live_123456789"

# GOOD: Environment variable
API_KEY = os.environ.get("API_KEY")
```

### 9. CI/CD Integration

#### GitHub Actions SAST
```yaml
name: SAST Scan

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
      
      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/default
            p/python
            p/javascript
      
      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json || true
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
```

## Validation Checklist

- [ ] All secrets detected and removed
- [ ] No hardcoded credentials
- [ ] Parameterized queries used
- [ ] Input validation implemented
- [ ] Output encoding used
- [ ] Dependencies up to date
- [ ] No known vulnerable libraries
- [ ] Custom rules created for project-specific patterns
- [ ] CI/CD pipeline includes SAST
- [ ] Regular scans scheduled
