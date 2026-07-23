---
name: api_fuzzing
description: Automated API fuzzing for edge cases, type juggling, mass assignment, and parameter pollution
---

# API Fuzzing

## Overview
API fuzzing automates the discovery of edge cases, type juggling vulnerabilities, mass assignment issues, and parameter pollution attacks.

## Testing Methodology

### 1. Type Juggling

#### Integer vs String
```python
async def test_type_juggling(session, endpoint):
    """Test type juggling vulnerabilities"""
    payloads = [
        {"id": "1"},           # String
        {"id": 1},             # Integer
        {"id": "1 OR 1=1"},   # SQL injection
        {"id": {"$gt": ""}},  # NoSQL injection
        {"id": ["1", "2"]},   # Array
        {"id": None},         # Null
        {"id": True},         # Boolean
    ]
    
    results = []
    for payload in payloads:
        response = await session.get(endpoint, params=payload)
        results.append({
            "payload": payload,
            "status": response.status,
            "body": await response.text()
        })
    
    return results
```

#### Float vs Integer
```python
async def test_float_integer(session, endpoint):
    """Test float vs integer handling"""
    payloads = [
        {"amount": 100},
        {"amount": 100.0},
        {"amount": "100"},
        {"amount": "100.0"},
        {"amount": "100.00"},
        {"amount": 1e2},
        {"amount": 0x64},  # Hex
        {"amount": 0144},  # Octal
    ]
    
    results = []
    for payload in payloads:
        response = await session.post(endpoint, json=payload)
        results.append({
            "payload": payload,
            "status": response.status,
            "body": await response.text()
        })
    
    return results
```

### 2. Mass Assignment

#### Extra Fields
```python
async def test_mass_assignment(session, endpoint, allowed_fields):
    """Test if extra fields are accepted"""
    # Fields that should NOT be assignable
    dangerous_fields = {
        "role": "admin",
        "is_admin": True,
        "permissions": ["*"],
        "balance": 999999,
        "credit": 999999,
        "verified": True,
        "email_verified": True
    }
    
    results = []
    for field, value in dangerous_fields.items():
        payload = {"name": "test"}  # Base valid payload
        payload[field] = value
        
        response = await session.post(endpoint, json=payload)
        if response.status == 201:
            results.append({
                "field": field,
                "value": value,
                "vulnerable": True
            })
    
    return results
```

#### Nested Object Injection
```python
async def test_nested_mass_assignment(session, endpoint):
    """Test nested object injection"""
    payloads = [
        {"user": {"role": "admin"}},
        {"user": {"permissions": ["admin"]}},
        {"profile": {"is_verified": True}},
        {"account": {"balance": 999999}}
    ]
    
    results = []
    for payload in payloads:
        response = await session.put(endpoint, json=payload)
        results.append({
            "payload": payload,
            "status": response.status
        })
    
    return results
```

### 3. Parameter Pollution

#### Duplicate Parameters
```python
async def test_parameter_pollution(session, endpoint):
    """Test parameter pollution attacks"""
    # Duplicate parameter
    url = f"{endpoint}?id=1&id=2"
    response = await session.get(url)
    
    # Check which ID was used
    data = response.json()
    return data.get("id")
```

#### Parameter Tampering
```python
async def test_parameter_tampering(session, endpoint):
    """Test parameter tampering"""
    payloads = [
        {"id": "1", "_method": "DELETE"},
        {"id": "1", "method": "DELETE"},
        {"id": "1", "X-HTTP-Method-Override": "DELETE"},
    ]
    
    results = []
    for payload in payloads:
        response = await session.post(endpoint, json=payload)
        results.append({
            "payload": payload,
            "status": response.status
        })
    
    return results
```

### 4. Boundary Testing

#### Integer Overflow
```python
async def test_integer_overflow(session, endpoint):
    """Test integer overflow vulnerabilities"""
    payloads = [
        {"quantity": 2147483647},      # Max 32-bit int
        {"quantity": 2147483648},      # Overflow
        {"quantity": -2147483648},     # Min 32-bit int
        {"quantity": -2147483649},     # Underflow
        {"quantity": 999999999999999}, # Large number
    ]
    
    results = []
    for payload in payloads:
        response = await session.post(endpoint, json=payload)
        results.append({
            "payload": payload,
            "status": response.status
        })
    
    return results
```

#### String Length
```python
async def test_string_length(session, endpoint):
    """Test string length boundaries"""
    payloads = [
        {"name": ""},                    # Empty
        {"name": "a"},                   # Single char
        {"name": "a" * 1000000},         # Very long
        {"name": "a" * 256},             # Common limit
        {"name": "a" * 65536},           # 64KB
    ]
    
    results = []
    for payload in payloads:
        response = await session.post(endpoint, json=payload)
        results.append({
            "length": len(payload["name"]),
            "status": response.status
        })
    
    return results
```

### 5. Encoding Attacks

#### Unicode Normalization
```python
async def test_unicode_normalization(session, endpoint):
    """Test Unicode normalization attacks"""
    payloads = [
        {"username": "admin"},
        {"username": "аdmin"},  # Cyrillic 'а'
        {"username": "аdmin"},  # Different Unicode
        {"username": "admin\u200b"},  # Zero-width space
        {"username": "admin\u0000"},  # Null byte
    ]
    
    results = []
    for payload in payloads:
        response = await session.post(endpoint, json=payload)
        results.append({
            "payload": payload["username"],
            "status": response.status
        })
    
    return results
```

#### URL Encoding
```python
async def test_url_encoding(session, endpoint):
    """Test URL encoding bypass"""
    payloads = [
        {"path": "../etc/passwd"},
        {"path": "%2e%2e%2fetc%2fpasswd"},
        {"path": "..%252f..%252fetc%252fpasswd"},
        {"path": "%252e%252e%252fetc%252fpasswd"},
    ]
    
    results = []
    for payload in payloads:
        response = await session.get(endpoint, params=payload)
        results.append({
            "payload": payload["path"],
            "status": response.status
        })
    
    return results
```

### 6. Tools & Scripts

#### API Fuzzer
```python
#!/usr/bin/env python3
"""API fuzzer for edge cases"""
import asyncio
import aiohttp
import json
from typing import Dict, List, Any

class APIFuzzer:
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url
        self.token = token
        self.headers = {"Content-Type": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.findings: List[Dict[str, Any]] = []
    
    async def fuzz_endpoint(self, session: aiohttp.ClientSession, endpoint: str, method: str = "GET"):
        """Fuzz a single endpoint"""
        payloads = [
            {"id": "1 OR 1=1"},
            {"id": {"$gt": ""}},
            {"id": ["1", "2"]},
            {"id": None},
            {"id": ""},
            {"id": " "},
            {"id": "../../../etc/passwd"},
        ]
        
        for payload in payloads:
            try:
                if method == "GET":
                    async with session.get(
                        f"{self.base_url}{endpoint}",
                        params=payload,
                        headers=self.headers
                    ) as resp:
                        if resp.status == 200:
                            self.findings.append({
                                "endpoint": endpoint,
                                "payload": payload,
                                "status": resp.status
                            })
                else:
                    async with session.post(
                        f"{self.base_url}{endpoint}",
                        json=payload,
                        headers=self.headers
                    ) as resp:
                        if resp.status == 200:
                            self.findings.append({
                                "endpoint": endpoint,
                                "payload": payload,
                                "status": resp.status
                            })
            except Exception as e:
                print(f"Error fuzzing {endpoint}: {e}")
    
    async def fuzz_mass_assignment(self, session: aiohttp.ClientSession, endpoint: str):
        """Test mass assignment vulnerabilities"""
        dangerous_fields = {
            "role": "admin",
            "is_admin": True,
            "permissions": ["*"],
            "balance": 999999
        }
        
        for field, value in dangerous_fields.items():
            payload = {"name": "test", field: value}
            
            try:
                async with session.post(
                    f"{self.base_url}{endpoint}",
                    json=payload,
                    headers=self.headers
                ) as resp:
                    if resp.status in [200, 201]:
                        self.findings.append({
                            "type": "MASS_ASSIGNMENT",
                            "field": field,
                            "severity": "CRITICAL"
                        })
            except Exception:
                pass
    
    async def run_all_tests(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Run all fuzzing tests"""
        print("Starting API fuzzing scan...")
        
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                print(f"Fuzzing {endpoint}...")
                await self.fuzz_endpoint(session, endpoint)
                await self.fuzz_mass_assignment(session, endpoint)
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python api_fuzzer.py <base_url> [token]")
        sys.exit(1)
    
    token = sys.argv[2] if len(sys.argv) > 2 else None
    fuzzer = APIFuzzer(sys.argv[1], token)
    asyncio.run(fuzzer.run_all_tests(["/api/users", "/api/items"]))
```

### 7. Remediation Guidance

#### Input Validation
```python
from pydantic import BaseModel, validator

class UserInput(BaseModel):
    name: str
    email: str
    age: int
    
    @validator('age')
    def validate_age(cls, v):
        if v < 0 or v > 150:
            raise ValueError('Invalid age')
        return v
    
    class Config:
        # Only allow these fields
        fields = {'name': True, 'email': True, 'age': True}
```

#### Allowlist Approach
```python
# BAD: Blacklist dangerous fields
dangerous_fields = ['role', 'admin', 'permissions']
if field not in dangerous_fields:
    user[field] = value

# GOOD: Allowlist safe fields
allowed_fields = ['name', 'email', 'phone']
if field in allowed_fields:
    user[field] = value
```

#### Type Coercion
```python
# BAD: Trust input type
amount = request.json["amount"]

# GOOD: Explicit type conversion
try:
    amount = int(request.json["amount"])
except (ValueError, TypeError):
    return error("Invalid amount")
```

## Validation Checklist

- [ ] Type juggling tested for all inputs
- [ ] Mass assignment tested for all endpoints
- [ ] Parameter pollution tested
- [ ] Integer overflow/underflow tested
- [ ] String length limits enforced
- [ ] Unicode normalization tested
- [ ] URL encoding tested
- [ ] Input validation on all fields
