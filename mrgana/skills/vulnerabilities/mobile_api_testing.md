---
name: mobile_api_testing
description: Mobile application API security testing including authentication, authorization, data exposure, and transport security
---

# Mobile API Security Testing

## Overview
Mobile apps communicate with backend APIs that often have different security postures than web apps. Testing must cover authentication, authorization, data exposure, and transport security.

## Testing Methodology

### 1. API Discovery

#### Intercept Mobile Traffic
```bash
# Using mitmproxy (if available)
mitmproxy --mode regular --listen-port 8080

# Configure mobile device to use proxy
# Settings > WiFi > HTTP Proxy > Manual
# Server: <your-ip>, Port: 8080

# Using Caido proxy
caido-cli --listen 0.0.0.0:8080
```

#### Extract API Endpoints
```bash
# Decompile APK and search for URLs
grep -rn "https://\|http://" /tmp/decompiled/ --include="*.java" --include="*.xml" | grep -v "android.com\|google.com"

# Search for Retrofit endpoints (Android)
grep -rn "@GET\|@POST\|@PUT\|@DELETE\|@PATCH" /tmp/decompiled/ --include="*.java"

# Search for Alamofire endpoints (iOS)
grep -rn "AF.request\|Alamofire" /tmp/ipa_extracted/ --include="*.swift"
```

### 2. Authentication Testing

#### Test Token Handling
```python
import requests
import json

def test_token_security(api_base, token):
    """Test token security mechanisms"""
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test token in different locations
    tests = {
        "header": {"Authorization": f"Bearer {token}"},
        "query": {"token": token},
        "cookie": {"session": token}
    }
    
    results = {}
    for location, test_headers in tests.items():
        response = requests.get(f"{api_base}/api/user", headers=test_headers)
        results[location] = response.status_code
    
    return results
```

#### Test Token Expiration
```python
def test_token_expiration(api_base, token):
    """Test if tokens expire properly"""
    headers = {"Authorization": f"Bearer {token}"}
    
    # Make multiple requests over time
    import time
    
    for i in range(5):
        response = requests.get(f"{api_base}/api/user", headers=headers)
        print(f"Request {i+1}: {response.status_code}")
        time.sleep(60)  # Wait 1 minute
    
    return response.status_code == 401
```

#### Test Refresh Token Flow
```python
def test_refresh_token(api_base, refresh_token):
    """Test refresh token mechanism"""
    # Request new access token
    response = requests.post(f"{api_base}/api/auth/refresh", json={
        "refresh_token": refresh_token
    })
    
    if response.status_code == 200:
        new_token = response.json().get("access_token")
        
        # Test if old token is invalidated
        old_response = requests.get(f"{api_base}/api/user", headers={
            "Authorization": f"Bearer {old_token}"
        })
        
        # Test new token works
        new_response = requests.get(f"{api_base}/api/user", headers={
            "Authorization": f"Bearer {new_token}"
        })
        
        return {
            "old_token_invalidated": old_response.status_code == 401,
            "new_token_works": new_response.status_code == 200
        }
    
    return {"error": "Refresh failed"}
```

### 3. Authorization Testing

#### Horizontal Privilege Escalation
```python
def test_horizontal_escalation(api_base, token, target_user_id):
    """Test if user can access other users' data"""
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try to access other user's data
    endpoints = [
        f"/api/users/{target_user_id}",
        f"/api/users/{target_user_id}/profile",
        f"/api/users/{target_user_id}/settings",
        f"/api/orders?user_id={target_user_id}"
    ]
    
    results = []
    for endpoint in endpoints:
        response = requests.get(f"{api_base}{endpoint}", headers=headers)
        results.append({
            "endpoint": endpoint,
            "status": response.status_code,
            "accessible": response.status_code == 200
        })
    
    return results
```

#### Vertical Privilege Escalation
```python
def test_vertical_escalation(api_base, user_token):
    """Test if regular user can access admin endpoints"""
    headers = {"Authorization": f"Bearer {user_token}"}
    
    admin_endpoints = [
        "/api/admin/users",
        "/api/admin/settings",
        "/api/admin/logs",
        "/api/admin/reports",
        "/api/internal/debug"
    ]
    
    results = []
    for endpoint in admin_endpoints:
        response = requests.get(f"{api_base}{endpoint}", headers=headers)
        results.append({
            "endpoint": endpoint,
            "status": response.status_code,
            "accessible": response.status_code == 200
        })
    
    return results
```

### 4. Data Exposure Testing

#### Test Response Data
```python
def test_data_exposure(api_base, token):
    """Test if API exposes sensitive data"""
    headers = {"Authorization": f"Bearer {token}"}
    
    sensitive_fields = [
        "password", "password_hash", "secret", "api_key",
        "credit_card", "ssn", "token", "private_key"
    ]
    
    response = requests.get(f"{api_base}/api/user", headers=headers)
    data = response.json()
    
    exposed = []
    for field in sensitive_fields:
        if field in str(data).lower():
            exposed.append(field)
    
    return exposed
```

#### Test Error Messages
```python
def test_error_disclosure(api_base):
    """Test if error messages leak information"""
    # Send invalid request
    response = requests.post(f"{api_base}/api/login", json={
        "email": "nonexistent@test.com",
        "password": "wrongpassword"
    })
    
    error_msg = response.json().get("error", "")
    
    # Check for information disclosure
    disclosures = []
    if "user not found" in error_msg.lower():
        disclosures.append("User enumeration possible")
    if "invalid password" in error_msg.lower():
        disclosures.append("Password validation disclosed")
    if "sql" in error_msg.lower():
        disclosures.append("SQL error disclosed")
    if "stack trace" in error_msg.lower():
        disclosures.append("Stack trace disclosed")
    
    return disclosures
```

### 5. Transport Security Testing

#### Test HTTPS Enforcement
```python
def test_https_enforcement(api_base):
    """Test if HTTP is redirected to HTTPS"""
    http_base = api_base.replace("https://", "http://")
    
    response = requests.get(f"{http_base}/api/user", allow_redirects=False)
    
    return {
        "redirects_to_https": response.status_code in [301, 302, 307, 308],
        "location": response.headers.get("Location")
    }
```

#### Test Certificate Pinning
```python
def test_certificate_pinning(api_base):
    """Test if certificate pinning is enforced"""
    import ssl
    import urllib.request
    
    # Try to connect with custom CA
    ctx = ssl.create_default_context()
    # Add custom CA to context
    
    try:
        response = urllib.request.urlopen(api_base, context=ctx)
        return {"pinning_enforced": False}
    except ssl.SSLCertificateError:
        return {"pinning_enforced": True}
```

### 6. Input Validation Testing

#### Test Injection Attacks
```python
def test_injection(api_base, token):
    """Test for injection vulnerabilities"""
    headers = {"Authorization": f"Bearer {token}"}
    
    payloads = {
        "sql": "' OR '1'='1",
        "xss": "<script>alert(1)</script>",
        "command": "; ls",
        "nosql": '{"$gt": ""}'
    }
    
    results = []
    for attack_type, payload in payloads.items():
        response = requests.get(
            f"{api_base}/api/search",
            params={"q": payload},
            headers=headers
        )
        
        if response.status_code == 200:
            results.append({
                "attack": attack_type,
                "vulnerable": True
            })
    
    return results
```

### 7. Rate Limiting Testing

#### Test Rate Limits
```python
def test_rate_limiting(api_base, token):
    """Test if rate limiting is enforced"""
    headers = {"Authorization": f"Bearer {token}"}
    
    # Send rapid requests
    results = []
    for i in range(100):
        response = requests.get(f"{api_base}/api/data", headers=headers)
        results.append(response.status_code)
        
        if response.status_code == 429:
            return {
                "rate_limited": True,
                "limit_reached_at": i + 1
            }
    
    return {
        "rate_limited": False,
        "total_requests": len(results)
    }
```

### 8. Tools & Scripts

#### Mobile API Scanner
```python
#!/usr/bin/env python3
"""Mobile API security scanner"""
import requests
import json
from typing import Dict, List, Any

class MobileAPIScanner:
    def __init__(self, api_base: str, token: str = None):
        self.api_base = api_base
        self.token = token
        self.headers = {}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.findings: List[Dict[str, Any]] = []
    
    def test_authentication(self):
        """Test authentication mechanisms"""
        # Test without token
        response = requests.get(f"{self.api_base}/api/user")
        if response.status_code != 401:
            self.findings.append({
                "type": "NO_AUTHENTICATION",
                "severity": "CRITICAL",
                "description": "Endpoint accessible without authentication"
            })
        
        # Test with invalid token
        response = requests.get(f"{self.api_base}/api/user", headers={
            "Authorization": "Bearer invalid_token"
        })
        if response.status_code != 401:
            self.findings.append({
                "type": "INVALID_TOKEN_ACCEPTED",
                "severity": "CRITICAL",
                "description": "Invalid token accepted"
            })
    
    def test_authorization(self, target_user_id: int = 2):
        """Test authorization mechanisms"""
        if not self.token:
            return
        
        # Try to access other user's data
        response = requests.get(f"{self.api_base}/api/users/{target_user_id}", headers=self.headers)
        if response.status_code == 200:
            self.findings.append({
                "type": "HORIZONTAL_PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "description": "Can access other users' data"
            })
    
    def test_data_exposure(self):
        """Test for sensitive data exposure"""
        if not self.token:
            return
        
        response = requests.get(f"{self.api_base}/api/user", headers=self.headers)
        if response.status_code == 200:
            data = response.json()
            sensitive_fields = ["password", "secret", "api_key", "token"]
            
            for field in sensitive_fields:
                if field in str(data).lower():
                    self.findings.append({
                        "type": "DATA_EXPOSURE",
                        "severity": "HIGH",
                        "description": f"Sensitive field exposed: {field}"
                    })
    
    def test_rate_limiting(self):
        """Test rate limiting"""
        results = []
        for i in range(50):
            response = requests.get(f"{self.api_base}/api/data")
            results.append(response.status_code)
        
        if 429 not in results:
            self.findings.append({
                "type": "NO_RATE_LIMIT",
                "severity": "MEDIUM",
                "description": "No rate limiting detected"
            })
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all API security tests"""
        print("Starting Mobile API security scan...")
        
        print("1. Testing authentication...")
        self.test_authentication()
        
        print("2. Testing authorization...")
        self.test_authorization()
        
        print("3. Testing data exposure...")
        self.test_data_exposure()
        
        print("4. Testing rate limiting...")
        self.test_rate_limiting()
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python mobile_api_scanner.py <api_base> [token]")
        sys.exit(1)
    
    token = sys.argv[2] if len(sys.argv) > 2 else None
    scanner = MobileAPIScanner(sys.argv[1], token)
    scanner.run_all_tests()
```

### 9. Common Vulnerabilities

| Vulnerability | Detection Method | Severity |
|---------------|------------------|----------|
| No authentication | Request without token | CRITICAL |
| Broken authentication | Token manipulation | CRITICAL |
| IDOR | Access other users' data | CRITICAL |
| Exposed admin endpoints | Access admin routes | CRITICAL |
| Sensitive data in responses | Response analysis | HIGH |
| Information disclosure | Error message analysis | MEDIUM |
| No rate limiting | Rapid requests | MEDIUM |
| Weak TLS | Certificate analysis | HIGH |
| Certificate pinning bypass | MITM testing | MEDIUM |
| Insecure direct object references | ID enumeration | HIGH |
| Mass assignment | Extra field injection | HIGH |
| GraphQL introspection | GraphQL queries | MEDIUM |

### 10. Remediation Guidance

#### Secure Authentication
```python
# Implement proper token validation
def validate_token(token):
    # Check token format
    if not token or not token.startswith("Bearer "):
        return False
    
    # Verify token signature
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True
    except jwt.InvalidTokenError:
        return False
```

#### Implement Authorization
```python
# Check user authorization
def check_authorization(current_user_id, requested_user_id):
    if current_user_id != requested_user_id:
        raise ForbiddenError("Access denied")
```

#### Rate Limiting
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/api/data")
@limiter.limit("100/hour")
def get_data():
    return jsonify(data)
```

#### Sanitize Error Messages
```python
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error"}), 500
```

## Validation Checklist

- [ ] Authentication required for all endpoints
- [ ] Authorization checked on every request
- [ ] No sensitive data in responses
- [ ] Error messages don't leak information
- [ ] Rate limiting enforced
- [ ] HTTPS enforced
- [ ] Certificate pinning implemented
- [ ] Input validation on all endpoints
- [ ] No IDOR vulnerabilities
- [ ] No mass assignment vulnerabilities
