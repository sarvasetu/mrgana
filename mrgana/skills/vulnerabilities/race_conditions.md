---
name: race_condition_testing
description: Advanced race condition and TOCTOU vulnerability testing techniques
---

# Race Condition Testing

## Overview
Race conditions occur when the timing or ordering of operations affects the correctness of a program. Testing for race conditions requires sending concurrent requests and analyzing responses for inconsistencies.

## Testing Methodology

### 1. Parallel Request Technique
Use Python's `concurrent.futures` or `asyncio` to send simultaneous requests:

```python
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

async def race_condition_test(url, method, headers, payload, num_requests=10):
    """Send parallel requests to detect race conditions"""
    results = []
    
    async def send_request(session, request_id):
        try:
            async with session.request(method, url, headers=headers, json=payload) as resp:
                result = {
                    'request_id': request_id,
                    'status': resp.status,
                    'body': await resp.text()
                }
                return result
        except Exception as e:
            return {'request_id': request_id, 'error': str(e)}
    
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, i) for i in range(num_requests)]
        results = await asyncio.gather(*tasks)
    
    return results
```

### 2. Key Race Condition Vectors

#### Balance/Amount Manipulation
```python
# Test double-spending or balance manipulation
async def test_double_spend(session, transfer_url, from_account, to_account, amount):
    """Test if concurrent transfers cause double-spending"""
    payload = {
        "from": from_account,
        "to": to_account,
        "amount": amount
    }
    
    # Send 10 concurrent transfer requests
    tasks = [
        session.post(transfer_url, json=payload)
        for _ in range(10)
    ]
    
    responses = await asyncio.gather(*tasks)
    successful = sum(1 for r in responses if r.status == 200)
    
    # If more than 1 succeeded, race condition exists
    return successful > 1
```

#### Coupon/Discount Abuse
```python
# Test if same coupon can be used multiple times
async def test_coupon_race(session, apply_url, coupon_code, order_id):
    """Test if concurrent coupon applications succeed"""
    payload = {
        "coupon": coupon_code,
        "order_id": order_id
    }
    
    tasks = [
        session.post(apply_url, json=payload)
        for _ in range(5)
    ]
    
    responses = await asyncio.gather(*tasks)
    successful = sum(1 for r in responses if r.status == 200)
    
    return successful > 1
```

#### Registration/Account Creation
```python
# Test if duplicate accounts can be created
async def test_duplicate_registration(session, register_url, email, password):
    """Test if concurrent registrations with same email succeed"""
    payload = {
        "email": email,
        "password": password,
        "name": "Test User"
    }
    
    tasks = [
        session.post(register_url, json=payload)
        for _ in range(5)
    ]
    
    responses = await asyncio.gather(*tasks)
    successful = sum(1 for r in responses if r.status == 201)
    
    return successful > 1
```

#### Voting/Like Manipulation
```python
# Test if concurrent votes are counted correctly
async def test_vote_race(session, vote_url, content_id):
    """Test if concurrent votes cause incorrect count"""
    initial_count = await get_vote_count(session, content_id)
    
    tasks = [
        session.post(vote_url, json={"content_id": content_id})
        for _ in range(10)
    ]
    
    await asyncio.gather(*tasks)
    final_count = await get_vote_count(session, content_id)
    
    # Count should increase by exactly 10
    return (final_count - initial_count) != 10
```

### 3. Analysis Techniques

#### Response Analysis
```python
def analyze_race_results(responses):
    """Analyze race condition test results"""
    status_codes = [r['status'] for r in responses if 'status' in r]
    
    # Check for mixed success/failure
    has_success = any(s in [200, 201, 202] for s in status_codes)
    has_failure = any(s in [400, 409, 422, 500] for s in status_codes)
    
    # Mixed results indicate race condition
    race_condition = has_success and has_failure
    
    # Check for duplicate success
    success_count = sum(1 for s in status_codes if s in [200, 201, 202])
    duplicate_success = success_count > 1
    
    return {
        'race_condition': race_condition,
        'duplicate_success': duplicate_success,
        'total_requests': len(responses),
        'successful': success_count,
        'failed': len(status_codes) - success_count
    }
```

### 4. Common Race Condition Vulnerabilities

| Vulnerability | Test Method | Expected Result |
|---------------|-------------|-----------------|
| Double-spending | Concurrent transfers | Only 1 should succeed |
| Coupon abuse | Concurrent applications | Only 1 should apply |
| Duplicate registration | Concurrent signups | Only 1 should succeed |
| Vote manipulation | Concurrent votes | Count should match requests |
| Point accumulation | Concurrent rewards | Points should be correct |
| Rate limit bypass | Concurrent requests | Rate limit should hold |
| Privilege escalation | Concurrent role changes | Role should change once |
| Resource exhaustion | Concurrent allocations | Limits should be enforced |

### 5. Tools Integration

#### Using Caido Proxy
```bash
# Send parallel requests through proxy
for i in {1..10}; do
    curl -X POST http://target/api/transfer \
        -H "Content-Type: application/json" \
        -d '{"from":"account1","to":"account2","amount":100}' &
done
wait
```

#### Using Python Script in Sandbox
```python
#!/usr/bin/env python3
"""Race condition testing script"""
import asyncio
import aiohttp
import json

async def test_endpoint(session, url, payload, num_requests=10):
    """Generic race condition test"""
    tasks = [session.post(url, json=payload) for _ in range(num_requests)]
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    
    results = []
    for i, r in enumerate(responses):
        if isinstance(r, Exception):
            results.append({'id': i, 'error': str(r)})
        else:
            results.append({'id': i, 'status': r.status, 'body': await r.text()})
    
    return results

async def main():
    url = "http://target.com/api/v1/transfer"
    payload = {
        "from_account": "acc_123",
        "to_account": "acc_456",
        "amount": 100
    }
    
    async with aiohttp.ClientSession() as session:
        results = await test_endpoint(session, url, payload)
        
    # Analyze results
    success_count = sum(1 for r in results if r.get('status') in [200, 201])
    print(f"Successful requests: {success_count}/{len(results)}")
    
    if success_count > 1:
        print("VULNERABILITY: Race condition detected!")
        print(f"Expected: 1 success, Got: {success_count}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 6. Remediation Guidance

#### Prevent Race Conditions
1. **Use database transactions** with proper isolation levels
2. **Implement distributed locks** for critical operations
3. **Use atomic operations** (e.g., `UPDATE ... WHERE balance >= amount`)
4. **Implement idempotency keys** for API endpoints
5. **Use optimistic locking** with version numbers
6. **Rate limit at business logic level**, not just API level

#### Example Fixes
```python
# BAD: Non-atomic balance check and update
balance = get_balance(account_id)
if balance >= amount:
    update_balance(account_id, balance - amount)

# GOOD: Atomic operation
execute("UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s", 
        (amount, account_id, amount))
```

## Validation Checklist

- [ ] Test with 5, 10, 20 concurrent requests
- [ ] Test with different timing intervals (0ms, 10ms, 50ms delays)
- [ ] Verify response codes and body content
- [ ] Check database state after test
- [ ] Test with authenticated and unauthenticated users
- [ ] Test across different user roles
