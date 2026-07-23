---
name: payment_business_logic
description: Payment manipulation, price tampering, quantity abuse, and business workflow bypass testing
---

# Payment & Business Logic Testing

## Overview
Business logic vulnerabilities exploit flaws in application workflows rather than technical bugs. Testing must cover price manipulation, quantity abuse, race conditions in payments, and workflow bypasses.

## Testing Methodology

### 1. Price Manipulation

#### Direct Price Modification
```python
async def test_price_manipulation(session, checkout_url, item_id):
    """Test if price can be modified in request"""
    payloads = [
        {"item_id": item_id, "price": 0},
        {"item_id": item_id, "price": -100},
        {"item_id": item_id, "price": 0.01},
        {"item_id": item_id, "price": 1, "discount": 999999},
        {"item_id": item_id, "original_price": 100, "price": 10}
    ]
    
    results = []
    for payload in payloads:
        response = await session.post(checkout_url, json=payload)
        results.append({
            "payload": payload,
            "status": response.status,
            "body": await response.text()
        })
    
    return results
```

#### Client-Side Price Validation Bypass
```python
async def test_client_side_validation(session, checkout_url, item_id):
    """Test if price validation is only client-side"""
    # Intercept and modify price before sending
    # This requires proxy interception
    
    # Direct API call with modified price
    payload = {
        "item_id": item_id,
        "quantity": 1,
        "price": 0.01,  # Modified price
        "currency": "USD"
    }
    
    response = await session.post(checkout_url, json=payload)
    return response.status == 200
```

### 2. Quantity Manipulation

#### Negative Quantity
```python
async def test_negative_quantity(session, cart_url, item_id):
    """Test if negative quantities are allowed"""
    payload = {
        "item_id": item_id,
        "quantity": -1
    }
    
    response = await session.post(cart_url, json=payload)
    
    if response.status == 200:
        # Check if balance increased (refund attack)
        return True
    return False
```

#### Zero Quantity
```python
async def test_zero_quantity(session, cart_url, item_id):
    """Test if zero quantity is handled"""
    payload = {
        "item_id": item_id,
        "quantity": 0
    }
    
    response = await session.post(cart_url, json=payload)
    return response.status == 200
```

#### Excessive Quantity
```python
async def test_excessive_quantity(session, cart_url, item_id):
    """Test if inventory limits are enforced"""
    payload = {
        "item_id": item_id,
        "quantity": 999999
    }
    
    response = await session.post(cart_url, json=payload)
    
    if response.status == 200:
        data = response.json()
        # Check if order was placed despite inventory
        return True
    return False
```

### 3. Discount & Coupon Abuse

#### Coupon Stacking
```python
async def test_coupon_stacking(session, checkout_url, coupons):
    """Test if multiple coupons can be stacked"""
    payload = {
        "items": [{"id": "item1", "quantity": 1}],
        "coupons": coupons  # Multiple coupons
    }
    
    response = await session.post(checkout_url, json=payload)
    
    if response.status == 200:
        data = response.json()
        # Check if all discounts were applied
        return len(data.get("discounts", [])) > 1
    return False
```

#### Coupon Reuse
```python
async def test_coupon_reuse(session, checkout_url, coupon_code):
    """Test if single-use coupon can be reused"""
    # First use
    payload = {"coupon": coupon_code}
    response1 = await session.post(checkout_url, json=payload)
    
    # Second use
    response2 = await session.post(checkout_url, json=payload)
    
    # Both should succeed if vulnerable
    return response1.status == 200 and response2.status == 200
```

#### Percentage Discount Abuse
```python
async def test_percentage_discount_abuse(session, checkout_url):
    """Test if excessive percentage discounts are allowed"""
    payload = {
        "items": [{"id": "item1", "quantity": 1, "price": 100}],
        "discount_type": "percentage",
        "discount_value": 200  # 200% discount = negative total
    }
    
    response = await session.post(checkout_url, json=payload)
    
    if response.status == 200:
        data = response.json()
        # Check if total is negative (store credit attack)
        return data.get("total", 0) < 0
    return False
```

### 4. Payment Method Abuse

#### Currency Mismatch
```python
async def test_currency_mismatch(session, checkout_url):
    """Test if currency can be changed after price calculation"""
    payload = {
        "items": [{"id": "item1", "quantity": 1, "price": 100, "currency": "USD"}],
        "payment_currency": "JPY"  # Different currency
    }
    
    response = await session.post(checkout_url, json=payload)
    return response.status == 200
```

#### Payment Method Switching
```python
async def test_payment_method_switching(session, checkout_url):
    """Test if payment method can be changed after authorization"""
    # Initial payment
    payload1 = {
        "items": [{"id": "item1", "quantity": 1}],
        "payment_method": "credit_card"
    }
    response1 = await session.post(checkout_url, json=payload1)
    
    # Switch to free method
    payload2 = {
        "order_id": response1.json().get("order_id"),
        "payment_method": "free_credit"
    }
    response2 = await session.post(checkout_url + "/complete", json=payload2)
    
    return response2.status == 200
```

### 5. Workflow Bypass

#### Skipping Steps
```python
async def test_skip_steps(session, order_url):
    """Test if order steps can be skipped"""
    # Try to complete order without payment
    payload = {
        "step": "complete",
        "order_id": "new_order"
    }
    
    response = await session.post(order_url + "/complete", json=payload)
    return response.status == 200
```

#### State Manipulation
```python
async def test_state_manipulation(session, order_url, order_id):
    """Test if order state can be manipulated"""
    states = ["pending", "processing", "shipped", "delivered", "refunded"]
    
    for state in states:
        payload = {"order_id": order_id, "status": state}
        response = await session.put(order_url + f"/{order_id}", json=payload)
        
        if response.status == 200:
            print(f"State changed to {state}")
            return True
    return False
```

### 6. Race Conditions in Payments

#### Double Payment
```python
async def test_double_payment(session, payment_url, order_id):
    """Test if concurrent payments cause double charge"""
    import asyncio
    
    payload = {
        "order_id": order_id,
        "payment_method": "credit_card"
    }
    
    # Send concurrent payment requests
    tasks = [
        session.post(payment_url, json=payload)
        for _ in range(5)
    ]
    
    responses = await asyncio.gather(*tasks)
    successful = sum(1 for r in responses if r.status == 200)
    
    # Should only succeed once
    return successful > 1
```

### 7. Refund Abuse

#### Excessive Refunds
```python
async def test_excessive_refunds(session, refund_url, order_id):
    """Test if refund can exceed original amount"""
    # Refund more than paid
    payload = {
        "order_id": order_id,
        "amount": 999999
    }
    
    response = await session.post(refund_url, json=payload)
    return response.status == 200
```

#### Refund to Different Method
```python
async def test_refund_method_switching(session, refund_url, order_id):
    """Test if refund can be sent to different payment method"""
    payload = {
        "order_id": order_id,
        "refund_method": "bank_transfer",
        "account_number": "attacker_account"
    }
    
    response = await session.post(refund_url, json=payload)
    return response.status == 200
```

### 8. Tools & Scripts

#### Business Logic Scanner
```python
#!/usr/bin/env python3
"""Business logic vulnerability scanner"""
import asyncio
import aiohttp
import json
from typing import Dict, List, Any

class BusinessLogicScanner:
    def __init__(self, base_url: str, session_token: str = None):
        self.base_url = base_url
        self.session_token = session_token
        self.headers = {}
        if session_token:
            self.headers["Authorization"] = f"Bearer {session_token}"
        self.findings: List[Dict[str, Any]] = []
    
    async def test_price_manipulation(self, session: aiohttp.ClientSession):
        """Test for price manipulation vulnerabilities"""
        url = f"{self.base_url}/api/checkout"
        payloads = [
            {"item_id": "1", "price": 0},
            {"item_id": "1", "price": -100},
            {"item_id": "1", "price": 0.01},
            {"item_id": "1", "original_price": 100, "price": 10}
        ]
        
        for payload in payloads:
            async with session.post(url, json=payload, headers=self.headers) as resp:
                if resp.status == 200:
                    self.findings.append({
                        "type": "PRICE_MANIPULATION",
                        "severity": "CRITICAL",
                        "description": f"Price manipulation accepted: {payload}"
                    })
                    return True
        return False
    
    async def test_quantity_abuse(self, session: aiohttp.ClientSession):
        """Test for quantity abuse vulnerabilities"""
        url = f"{self.base_url}/api/cart"
        payloads = [
            {"item_id": "1", "quantity": -1},
            {"item_id": "1", "quantity": 0},
            {"item_id": "1", "quantity": 999999}
        ]
        
        for payload in payloads:
            async with session.post(url, json=payload, headers=self.headers) as resp:
                if resp.status == 200:
                    self.findings.append({
                        "type": "QUANTITY_ABUSE",
                        "severity": "HIGH",
                        "description": f"Quantity abuse accepted: {payload}"
                    })
                    return True
        return False
    
    async def test_coupon_abuse(self, session: aiohttp.ClientSession):
        """Test for coupon abuse vulnerabilities"""
        url = f"{self.base_url}/api/checkout"
        
        # Test coupon stacking
        payload = {
            "items": [{"id": "1", "quantity": 1}],
            "coupons": ["COUPON1", "COUPON2", "COUPON3"]
        }
        
        async with session.post(url, json=payload, headers=self.headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                if len(data.get("discounts", [])) > 1:
                    self.findings.append({
                        "type": "COUPON_STACKING",
                        "severity": "HIGH",
                        "description": "Multiple coupons accepted"
                    })
                    return True
        return False
    
    async def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all business logic tests"""
        print("Starting business logic scan...")
        
        async with aiohttp.ClientSession() as session:
            print("1. Testing price manipulation...")
            await self.test_price_manipulation(session)
            
            print("2. Testing quantity abuse...")
            await self.test_quantity_abuse(session)
            
            print("3. Testing coupon abuse...")
            await self.test_coupon_abuse(session)
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        for finding in self.findings:
            print(f"  [{finding['severity']}] {finding['description']}")
        
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python business_logic_scanner.py <base_url> [token]")
        sys.exit(1)
    
    token = sys.argv[2] if len(sys.argv) > 2 else None
    scanner = BusinessLogicScanner(sys.argv[1], token)
    asyncio.run(scanner.run_all_tests())
```

### 9. Remediation Guidance

#### Server-Side Price Validation
```python
# BAD: Client sends price
price = request.json["price"]

# GOOD: Server calculates price
item = db.get_item(item_id)
price = item.price * quantity
```

#### Inventory Checks
```python
# BAD: No inventory check
order = create_order(items)

# GOOD: Atomic inventory check
with db.transaction():
    for item in items:
        result = db.execute(
            "UPDATE inventory SET quantity = quantity - %s WHERE id = %s AND quantity >= %s",
            (item.quantity, item.id, item.quantity)
        )
        if result.rowcount == 0:
            raise InsufficientInventoryError()
```

#### Idempotency Keys
```python
# Generate unique idempotency key per payment
idempotency_key = str(uuid.uuid4())

# Check if payment already processed
existing = db.get_payment_by_idempotency(idempotency_key)
if existing:
    return existing

# Process payment
payment = process_payment(amount, idempotency_key)
```

## Validation Checklist

- [ ] Prices validated server-side
- [ ] Quantities validated (no negatives, zeros, excessive)
- [ ] Coupons cannot be stacked unless intended
- [ ] Single-use coupons cannot be reused
- [ ] Currency matches throughout transaction
- [ ] Payment method cannot be switched after authorization
- [ ] Order steps cannot be skipped
- [ ] Race conditions tested for payments
- [ ] Refund amounts cannot exceed original payment
