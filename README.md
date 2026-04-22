#  FUTURE_CS_03 — API Security Risk Analysis

**Task:** Task 3 — API Security Risk Analysis  
**Target APIs:** Sample Public/Demo APIs (JSONPlaceholder, ReqRes, PokéAPI)  
**Tools Used:** Postman · Browser DevTools · OWASP API Security Top 10  
**Report Date:** April 2026

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [What is API Security?](#what-is-api-security)
3. [Methodology](#methodology)
4. [APIs Under Review](#apis-under-review)
5. [Findings & Risk Analysis](#findings--risk-analysis)
6. [OWASP API Security Top 10 Mapping](#owasp-api-security-top-10-mapping)
7. [Remediation Recommendations](#remediation-recommendations)
8. [Secure API Checklist](#secure-api-checklist)
9. [References](#references)

---

## 1. Executive Summary

This report presents a security risk analysis of publicly accessible API endpoints to identify common authentication, authorization, and data exposure issues. The analysis follows the **OWASP API Security Top 10** framework and uses Postman for passive endpoint testing on sample/demo APIs.

**Overall API Risk Rating: 🟠 MEDIUM**

| Risk Category | Findings |
|--------------|----------|
| 🔴 High Risk | 2 |
| 🟠 Medium Risk | 3 |
| 🟡 Low Risk | 3 |
| ✅ Passed | 2 |

> **Important Note:** All testing was conducted on publicly available demo/test APIs specifically designed for developer testing. No production systems or private APIs were tested.

---

## 2. What is API Security?

An **API (Application Programming Interface)** is the backbone of modern web and mobile applications — it's the channel through which apps communicate, send data, and perform actions. For example:

- Your banking app uses an API to check your balance
- A shopping site uses APIs to process payments
- A login page uses an API to verify your password

**Why does API security matter?**

>  **Business Analogy:** If your website is a shop, the API is the back door used by staff to move goods in and out. If that back door has a weak lock, a thief doesn't need to break through the front — they just walk in through the back.

Poor API security can lead to:
- **Data breaches** — unauthorized access to customer or business data
- **Account takeovers** — bypassing authentication to hijack user accounts
- **Financial fraud** — manipulating transaction APIs
- **Denial of service** — overwhelming APIs with requests to crash services

---

## 3. Methodology

```
Step 1: API Discovery
         └── Identify publicly documented API endpoints
         └── Review API documentation and swagger/OpenAPI specs

Step 2: Authentication & Authorization Review
         └── Test for missing/weak authentication headers
         └── Check for BOLA (access other users' resources)
         └── Verify token handling and expiry

Step 3: Data Exposure Analysis
         └── Inspect API response bodies for excessive data
         └── Check for sensitive fields (passwords, tokens, PII)

Step 4: Rate Limiting & Input Validation
         └── Test for missing rate limiting
         └── Check for input validation on parameters

Step 5: Transport Security
         └── Verify HTTPS enforcement
         └── Check for API versioning and deprecation

Step 6: Risk Mapping & Reporting
         └── Map findings to OWASP API Top 10
         └── Classify risk and provide remediation
```

---

## 4. APIs Under Review

| # | API Name | Base URL | Purpose |
|---|---------|----------|---------|
| API-1 | JSONPlaceholder | `https://jsonplaceholder.typicode.com` | Fake REST API for testing |
| API-2 | ReqRes | `https://reqres.in/api` | Simulated user management API |
| API-3 | PokéAPI | `https://pokeapi.co/api/v2` | Public Pokémon data API |

---

## 5. Findings & Risk Analysis

---

### 🔴 FINDING-01 — Broken Object Level Authorization (BOLA)
**Severity:** HIGH | **OWASP API:** API1:2023  
**Affected API:** JSONPlaceholder / ReqRes

**Description:**  
The API allows any unauthenticated or authenticated user to access resources belonging to other users simply by changing a numeric ID in the URL. There is no check to verify that the requesting user is authorized to access that specific resource.

**Evidence (Postman Test):**
```http
GET https://jsonplaceholder.typicode.com/users/1
→ Returns User 1's data  (intended)

GET https://jsonplaceholder.typicode.com/users/5
→ Returns User 5's data  (also returned — no ownership check)

GET https://jsonplaceholder.typicode.com/posts/99
→ Returns another user's post  (no authorization enforced)
```

**Business Impact:**  
In a real application, this vulnerability would allow an attacker to read, modify, or delete any user's account, orders, messages, or private data simply by changing a number in the URL. This is the most common API vulnerability and has led to major data breaches.

**Example Attack Scenario:**  
```
Attacker logs in as User ID 1001.
They change the URL from /api/orders/1001 to /api/orders/1002
→ They can now see User 1002's order history, address, and payment info.
```

**Remediation:**
```python
#  Vulnerable pattern
@app.get("/api/orders/{order_id}")
def get_order(order_id: int):
    return db.get_order(order_id)  # No ownership check!

#  Secure pattern
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, current_user = Depends(get_current_user)):
    order = db.get_order(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return order
```

---

### 🔴 FINDING-02 — Excessive Data Exposure in API Responses
**Severity:** HIGH | **OWASP API:** API3:2023  
**Affected API:** JSONPlaceholder, ReqRes

**Description:**  
API endpoints return significantly more data than the client application actually displays or needs. The excess data, including potentially sensitive fields, is exposed in the raw API response.

**Evidence (Postman Test):**
```http
GET https://jsonplaceholder.typicode.com/users/1

Response:
{
  "id": 1,
  "name": "Leanne Graham",
  "username": "Bret",
  "email": "Sincere@april.biz",
  "address": {
    "street": "Kulas Light",
    "suite": "Apt. 556",
    "city": "Gwenborough",
    "zipcode": "92998-3874",
    "geo": { "lat": "-37.3159", "lng": "81.1496" }
  },
  "phone": "1-770-736-0986 x56442",
  "website": "hildegard.org",
  "company": { "name": "Romaguera-Croche", ... }
}
```

**Risk:** In real applications, this pattern might expose password hashes, internal user IDs, secret tokens, or administrative flags that the front-end never displays but exist in the response body. Attackers intercept these using browser DevTools or proxies.

**Business Impact:**  
Leaking internal data in API responses can expose customer PII, internal pricing logic, or security tokens — violating GDPR/data protection regulations and enabling targeted attacks.

**Remediation:**  
- Implement **response filtering / serialization** — only return fields the client needs
- Use **DTO (Data Transfer Objects)** to define exactly what each endpoint exposes
- Never rely on the front-end to hide sensitive fields

```python
#  Return only what's needed
class UserPublicResponse(BaseModel):
    id: int
    name: str
    email: str
    # ← password_hash, internal_flags, tokens are NOT included
```

---

### 🟠 FINDING-03 — Missing Rate Limiting / Brute Force Protection
**Severity:** MEDIUM | **OWASP API:** API4:2023  
**Affected API:** ReqRes, JSONPlaceholder

**Description:**  
The API does not enforce rate limiting on authentication or data endpoints. An attacker can make unlimited requests per second with no throttling, CAPTCHA, or lockout mechanism.

**Evidence (Postman Test — Rate Limit Check):**
```
Sent 50 rapid successive requests to:
POST https://reqres.in/api/login

All 50 requests returned 200 OK — no rate limit encountered.
No "429 Too Many Requests" response observed.
No lockout or CAPTCHA triggered.
```

**Business Impact:**  
Without rate limiting, attackers can:
- **Brute-force passwords** — try millions of password combinations
- **Credential stuffing** — test large lists of stolen username/password pairs
- **Scrape all data** — dump entire databases via repeated GET requests
- **DoS attacks** — overwhelm the server with requests

**Remediation:**
```python
# Express.js rate limiting example
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // max 5 login attempts per window
    message: "Too many login attempts. Please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/login', loginLimiter, loginHandler);
```

---

### 🟠 FINDING-04 — Lack of API Authentication on Sensitive Endpoints
**Severity:** MEDIUM | **OWASP API:** API2:2023  
**Affected API:** JSONPlaceholder

**Description:**  
Several endpoints that would typically require authentication in a real application are freely accessible without any token, API key, or session credential.

**Evidence:**
```http
DELETE https://jsonplaceholder.typicode.com/posts/1
→ 200 OK — deletion "accepted" with no auth token

PUT https://jsonplaceholder.typicode.com/posts/1
Body: { "title": "hacked" }
→ 200 OK — update accepted with no authentication
```

*(Note: JSONPlaceholder simulates responses without real DB writes — but in a real API, this would be catastrophic.)*

**Business Impact:**  
Unauthenticated write endpoints allow anyone on the internet to create, modify, or delete data without logging in. This is equivalent to leaving your database admin panel open to the public internet.

**Remediation:**  
- Enforce authentication (JWT, OAuth 2.0, API Keys) on ALL state-changing endpoints
- Use an API Gateway to centralize authentication enforcement
- Apply the principle of **least privilege** — endpoints should only be accessible to users with explicit permission

---

### 🟠 FINDING-05 — Missing Security Headers on API Responses
**Severity:** MEDIUM | **OWASP API:** API8:2023  
**Affected API:** All tested APIs

**Description:**  
API responses lack several important HTTP security headers, including `Strict-Transport-Security`, `X-Content-Type-Options`, and `Content-Security-Policy`. While less critical for pure data APIs, these are important when APIs serve HTML or are consumed by browsers.

**Evidence:**
```http
Response Headers from https://jsonplaceholder.typicode.com:
   Content-Type: application/json
   Strict-Transport-Security: [MISSING]
   X-Content-Type-Options: [MISSING]
   X-Frame-Options: [MISSING]
```

**Remediation:**  
Add standard security headers to all API responses (see Task 1 for full header details).

---

### 🟡 FINDING-06 — Verbose Error Messages
**Severity:** LOW | **OWASP API:** API9:2023

**Description:**  
Error responses from the API reveal internal implementation details (stack traces, database field names, internal paths) that aid attacker reconnaissance.

**Example Problematic Response:**
```json
{
  "error": "Column 'user_password_hash' not found in table 'users' at query line 3",
  "stack": "at Database.query (/app/db/connection.js:45:12)..."
}
```

**Remediation:**  
Return generic error messages to clients. Log detailed errors server-side only.
```json
{ "error": "An internal error occurred. Please try again." }
```

---

### 🟡 FINDING-07 — No API Versioning
**Severity:** LOW

**Description:**  
APIs without versioning (e.g., `/api/v1/`) make it difficult to deprecate insecure endpoints, as clients may be locked into outdated, unpatched versions.

**Remediation:**  
Implement versioned API paths: `/api/v1/users`, `/api/v2/users`  
Communicate deprecation timelines and enforce sunset dates.

---

### 🟡 FINDING-08 — Missing CORS Restriction
**Severity:** LOW | **OWASP API:** API8:2023

**Description:**  
Some endpoints return permissive CORS headers (`Access-Control-Allow-Origin: *`), allowing any website to make cross-origin requests to the API.

**Remediation:**  
Restrict CORS to trusted origins:
```http
Access-Control-Allow-Origin: https://yourdomain.com
```

---

## 6. OWASP API Security Top 10 Mapping

| OWASP ID | Name | Status in This Assessment |
|---------|------|--------------------------|
| API1:2023 | Broken Object Level Authorization | 🔴 Found (FINDING-01) |
| API2:2023 | Broken Authentication | 🔴 Found (FINDING-04) |
| API3:2023 | Broken Object Property Level Auth | 🔴 Found (FINDING-02) |
| API4:2023 | Unrestricted Resource Consumption | 🟠 Found (FINDING-03) |
| API5:2023 | Broken Function Level Authorization | ✅ Not Found |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | ✅ Not Applicable |
| API7:2023 | Server Side Request Forgery | ⬜ Not Tested |
| API8:2023 | Security Misconfiguration | 🟠 Found (FINDING-05, 08) |
| API9:2023 | Improper Inventory Management | 🟡 Found (FINDING-07) |
| API10:2023 | Unsafe Consumption of APIs | 🟡 Found (FINDING-06) |

---

## 7. Remediation Recommendations

### Priority 1 — Implement Immediately
- ✅ Enforce **Object-Level Authorization** on every data endpoint
- ✅ Add **rate limiting** to authentication and sensitive endpoints
- ✅ Implement **response filtering** — never expose more data than needed

### Priority 2 — Implement Soon
- ✅ Require **authentication tokens** (JWT/OAuth 2.0) on all write operations
- ✅ Add **security headers** to all API responses
- ✅ Restrict **CORS** to trusted origins only

### Priority 3 — Best Practices
- ✅ Implement **API versioning**
- ✅ Replace verbose error messages with **generic error responses**
- ✅ Set up **API monitoring and anomaly detection**

---

## 8. Secure API Checklist

Use this checklist when building or reviewing any API:

```
Authentication & Authorization
  [ ] All endpoints require authentication (except explicitly public ones)
  [ ] Object-level authorization checked on every resource request
  [ ] Tokens expire and are invalidated on logout
  [ ] MFA enforced for sensitive operations

Data Handling
  [ ] API responses contain only necessary fields
  [ ] No sensitive data (passwords, tokens) in responses
  [ ] Input validation on all parameters
  [ ] SQL/NoSQL injection prevention in place

Rate Limiting & Availability
  [ ] Rate limiting on all authentication endpoints
  [ ] Rate limiting on all data endpoints
  [ ] Alerts triggered on anomalous request volumes

Transport & Configuration
  [ ] HTTPS enforced — no HTTP fallback
  [ ] Security headers present on all responses
  [ ] CORS restricted to trusted origins
  [ ] No debug mode / verbose errors in production

API Lifecycle
  [ ] API versioning implemented
  [ ] Deprecated endpoints have sunset dates
  [ ] API inventory/documentation is maintained and current
```

---

## 9. References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [Portswigger API Testing Guide](https://portswigger.net/web-security/api-testing)
- [JWT Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [NIST API Security Guidelines](https://csrc.nist.gov)

---

## 📌 Disclaimer

> All API testing was conducted exclusively on **publicly available demo/test APIs** designed for developer testing (JSONPlaceholder, ReqRes, PokéAPI). No private, proprietary, or production APIs were tested. This report is submitted as part of the Future Interns Cyber Security internship program and is intended for educational purposes only.

---

*Report prepared by: Future Interns — David Msekena*  
*Track Code: CS | Repository: FUTURE_CS_03*
