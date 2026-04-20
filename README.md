# 🎣 FUTURE_CS_02 — Phishing Email Detection & Awareness System

**Internship:** Future Interns — Cyber Security Track  
**Task:** Task 2 — Phishing Email Detection & Awareness System  
**Track Code:** CS  
**Report Date:** April 2026  

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [What is Phishing?](#what-is-phishing)
3. [Phishing Indicator Framework](#phishing-indicator-framework)
4. [Email Sample Analysis](#email-sample-analysis)
5. [Classification Results](#classification-results)
6. [Phishing Techniques Explained](#phishing-techniques-explained)
7. [Prevention & Awareness Guidelines](#prevention--awareness-guidelines)
8. [References](#references)

---

## 1. Executive Summary

This report presents an analysis of phishing email samples to identify common attack indicators, classify their threat level, and provide clear guidance to help users and organizations recognize and avoid phishing attacks.

**Phishing remains the #1 initial attack vector** in data breaches worldwide. This task analyzed **5 email samples** across different phishing categories.

| Classification | Count |
|---------------|-------|
| 🔴 Phishing   | 3     |
| 🟠 Suspicious | 1     |
| 🟢 Safe       | 1     |

---

## 2. What is Phishing?

**Phishing** is a type of social engineering attack where cybercriminals impersonate trusted entities (banks, employers, government agencies, popular services) via email to trick victims into:

- Clicking malicious links
- Downloading malware
- Revealing passwords or financial information
- Transferring money or gift cards

> 💡 **Simple explanation:** Phishing is the digital equivalent of a scammer calling you and pretending to be your bank. Instead of the phone, they use email — and instead of voice, they use fake logos, urgent language, and spoofed addresses.

---

## 3. Phishing Indicator Framework

When analyzing any email, check for these key red flags:

### 🔍 Sender Analysis
| Indicator | What to Look For |
|-----------|-----------------|
| Spoofed Display Name | Name says "PayPal Support" but email is `paypal-support@randomdomain.xyz` |
| Domain Lookalike | `arnazon.com`, `paypa1.com`, `microsoft-support.net` |
| Free Email Provider | Legitimate banks never use `@gmail.com` or `@yahoo.com` |
| Reply-To Mismatch | Reply-To address differs from the From address |

### 🔍 Content Analysis
| Indicator | What to Look For |
|-----------|-----------------|
| Urgency / Fear | "Your account will be suspended in 24 hours!" |
| Too-Good-To-Be-True | "You've won a $500 Amazon gift card!" |
| Grammar & Spelling | Unusual phrasing, inconsistent capitalization, typos |
| Generic Greeting | "Dear Customer" instead of your actual name |
| Suspicious Attachments | `.exe`, `.zip`, `.docm`, unexpected invoice PDFs |

### 🔍 Link Analysis
| Indicator | What to Look For |
|-----------|-----------------|
| Mismatched URL | Link text says `paypal.com` but points to `paypa1-secure.ru` |
| URL Shorteners | `bit.ly/...`, `tinyurl.com/...` hiding destination |
| Suspicious TLDs | `.xyz`, `.ru`, `.tk`, `.cn` for impersonated US brands |
| HTTP instead of HTTPS | Legitimate login pages always use HTTPS |

---

## 4. Email Sample Analysis

---

### 📧 Sample 1 — "Urgent: Verify Your Bank Account"
**Classification: 🔴 PHISHING**

```
From:    "Chase Bank Security" <security-alert@chase-verify.net>
To:      victim@example.com
Subject: ⚠️ URGENT: Your account has been compromised — verify now
Date:    Mon, 14 Apr 2025 09:23:11 -0400

Dear Valued Customer,

We have detected unusual activity on your account. Your online 
banking access has been temporarily limited.

To restore full access, please verify your identity immediately:

[VERIFY MY ACCOUNT NOW]  ← links to http://chase-login.verify-secure.xyz/login

Failure to verify within 24 hours will result in permanent suspension.

Chase Bank Security Team
```

**Indicators Identified:**

| # | Indicator | Detail | Severity |
|---|-----------|--------|---------|
| 1 | Spoofed Domain | Sender uses `chase-verify.net` — NOT `chase.com` | 🔴 High |
| 2 | Urgency Language | "Failure to verify will result in permanent suspension" | 🔴 High |
| 3 | Suspicious Link | URL points to `chase-login.verify-secure.xyz` — fake domain | 🔴 High |
| 4 | HTTP Link | Login page link uses HTTP, not HTTPS | 🟠 Medium |
| 5 | Generic Greeting | "Dear Valued Customer" — no personalization | 🟠 Medium |
| 6 | Suspicious TLD | `.xyz` is a common phishing TLD | 🔴 High |

**Technique:** Credential Harvesting via Fake Login Page  
**Target:** Banking credentials / personal information  

---

### 📧 Sample 2 — "You've Won! Claim Your Prize"
**Classification: 🔴 PHISHING**

```
From:    "Amazon Rewards" <rewards@amaz0n-gifts.com>
To:      victim@example.com
Subject: 🎁 Congratulations! You've been selected for a $500 gift card

Hi there,

You are one of our lucky winners this month!
Click below to claim your FREE $500 Amazon Gift Card before it expires.

[CLAIM YOUR GIFT CARD]  ← links to http://bit.ly/am4z0n-reward-claim

Offer expires in: 02:34:17  ← fake countdown timer

Amazon Customer Team
```

**Indicators Identified:**

| # | Indicator | Detail | Severity |
|---|-----------|--------|---------|
| 1 | Lookalike Domain | `amaz0n-gifts.com` — zero instead of 'o' | 🔴 High |
| 2 | Too-Good-To-Be-True | Unsolicited $500 prize with no prior entry | 🔴 High |
| 3 | URL Shortener | `bit.ly` link hides actual destination | 🟠 Medium |
| 4 | Fake Countdown | Artificial urgency via countdown timer | 🟠 Medium |
| 5 | Generic Greeting | "Hi there" — no personalization | 🟡 Low |

**Technique:** Prize/Reward Lure → Credential/Payment harvesting  
**Target:** Personal information, credit card details  

---

### 📧 Sample 3 — "IT Department: Password Reset Required"
**Classification: 🔴 PHISHING (Spear Phishing)**

```
From:    "IT Helpdesk" <it-support@company-helpdesk.net>
To:      employee@targetcompany.com
Subject: [ACTION REQUIRED] Your company password expires tonight

Hello,

Your Microsoft 365 password is scheduled to expire at 11:59 PM tonight.
Please reset your password immediately to avoid losing email access.

[RESET PASSWORD]  ← links to https://microsoft-reset.company-helpdesk.net/login

If you have questions, contact IT at extension 5500.

IT Support Team
CompanyName Corporation
```

**Indicators Identified:**

| # | Indicator | Detail | Severity |
|---|-----------|--------|---------|
| 1 | Impersonation | Pretends to be internal IT — domain is external | 🔴 High |
| 2 | Credential Target | Attempts to capture Microsoft 365 credentials | 🔴 High |
| 3 | Fake Reset URL | `microsoft-reset.company-helpdesk.net` — not Microsoft | 🔴 High |
| 4 | Urgency Language | Password "expires tonight" creates false pressure | 🟠 Medium |
| 5 | Plausible Lure | References a real tool (Microsoft 365) to seem legitimate | 🟠 Medium |

**Technique:** Spear Phishing + Corporate Credential Harvesting  
**Target:** Microsoft 365 / corporate credentials  

---

### 📧 Sample 4 — "Invoice #INV-2847 Attached"
**Classification: 🟠 SUSPICIOUS**

```
From:    "Accounting Dept" <accounting@globalventures-ltd.com>
To:      finance@targetcompany.com
Subject: Invoice #INV-2847 — Please process

Hi,

Please find the attached invoice for processing.

Total Amount: $4,250.00
Due Date: April 20, 2025

Let me know if you have any questions.

Regards,
Michael Thompson
Global Ventures Ltd
```

**Indicators Identified:**

| # | Indicator | Detail | Severity |
|---|-----------|--------|---------|
| 1 | Unexpected Invoice | No prior business context — could be BEC | 🟠 Medium |
| 2 | Generic Greeting | "Hi" with no specific recipient name | 🟡 Low |
| 3 | Unknown Sender | `globalventures-ltd.com` — unverified vendor | 🟠 Medium |
| 4 | No Attachment Shown | If attachment is `.docm` or `.exe`, escalate to Phishing | ⚠️ Verify |

**Note:** This email is classified Suspicious rather than confirmed Phishing because it lacks obvious malicious links or extreme urgency. However, the unsolicited invoice is a classic Business Email Compromise (BEC) pattern. **Do not open any attachment without verifying with the sender via phone.**

---

### 📧 Sample 5 — "Your Google Account Security Alert"
**Classification: 🟢 SAFE**

```
From:    "Google" <no-reply@accounts.google.com>
To:      user@gmail.com
Subject: Security alert for your Google Account

Hi [Name],

A new sign-in to your Google Account was detected.

Device: Chrome on Windows
Location: Nairobi, Kenya
Time: April 17, 2025, 10:42 AM

If this was you, no action is needed.
If you don't recognize this activity, secure your account at:
https://myaccount.google.com/security

The Google Accounts Team
```

**Verification Points:**

| # | Check | Result |
|---|-------|--------|
| 1 | Sender domain | `@accounts.google.com` — legitimate Google domain | ✅ Pass |
| 2 | Link destination | `myaccount.google.com` — official Google property | ✅ Pass |
| 3 | No urgency manipulation | No threats or countdown timers | ✅ Pass |
| 4 | Personalized greeting | Uses actual account name | ✅ Pass |
| 5 | No credential request | Directs to official Google site, no inline form | ✅ Pass |

---

## 5. Classification Results

```
┌─────────────────────────────────────────────────────┐
│           EMAIL CLASSIFICATION SUMMARY               │
├──────────────────┬────────────────┬─────────────────┤
│ Sample           │ Classification │ Risk Level      │
├──────────────────┼────────────────┼─────────────────┤
│ Sample 1 (Bank)  │ 🔴 PHISHING    │ HIGH            │
│ Sample 2 (Prize) │ 🔴 PHISHING    │ HIGH            │
│ Sample 3 (IT)    │ 🔴 PHISHING    │ HIGH (Spear)    │
│ Sample 4 (Inv.)  │ 🟠 SUSPICIOUS  │ MEDIUM          │
│ Sample 5 (Google)│ 🟢 SAFE        │ NONE            │
└──────────────────┴────────────────┴─────────────────┘
```

---

## 6. Phishing Techniques Explained

### 🎭 Spoofing
Attackers forge the "From" display name to appear as a trusted entity. The actual sending domain, however, is different from the legitimate one.
> **Example:** Display name says "PayPal" but email comes from `paypal-support@randomdomain.xyz`

### 🔗 Homograph / Typosquatting Domains
Replacing characters in a domain name with look-alikes:
- `arnazon.com` (rn looks like m)
- `paypa1.com` (1 instead of l)
- `micros0ft.com` (zero instead of o)

### ⏰ Urgency & Fear Tactics
Creating artificial time pressure to bypass the victim's critical thinking:
- "Your account will be closed in 2 hours"
- "Unauthorized access detected — act now"
- Fake countdown timers

### 🏢 Spear Phishing
Highly targeted attacks that reference specific names, job titles, or company information to appear more credible. More dangerous than generic phishing.

### 💼 Business Email Compromise (BEC)
Impersonating executives, vendors, or colleagues to request fraudulent wire transfers or sensitive documents.

---

## 7. Prevention & Awareness Guidelines

### For Individual Users

| ✅ Do This | ❌ Avoid This |
|-----------|--------------|
| Always check the actual sender email address | Trusting only the display name |
| Hover over links before clicking | Clicking links in unexpected emails |
| Verify urgent requests via phone | Responding to email alone for sensitive requests |
| Enable Multi-Factor Authentication (MFA) | Using the same password across sites |
| Report suspicious emails to IT/security | Ignoring or deleting without reporting |
| Keep software and browsers updated | Running outdated email clients |

### For Organizations

1. **Deploy Email Authentication Protocols**
   - `SPF` (Sender Policy Framework) — validates sending servers
   - `DKIM` (DomainKeys Identified Mail) — cryptographic email signing
   - `DMARC` — enforces SPF/DKIM policies and provides reporting

2. **Enable Anti-Phishing Filters**
   - Microsoft Defender for Office 365 Anti-Phishing
   - Google Workspace Advanced Protection

3. **Conduct Regular Phishing Simulations**
   - Use platforms like KnowBe4, Proofpoint, or Gophish to run internal phishing drills

4. **User Awareness Training**
   - Mandatory security awareness training for all staff
   - Focus on recognizing urgency, domain spoofing, and BEC patterns

5. **Incident Response Plan**
   - Clear process for users to report phishing
   - Dedicated security inbox (e.g., `phishing@yourcompany.com`)

---

## 8. References

- [OWASP Phishing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Phishing_Prevention_Cheat_Sheet.html)
- [CISA — Phishing Guidance](https://www.cisa.gov/phishing)
- [Google Safe Browsing](https://safebrowsing.google.com)
- [PhishTank — Phishing Database](https://phishtank.org)
- [Anti-Phishing Working Group (APWG)](https://apwg.org)

---

## 📌 Disclaimer

> All email samples analyzed in this report are either **fabricated for educational purposes** or sourced from publicly available phishing datasets. No real individuals or organizations were targeted or harmed. This report is submitted as part of the Future Interns Cyber Security internship program.

---

*Report prepared by: Future Interns — Cyber Security Intern*  
*Track Code: CS | Repository: FUTURE_CS_02*
