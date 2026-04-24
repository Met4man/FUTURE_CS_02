# Phishing Email Detection & Awareness System
### Task 2 — FUTURE_CS_02

Academic phishing analysis report submitted as part of the **Future Interns Cyber Security Internship Programme**, Institute of Finance Management, Dar es Salaam.

---

## Report Overview

| Field | Details |
|---|---|
| **Report Title** | Phishing Email Detection & Awareness System |
| **Track Code** | CS |
| **Task Reference** | FUTURE_CS_02 |
| **Analyst** | Cyber Security Intern |
| **Internship** | Future Interns |
| **Institution** | Institute of Finance Management |
| **Date** | April 2025 |
| **Classification** | Phishing Analysis — Educational |

> **Disclaimer:** All email samples analysed in this report are either fabricated for educational purposes or sourced from publicly available phishing datasets. No real individuals or organisations were targeted or harmed.

---

## Tools Used

| Tool | Purpose |
|---|---|
| **MXToolbox** | Email header analysis, SPF/DKIM/DMARC record lookup, blacklist check |
| **Outlook / Browser** | Initial receipt and inspection of raw email, header viewing |
| **VirusTotal** | URL and domain reputation scanning, threat intelligence lookup |
| **VS Code** | Manual inspection of raw `.eml` file source and header parsing |
| **OWASP ZAP** | Passive scanning of embedded URLs and web content |
| **Kali Linux** | Testing environment for all analysis activities |

---

## Email Samples Overview

| # | Subject / Type | From Address | Classification |
|---|---|---|---|
| 1 | [Action Required] Unusual Sign-in Activity | noreply@chase-verify.net | Phishing — High |
| 2 | Congratulations! You've won a $500 Gift Card | rewards@amaz0n-gifts.com | Phishing — High |
| 3 | [ACTION REQUIRED] Your password expires tonight | it-support@company-helpdesk.net | Phishing — Critical |
| 4 | Invoice #INV-2847 Attached | accounting@globalventures-ltd.com | Suspicious — Medium |
| 5 | Security alert for your Google Account | no-reply@accounts.google.com | Safe |

### Header Authentication Results

| # | Sample | SPF | DKIM | DMARC | Verdict |
|---|---|---|---|---|---|
| 1 | Bank Phishing | FAIL | FAIL | FAIL | Definitive spoofing |
| 2 | Prize Lure | FAIL | FAIL | FAIL | Definitive spoofing |
| 3 | IT Spear Phish | FAIL | FAIL | FAIL | Definitive spoofing |
| 4 | BEC Invoice | PASS | NONE | NONE | Suspicious — verify |
| 5 | Google (Legit) | PASS | PASS | PASS | Authenticated — safe |

---

## Phishing Indicators by Sample

### Sample 1 — Bank Account Credential Harvest

| # | Indicator | Technical Detail | Severity |
|---|---|---|---|
| 1 | Spoofed Sender Domain | `chase-verify.net` mimics `chase.com` | Critical |
| 2 | SPF / DKIM / DMARC All Fail | Triple authentication failure — definitive spoofing | Critical |
| 3 | URL Shortener Hiding Destination | Action button links to `bit.ly` — legitimate banks never use shorteners | High |
| 4 | Urgency & Social Engineering | `[Action Required]` + fabricated sign-in location | High |
| 5 | Generic Greeting | "Dear Valued Customer" — no personalisation | Medium |
| 6 | HTTP Login Link | Login link uses HTTP not HTTPS | High |

---

### Sample 2 — Prize / Reward Lure

| # | Indicator | Technical Detail | Severity |
|---|---|---|---|
| 1 | Lookalike Domain | `amaz0n-gifts.com` — zero replacing letter 'o' (typosquatting) | Critical |
| 2 | Too-Good-To-Be-True Offer | Unsolicited $500 prize with no prior entry | High |
| 3 | URL Shortener | `bit.ly` link concealing real destination | High |
| 4 | Fake Countdown Timer | Artificial urgency to prevent verification | Medium |
| 5 | Generic Greeting | "Hi there" — bulk campaign targeting | Low |

---

### Sample 3 — Corporate IT Spear Phishing (Critical)

| # | Indicator | Technical Detail | Severity |
|---|---|---|---|
| 1 | IT Department Impersonation | Claims to be internal helpdesk — actual domain is `company-helpdesk.net` | Critical |
| 2 | Credential Harvest Target | Fake Microsoft 365 reset page designed to capture corporate credentials | Critical |
| 3 | Fake Reset URL | `microsoft-reset.company-helpdesk.net` — not a Microsoft domain | High |
| 4 | Urgency Language | "Password expires tonight" — artificial deadline | High |
| 5 | Plausible Internal Lure | References real enterprise tool (Microsoft 365) to appear as internal IT comms | Medium |

---

### Sample 4 — Unsolicited Invoice (BEC Pattern)

Classified as **Suspicious** rather than confirmed Phishing. Matches the Business Email Compromise (BEC) pattern. The attachment must not be opened without verifying with the sender by phone.

| # | Indicator | Technical Detail | Severity |
|---|---|---|---|
| 1 | Unexpected Invoice | No prior business context — classic BEC pattern | Medium |
| 2 | Unknown Sender | `globalventures-ltd.com` — unverified vendor | Medium |
| 3 | Generic Greeting | "Hi" with no recipient name | Low |
| 4 | Unverified Attachment | If `.docm`, `.exe`, or macro-enabled — escalate immediately | Verify |

---

### Sample 5 — Legitimate Google Security Alert

| # | Check | Result | Status |
|---|---|---|---|
| 1 | Sender Domain | `no-reply@accounts.google.com` — legitimate Google domain | PASS |
| 2 | Link Destination | `myaccount.google.com` — official Google property | PASS |
| 3 | No Urgency Tactics | No threats, countdown timers, or manufactured fear | PASS |
| 4 | Personalised Greeting | Uses actual account holder name | PASS |
| 5 | No Credential Request | Directs to official Google site — no inline credential form | PASS |

---

## Risk Classification

### Classification Framework

| Classification | Criteria | Recommended Action |
|---|---|---|
| **Safe** | No suspicious indicators. Passes all authentication checks. | No action required. Deliver to inbox normally. |
| **Suspicious** | 1–2 minor indicators. Partial authentication failure. | Quarantine and review. Notify user. Do not click links. |
| **Phishing** | 3+ confirmed indicators. Clear impersonation or malicious intent. | Block sender/domain. Quarantine all matching emails. Escalate if user interacted. |

### Classification Results

| # | Sample | Classification | Confidence | Indicators |
|---|---|---|---|---|
| 1 | Bank Credential Harvest | Phishing | High | 6 / 6 confirmed |
| 2 | Prize / Reward Lure | Phishing | High | 5 / 5 confirmed |
| 3 | IT Spear Phishing (M365) | Phishing | Critical | 5 / 5 confirmed |
| 4 | BEC Invoice Pattern | Suspicious | Medium | 2 / 4 (attachment unverified) |
| 5 | Google Security Alert | Safe | High | 0 / 5 — all checks passed |

---

## How Phishing Attacks Work

| Step | Phase | What Happens |
|---|---|---|
| 1 | Email Delivery | Attacker sends email from spoofed domain. Display name matches the legitimate organisation; actual domain is attacker-controlled. |
| 2 | Creating Urgency | Subject contains `[Action Required]` with fabricated security events to bypass rational verification behaviour. |
| 3 | The Malicious Link | Action button links to a URL shortener or typosquatted domain. Victim cannot see the real destination. |
| 4 | Credential Capture | Victim enters credentials on fake login page. Credentials are forwarded to attacker silently; victim is redirected to real site to avoid suspicion. |
| 5 | Account Compromise | Attacker accesses the account, reads communications, accesses cloud storage, or sells credentials on dark web markets. |
| 6 | Lateral Movement | If password is reused elsewhere, attacker can compromise multiple additional accounts from a single stolen credential. |

---

## Extracted Indicators of Compromise (IOCs)

| IOC Type | Value | Description |
|---|---|---|
| Sender Email | `noreply@chase-verify.net` | Typosquat of `chase.com` |
| Sender Email | `rewards@amaz0n-gifts.com` | Typosquat of `amazon.com` — zero replacing 'o' |
| Sender Email | `it-support@company-helpdesk.net` | External domain impersonating internal IT helpdesk |
| Domain | `chase-verify.net` | Registered to impersonate bank login. All DNS auth checks fail. |
| Domain | `amaz0n-gifts.com` | Typosquatted Amazon domain used for prize lure campaign |
| Domain | `company-helpdesk.net` | External domain impersonating corporate IT department |
| Shortened URL | `https://bit.ly/3vF9xKz` | URL shortener concealing real phishing destination |
| Subject Pattern | `[Action Required] Unusual sign-in activity` | Standard credential phishing subject line |
| Subject Pattern | `Congratulations! You've won` | Prize lure subject pattern |

---

## Verdict & Recommended Actions

**Overall Verdict: 3 Phishing (High / Critical) &nbsp;|&nbsp; 1 Suspicious &nbsp;|&nbsp; 1 Safe**

| # | Action | Details |
|---|---|---|
| 1 | Block sender domains | Block `chase-verify.net`, `amaz0n-gifts.com`, `company-helpdesk.net` and all subdomains at the mail gateway immediately |
| 2 | Quarantine matching emails | Search and remove all emails from these domains across all user mailboxes |
| 3 | Notify users | Alert users that legitimate security alerts never use URL shorteners or non-official domains |
| 4 | Escalate if user interacted | If any user clicked a link or entered credentials, escalate to Tier 2 / Incident Response immediately |
| 5 | Block IPs at perimeter | Add sending IP addresses to perimeter firewall blocklist and update threat intelligence feeds |

---

## Prevention Tips for Users

### How to Spot a Phishing Email

| # | Warning Sign | What to Look For |
|---|---|---|
| 1 | Check the sender's full email address | Look at the actual domain — not just the display name |
| 2 | Hover over links before clicking | See the real URL before clicking — if it uses a shortener or goes to an unexpected domain, do not click |
| 3 | Be suspicious of urgency | Phrases like `[Action Required]` are designed to make you act without thinking |
| 4 | Never trust URL shorteners | Legitimate companies will never hide links behind `bit.ly` |
| 5 | Verify through official channels | Go directly to the official website in a new tab — never use the link in the email |
| 6 | Enable Multi-Factor Authentication | MFA stops attackers even if they steal your password |

### What to Do If You Receive a Suspicious Email

1. Do not click any links or open any attachments
2. Report the email to your IT or Security team using the official reporting process
3. Do not forward the email to colleagues
4. If you accidentally clicked a link, disconnect from the network immediately and notify IT
5. Change your password from a safe device if you believe you entered credentials on a suspicious page

---

## Do's and Don'ts for Employees

| Do | Don't |
|---|---|
| Verify the sender's full email address before taking any action | Do not trust the display name alone — always check the actual email domain |
| Hover over all links to preview the real URL before clicking | Do not click links in emails that use URL shorteners |
| Navigate to official websites by typing the address directly in the browser | Do not enter login credentials on any page reached through an email link |
| Enable MFA on all work and personal accounts | Do not reuse the same password across multiple accounts |
| Report any suspicious email to your IT/Security team immediately | Do not forward suspicious emails to colleagues |
| Keep OS, browser, and antivirus software up to date | Do not open unexpected attachments, even from known senders |
| Use a password manager to create and store strong, unique passwords | Do not write passwords on paper or store them in unencrypted files |

---

## Long-Term Mitigation Recommendations

| # | Control | Category | Detail |
|---|---|---|---|
| 1 | Enforce MFA on all accounts | Identity | Conditional access policies requiring MFA prevent account compromise even when credentials are stolen |
| 2 | Advanced phishing filter at mail gateway | Email Security | Block emails from lookalike domains using AI-powered anti-phishing filtering |
| 3 | Real-time URL reputation filtering | Network | Block access to URL shorteners and perform URL reputation checks before email delivery |
| 4 | DMARC policy enforcement (`p=reject`) | Email Security | Implement DMARC reject policy to prevent spoofing of your own organisation's domain |
| 5 | Quarterly security awareness training | Human Layer | Conduct phishing simulation exercises and train users to report suspicious emails |
| 6 | Incident response plan for phishing | Governance | Document and rehearse the response process for users who click phishing links or submit credentials |

---

## Conclusion

Three of the five email samples analysed are high-confidence phishing attacks designed to steal credentials through domain spoofing, social engineering, and URL obfuscation. One sample matches the Business Email Compromise pattern and requires further verification. One sample — the Google security alert — passed all authentication checks and is confirmed legitimate.

The most dangerous sample is the Corporate IT Spear Phishing attempt (Sample 3), which targets Microsoft 365 credentials through a convincing impersonation of an internal IT communication. This attack is particularly effective because it exploits trust in authority and creates urgency around a plausible workplace scenario.

Immediate action should be taken to block the identified sender domains, quarantine all matching emails, and notify affected users. Long-term, the deployment of MFA, DMARC enforcement, and regular phishing awareness training represents the most effective organisational defence against credential harvesting campaigns.

---

| Field | Details |
|---|---|
| **Prepared By** | Cyber Security Intern — Future Interns |
| **Track Code** | CS |
| **Repository** | FUTURE_CS_02 |
| **Date** | April 2025 |
| **Classification** | Educational — Future Interns Cyber Security Programme |
