# SentinelShield — Practical Journal

**Name:** Akshat Saklani
**Course:** TCS 619 — Network and System Security
**Date:** July 21, 2026

## 1. Purpose of the Experiment

To design and implement a simplified Web Application Firewall (WAF) that demonstrates:
- Signature-based attack detection using regex pattern matching (SQLi, XSS, LFI, Command Injection)
- Behavior-based abuse detection via rate limiting (brute-force/scanning prevention)
- Structured logging and dashboard visualization of security events
- End-to-end request processing: inspection → detection → decision → logging → alerting

## 2. Tools Used

- **Python 3.11** with Flask web framework
- **pytest** for unit testing detection rules
- **CSV logging** for persistent event recording
- **Chart.js** for dashboard visualization
- **Git** for version control and documentation of development phases
- **curl** / Browser for manual attack payload testing

## 3. System Architecture

Client Request (Browser/curl)
↓
Flask App receives request
↓
WAF Middleware (@app.before_request)
├─ Rate Limiter: Check if IP is cooldown-blocked
├─ Rate Limiter: Register request, check threshold
├─ Signature Scanner: Run request fields against all rules
└─ Decision: Allow (return None) or Block (return 403 page)
↓
Logger: Write row to CSV with {timestamp, ip, method, path, action, reason, category, rule_id, severity}
↓
Dashboard: Reads CSV, displays stats/charts

## 4. Step-by-Step Execution

### 4.1 Rule Review

**Four attack signature rules implemented:**

| Rule ID | Category | Pattern | Example Payload | Severity |
|---|---|---|---|---|
| SQLI-001 | SQL Injection | `(\bor\b\|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+` | `' OR 1=1 --` | HIGH |
| XSS-001 | XSS | `<script.*?>` | `<script>alert(1)</script>` | HIGH |
| LFI-001 | LFI/Path Traversal | `(\.\./\|\.\.\\)+` | `../../../../etc/passwd` | HIGH |
| CMDI-001 | Command Injection | `[;&\|]\s*\b(whoami\|ls\|cat\|id\|pwd\|uname)\b` | `8.8.8.8; whoami` | HIGH |

**Rate Limiter Configuration:**
- Time Window: 10 seconds
- Threshold: 8 requests per window
- Block Duration: 30 seconds (cooldown after threshold crossed)

### 4.2 Request Simulation & Detection Results

| Endpoint | Attack Type | Payload Tested | Expected | Actual Result | Log Timestamp |
|---|---|---|---|---|---|
| `/login` (POST) | SQL Injection | `' OR 1=1 --` | Blocked (SQLI-001) | ✅ BLOCKED, SQLI-001 | 2026-07-21T14:22:02 |
| `/search` (GET) | XSS | `<script>alert(1)</script>` | Blocked (XSS-001) | ✅ BLOCKED, XSS-001 | 2026-07-21T14:22:21 |
| `/file` (GET) | LFI | `../../../../etc/passwd` | Blocked (LFI-001) | ✅ BLOCKED, LFI-001 | 2026-07-21T14:23:13 |
| `/ping` (GET) | CMDI | `8.8.8.8; whoami` | Blocked (CMDI-001) | ✅ BLOCKED, CMDI-001 | 2026-07-21T14:23:40 |

**Rate Limiting Evidence:**
Rapid refresh of `/dashboard` (9+ times in <2 seconds):
- Requests 1-8: `ALLOWED, clean`
- Request 9: `BLOCKED, rate_limit_exceeded` (threshold crossed)
- Requests 10+: `BLOCKED, rate_limit_active` (in cooldown)
- Recovery: After 30s cooldown, requests allowed again

### 4.3 Log File Examination

**Raw Log Excerpt (filtered to show key events):**

```csv
timestamp,ip,method,path,action,reason,category,rule_id,severity
2026-07-21T14:22:02.751715,127.0.0.1,POST,/login,BLOCKED,signature_match,SQL Injection,SQLI-001,HIGH
2026-07-21T14:22:21.670377,127.0.0.1,GET,/search,BLOCKED,signature_match,XSS,XSS-001,HIGH
2026-07-21T14:23:13.575532,127.0.0.1,GET,/file,BLOCKED,signature_match,LFI/Path traversal,LFI-001,HIGH
2026-07-21T14:23:40.988056,127.0.0.1,GET,/ping,BLOCKED,signature_match,Command Injection,CMDI-001,HIGH
2026-07-21T14:24:26.400525,127.0.0.1,GET,/dashboard,BLOCKED,rate_limit_exceeded,Behavioral,,HIGH
2026-07-21T14:24:26.598577,127.0.0.1,GET,/dashboard,BLOCKED,rate_limit_active,,,
```

**Annotations:**
- All four attacks originate from the same IP (127.0.0.1 — localhost testing)
- Each attack is timestamped to the second, allowing correlation with browser actions
- Severity column correctly identifies HIGH for all signature-based blocks
- Rate limiter shows two-stage blocking: `rate_limit_exceeded` at the trigger point, then `rate_limit_active` for subsequent requests
- Empty `category`/`rule_id` fields for rate-limit blocks are expected (behavior-based, not signature-based)

## 5. Interpretation Notes

### Why Certain Attacks Were Detected

**SQL Injection (SQLI-001):**
The payload `' OR 1=1 --` was detected because the regex correctly identifies the tautology pattern: the word boundary `\bor\b` followed by a digit on each side of an equals sign. In real SQL, this transforms `WHERE username = 'X'` into `WHERE username = '' OR 1=1 --`, which always evaluates true. The regex's case-insensitivity (`re.I` flag) ensures both `OR` and `or` variants are caught.

**Cross-Site Scripting (XSS-001):**
The `<script>` tag opening was detected via the simple but effective pattern `<script.*?>`, which uses lazy matching (`.*?`) to capture any attributes (e.g., `<script src=...>`) while keeping the pattern concise. Browsers render any `<script>` tag as executable code, regardless of how it arrived, so detecting the tag itself is sufficient for prevention.

**Local File Inclusion (LFI-001):**
The directory traversal pattern `../` and `..\` (both forward and backslash variants) are the universal signature of path traversal attacks. By detecting this sequence anywhere in the request, we prevent attackers from escaping the intended directory. The `+` quantifier matches repeated sequences like `../../../../`, which is a common hardening technique against simple `../` filters.

**Command Injection (CMDI-001):**
Semicolon, pipe, and ampersand are shell metacharacters that chain commands. The rule specifically requires a *known command* (`whoami|ls|cat|...`) after the metacharacter to avoid false positives on legitimate data like `user&pass`. This deliberate narrowing trades coverage (misses unknown commands) for precision (no false positives on normal strings).

### How Rate Limiting Contributed to Detection

The rate limiter operates independently of signatures: even if a payload looked "clean" by regex standards, sending 9+ requests in 10 seconds triggers a block at the *behavior* layer. This caught automated scanners and brute-force attempts that wouldn't be detected by content alone. The log shows this clearly — after legitimate requests were exhausted, the 9th request crossed the threshold, and the cooldown protected the application from further abuse for 30 seconds.

### Workflow Validation

The practical demonstrated the exact sequence from the original project brief:
1. **Inspect:** middleware examines path, query params, form fields
2. **Detect:** rules fire on matching patterns, rate limiter checks frequency
3. **Decide:** HIGH severity → block immediately; LOW → log but allow
4. **Log:** every verdict (allowed or blocked) written to CSV with full context
5. **Alert:** dashboard reads log and visualizes events in real-time

## 7. Suggested Improvements to Rules

### 1. SQLi Rule: Expand to Blind/Time-Based SQLi
**Current limitation:** SQLI-001 only catches tautology-based patterns (`OR 1=1`). Blind SQL injection (e.g., `' AND SLEEP(5) --`) and stacked queries (e.g., `'; DROP TABLE users; --`) slip through.

**Improvement:** Add rules for:
- Comment sequences: `--`, `#`, `/* */` appearing after quotes
- Time-delay functions: `SLEEP()`, `BENCHMARK()`, `WAITFOR()`
- DDL keywords: `DROP`, `DELETE`, `INSERT`, `UPDATE` in suspicious contexts

### 2. XSS Rule: Event Handlers & Protocol Schemes
**Current limitation:** XSS-001 catches `<script>` tags but misses event-handler injection (e.g., `<img onerror=alert(1)>`) and javascript: URIs (e.g., `href="javascript:void(0)"`).

**Improvement:** Add rules for:
- Event handlers: `on(error|load|click|mouseover|keydown)\s*=`
- Protocol schemes: `javascript:`, `data:`, `vbscript:`
- Encoded payloads: `&#60;script&#62;` (HTML entity encoding)

### 3. CMDI Rule: Expand Known-Command List
**Current limitation:** Command list is static (`whoami|ls|cat|id|pwd|uname`). Attackers can use `curl`, `nc`, `wget`, `base64` which aren't listed.

**Improvement:**
- Expand command whitelist dynamically based on common payloads observed in the wild
- OR: switch to a behavioral heuristic (flag any metacharacter regardless of command, use rate-limiting to catch floods)

### 4. LFI Rule: Handle Encoding Evasion
**Current limitation:** `../../../../etc/passwd` is caught, but URL-encoded (`..%2F..%2F`), double-encoded (`..%252F..%252F`), or case-variation (`..%2E%2E%2F`) variants may slip through.

**Improvement:**
- Decode URL encoding before rule evaluation (Flask's `request.get_data()` and `urllib.parse.unquote()`)
- Add rules for known sensitive file targets directly: `/etc/passwd`, `/etc/shadow`, `C:\Windows\System32`, `web.config`

## 5. Interpretation Notes

### Why Certain Attacks Were Detected

**SQL Injection (SQLI-001):**
The payload `' OR 1=1 --` was detected because the regex correctly identifies the tautology pattern: the word boundary `\bor\b` followed by a digit on each side of an equals sign. In real SQL, this transforms `WHERE username = 'X'` into `WHERE username = '' OR 1=1 --`, which always evaluates true. The regex's case-insensitivity (`re.I` flag) ensures both `OR` and `or` variants are caught.

**Cross-Site Scripting (XSS-001):**
The `<script>` tag opening was detected via the simple but effective pattern `<script.*?>`, which uses lazy matching (`.*?`) to capture any attributes (e.g., `<script src=...>`) while keeping the pattern concise. Browsers render any `<script>` tag as executable code, regardless of how it arrived, so detecting the tag itself is sufficient for prevention.

**Local File Inclusion (LFI-001):**
The directory traversal pattern `../` and `..\` (both forward and backslash variants) are the universal signature of path traversal attacks. By detecting this sequence anywhere in the request, we prevent attackers from escaping the intended directory. The `+` quantifier matches repeated sequences like `../../../../`, which is a common hardening technique against simple `../` filters.

**Command Injection (CMDI-001):**
Semicolon, pipe, and ampersand are shell metacharacters that chain commands. The rule specifically requires a *known command* (`whoami|ls|cat|...`) after the metacharacter to avoid false positives on legitimate data like `user&pass`. This deliberate narrowing trades coverage (misses unknown commands) for precision (no false positives on normal strings).

### How Rate Limiting Contributed to Detection

The rate limiter operates independently of signatures: even if a payload looked "clean" by regex standards, sending 9+ requests in 10 seconds triggers a block at the *behavior* layer. This caught automated scanners and brute-force attempts that wouldn't be detected by content alone. The log shows this clearly — after legitimate requests were exhausted, the 9th request crossed the threshold, and the cooldown protected the application from further abuse for 30 seconds.

### Workflow Validation

The practical demonstrated the exact sequence from the original project brief:
1. **Inspect:** middleware examines path, query params, form fields
2. **Detect:** rules fire on matching patterns, rate limiter checks frequency
3. **Decide:** HIGH severity → block immediately; LOW → log but allow
4. **Log:** every verdict (allowed or blocked) written to CSV with full context
5. **Alert:** dashboard reads log and visualizes events in real-time

## 6. Final Report Summary

| Metric | Value |
|---|---|
| Total requests processed | 39 |
| Total blocked | 15 |
| Total allowed | 24 |
| Detection accuracy (signature-based) | 100% (4/4 attack types caught) |
| **Attack Category Breakdown:** | |
| SQLi attempts / detected | 1 / 1 (100%) |
| XSS attempts / detected | 1 / 1 (100%) |
| LFI attempts / detected | 1 / 1 (100%) |
| CMDI attempts / detected | 1 / 1 (100%) |
| **Behavioral Detection:** | |
| Rate-limit triggers | 1 (rapid /dashboard refresh) |
| False positives observed | 0 |
| False negatives observed | 0 |
| Dashboard visualization | ✅ Functional (Chart.js bar + doughnut charts, live feed) |

**Key Statistics:**
- Detection precision: 100% — no false positives across 39 requests
- All HIGH severity rules functioned as designed
- Rate limiter correctly escalated from per-request detection to behavior-based blocking
- Cooldown mechanism prevented cascade of rate-limit blocks after initial trigger

## 7. Suggested Improvements to Rules

### 1. SQLi Rule: Expand to Blind/Time-Based SQLi
**Current limitation:** SQLI-001 only catches tautology-based patterns (`OR 1=1`). Blind SQL injection (e.g., `' AND SLEEP(5) --`) and stacked queries (e.g., `'; DROP TABLE users; --`) slip through.

**Improvement:** Add rules for:
- Comment sequences: `--`, `#`, `/* */` appearing after quotes
- Time-delay functions: `SLEEP()`, `BENCHMARK()`, `WAITFOR()`
- DDL keywords: `DROP`, `DELETE`, `INSERT`, `UPDATE` in suspicious contexts

### 2. XSS Rule: Event Handlers & Protocol Schemes
**Current limitation:** XSS-001 catches `<script>` tags but misses event-handler injection (e.g., `<img onerror=alert(1)>`) and javascript: URIs (e.g., `href="javascript:void(0)"`).

**Improvement:** Add rules for:
- Event handlers: `on(error|load|click|mouseover|keydown)\s*=`
- Protocol schemes: `javascript:`, `data:`, `vbscript:`
- Encoded payloads: `&#60;script&#62;` (HTML entity encoding)

### 3. CMDI Rule: Expand Known-Command List
**Current limitation:** Command list is static (`whoami|ls|cat|id|pwd|uname`). Attackers can use `curl`, `nc`, `wget`, `base64` which aren't listed.

**Improvement:**
- Expand command whitelist dynamically based on common payloads observed in the wild
- OR: switch to a behavioral heuristic (flag any metacharacter regardless of command, use rate-limiting to catch floods)

### 4. LFI Rule: Handle Encoding Evasion
**Current limitation:** `../../../../etc/passwd` is caught, but URL-encoded (`..%2F..%2F`), double-encoded (`..%252F..%252F`), or case-variation (`..%2E%2E%2F`) variants may slip through.

**Improvement:**
- Decode URL encoding before rule evaluation (Flask's `request.get_data()` and `urllib.parse.unquote()`)
- Add rules for known sensitive file targets directly: `/etc/passwd`, `/etc/shadow`, `C:\Windows\System32`, `web.config`

### 5. Rate Limiter: Adaptive Thresholds
**Current limitation:** Fixed threshold (8 req/10s) treats all IPs equally. Legitimate bulk requests (e.g., automated monitoring) can trigger false blocks.

**Improvement:**
- Implement reputation scoring: IPs with clean history get higher thresholds
- Differentiate by endpoint: `/api/` might allow 50 req/min, but `/login` stays strict at 1 req/min
- Add exponential backoff: first violation → 30s block, second → 5 min, third → 1 hour

### 6. Dashboard: Add Alerting Thresholds
**Current limitation:** Dashboard shows stats but doesn't *alert* on anomalies (e.g., "50 blocks in 5 minutes").

**Improvement:**
- Email/Slack alerts when blocked count exceeds threshold
- Spike detection: compare hourly block rate to 7-day average, alert on >200% increase
## 8. Personal Reflection & Learning Outcomes

### What I Understood Better Through Building

1. **Attack Signatures**: Regex feels like a blunt instrument until you realize it's exact enough for known-pattern matching. Understanding *why* real WAFs use regex (not AI, not parsing) changed how I think about rule-based systems.

2. **Rate Limiting Edge Cases**: The sliding window vs. fixed bucket decision taught me that even simple algorithms have subtle tradeoffs. Cool-down timing, threshold tuning, false positives on legitimate users — these are real production headaches.

3. **Logging as a Security Tool**: I used to think logs were just for debugging. Realizing that a well-structured log is the entire evidence trail for forensics and auditing was a shift.

### If I Were to Do This Again

1. Start with a state machine diagram for the WAF decision logic (before coding)
2. Implement encoding-detection early, not as an afterthought
3. Build a testing harness that can replay log entries to verify detection

### How This Connects to Real Security Work

A real WAF (ModSecurity, AWS WAF) does exactly this at scale: signature matching, rate limiting, structured logging. The main differences are:
- Distributed systems (handles millions of requests/sec)
- Machine learning added on top (behavioral detection)
- Integration with SIEM/alerting systems
- Regular rule updates from threat intel feeds

This practical proved I understand the *core* that all of that is built on.