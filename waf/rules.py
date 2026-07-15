import re

RULES = [
    ("SQLI-001", "SQL Injection", re.compile(r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I),
 "Classic tautology (e.g. ' OR 1=1)", "HIGH"), ("XSS-001", "XSS", re.compile(r"<script.*?>.*?</script>", re.I),
 "Cross-Site Scripting (XSS)", "HIGH"), ("LFI-001", "LFI/Path traversal", re.compile(r"(\.\./|\.\.\\)+", re.I),
 "Directory traversal sequence", "HIGH"), ("CMDI-001", "Command Injection", re.compile(r"[;&|]\s*\b(whoami|ls|cat|id|pwd|uname|grep|nc|curl|bash)\b", re.I),
 "Shell metacharacter followed by known command", "HIGH"),
]