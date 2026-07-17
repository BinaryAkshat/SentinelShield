import re

RULES = [
    ("SQLI-001", "SQL Injection", re.compile(r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I),
 "Classic tautology (e.g. ' OR 1=1)", "HIGH"), ("XSS-001", "XSS", re.compile(r"<script.*?>.*?</script>", re.I),
 "Cross-Site Scripting (XSS)", "HIGH"), ("LFI-001", "LFI/Path traversal", re.compile(r"(\.\./|\.\.\\)+", re.I),
 "Directory traversal sequence", "HIGH"), ("CMDI-001", "Command Injection", re.compile(r"[;&|]\s*\b(whoami|ls|cat|id|pwd|uname|grep|nc|curl|bash)\b", re.I),
 "Shell metacharacter followed by known command", "HIGH"),
]

def scan_request(args: dict, form: dict, path: str):
    all_matches = []
    sources = {"path": path}
    sources.update({f"query:{k}": v for k, v in args.items()})
    sources.update({f"form:{k}": v for k, v in form.items()})

    for field_name, value in sources.items():
        for rule_id, category, pattern, description, severity in RULES:
            if pattern.search(str(value)):
                all_matches.append({
                    "rule_id": rule_id,
                    "category": category,
                    "severity": severity,
                    "field": field_name,
                })
    return all_matches