import re

RULES = [
    ("SQLI-001", "SQL Injection", re.compile(r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I),
 "Classic tautology (e.g. ' OR 1=1)", "HIGH"),
]