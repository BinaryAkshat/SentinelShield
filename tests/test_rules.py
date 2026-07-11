import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from waf.rules import RULES

def scan(value):
    """Helper: returns list of rule_ids that match this input."""
    matches = []
    for rule_id, category, pattern, description, severity in RULES:
        if pattern.search(value):
            matches.append(rule_id)
    return matches

def test_sqli_tautology_detected():
    assert "SQLI-001" in scan("' OR 1=1 --")

def test_sqli_variant_and_detected():
    assert "SQLI-001" in scan("admin' AND 1=1--")

def test_clean_login_not_flagged():
    assert scan("student") == []
    assert scan("password123") == []