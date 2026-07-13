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
    
def test_xss_detected():
    assert "XSS-001" in scan("<script>alert('XSS');</script>")
def test_xss_variant_detected():
    assert "XSS-001" in scan("<ScRiPt>alert('XSS');</sCrIpT>")
def test_clean_search_not_flagged():
    assert scan("cybersecurity internship") == []

    