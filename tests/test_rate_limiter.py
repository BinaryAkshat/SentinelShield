import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from waf.rate_limiter import register_request, is_blocked, THRESHOLD

def test_under_threshold_not_abusive():
    for i in range(THRESHOLD):
        result = register_request("10.0.0.1")
    assert result["abusive"] == False

def test_over_threshold_is_abusive():
    for i in range(THRESHOLD + 2):
        result = register_request("10.0.0.2")
    assert result["abusive"] == True

def test_is_blocked_after_abusive():
    for i in range(THRESHOLD + 2):
        register_request("10.0.0.3")
    assert is_blocked("10.0.0.3") == True

def test_different_ip_not_affected():
    for i in range(THRESHOLD + 2):
        register_request("10.0.0.4")
    assert is_blocked("10.0.0.5") == False