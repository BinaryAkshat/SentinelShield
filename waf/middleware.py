from flask import request, render_template

from waf import rules
from waf import rate_limiter
from waf import logger

BLOCK_SEVERITIES = {"HIGH"}

def inspect_and_decide():
    ip = request.remote_addr or "unknown"
    method = request.method
    path = request.path
    
    if rate_limiter.is_blocked(ip):
        logger.log_event(ip, method, path, "BLOCKED", reason="rate_limit_active")
        return render_template("blocked.html", reason="Too many requests"), 429
    
    status = rate_limiter.register_request(ip)
    if status["abusive"]:
        logger.log_event(ip, method, path, "BLOCKED", reason="rate_limit_exceeded", category="Behavioral", severity="HIGH")
        return render_template("blocked.html", reason="Too many requests"), 429
    
    matches = rules.scan_request(dict(request.args), dict(request.form), path)
    
    if matches:
        high_matches = [m for m in matches if m["severity"] in BLOCK_SEVERITIES]
        if high_matches:
            top = high_matches[0]
            logger.log_event(ip, method, path, "BLOCKED", reason="signature_match", category=top["category"], rule_id=top["rule_id"] ,severity=top["severity"])
            return render_template("blocked.html", reason=f"Malicious pattern detected: {top['category']}"), 403
    logger.log_event(ip, method, path, "ALLOWED", reason="clean")
    return None
