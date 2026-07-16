import time
from collections import defaultdict, deque

WINDOW_SECONDS = 10
THRESHOLD = 8
BLOCK_DURATION = 30

_request_log = defaultdict(deque)
_blocked_until = {}

def is_blocked(ip: str) -> bool:
    until = _blocked_until.get(ip)
    if until is None:
        return False
    if time.time() < until:
        return True
    del _blocked_until[ip]
    return False

def register_request(ip: str) -> dict:
    now = time.time()
    log = _request_log[ip]
    log.append(now)
    while log and now - log[0] > WINDOW_SECONDS:
        log.popleft()
    request_count = len(log)
    if request_count > THRESHOLD:
        _blocked_until[ip] = now + BLOCK_DURATION
        return {"ip": ip, "request_count": request_count, "abusive": True}
    return {"ip": ip, "request_count": request_count, "abusive": False}