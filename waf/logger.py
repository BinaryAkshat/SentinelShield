import csv
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "waf_log.csv")

FIELDS = ["timestamp", "ip", "method", "path", "action", "reason", "category", "rule_id", "severity"]

def _ensure_log_file():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            
def log_event(ip, method, path, action, reason="", category="", rule_id="", severity=""):
    _ensure_log_file()
    timestamp = datetime.utcnow().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "ip": ip,
        "method": method,
        "path": path,
        "action": action,
        "reason": reason,
        "category": category,
        "rule_id": rule_id,
        "severity": severity
    }
    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writerow(log_entry)

def read_all_logs():
    _ensure_log_file()
    with open(LOG_FILE, mode='r', newline='') as f:
        reader = csv.DictReader(f)
        return list(reader)
    
    