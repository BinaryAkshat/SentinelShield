import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from waf.logger import log_event, read_all_logs

def test_log_event_writes_row():
    before_count = len(read_all_logs())
    log_event("9.9.9.9", "GET", "test-log", "ALLOED", reason= "clean")
    after = read_all_logs()
    assert len(after) == before_count + 1
    assert after[-1]["ip"] == "9.9.9.9"
    assert after[-1]["path"] == "test-log"
    