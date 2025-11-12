from pytest import raises
from petra_domain.entities.log_entry import LogEntry
from datetime import datetime

def test_valid_log_entry():
    LogEntry(timestamp=datetime.now(), event_type="test", success=True)

def test_invalid_log_entry():
    with raises(ValueError):
        LogEntry(timestamp="not a datetime", event_type="test", success=True)