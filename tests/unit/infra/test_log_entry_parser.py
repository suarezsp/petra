from pytest import raises, fixture
from datetime import datetime
import logging
from petra_domain.entities.log_entry import LogEntry
from petra_infra.parsers.auth_log_parser import AuthLogParser
from unittest.mock import patch 
from pydantic import ValidationError
from pathlib import Path

@fixture
def valid_log_data():
    """Fixture for valid data """
    return {
        "timestamp": datetime(2025, 11, 12, 17, 39, 12),
        "user": "admin",
        "ip": "192.168.1.1",
        "event_type": "login_fail",
        "success": False,
        "details": "Failed password"
    }

def test_log_entry_valid_full(valid_log_data):
    """positive all"""
    entry = LogEntry(**valid_log_data)
    assert entry.timestamp == valid_log_data["timestamp"]
    assert entry.user == "admin"
    assert entry.ip == "192.168.1.1"
    assert entry.event_type == "login_fail"
    assert not entry.success
    assert entry.details == "Failed password"

def test_log_entry_valid_minimal():
    """positive but only required"""
    entry = LogEntry(timestamp=datetime.now(), event_type="test", success=True)
    assert entry.user is None
    assert entry.ip is None
    assert entry.details is None

def test_log_entry_immutable():
    """Edge: Verifica frozen – no se puede modificar."""
    entry = LogEntry(timestamp=datetime.now(), event_type="test", success=True)
    with raises(ValidationError) as exc_info:
        entry.timestamp = datetime.now()  # should fail
    assert 'frozen_instance' in str(exc_info.value)

def test_log_entry_invalid_timestamp():
    """negative no datatime"""
    with raises(ValueError):
        LogEntry(timestamp="invalid", event_type="test", success=True)

def test_log_entry_invalid_event_type():
    """negative no type """
    with raises(ValueError):
        LogEntry(timestamp=datetime.now(), event_type="", success=True)

def test_log_entry_invalid_success_type():
    """negative on success"""
    with raises(ValueError):
        LogEntry(timestamp=datetime.now(), event_type="test", success="yes")

def test_log_entry_serialization():
    """positive json validate"""
    entry = LogEntry(timestamp=datetime.now(), event_type="test", success=True)
    json_data = entry.model_dump_json()
    assert "timestamp" in json_data
    reloaded = LogEntry.model_validate_json(json_data)
    assert reloaded.event_type == "test"
