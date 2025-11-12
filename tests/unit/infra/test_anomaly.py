from pytest import raises
from petra_domain.entities.anomaly import Anomaly, AnomalyLevel
from petra_domain.entities.log_entry import LogEntry
from datetime import datetime

def test_anomaly_valid():
    """positive with evidence"""
    entry = LogEntry(timestamp=datetime.now(), event_type="test", success=False)
    anomaly = Anomaly(
        level=AnomalyLevel.CRITICAL,
        score=0.95,
        type="brute_force",
        evidence=[entry],
        description="High fails"
    )
    assert anomaly.level == AnomalyLevel.CRITICAL
    assert anomaly.score == 0.95
    assert len(anomaly.evidence) == 1
    assert anomaly.evidence[0].event_type == "test"

def test_anomaly_invalid_level():
    """negative, level is not in enum"""
    with raises(ValueError):
        Anomaly(level="invalid", score=0.5, type="test", evidence=[], description="test")

def test_anomaly_invalid_score_low():
    """negative score <0."""
    with raises(ValueError):
        Anomaly(level=AnomalyLevel.LOW, score=-0.1, type="test", evidence=[], description="test")

def test_anomaly_invalid_score_high():
    """negative score >1."""
    with raises(ValueError):
        Anomaly(level=AnomalyLevel.LOW, score=1.1, type="test", evidence=[], description="test")

def test_anomaly_required_fields():
    """negative fields required fail"""
    with raises(ValueError):
        Anomaly(level=AnomalyLevel.MEDIUM, score=0.5, type="", evidence=[], description="")

def test_anomaly_enum_values():
    """edge enum"""
    assert AnomalyLevel.LOW == "low"
    assert AnomalyLevel("high") == AnomalyLevel.HIGH 

def test_anomaly_serialization():
    """positive json roundtrip"""
    entry = LogEntry(timestamp=datetime.now(), event_type="test", success=False)
    anomaly = Anomaly(level=AnomalyLevel.HIGH, score=0.8, type="unusual", evidence=[entry], description="Test")
    json_data = anomaly.model_dump_json()
    reloaded = Anomaly.model_validate_json(json_data)
    assert reloaded.level == AnomalyLevel.HIGH
    assert len(reloaded.evidence) == 1