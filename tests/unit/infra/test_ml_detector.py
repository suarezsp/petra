from pytest import fixture
from petra_infra.detectors.ml_detector import MLDetector
from petra_domain.entities.log_entry import LogEntry
from datetime import datetime, timedelta

@fixture
def sample_entries():
    now = datetime.now()
    return [
        LogEntry(timestamp=now + timedelta(minutes=i), event_type="login", success=True) for i in range(20)
    ] + [
        LogEntry(timestamp=now + timedelta(hours=3), event_type="login", success=True) for i in range(3)
    ]

def test_detect_outliers(sample_entries):
    detector = MLDetector(clusters=2)
    anomalies = detector.detect_outliers(sample_entries)
    assert len(anomalies) > 0
    assert anomalies[0].type == "unusual_timing"
    assert len(anomalies[0].evidence) == 3

def test_no_outliers():
    now = datetime.now()
    entries = [LogEntry(timestamp=now + timedelta(seconds=i), event_type="login", success=True) for i in range(10)]  # Close timestamps, no outliers
    detector = MLDetector(clusters=2)
    anomalies = detector.detect_outliers(entries)
    assert len(anomalies) == 0

def test_too_few_entries():
    entries = [LogEntry(timestamp=datetime.now(), event_type="login", success=True)]
    detector = MLDetector()
    anomalies = detector.detect_outliers(entries)
    assert len(anomalies) == 0