from pytest import fixture, raises
from unittest.mock import patch
from pathlib import Path
from petra_model.application.scan_service import ScanService
from petra_domain.entities.anomaly import AnomalyLevel

@fixture
def mock_parser():
    """mock parser with sample entries."""
    from petra_domain.entities.log_entry import LogEntry
    from datetime import datetime
    return [LogEntry(timestamp=datetime.now(), ip="192.168.1.1", event_type="login", success=False) for _ in range(6)]

@fixture
def scan_service(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("thresholds:\n  login_fails: 5")
    return ScanService(config_path=config_path)

def test_scan_basic_detection(scan_service, mock_parser):
    with patch('petra_infra.parsers.auth_log_parser.AuthLogParser.parse_file', return_value=mock_parser):
        anomalies = scan_service.scan(Path("dummy.log"))
        assert len(anomalies) == 1
        assert anomalies[0].level == AnomalyLevel.HIGH
        assert anomalies[0].type == "brute_force"
        assert len(anomalies[0].evidence) == 6
        assert anomalies[0].score == 0.06

def test_scan_no_anomalies(scan_service, mock_parser):
    mock_parser = mock_parser[:4]  # <5 fails
    with patch('petra_infra.parsers.auth_log_parser.AuthLogParser.parse_file', return_value=mock_parser):
        anomalies = scan_service.scan(Path("dummy.log"))
        assert len(anomalies) == 0

def test_scan_multiple_ips(scan_service):
    from petra_domain.entities.log_entry import LogEntry
    from datetime import datetime
    entries = [
        LogEntry(timestamp=datetime.now(), ip="1.1.1.1", event_type="login", success=False) for _ in range(6)
    ] + [
        LogEntry(timestamp=datetime.now(), ip="2.2.2.2", event_type="login", success=False) for _ in range(3)
    ]
    with patch('petra_infra.parsers.auth_log_parser.AuthLogParser.parse_file', return_value=entries):
        anomalies = scan_service.scan(Path("dummy.log"))
        assert len(anomalies) == 1

def test_invalid_config():
    with raises(FileNotFoundError):
        service = ScanService(Path("nonexistent.yaml"))