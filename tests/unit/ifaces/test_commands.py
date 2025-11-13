from click.testing import CliRunner
from petra_ifaces.cli.commands import cli
from unittest.mock import patch

runner = CliRunner()

def test_scan_command_success():
    with patch('petra_model.application.scan_service.ScanService.scan', return_value=[]):
        result = runner.invoke(cli, ['scan', '-f', 'examples/sample_auth.log'])
        assert result.exit_code == 0
        assert "No anomalies detected" in result.output

def test_scan_command_anomalies(tmp_path):
    from petra_domain.entities.anomaly import Anomaly, AnomalyLevel
    from petra_domain.entities.log_entry import LogEntry
    from datetime import datetime
    anomaly = Anomaly(level=AnomalyLevel.CRITICAL, score=0.9, type="test", evidence=[LogEntry(timestamp=datetime.now(), event_type="test", success=False)], description="Test")

    dummy_file = tmp_path / 'dummy.log'
    dummy_file.write_text("test log content")

    with patch('petra_model.application.scan_service.ScanService.scan', return_value=[anomaly]):
        result = runner.invoke(cli, ['scan', '-f', str(dummy_file)])
        assert result.exit_code == 0
        assert "ANOMALIES DETECTED" in result.output
        assert "CRITICAL" in result.output

def test_scan_command_file_not_found():
    result = runner.invoke(cli, ['scan', '-f', 'nonexistent.log'])
    assert result.exit_code != 0
    assert "Error" in result.output

def test_scan_missing_file_arg():
    result = runner.invoke(cli, ['scan'])
    assert result.exit_code != 0
    assert "Missing option '-f' / '--file'" in result.output