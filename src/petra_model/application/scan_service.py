from typing import List, Dict
from pathlib import Path
import yaml
from collections import defaultdict

from petra_infra.parsers.auth_log_parser import AuthLogParser
from petra_domain.entities.log_entry import LogEntry
from petra_domain.entities.anomaly import Anomaly, AnomalyLevel
from petra_domain.entities.anomaly import Anomaly

class ScanService:
    """service to scan logs and detect anomalies"""

    def __init__(self, config_path: Path = Path("config/default.yaml")):
        """configs for thresholds"""
        self.config = self._load_config(config_path)
        self.parser = AuthLogParser()

    def _load_config(self, config_path: Path) -> Dict:
        """YAML config."""
        if not config_path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")
        with config_path.open("r") as f:
            return yaml.safe_load(f)
        
    def scan(self, file_path: Path) -> List[Anomaly]:
        """scans log file and returns anomalías."""
        entries = list(self.parser.parse_file(file_path))
        anomalies = []

        # basic detection: brute-force IP (fails > threshold)
        fails_by_ip = defaultdict(int)
        evidence_by_ip = defaultdict(list)

        for entry in entries:
            if entry.event_type == "login" and not entry.success and entry.ip:
                fails_by_ip[entry.ip] += 1
                evidence_by_ip[entry.ip].append(entry)

        for ip, count in fails_by_ip.items():
            threshold = self.config.get("thresholds", {}).get("login_fails", 10)
            if count > threshold:
                anomalies.append(
                    Anomaly(
                        level=AnomalyLevel.HIGH if count < 50 else AnomalyLevel.CRITICAL,
                        score=min(1.0, count / 100.0),  # simple score
                        type="brute_force",
                        evidence=evidence_by_ip[ip],
                        description=f"{count} login fails from IP {ip}. Ref: NIST SP 800-63B"
                    )
                )

        return anomalies