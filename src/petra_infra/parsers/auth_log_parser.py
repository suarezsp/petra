import re
from typing import Generator, Optional
from datetime import datetime
import logging
from pathlib import Path

from petra_domain.entities.log_entry import LogEntry  # import from domain

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.WARNING) 

class AuthLogParser:
    """Parser for auth.log. Gets LogEntry from logs lines"""

    # basic regex lines
    LINE_REGEX = re.compile(
        r"^(?P<month>\w{3}) (?P<day>\d{1,2}) (?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2}) "
        r"(?P<host>\w+) (?P<service>\w+)\[(?P<pid>\d+)\]: (?P<event>.*)"
    )

    def parse_file(self, file_path: Path) -> Generator[LogEntry, None, None]:
        """reads valid auth.log and yield LogEntry. skips invalid lines."""
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        current_year = datetime.now().year  # assuming actual year

        with file_path.open("r") as f:
            for line_num, line in enumerate(f, start=1):
                match = self.LINE_REGEX.match(line.strip())
                if not match:
                    logger.warning(f"Invalid line {line_num}: {line.strip()}")
                    continue

                # gets data
                try:
                    timestamp_str = f"{current_year} {match['month']} {match['day']} {match['hour']}:{match['min']}:{match['sec']}"
                    timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")

                    event = match['event']
                    user = self._extract_user(event)
                    ip = self._extract_ip(event)
                    success = "Accepted" in event  # simple check; extend for more cases
                    event_type = "login" if "password" in event else "other"

                    entry = LogEntry(
                        timestamp=timestamp,
                        user=user,
                        ip=ip,
                        event_type=event_type,
                        success=success,
                        details=event
                    )
                    yield entry

                except ValueError as e:
                    logger.error(f"Parse error line {line_num}: {e}")

    def _extract_user(self, event: str) -> Optional[str]:
        match = re.search(r"for (?P<user>\w+) from", event) 
        return match.group("user") if match else None

    def _extract_ip(self, event: str) -> Optional[str]:
        match = re.search(r"from (?P<ip>[\d.]+)", event)
        return match.group("ip") if match else None