from pytest import raises, fixture
from pathlib import Path
from petra_infra.parsers.auth_log_parser import AuthLogParser
from petra_domain.entities.log_entry import LogEntry

@fixture
def valid_sample_log(tmp_path: Path):
    log_path = tmp_path / "valid.log"
    content = """
    Nov 12 17:39:12 server sshd[1234]: Failed password for admin from 192.168.1.1 port 22 ssh2
    Nov 12 17:40:15 server sshd[5678]: Accepted password for user from 10.0.0.2 port 22 ssh2
    """.strip()
    log_path.write_text(content)
    return log_path

@fixture
def invalid_sample_log(tmp_path: Path):
    log_path = tmp_path / "invalid.log"
    content = "Invalid line without format"
    log_path.write_text(content)
    return log_path

@fixture
def empty_sample_log(tmp_path: Path):
    log_path = tmp_path / "empty.log"
    log_path.touch()
    return log_path

@fixture
def mixed_sample_log(tmp_path: Path):
    log_path = tmp_path / "mixed.log"
    content = """
    Nov 12 17:39:12 server sshd[1234]: Failed password for admin from 192.168.1.1 port 22 ssh2
    Invalid line
    Nov 12 17:40:15 server sshd[5678]: Accepted password for user from 10.0.0.2 port 22 ssh2
    """.strip()
    log_path.write_text(content)
    return log_path

def test_parse_valid_file(valid_sample_log):
    """positive lines"""
    parser = AuthLogParser()
    entries = list(parser.parse_file(valid_sample_log))
    assert len(entries) == 2
    assert entries[0].user == "admin"
    assert entries[0].ip == "192.168.1.1"
    assert not entries[0].success
    assert entries[0].event_type == "login"
    assert "Failed password" in entries[0].details

    assert entries[1].user == "user"
    assert entries[1].ip == "10.0.0.2"
    assert entries[1].success  # accepted

def test_parse_invalid_file(invalid_sample_log):
    """negative crashes"""
    parser = AuthLogParser()
    entries = list(parser.parse_file(invalid_sample_log))
    assert len(entries) == 0  # no valid

def test_parse_empty_file(empty_sample_log):
    """edge empty file"""
    parser = AuthLogParser()
    entries = list(parser.parse_file(empty_sample_log))
    assert len(entries) == 0

def test_parse_mixed_file(mixed_sample_log):
    """edge mixes valid and invalid"""
    parser = AuthLogParser()
    entries = list(parser.parse_file(mixed_sample_log))
    assert len(entries) == 2  # ignores invalid

def test_nonexistent_file():
    """negative files doesnt exist"""
    parser = AuthLogParser()
    with raises(FileNotFoundError):
        list(parser.parse_file(Path("nonexistent.log")))

def test_extract_user_ip():
    """unit private methods"""
    parser = AuthLogParser()
    event = "Failed password for admin from 192.168.1.1 port 22 ssh2"
    assert parser._extract_user(event) == "admin"
    assert parser._extract_ip(event) == "192.168.1.1"

    event_no_user = "Some event without for user"
    assert parser._extract_user(event_no_user) is None
    assert parser._extract_ip(event_no_user) is None

def test_timestamp_parsing():
    """edge timestamp"""
    parser = AuthLogParser()
    line = "Jan 1 00:00:00 server sshd[1]: Failed password for admin from 192.168.1.1"
    match = parser.LINE_REGEX.match(line)
    assert match is not None

def test_regex_variations():
    """Edge: Regex maneja variaciones comunes."""
    parser = AuthLogParser()
    lines = [
        "Nov 12 17:39:12 server sshd[1234]: Failed password for admin from 192.168.1.1 port 22 ssh2",  # Estándar
        "Dec 31 23:59:59 host crond[999]: PAM adding faulty module",  
        "Invalid line"  
    ]
    entries = list(parser.parse_file(Path("examples/sample_auth.log"))) #asumes samples