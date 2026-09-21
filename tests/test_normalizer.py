from parsers.normalizer import parse_ssh_line

def test_parses_failed_login():
    line = "Jan 05 14:22:10 web01 sshd[1234]: Failed password for admin from 203.0.113.55 port 51514 ssh2"
    evt = parse_ssh_line(line)
    assert evt is not None
    assert evt.event_action == "login_failed"
    assert evt.user == "admin"
    assert evt.src_ip == "203.0.113.55"

def test_parses_successful_login():
    line = "Jan 05 09:00:00 web01 sshd[4321]: Accepted password for alice from 10.0.0.5 port 51000 ssh2"
    evt = parse_ssh_line(line)
    assert evt.event_action == "login_success"

def test_ignores_unrelated_lines():
    line = "Jan 05 09:00:00 web01 kernel: some unrelated message"
    assert parse_ssh_line(line) is None
