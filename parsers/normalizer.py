import re
from parsers.schema import NormalizedEvent

# e.g. "Jan 05 14:22:10 web01 sshd[1234]: Failed password for admin from 203.0.113.55 port 51514 ssh2"
SYSLOG_SSH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+password\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

def parse_ssh_line(line: str):
    m = SYSLOG_SSH_RE.match(line)
    if not m:
        return None
    gd = m.groupdict()
    action = "login_success" if gd["result"] == "Accepted" else "login_failed"
    return NormalizedEvent(
        timestamp=gd["ts"],
        host=gd["host"],
        source_type="ssh_auth",
        event_action=action,
        user=gd["user"],
        src_ip=gd["ip"],
        raw=line,
    )

def normalize_lines(lines, parser=parse_ssh_line):
    events = []
    for line in lines:
        evt = parser(line)
        if evt:
            events.append(evt)
    return events
