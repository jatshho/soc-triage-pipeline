from dataclasses import dataclass, field
from typing import Optional

@dataclass
class NormalizedEvent:
    timestamp: str
    host: str
    source_type: str        # e.g. "ssh_auth", "firewall"
    event_action: str       # e.g. "login_failed", "login_success", "conn_denied"
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    raw: str = ""

    def to_dict(self):
        return self.__dict__
