from dataclasses import dataclass
from datetime import datetime

@dataclass
class AuthenticationEvent:
    timestamp: datetime
    username: str
    source_ip: str
    destination_host: str
    protocol: str
    success: bool
    line_number: int
    raw_log: str