from dataclasses import dataclass


@dataclass
class AuthenticationEvent:
    timestamp: str
    username: str
    source_ip: str
    destination_host: str
    protocol: str
    success: bool
    line_number: int
    raw_log: str