from dataclasses import dataclass

from app.model.authentication_event import AuthenticationEvent

@dataclass
class Detection:
    rule_id: str
    name: str
    description: str
    source_ip: str
    event_count: int
    evidence: list[AuthenticationEvent]
