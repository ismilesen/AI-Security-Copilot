from dataclasses import dataclass, field

from app.model.authentication_event import AuthenticationEvent


@dataclass
class ParsedLog:
    filename: str
    size: int
    text: str
    authentication_events: list[AuthenticationEvent] = field(
        default_factory=list
    )