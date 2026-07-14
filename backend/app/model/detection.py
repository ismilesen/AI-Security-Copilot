from dataclasses import dataclass

@dataclass
class Detection:
    rule_id: str
    name: str
    description: str
    evidence: list[str]
