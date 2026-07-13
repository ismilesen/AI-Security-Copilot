from dataclasses import dataclass

@dataclass
class ParsedLog:
    filename: str
    size: int
    text: str
    