from fastapi import UploadFile
from app.model.parsed_log import ParsedLog
import re
from app.model.authentication_event import AuthenticationEvent
from datetime import datetime

FAILED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"Failed password for "
    r"(?:(?:invalid user)\s+)?"
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\S+)"
)

ACCEPTED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"Accepted password for "
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\S+)"
)

def parse_sys_timestamp(value: str) -> datetime:
    current_year = datetime.now(). year
    return datetime.strptime(
        f"{current_year} {value}",
        "%Y %b %d %H:%M:%S",
    )


def parse_authentication_events(text: str) -> list[AuthenticationEvent]:
    events: list[AuthenticationEvent] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        match = FAILED_SSH_PATTERN.search(line)
        success = False

        if match is None:
            match = ACCEPTED_SSH_PATTERN.search(line)
            success = True

        if match is None:
            continue

        events.append(
            AuthenticationEvent(
                timestamp=parse_sys_timestamp(match.group("timestamp")),
                username=match.group("username"),
                source_ip=match.group("source_ip"),
                destination_host=match.group("host"),
                protocol="SSH",
                success=success,
                line_number=line_number,
                raw_log=line,
            )
        )

    return events


async def parse_log(file: UploadFile) -> ParsedLog:
    contents = await file.read()
    text = contents.decode("utf-8", errors="replace")

    return ParsedLog(
        filename=file.filename or "unknown",
        size=len(contents),
        text=text,
        authentication_events=parse_authentication_events(text),
    )
        
    