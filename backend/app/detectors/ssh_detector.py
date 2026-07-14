from app.model.detection import Detection
from app.model.parsed_log import ParsedLog


FAILED_PASSWORD_PATTERN = "Failed password"
MINIMUM_FAILURES = 5


def detect_ssh_bruteforce(log: ParsedLog) -> list[Detection]:
    failed_lines = [
        line
        for line in log.text.splitlines()
        if FAILED_PASSWORD_PATTERN in line
    ]

    if len(failed_lines) < MINIMUM_FAILURES:
        return []

    detection = Detection(
        rule_id="SSH-BRUTEFORCE-001",
        name="Possible SSH Brute Force",
        description=(
            f"Detected {len(failed_lines)} failed SSH login attempts."
        ),
        evidence=failed_lines,
    )

    return [detection]