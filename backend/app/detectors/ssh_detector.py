from collections import defaultdict
from app.model.authentication_event import AuthenticationEvent
from app.model.detection import Detection
from app.model.parsed_log import ParsedLog

MINIMUM_FAILURES = 5

def detect_ssh_bruteforce(log: ParsedLog) -> list[Detection]:
    failures_by_ip: dict[str, list[AuthenticationEvent]] = defaultdict(list)

    for event in log.authentication_events:
        if event.protocol == "SSH" and not event.success:
            failures_by_ip[event.source_ip].append(event)

    detections: list[Detection] = []

    for source_ip, failed_events in failures_by_ip.items():
        if len(failed_events) < MINIMUM_FAILURES:
            continue

        detections.append(
            Detection(
                rule_id="SSH-BRUTEFORCE-001",
                name="Possible SSH Brute Force",
                description=(
                    f"Detected {len(failed_events)} failed SSH login attempts "
                    f"from source IP {source_ip}."
                ),
                source_ip=source_ip,
                event_count=len(failed_events),
                evidence=failed_events,
            )
        )

    return detections