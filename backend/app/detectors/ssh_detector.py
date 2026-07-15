from collections import defaultdict
from app.model.authentication_event import AuthenticationEvent
from app.model.detection import Detection
from app.model.parsed_log import ParsedLog
from datetime import timedelta

MINIMUM_FAILURES = 5
DETECTION_WINDOW = timedelta(seconds=60)

def detect_ssh_bruteforce(log: ParsedLog) -> list[Detection]:
    failures_by_ip: dict[str, list[AuthenticationEvent]] = defaultdict(list)

    for event in log.authentication_events:
        if event.protocol == "SSH" and not event.success:
            failures_by_ip[event.source_ip].append(event)

    detections: list[Detection] = []

    for source_ip, failed_events in failures_by_ip.items():
        failed_events.sort(key=lambda event: event.timestamp)
    
        #sliding window algorithm to implement a time interval between login attempts
        window_start = 0

        for window_end in range(len(failed_events)):
            while (
                failed_events[window_end].timestamp
                - failed_events[window_start].timestamp
                > DETECTION_WINDOW
            ):
                window_start += 1

            window_events = failed_events[window_start : window_end + 1]

            if len(window_events) >= MINIMUM_FAILURES:
                detections.append(
                    Detection(
                        rule_id="SSH-BRUTEFORCE-001",
                        name="Possible SSH Brute Force",
                        description=(
                            f"Detected {len(window_events)} failed SSH login attempts "
                            f"from source IP {source_ip} within "
                            f"{int(DETECTION_WINDOW.total_seconds())} seconds."
                        ),
                        source_ip=source_ip,
                        event_count=len(window_events),
                        evidence=window_events,
                    )
                )
                break

    return detections


