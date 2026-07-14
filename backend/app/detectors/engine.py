from collections.abc import Callable

from app.model.detection import Detection
from app.model.parsed_log import ParsedLog
from app.detectors.ssh_detector import detect_ssh_bruteforce

Detector = Callable[[ParsedLog], list[Detection]]

#modular detectors
DETECTORS: list[Detector] = [
    detect_ssh_bruteforce
    #more to be added as I learn
]

def run_detectors(log: ParsedLog) -> list[Detection]:
    detections: list[Detection] = []

    for detector in DETECTORS:
        detections.extend(detector(log))
    return detections