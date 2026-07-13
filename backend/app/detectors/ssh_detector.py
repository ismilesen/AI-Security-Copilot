from app.model.detection import Detection
from app.model.parsed_log import ParsedLog

def detect_ssh_bruteforce(log: ParsedLog):

    if "Failed password" in log.text:
        return Detection(
            name="Possible SSH Brute Force",
            severity="Medium",
            description="Detected failed SSH login attempts."
        )
    return None