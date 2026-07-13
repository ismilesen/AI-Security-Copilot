from fastapi import FastAPI, UploadFile, File, HTTPException

from app.parsers.log_parser import parse_log
from app.detectors.ssh_detector import detect_ssh_bruteforce 
app = FastAPI(
    title = "AI Security Copilot",
    description = "Security log analysis platform",
    version = "1.0.0"
)

MAX_FILE_SIZE = 5 * 1024 * 1024

@app.get("/")
def root():
    return { 
        "message": "AI Security Copilot API is running stable..."
    }
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    

    
    
    parsed = await parse_log(file)

    if parsed.size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code = 413,
            detail = "file too large to analyze. Max file size 5 MB"
        )

    detection = detect_ssh_bruteforce(parsed)
    
    return {
        "filename": parsed.filename,
        "size": parsed.size,
        "preview": parsed.text,
        "detection": detection
    }