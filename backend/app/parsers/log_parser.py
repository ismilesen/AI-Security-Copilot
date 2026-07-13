from fastapi import UploadFile
from app.model.parsed_log import ParsedLog


async def parse_log(file: UploadFile):
    """
    Reads an uploaded log file and returns
    useful structured information.
    """

    contents = await file.read()

    text = contents.decode(
        "utf-8",
        errors="replace"
    )

    return ParsedLog(
        filename=file.filename,
        size=len(contents),
        text=text
    )
        
    