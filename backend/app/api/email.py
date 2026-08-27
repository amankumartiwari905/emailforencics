from fastapi import APIRouter, UploadFile, File
from app.services.email_parser import parse_email

router = APIRouter()


@router.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    email_data = await file.read()

    parsed_email = parse_email(email_data)

    return parsed_email