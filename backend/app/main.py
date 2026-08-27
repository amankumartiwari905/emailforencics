from  fastapi import FastAPI
from app.api.email import router as email_router

app = FastAPI()
@app.get("/")
def home():
    return {"email_parser": "Email Parser API is running."}

app.include_router(email_router)