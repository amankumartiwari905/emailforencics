from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.email import router as email_router
from app.proxy import router as proxy_router


app = FastAPI(
    title="MailTrace AI API",
    version="1.0.0"
)


# CORS - allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8443",
        "http://127.0.0.1:8443",

        "http://localhost:5173",
        "http://127.0.0.1:5173",

        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "status": "ok",
        "message": "MailTrace AI API is running"
    }


app.include_router(email_router)
app.include_router(proxy_router)