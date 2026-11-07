
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app import models
from app.routes.scanner import router


# Create database tables
Base.metadata.create_all(bind=engine)


# Initialize FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description="Advanced URL Threat Detection System",
    version="2.0.0"
)


# Configure frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"]
)


# Register API routes
app.include_router(router)


# Home endpoint
@app.get("/")
def home():

    return {
        "message": "SafeLink Checker API is running",
        "version": "2.0.0"
    }


# Health check endpoint
@app.get("/health")
def health():

    return {
        "status": "healthy"
    }
