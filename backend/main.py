"""
main.py — FastAPI application entry point.

URL Tracer — URL-Based Phishing & Cyber Attack Detection Platform

Run with:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

# Load .env FIRST — before any module that reads os.environ at import time
from dotenv import load_dotenv
load_dotenv()

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from database import engine
from models import Base

from api import dashboard, attacks, ips, upload, export, ml


# ─────────────────────────────────────────────
# Startup / Shutdown lifecycle
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables on startup (no-op if already exist)
    Base.metadata.create_all(bind=engine)

    yield  # server is running


# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────

app = FastAPI(
    title="URL Tracer — Cyber Attack Detection Platform",
    description=(
        "URL-based phishing and cyber attack detection. "
        "Analyzes HTTP traffic, PCAP files, and URLs for malicious patterns "
        "using rule-based detection and ML classification."
    ),
    version="1.1.0",
    lifespan=lifespan,
)

# ─────────────────────────────────────────────
# CORS — locked in Phase 9 to production origins
# ─────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # TODO Phase 9: restrict to production frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Global exception handler — never expose stack traces
# ─────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "An unexpected error occurred."},
    )


# ─────────────────────────────────────────────
# Register API routers
# ─────────────────────────────────────────────

app.include_router(dashboard.router, prefix="/api")
app.include_router(attacks.router, prefix="/api")
app.include_router(ips.router, prefix="/api")
app.include_router(upload.router, prefix="/api")
app.include_router(export.router, prefix="/api")
app.include_router(ml.router, prefix="/api")


# ─────────────────────────────────────────────
# Root health check
# ─────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "status": "online",
        "system": "URL Tracer — Cyber Attack Detection Platform",
        "version": "1.1.0",
        "docs": "/docs",
        "redoc": "/redoc",
    }


@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "version": "1.1.0"}
