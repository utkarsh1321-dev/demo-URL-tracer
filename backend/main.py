"""
main.py — FastAPI application entry point.
URL Tracer — URL-Based Phishing & Cyber Attack Detection Platform

Run locally:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

# ─── Load .env FIRST — before any module reads os.environ ────────────────────
from dotenv import load_dotenv
load_dotenv()

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from database import engine
from models import Base

from api import dashboard, attacks, ips, upload, export, ml, analyze, pcap, public_analyze

# ─────────────────────────────────────────────
# Environment & Version
# ─────────────────────────────────────────────

APP_ENV  = os.getenv("APP_ENV", "development")
_IS_PROD = APP_ENV == "production"
_VERSION = "1.5.0"

# ─────────────────────────────────────────────
# Logging — structured, no secrets
# ─────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("urltracer")

# ─────────────────────────────────────────────
# Startup / Shutdown lifecycle
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("URL Tracer v%s started  env=%s", _VERSION, APP_ENV)
    yield
    logger.info("URL Tracer shutting down")


# ─────────────────────────────────────────────
# FastAPI App
# Swagger/ReDoc disabled in production to prevent
# information disclosure about internal API structure.
# ─────────────────────────────────────────────

app = FastAPI(
    title="URL Tracer — Cyber Attack Detection Platform",
    description=(
        "URL-based phishing and cyber attack detection. "
        "Analyzes HTTP traffic, PCAP files, and URLs for malicious patterns "
        "using rule-based detection and ML classification."
    ),
    version=_VERSION,
    lifespan=lifespan,
    docs_url=None  if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
)


# ─────────────────────────────────────────────
# CORS — env-var controlled (Phase 9)
# Set ALLOWED_ORIGINS in Render/Vercel env (comma-separated):
#   Production  : https://url-tracer.vercel.app
#   Development : http://localhost:5173,http://localhost:3000
#
# Chrome extensions with host_permissions bypass CORS entirely —
# this restriction applies only to browser (web frontend) requests.
# ─────────────────────────────────────────────

_raw_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173",
)
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Extension-Id"],
)


# ─────────────────────────────────────────────
# Security headers middleware (Phase 10)
# Added to every response — prevents clickjacking,
# MIME sniffing, and protocol downgrade attacks.
# ─────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=()"
    if _IS_PROD:
        # HSTS only on HTTPS (Render always uses HTTPS in production)
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
    return response


# ─────────────────────────────────────────────
# Request logging — method + path + status + latency
# NEVER logs: Authorization headers, request body,
#             query strings, or user-submitted content
# ─────────────────────────────────────────────

@app.middleware("http")
async def request_logger(request: Request, call_next):
    t0     = time.perf_counter()
    method = request.method
    path   = request.url.path   # path only — no query string (may contain tokens)

    response = await call_next(request)

    latency_ms = round((time.perf_counter() - t0) * 1000, 1)
    logger.info("%s %s -> %d  %.1fms", method, path, response.status_code, latency_ms)
    return response


# ─────────────────────────────────────────────
# Global exception handler — never expose stack traces
# ─────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled exception on %s %s: %s",
        request.method,
        request.url.path,
        type(exc).__name__,   # log type only — exc message may contain secrets
    )
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "An unexpected error occurred."},
    )


# ─────────────────────────────────────────────
# API routers
# ─────────────────────────────────────────────

app.include_router(dashboard.router,        prefix="/api")
app.include_router(attacks.router,          prefix="/api")
app.include_router(ips.router,              prefix="/api")
app.include_router(upload.router,           prefix="/api")
app.include_router(export.router,           prefix="/api")
app.include_router(ml.router,               prefix="/api")
app.include_router(analyze.router,          prefix="/api")   # Phase 3-5: URL analysis + history
app.include_router(pcap.router,             prefix="/api")   # Phase 7: PCAP history
app.include_router(public_analyze.router,   prefix="/api")   # Phase 8: Chrome extension endpoint


# ─────────────────────────────────────────────
# Health endpoints
# ─────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "status":  "online",
        "system":  "URL Tracer — Cyber Attack Detection Platform",
        "version": _VERSION,
        "env":     APP_ENV,
        # Docs URLs intentionally omitted in production
        **({"docs": "/docs", "redoc": "/redoc"} if not _IS_PROD else {}),
    }


@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "version": _VERSION, "env": APP_ENV}
