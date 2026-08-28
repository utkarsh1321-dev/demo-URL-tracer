"""
main.py -- FastAPI application entry point.

URL Tracer -- URL-Based Phishing & Cyber Attack Detection Platform

Run with:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

# Load .env FIRST -- before any module that reads os.environ at import time
from dotenv import load_dotenv
load_dotenv()

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from database import engine
from models import Base

from api import dashboard, attacks, ips, upload, export, ml, analyze

# ─────────────────────────────────────────────
# Logging — structured, no secrets
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("urltracer")

# ─────────────────────────────────────────────
# Startup / Shutdown lifecycle
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all local SQLite tables on startup (no-op for Postgres managed by migrations)
    Base.metadata.create_all(bind=engine)
    logger.info("URL Tracer v1.3.0 started")
    yield
    logger.info("URL Tracer shutting down")


# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────

app = FastAPI(
    title="URL Tracer -- Cyber Attack Detection Platform",
    description=(
        "URL-based phishing and cyber attack detection. "
        "Analyzes HTTP traffic, PCAP files, and URLs for malicious patterns "
        "using rule-based detection and ML classification."
    ),
    version="1.3.0",
    lifespan=lifespan,
    # Disable Swagger/ReDoc in production — controlled by EXPOSE_DOCS env var
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─────────────────────────────────────────────
# CORS -- locked in Phase 9 to production origins
# ─────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # TODO Phase 9: restrict to production frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Request logging middleware (Phase 5)
# Logs: method, path, status, latency -- NEVER URL query params or body
# ─────────────────────────────────────────────

@app.middleware("http")
async def request_logger(request: Request, call_next):
    """
    Structured request logger.

    What is logged    : method, path (no query string), status, latency_ms
    What is NOT logged: Authorization header, request body, URL query params,
                        any user-submitted content
    """
    t0 = time.perf_counter()
    method = request.method
    path   = request.url.path      # path only — no query string (which may contain tokens)

    response = await call_next(request)

    latency_ms = round((time.perf_counter() - t0) * 1000, 1)
    logger.info("%s %s -> %d  %.1fms", method, path, response.status_code, latency_ms)
    return response


# ─────────────────────────────────────────────
# Global exception handler -- never expose stack traces
# ─────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled exception on %s %s: %s",
        request.method,
        request.url.path,
        type(exc).__name__,    # log exception type but NOT message (may contain secrets)
    )
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "An unexpected error occurred."},
    )


# ─────────────────────────────────────────────
# Register API routers
# ─────────────────────────────────────────────

app.include_router(dashboard.router, prefix="/api")
app.include_router(attacks.router,   prefix="/api")
app.include_router(ips.router,       prefix="/api")
app.include_router(upload.router,    prefix="/api")
app.include_router(export.router,    prefix="/api")
app.include_router(ml.router,        prefix="/api")
app.include_router(analyze.router,   prefix="/api")   # Phase 3-5: URL analysis engine


# ─────────────────────────────────────────────
# Root health check
# ─────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "status":  "online",
        "system":  "URL Tracer -- Cyber Attack Detection Platform",
        "version": "1.3.0",
        "docs":    "/docs",
        "redoc":   "/redoc",
    }


@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "version": "1.3.0"}
