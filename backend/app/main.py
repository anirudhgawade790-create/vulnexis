import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import get_settings
from app.database import async_engine, Base
from app.routers import (
    auth,
    assets,
    baseline,
    dashboard,
    findings,
    remediation,
    scans,
    targets,
    users,
    vulnerabilities,
    websocket,
)

logger = logging.getLogger(__name__)
settings = get_settings()

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle."""
    if settings.demo_mode:
        logger.info("DEMO_MODE=true — creating tables and seeding demo data")
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        from app.database import AsyncSessionLocal
        from app.demo.seed_demo import seed

        async with AsyncSessionLocal() as db:
            await seed(db)
            await db.commit()

    yield

    await async_engine.dispose()


app = FastAPI(
    title="SIH1684 Scanner Platform API",
    description=(
        "Advanced agent-less Windows vulnerability and network scanner API. "
        "Provides endpoints for asset discovery, vulnerability assessment, "
        "finding management, and AI-assisted remediation."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# ── Rate limiting ───────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────────────────────────
API_PREFIX = "/api/v1"

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(users.router, prefix=API_PREFIX)
app.include_router(targets.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(assets.router, prefix=API_PREFIX)
app.include_router(vulnerabilities.router, prefix=API_PREFIX)
app.include_router(findings.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(remediation.router, prefix=API_PREFIX)
app.include_router(baseline.router, prefix=API_PREFIX)

# WebSocket router has its own path (/ws/scan/{id}), no API prefix
app.include_router(websocket.router)


# ── Health endpoint ─────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "ok"}
