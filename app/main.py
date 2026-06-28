import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.decoder import engine as decoder_engine
from app.alerts.router import router as alerts_router
from app.auth_router import router as auth_router
from app.events.router import router as events_router
from app.ingest.router import router as ingest_router
from app.parsers.router import router as parsers_router
from app.rules.router import router as rules_crud_router
from app.users.router import router as users_router
from app.password import hash_password
from app.rules import engine as rule_engine
from app.storage import chroma_store, duckdb_store

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("TinySIEM starting up")
    duckdb_store.init_db()
    chroma_store.init_chroma()
    decoder_engine.load_decoders()
    rule_engine.load_rules()
    duckdb_store.ensure_superadmin(hash_password(settings.tinysiem_superadmin_password))
    yield
    logger.info("TinySIEM shutting down")
    duckdb_store.close_db()


app = FastAPI(
    title="TinySIEM",
    version=settings.tinysiem_version,
    docs_url="/docs" if settings.tinysiem_debug else None,
    redoc_url="/redoc" if settings.tinysiem_debug else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(ingest_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(parsers_router)
app.include_router(rules_crud_router)

app.mount("/ui", StaticFiles(directory="/app/ui"), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/ui/dashboard.html")


@app.get("/health")
def health():
    return {"status": "ok", "version": settings.tinysiem_version}
