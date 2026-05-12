import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.decoder import engine as decoder_engine
from app.ingest.router import router as ingest_router
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

app.include_router(ingest_router)


@app.get("/health")
def health():
    return {"status": "ok", "version": settings.tinysiem_version}
