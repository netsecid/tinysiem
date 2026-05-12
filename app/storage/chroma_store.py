import logging
from typing import Optional

import chromadb

from app.config import settings

logger = logging.getLogger(__name__)

_client: Optional[chromadb.ClientAPI] = None
_collection = None


def init_chroma(path: Optional[str] = None) -> None:
    global _client, _collection
    chroma_path = path or settings.tinysiem_chroma_path
    _client = chromadb.PersistentClient(path=chroma_path)
    _collection = _client.get_or_create_collection("events")


def get_collection():
    if _collection is None:
        raise RuntimeError("ChromaDB not initialized — call init_chroma() first")
    return _collection


def upsert_event(event: dict) -> None:
    collection = get_collection()
    collection.upsert(
        ids=[event["id"]],
        documents=[event["raw"]],
        metadatas=[
            {
                "source": event.get("source", ""),
                "ingested_at": str(event.get("ingested_at", "")),
                "source_ip": event.get("source_ip") or "",
                "status_code": str(event.get("status_code") or ""),
                "uri": event.get("uri") or "",
            }
        ],
    )


def search_similar(text: str, n_results: int = 5) -> list:
    collection = get_collection()
    return collection.query(query_texts=[text], n_results=n_results)
