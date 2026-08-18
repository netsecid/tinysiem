from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.auth import AuthUser, require_analyst
from app.cases import store as case_store
from app.storage import duckdb_store
from app.storage.csv_export import rows_to_csv

router = APIRouter(prefix="/events", tags=["events"])

_FILTER_PARAMS = dict(
    source=None, source_ip=None,
    status_code=None, status_min=None, status_max=None,
    method=None, uri=None, q=None,
    start=None, end=None,
    country_code=None, city=None, asn=None,
    response_size_min=None, response_size_max=None,
    user_agent=None, referer=None,
)

_CSV_EXPORT_CAP = 10_000
_CSV_COLUMNS = [
    "id", "source", "ingested_at", "event_time", "source_ip", "method",
    "uri", "status_code", "response_size", "user_agent", "referer", "raw",
    "country_code", "country_name", "city", "asn",
]


def _filter_kwargs(
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    status_code: Optional[int] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    method: Optional[str] = None,
    uri: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    country_code: Optional[str] = None,
    city: Optional[str] = None,
    asn: Optional[int] = None,
    response_size_min: Optional[int] = None,
    response_size_max: Optional[int] = None,
    user_agent: Optional[str] = None,
    referer: Optional[str] = None,
) -> dict:
    return dict(
        source=source, source_ip=source_ip,
        status_code=status_code, status_min=status_min, status_max=status_max,
        method=method, uri=uri, q=q, start=start, end=end,
        country_code=country_code, city=city, asn=asn,
        response_size_min=response_size_min, response_size_max=response_size_max,
        user_agent=user_agent, referer=referer,
    )


@router.get("")
def list_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    status_code: Optional[int] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    method: Optional[str] = None,
    uri: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    country_code: Optional[str] = None,
    city: Optional[str] = None,
    asn: Optional[int] = None,
    response_size_min: Optional[int] = None,
    response_size_max: Optional[int] = None,
    user_agent: Optional[str] = None,
    referer: Optional[str] = None,
    format: Optional[str] = None,
    _: AuthUser = Depends(require_analyst),
):
    filter_kwargs = _filter_kwargs(source, source_ip, status_code, status_min, status_max,
                                    method, uri, q, start, end,
                                    country_code, city, asn,
                                    response_size_min, response_size_max,
                                    user_agent, referer)
    if format == "csv":
        result = duckdb_store.query_events(limit=_CSV_EXPORT_CAP, offset=0, **filter_kwargs)
        csv_text = rows_to_csv(result["events"], _CSV_COLUMNS)
        return StreamingResponse(
            iter([csv_text]),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="events.csv"'},
        )
    return duckdb_store.query_events(
        limit=limit, offset=offset,
        **filter_kwargs,
    )


@router.get("/facets")
def event_facets(
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    status_code: Optional[int] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    method: Optional[str] = None,
    uri: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    country_code: Optional[str] = None,
    city: Optional[str] = None,
    asn: Optional[int] = None,
    response_size_min: Optional[int] = None,
    response_size_max: Optional[int] = None,
    user_agent: Optional[str] = None,
    referer: Optional[str] = None,
    _: AuthUser = Depends(require_analyst),
):
    return duckdb_store.get_event_facets(
        **_filter_kwargs(source, source_ip, status_code, status_min, status_max,
                         method, uri, q, start, end,
                         country_code, city, asn,
                         response_size_min, response_size_max,
                         user_agent, referer),
    )


@router.get("/histogram")
def event_histogram(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    buckets: int = Query(60, ge=10, le=200),
    _: AuthUser = Depends(require_analyst),
):
    now = datetime.utcnow()
    resolved_start = start or (now - timedelta(hours=1))
    resolved_end = end or now
    return duckdb_store.get_event_histogram(
        start=resolved_start, end=resolved_end, buckets=buckets
    )


@router.get("/{event_id}")
def get_event_by_id(event_id: str, _: AuthUser = Depends(require_analyst)):
    event = duckdb_store.get_event_full(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/{event_id}/cases")
def get_event_cases(event_id: str, _: AuthUser = Depends(require_analyst)):
    cases = case_store.get_cases_for_event(event_id)
    return {"cases": cases}
