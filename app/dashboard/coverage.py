"""Detection Coverage dashboard payload builder.

Joins rule YAMLs against the bundled MITRE ATT&CK matrix (see
``app/rules.mitre``) and overlays alert activity from the JSONL alert log
(scoped to a rolling window). Returns the full Navigator-style matrix —
including empty (gap) techniques — so the UI can render honest coverage.

This module deliberately does NOT query DuckDB; alerts live in the JSONL
file (small, <10k lines/day) and a single scan per request is acceptable
for the 7.5s polling cadence. See ``_alert_stats_by_technique``.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from app.config import settings
from app.rules import mitre


def _alert_stats_by_technique(window_seconds: int) -> tuple[dict[str, int], int]:
    """Walk the alerts JSONL once and bucket in-window alerts by MITRE technique.

    Returns ``({mitre_technique: count}, alerts_unmapped)``. Records with
    missing/empty ``mitre_technique`` land in ``alerts_unmapped`` so the
    dashboard can surface "X unmapped alerts" without losing them. Any
    parse/IO error returns empty shapes — never crashes the endpoint.
    """
    empty = ({}, 0)
    try:
        path = Path(settings.tinysiem_alerts_path)
        if not path.exists():
            return empty
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        counts: dict[str, int] = {}
        unmapped = 0
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = rec.get("triggered_at")
                if not ts:
                    continue
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if dt < cutoff:
                    continue
                tech = (rec.get("mitre_technique") or "").strip()
                if not tech:
                    unmapped += 1
                    continue
                # Sub-technique IDs (T1059.001) → bucket under prefix (T1059)
                # so they line up with the matrix's top-level rows.
                base = tech.split(".", 1)[0] if "." in tech else tech
                counts[base] = counts.get(base, 0) + 1
        return counts, unmapped
    except Exception:
        return empty


def build_coverage_payload(
    rule_files: Iterable[tuple[Path, bool]],
    window_seconds: int,
) -> dict | None:
    """Build the Detection Coverage payload, or ``None`` when the matrix
    dataset is unavailable (caller returns 503).
    """
    alert_counts, alerts_unmapped = _alert_stats_by_technique(window_seconds)
    payload = mitre.compute_full_coverage(
        rule_files=rule_files,
        alert_counts_by_technique=alert_counts,
        alerts_unmapped=alerts_unmapped,
    )
    if payload is None:
        return None
    payload["window_seconds"] = window_seconds
    payload["window_label"] = (
        "1m" if window_seconds == 60
        else "1h" if window_seconds == 3600
        else "24h" if window_seconds == 86400
        else f"{window_seconds}s"
    )
    payload["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return payload
