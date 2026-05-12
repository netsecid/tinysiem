import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_decoders: dict[str, dict] = {}

_SCHEMA_FIELDS = {
    "source_ip", "method", "uri", "status_code",
    "response_size", "user_agent", "referer", "event_time",
}


def load_decoders(decoders_dir: Optional[Path] = None) -> None:
    global _decoders
    if decoders_dir is None:
        decoders_dir = Path(__file__).parent / "decoders"

    _decoders = {}
    for yaml_file in decoders_dir.glob("*.yaml"):
        try:
            with open(yaml_file) as f:
                decoder = yaml.safe_load(f)
            source = decoder.get("source")
            if source:
                _decoders[source] = decoder
                logger.info(f"Loaded decoder '{decoder.get('name')}' for source '{source}'")
        except Exception as exc:
            logger.warning(f"Failed to load decoder {yaml_file}: {exc}")


def decode(source: str, raw: str) -> Optional[dict]:
    decoder = _decoders.get(source)
    if not decoder:
        logger.warning(f"No decoder for source '{source}'")
        return None

    dtype = decoder.get("type", "regex")
    try:
        if dtype == "regex":
            return _decode_regex(decoder, source, raw)
        if dtype == "json":
            return _decode_json(decoder, source, raw)
        if dtype == "kv":
            return _decode_kv(decoder, source, raw)
    except Exception as exc:
        logger.warning(f"Decoder error for source '{source}': {exc}")
        return None

    logger.warning(f"Unknown decoder type '{dtype}'")
    return None


def _base_event(source: str, raw: str) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "source": source,
        "ingested_at": datetime.now(timezone.utc),
        "raw": raw,
    }


def _apply_fields(event: dict, fields: dict, data: dict) -> dict:
    extra: dict = {}
    for normalized, src_key in fields.items():
        value = data.get(src_key)
        if normalized in _SCHEMA_FIELDS:
            event[normalized] = _coerce(normalized, value)
        else:
            extra[normalized] = value
    event.setdefault("extra", {}).update(extra)
    return event


def _coerce(name: str, value):
    if value is None or value == "-":
        return None
    if name in ("status_code", "response_size"):
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    return value


def _parse_timestamp(event: dict, decoder: dict, data: dict) -> None:
    ts_field = decoder.get("timestamp_field")
    ts_format = decoder.get("timestamp_format")
    fields = decoder.get("fields", {})
    if not (ts_field and ts_format and ts_field in fields):
        return
    ts_str = data.get(fields[ts_field])
    if ts_str:
        try:
            event["event_time"] = datetime.strptime(ts_str, ts_format)
        except ValueError:
            pass


def _decode_regex(decoder: dict, source: str, raw: str) -> Optional[dict]:
    pattern = decoder.get("pattern")
    if not pattern:
        logger.warning("Decoder missing 'pattern' field")
        return None

    try:
        match = re.match(pattern, raw)
    except re.error as exc:
        logger.warning(f"Regex error: {exc}")
        return None

    if not match:
        logger.warning(f"Pattern did not match for source '{source}'")
        return None

    groups = match.groupdict()
    event = _base_event(source, raw)
    fields = decoder.get("fields", {})
    _apply_fields(event, fields, groups)
    _parse_timestamp(event, decoder, groups)
    return event


def _decode_json(decoder: dict, source: str, raw: str) -> Optional[dict]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning(f"JSON decode error: {exc}")
        return None

    event = _base_event(source, raw)
    fields = decoder.get("fields", {})
    _apply_fields(event, fields, data)
    # Unmapped keys go to extra
    mapped_src_keys = set(fields.values())
    for key, val in data.items():
        if key not in mapped_src_keys:
            event.setdefault("extra", {})[key] = val
    return event


def _decode_kv(decoder: dict, source: str, raw: str) -> Optional[dict]:
    import shlex
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()

    data: dict = {}
    for token in tokens:
        if "=" in token:
            k, _, v = token.partition("=")
            data[k.strip()] = v.strip()

    event = _base_event(source, raw)
    fields = decoder.get("fields", {})
    _apply_fields(event, fields, data)
    return event
