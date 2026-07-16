import re
from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from app.audit import store as audit
from app.auth import AuthUser, require_admin, require_analyst
from app.decoder import engine as decoder_engine

router = APIRouter(prefix="/parsers", tags=["parsers"])

_DECODERS_DIR = Path(__file__).parent.parent / "decoder" / "decoders"
_CUSTOM_DIR = _DECODERS_DIR / "custom"
_REQUIRED_KEYS = {"name", "source", "type", "pattern", "fields"}
_VALID_NAME = re.compile(r'^[a-z0-9][a-z0-9\-_]{0,63}$')
_REDOS_PATTERN = re.compile(r'\([^()]*[+*][^()]*\)[+*]')


def _check_name(name: str) -> None:
    if not _VALID_NAME.match(name):
        raise HTTPException(
            status_code=422,
            detail="Name must be lowercase alphanumeric, hyphens or underscores only",
        )


def _check_redos_risk(pattern: str) -> None:
    """Reject regex patterns with a classic nested-quantifier ReDoS shape, e.g. (a+)+ or (a*)*.
    This is a heuristic, not a full ReDoS detector — it catches the most common catastrophic-
    backtracking construction without executing the pattern."""
    if _REDOS_PATTERN.search(pattern):
        raise HTTPException(
            status_code=422,
            detail="Pattern contains a nested quantifier (e.g. (a+)+) that risks catastrophic "
            "backtracking (ReDoS) — restructure the regex to avoid nested repetition.",
        )


def _list_parser_files() -> list[tuple[Path, bool]]:
    files = []
    for p in sorted(_DECODERS_DIR.glob("*.yaml")):
        files.append((p, False))
    if _CUSTOM_DIR.exists():
        for p in sorted(_CUSTOM_DIR.glob("*.yaml")):
            files.append((p, True))
    return files


def _get_parser_file(name: str) -> tuple[Optional[Path], bool]:
    custom = _CUSTOM_DIR / f"{name}.yaml"
    if custom.exists():
        return custom, True
    builtin = _DECODERS_DIR / f"{name}.yaml"
    if builtin.exists():
        return builtin, False
    return None, False


def _validate_parser_yaml(yaml_text: str) -> dict:
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {exc}")
    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="YAML must be a mapping")
    missing = _REQUIRED_KEYS - data.keys()
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required keys: {', '.join(sorted(missing))}",
        )
    if data.get("type", "regex") == "regex" and data.get("pattern"):
        _check_redos_risk(data["pattern"])
    return data


class ParserRequest(BaseModel):
    name: str
    yaml_text: str


class TestRequest(BaseModel):
    log_line: str


@router.get("")
def list_parsers(_: AuthUser = Depends(require_analyst)):
    result = []
    for path, is_custom in _list_parser_files():
        try:
            data = yaml.safe_load(path.read_text())
            result.append({
                "name": path.stem,
                "source": data.get("source", ""),
                "type": data.get("type", ""),
                "is_custom": is_custom,
            })
        except Exception:
            pass
    return {"parsers": result}


@router.post("", status_code=201)
def create_parser(req: ParserRequest, actor: AuthUser = Depends(require_admin)):
    _check_name(req.name)
    data = _validate_parser_yaml(req.yaml_text)
    dest = _CUSTOM_DIR / f"{req.name}.yaml"
    if dest.exists():
        raise HTTPException(status_code=409, detail="Parser already exists")
    _CUSTOM_DIR.mkdir(exist_ok=True)
    dest.write_text(req.yaml_text)
    decoder_engine.load_decoders()
    audit.log_event(
        "parser.create", "created", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="parser", resource_id=req.name,
        detail={"parser_name": req.name, "source": data.get("source"), "type": data.get("type")},
    )
    return {"name": req.name, "status": "created"}


@router.post("/{name}/test")
def test_parser(name: str, req: TestRequest, actor: AuthUser = Depends(require_analyst)):
    _check_name(name)
    path, _ = _get_parser_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Parser not found")
    try:
        decoder = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Parser YAML invalid: {exc}")
    event = decoder_engine.decode_with(decoder, req.log_line)
    matched = event is not None
    audit.log_event(
        "parser.test", "tested", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="parser", resource_id=name,
        detail={"parser_name": name, "matched": matched, "log_line_preview": req.log_line[:200]},
    )
    if not matched:
        return {"matched": False, "fields": {}}
    fields = {k: v for k, v in event.items() if k not in ("id", "ingested_at", "raw", "source")}
    return {"matched": True, "fields": fields}


class GenerateParserRequest(BaseModel):
    log_sample: str


@router.post("/generate")
def generate_parser_endpoint(req: GenerateParserRequest, actor: AuthUser = Depends(require_admin)):
    from app.ai.claude import generate_parser
    from app.ai.enrichment import build_generation_context
    ctx = build_generation_context()
    try:
        yaml_text = generate_parser(ctx + req.log_sample, actor=actor.username)
    except RuntimeError as exc:
        audit.log_event(
            "parser.generate", "generated", "error",
            actor=actor.username, actor_role=actor.role,
            resource_type="parser",
            detail={"log_sample_length": len(req.log_sample), "log_sample_preview": req.log_sample[:200]},
            error_msg=str(exc),
        )
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        audit.log_event(
            "parser.generate", "generated", "error",
            actor=actor.username, actor_role=actor.role,
            resource_type="parser",
            detail={"log_sample_length": len(req.log_sample), "log_sample_preview": req.log_sample[:200]},
            error_msg=str(exc),
        )
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")
    try:
        data = _validate_parser_yaml(yaml_text)
    except HTTPException:
        raise HTTPException(
            status_code=422,
            detail=f"Generated YAML failed validation. Raw output:\n{yaml_text}",
        )
    audit.log_event(
        "parser.generate", "generated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="parser", resource_id=data.get("name"),
        detail={
            "log_sample_length": len(req.log_sample),
            "log_sample_preview": req.log_sample[:200],
            "generated_name": data.get("name"),
            "generated_source": data.get("source"),
        },
    )
    return {"yaml_text": yaml_text, "preview": True}


@router.get("/{name}")
def get_parser(name: str, _: AuthUser = Depends(require_analyst)):
    _check_name(name)
    path, _ = _get_parser_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Parser not found")
    return {"name": name, "yaml_text": path.read_text()}


@router.put("/{name}")
def update_parser(name: str, req: ParserRequest, actor: AuthUser = Depends(require_admin)):
    _check_name(name)
    path, is_custom = _get_parser_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Parser not found")
    if not is_custom:
        raise HTTPException(status_code=403, detail="Cannot modify built-in parsers")
    data = _validate_parser_yaml(req.yaml_text)
    path.write_text(req.yaml_text)
    decoder_engine.load_decoders()
    audit.log_event(
        "parser.update", "updated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="parser", resource_id=name,
        detail={"parser_name": name, "source": data.get("source")},
    )
    return {"name": name, "status": "updated"}


@router.delete("/{name}", status_code=204)
def delete_parser(name: str, actor: AuthUser = Depends(require_admin)):
    _check_name(name)
    path, is_custom = _get_parser_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Parser not found")
    if not is_custom:
        raise HTTPException(status_code=403, detail="Cannot delete built-in parsers")
    path.unlink()
    decoder_engine.load_decoders()
    audit.log_event(
        "parser.delete", "deleted", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="parser", resource_id=name,
        detail={"parser_name": name},
    )
    return Response(status_code=204)
