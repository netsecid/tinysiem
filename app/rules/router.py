import re
from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from app.auth import AuthUser, require_admin, require_analyst
from app.rules import engine as rule_engine

router = APIRouter(prefix="/rules", tags=["rules"])

_RULES_DIR = Path(__file__).parent / "rules"
_CUSTOM_DIR = _RULES_DIR / "custom"
_REQUIRED_KEYS = {"name", "severity", "source", "condition"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_NAME = re.compile(r'^[a-z0-9][a-z0-9\-_]{0,63}$')


def _check_name(name: str) -> None:
    if not _VALID_NAME.match(name):
        raise HTTPException(
            status_code=422,
            detail="Name must be lowercase alphanumeric, hyphens or underscores only",
        )


def _list_rule_files() -> list[tuple[Path, bool]]:
    files = []
    for p in sorted(_RULES_DIR.glob("*.yaml")):
        files.append((p, False))
    if _CUSTOM_DIR.exists():
        for p in sorted(_CUSTOM_DIR.glob("*.yaml")):
            files.append((p, True))
    return files


def _get_rule_file(name: str) -> tuple[Optional[Path], bool]:
    custom = _CUSTOM_DIR / f"{name}.yaml"
    if custom.exists():
        return custom, True
    builtin = _RULES_DIR / f"{name}.yaml"
    if builtin.exists():
        return builtin, False
    return None, False


def _validate_rule_yaml(yaml_text: str) -> dict:
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
    sev = data.get("severity", "")
    if sev not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"severity must be one of: {', '.join(sorted(_VALID_SEVERITIES))}",
        )
    return data


class RuleRequest(BaseModel):
    name: str
    yaml_text: str


@router.get("")
def list_rules(_: AuthUser = Depends(require_analyst)):
    result = []
    for path, is_custom in _list_rule_files():
        try:
            data = yaml.safe_load(path.read_text())
            result.append({
                "name": path.stem,
                "severity": data.get("severity", ""),
                "source": data.get("source", ""),
                "is_custom": is_custom,
            })
        except Exception:
            pass
    return {"rules": result}


class GenerateRuleRequest(BaseModel):
    description: str
    source: str


@router.post("/generate")
def generate_rule_endpoint(req: GenerateRuleRequest, _: AuthUser = Depends(require_admin)):
    from app.ai.claude import generate_rule
    try:
        yaml_text = generate_rule(req.description, req.source)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Claude API error: {exc}")
    try:
        _validate_rule_yaml(yaml_text)
    except HTTPException:
        raise HTTPException(
            status_code=422,
            detail=f"Generated YAML failed validation. Raw output:\n{yaml_text}",
        )
    return {"yaml_text": yaml_text, "preview": True}


@router.get("/{name}")
def get_rule(name: str, _: AuthUser = Depends(require_analyst)):
    _check_name(name)
    path, _ = _get_rule_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"name": name, "yaml_text": path.read_text()}


@router.post("", status_code=201)
def create_rule(req: RuleRequest, _: AuthUser = Depends(require_admin)):
    _check_name(req.name)
    _validate_rule_yaml(req.yaml_text)
    dest = _CUSTOM_DIR / f"{req.name}.yaml"
    if dest.exists():
        raise HTTPException(status_code=409, detail="Rule already exists")
    _CUSTOM_DIR.mkdir(exist_ok=True)
    dest.write_text(req.yaml_text)
    rule_engine.load_rules()
    return {"name": req.name, "status": "created"}


@router.put("/{name}")
def update_rule(name: str, req: RuleRequest, _: AuthUser = Depends(require_admin)):
    _check_name(name)
    path, is_custom = _get_rule_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not is_custom:
        raise HTTPException(status_code=403, detail="Cannot modify built-in rules")
    _validate_rule_yaml(req.yaml_text)
    path.write_text(req.yaml_text)
    rule_engine.load_rules()
    return {"name": name, "status": "updated"}


@router.delete("/{name}", status_code=204)
def delete_rule(name: str, _: AuthUser = Depends(require_admin)):
    _check_name(name)
    path, is_custom = _get_rule_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not is_custom:
        raise HTTPException(status_code=403, detail="Cannot delete built-in rules")
    path.unlink()
    rule_engine.load_rules()
    return Response(status_code=204)
