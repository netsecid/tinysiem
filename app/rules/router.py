import re
from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from app.audit import store as audit
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
    if data.get("playbook"):
        _validate_playbook(data["playbook"])
    return data


def _validate_playbook(playbook: dict) -> None:
    """Raises HTTPException 422 if playbook steps are malformed."""
    steps = playbook.get("steps", [])
    if not isinstance(steps, list):
        raise HTTPException(status_code=422, detail="playbook.steps must be a list")
    seen_ids: set[str] = set()
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise HTTPException(status_code=422, detail=f"playbook step {i} must be a mapping")
        if not step.get("id"):
            raise HTTPException(status_code=422, detail=f"playbook step {i} missing required field: id")
        if not step.get("name"):
            raise HTTPException(status_code=422, detail=f"playbook step {i} missing required field: name")
        if step["id"] in seen_ids:
            raise HTTPException(status_code=422, detail=f"duplicate playbook step id: {step['id']!r}")
        seen_ids.add(step["id"])


class RuleRequest(BaseModel):
    name: str
    yaml_text: str


class GenerateRuleRequest(BaseModel):
    description: str
    source: str


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


@router.post("/generate")
def generate_rule_endpoint(req: GenerateRuleRequest, actor: AuthUser = Depends(require_admin)):
    from app.ai.claude import generate_rule
    from app.ai.enrichment import build_generation_context
    ctx = build_generation_context()
    try:
        yaml_text = generate_rule(ctx + req.description, req.source, actor=actor.username)
    except RuntimeError as exc:
        audit.log_event(
            "rule.generate", "generated", "error",
            actor=actor.username, actor_role=actor.role,
            resource_type="rule",
            detail={"description_preview": req.description[:200], "source": req.source},
            error_msg=str(exc),
        )
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        audit.log_event(
            "rule.generate", "generated", "error",
            actor=actor.username, actor_role=actor.role,
            resource_type="rule",
            detail={"description_preview": req.description[:200], "source": req.source},
            error_msg=str(exc),
        )
        raise HTTPException(status_code=502, detail=f"Claude API error: {exc}")
    try:
        data = _validate_rule_yaml(yaml_text)
    except HTTPException:
        raise HTTPException(
            status_code=422,
            detail=f"Generated YAML failed validation. Raw output:\n{yaml_text}",
        )
    audit.log_event(
        "rule.generate", "generated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="rule", resource_id=data.get("name"),
        detail={
            "description_preview": req.description[:200],
            "source": req.source,
            "generated_name": data.get("name"),
            "severity": data.get("severity"),
        },
    )
    return {"yaml_text": yaml_text, "preview": True}


@router.post("/{name}/playbook/generate")
def generate_playbook_endpoint(name: str, actor: AuthUser = Depends(require_admin)):
    rule_path, _ = _get_rule_file(name)
    if not rule_path:
        raise HTTPException(404, f"Rule '{name}' not found")
    try:
        rule = yaml.safe_load(rule_path.read_text())
    except Exception as exc:
        raise HTTPException(422, f"Could not parse rule YAML: {exc}")
    from app.ai.enrichment import generate_playbook
    try:
        result = generate_playbook(rule, actor.username)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Claude API error: {exc}")
    audit.log_event(
        "rule.playbook.generate", "generated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="rule", resource_id=name,
    )
    return result


@router.get("/{name}")
def get_rule(name: str, _: AuthUser = Depends(require_analyst)):
    _check_name(name)
    path, _ = _get_rule_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"name": name, "yaml_text": path.read_text()}


@router.post("", status_code=201)
def create_rule(req: RuleRequest, actor: AuthUser = Depends(require_admin)):
    _check_name(req.name)
    data = _validate_rule_yaml(req.yaml_text)
    dest = _CUSTOM_DIR / f"{req.name}.yaml"
    if dest.exists():
        raise HTTPException(status_code=409, detail="Rule already exists")
    _CUSTOM_DIR.mkdir(exist_ok=True)
    dest.write_text(req.yaml_text)
    rule_engine.load_rules()
    audit.log_event(
        "rule.create", "created", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="rule", resource_id=req.name,
        detail={"rule_name": req.name, "severity": data.get("severity"), "source": data.get("source")},
    )
    return {"name": req.name, "status": "created"}


@router.put("/{name}")
def update_rule(name: str, req: RuleRequest, actor: AuthUser = Depends(require_admin)):
    _check_name(name)
    path, is_custom = _get_rule_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not is_custom:
        raise HTTPException(status_code=403, detail="Cannot modify built-in rules")
    data = _validate_rule_yaml(req.yaml_text)
    path.write_text(req.yaml_text)
    rule_engine.load_rules()
    audit.log_event(
        "rule.update", "updated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="rule", resource_id=name,
        detail={"rule_name": name, "severity": data.get("severity")},
    )
    return {"name": name, "status": "updated"}


@router.delete("/{name}", status_code=204)
def delete_rule(name: str, actor: AuthUser = Depends(require_admin)):
    _check_name(name)
    path, is_custom = _get_rule_file(name)
    if not path:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not is_custom:
        raise HTTPException(status_code=403, detail="Cannot delete built-in rules")
    path.unlink()
    rule_engine.load_rules()
    audit.log_event(
        "rule.delete", "deleted", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="rule", resource_id=name,
        detail={"rule_name": name},
    )
    return Response(status_code=204)
