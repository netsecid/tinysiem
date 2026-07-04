import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth import AuthUser, require_analyst, require_admin
from app.audit import store as audit
from app.cases import store as case_store
from app.config import settings

router = APIRouter(prefix="/cases", tags=["cases"])

_VALID_STATUSES = {"open", "investigating", "resolved"}
_VALID_RESOLUTIONS = {"true_positive", "false_positive", "benign", "undetermined"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _load_alert_playbooks(alert_ids: list[str]) -> list[dict]:
    """Return [{alert_id, rule_name, playbook}] for alerts that have a playbook snapshot."""
    path = Path(settings.tinysiem_alerts_path)
    if not path.exists() or not alert_ids:
        return []
    id_set = set(alert_ids)
    found = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                if a.get("alert_id") in id_set and a.get("playbook"):
                    found.append({
                        "alert_id": a["alert_id"],
                        "rule_name": a.get("rule_name", ""),
                        "playbook": a["playbook"],
                    })
            except json.JSONDecodeError:
                continue
    return found


def _load_alerts_by_id(alert_ids: list[str]) -> list[dict]:
    """Read JSONL alerts file and return records matching the given IDs."""
    path = Path(settings.tinysiem_alerts_path)
    if not path.exists() or not alert_ids:
        return []
    id_set = set(alert_ids)
    found = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                if a.get("alert_id") in id_set:
                    found.append({
                        "alert_id": a.get("alert_id"),
                        "rule_name": a.get("rule_name"),
                        "severity": a.get("severity"),
                        "source_ip": a.get("source_ip"),
                        "summary": a.get("summary"),
                        "triggered_at": a.get("triggered_at"),
                    })
            except json.JSONDecodeError:
                continue
    return found


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: Optional[str] = Field(None, max_length=5000)
    severity: str = "medium"
    assignee: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    tags: Optional[list[str]] = None
    alert_ids: Optional[list[str]] = None


class CasePatch(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=300)
    description: Optional[str] = Field(None, max_length=5000)
    severity: Optional[str] = None
    status: Optional[str] = None
    resolution: Optional[str] = None
    assignee: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    tags: Optional[list[str]] = None


class CommentCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=10000)


class AlertsLink(BaseModel):
    alert_ids: list[str] = Field(..., min_length=1)


class StepComplete(BaseModel):
    rule_name: str = Field(..., min_length=1)
    step_id: str = Field(..., min_length=1)
    note: Optional[str] = Field(None, max_length=2000)


@router.get("/facets")
def case_facets(_: AuthUser = Depends(require_analyst)):
    return case_store.get_case_facets()


@router.get("")
def list_cases(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: AuthUser = Depends(require_analyst),
):
    return case_store.query_cases(
        status=status, severity=severity, assignee=assignee,
        q=q, start=start, end=end, limit=limit, offset=offset,
    )


@router.post("", status_code=201)
def create_case(body: CaseCreate, current_user: AuthUser = Depends(require_analyst)):
    if body.severity not in _VALID_SEVERITIES:
        raise HTTPException(422, f"severity must be one of {sorted(_VALID_SEVERITIES)}")

    case = case_store.insert_case(
        title=body.title,
        created_by=current_user.username,
        description=body.description,
        severity=body.severity,
        assignee=body.assignee,
        mitre_tactic=body.mitre_tactic,
        mitre_technique=body.mitre_technique,
        tags=body.tags,
    )
    case_id = case["case_id"]

    # Auto system comment
    case_store.insert_comment(case_id, "system", f"Case created by {current_user.username}", is_system=True)

    # Link any initial alerts
    if body.alert_ids:
        case_store.link_alerts(case_id, body.alert_ids, current_user.username)
        for aid in body.alert_ids:
            case_store.insert_comment(case_id, "system", f"Alert {aid} linked by {current_user.username}", is_system=True)

    audit.log_event(
        "case.create", "created", actor=current_user.username, actor_role=current_user.role,
        resource_type="case", resource_id=case_id,
        detail={"title": body.title, "severity": body.severity},
    )
    return case


@router.get("/{case_id}")
def get_case(case_id: str, _: AuthUser = Depends(require_analyst)):
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    # Hydrate linked alerts
    ids = [la["alert_id"] for la in case.get("linked_alert_ids", [])]
    case["alerts"] = _load_alerts_by_id(ids)
    return case


@router.patch("/{case_id}")
def patch_case(case_id: str, body: CasePatch, current_user: AuthUser = Depends(require_analyst)):
    existing = case_store.get_case(case_id)
    if not existing:
        raise HTTPException(404, "Case not found")

    updates = body.model_dump(exclude_none=True)

    if "status" in updates and updates["status"] not in _VALID_STATUSES:
        raise HTTPException(422, f"status must be one of {sorted(_VALID_STATUSES)}")
    if "severity" in updates and updates["severity"] not in _VALID_SEVERITIES:
        raise HTTPException(422, f"severity must be one of {sorted(_VALID_SEVERITIES)}")
    if updates.get("status") == "resolved":
        res = updates.get("resolution") or existing.get("resolution")
        if not res or res not in _VALID_RESOLUTIONS:
            raise HTTPException(422, f"resolution required when closing: {sorted(_VALID_RESOLUTIONS)}")
        updates["resolution"] = res

    old_status = existing.get("status")
    case = case_store.update_case(case_id, updates)

    # System comments for significant state changes
    new_status = updates.get("status")
    if new_status and new_status != old_status:
        if new_status == "resolved":
            res_label = updates.get("resolution", "").replace("_", " ").title()
            case_store.insert_comment(
                case_id, "system",
                f"Case closed as {res_label} by {current_user.username}",
                is_system=True,
            )
        else:
            case_store.insert_comment(
                case_id, "system",
                f"Status changed from {old_status} to {new_status} by {current_user.username}",
                is_system=True,
            )

    audit.log_event(
        "case.update", "updated", actor=current_user.username, actor_role=current_user.role,
        resource_type="case", resource_id=case_id,
        detail={"changes": list(updates.keys())},
    )
    return case


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: str, current_user: AuthUser = Depends(require_admin)):
    if not case_store.delete_case(case_id):
        raise HTTPException(404, "Case not found")
    audit.log_event(
        "case.delete", "deleted", actor=current_user.username, actor_role=current_user.role,
        resource_type="case", resource_id=case_id,
    )


@router.post("/{case_id}/comments", status_code=201)
def add_comment(case_id: str, body: CommentCreate, current_user: AuthUser = Depends(require_analyst)):
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    return case_store.insert_comment(case_id, current_user.username, body.body)


@router.put("/{case_id}/comments/{comment_id}")
def edit_comment(
    case_id: str, comment_id: str, body: CommentCreate,
    current_user: AuthUser = Depends(require_analyst),
):
    existing = case_store.get_comment(comment_id)
    if not existing or existing["case_id"] != case_id:
        raise HTTPException(404, "Comment not found")
    if existing["is_system"]:
        raise HTTPException(403, "System comments cannot be edited")
    if existing["author"] != current_user.username and current_user.role not in ("admin", "superadmin"):
        raise HTTPException(403, "You can only edit your own comments")
    updated = case_store.update_comment(comment_id, body.body)
    return updated


@router.delete("/{case_id}/comments/{comment_id}", status_code=204)
def delete_comment(
    case_id: str, comment_id: str,
    current_user: AuthUser = Depends(require_analyst),
):
    existing = case_store.get_comment(comment_id)
    if not existing or existing["case_id"] != case_id:
        raise HTTPException(404, "Comment not found")
    if existing["is_system"]:
        raise HTTPException(403, "System comments cannot be deleted")
    if existing["author"] != current_user.username and current_user.role not in ("admin", "superadmin"):
        raise HTTPException(403, "You can only delete your own comments")
    case_store.delete_comment(comment_id)


@router.post("/{case_id}/alerts")
def link_alerts(case_id: str, body: AlertsLink, current_user: AuthUser = Depends(require_analyst)):
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    linked = case_store.link_alerts(case_id, body.alert_ids, current_user.username)
    for aid in linked:
        case_store.insert_comment(case_id, "system", f"Alert {aid} linked by {current_user.username}", is_system=True)
    audit.log_event(
        "case.link_alert", "linked", actor=current_user.username, actor_role=current_user.role,
        resource_type="case", resource_id=case_id,
        detail={"alert_ids": linked},
    )
    return {"linked": linked}


@router.delete("/{case_id}/alerts/{alert_id}", status_code=204)
def unlink_alert(case_id: str, alert_id: str, current_user: AuthUser = Depends(require_analyst)):
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    if not case_store.unlink_alert(case_id, alert_id):
        raise HTTPException(404, "Alert not linked to this case")
    case_store.insert_comment(
        case_id, "system", f"Alert {alert_id} unlinked by {current_user.username}", is_system=True
    )


@router.get("/{case_id}/playbook")
def get_case_playbook(case_id: str, _: AuthUser = Depends(require_analyst)):
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    alert_ids = [la["alert_id"] for la in case.get("linked_alert_ids", [])]
    alert_playbooks = _load_alert_playbooks(alert_ids)

    # Deduplicate: one playbook section per rule_name (first alert wins)
    seen_rules: set[str] = set()
    unique: list[dict] = []
    for ap in alert_playbooks:
        if ap["rule_name"] not in seen_rules:
            seen_rules.add(ap["rule_name"])
            unique.append(ap)

    completed = case_store.get_completed_steps(case_id)
    # Build lookup: {(rule_name, step_id): completion_record}
    comp_map: dict[tuple[str, str], dict] = {
        (c["rule_name"], c["step_id"]): c for c in completed
    }

    playbooks = []
    for ap in unique:
        pb = ap["playbook"]
        steps = []
        for step in pb.get("steps", []):
            key = (ap["rule_name"], step["id"])
            comp = comp_map.get(key)
            enriched = {**step, "completed": comp is not None}
            if comp:
                enriched["completed_by"] = comp["completed_by"]
                enriched["completed_at"] = comp["completed_at"]
                enriched["completion_note"] = comp.get("note")
            steps.append(enriched)
        playbooks.append({
            "rule_name": ap["rule_name"],
            "summary": pb.get("summary", ""),
            "steps": steps,
        })

    return {"playbooks": playbooks}


@router.post("/{case_id}/playbook/steps", status_code=201)
def complete_playbook_step(
    case_id: str,
    body: StepComplete,
    current_user: AuthUser = Depends(require_analyst),
):
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    record, created = case_store.complete_step(
        case_id, body.rule_name, body.step_id, current_user.username, body.note
    )
    status_code = 201 if created else 200
    return JSONResponse(content=record, status_code=status_code)


@router.delete("/{case_id}/playbook/steps/{step_id}", status_code=204)
def uncomplete_playbook_step(
    case_id: str,
    step_id: str,
    rule_name: str,
    _: AuthUser = Depends(require_analyst),
):
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    removed = case_store.uncomplete_step(case_id, rule_name, step_id)
    if not removed:
        raise HTTPException(404, "Step completion not found")
