from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse

from app.audit import store as audit
from app.auth import AuthUser, require_admin, require_analyst
from app.reports.generator import generate_report, render_html, _send_report_email

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/generate")
def report_generate(
    period: str = Query("daily", pattern="^(daily|weekly)$"),
    _: AuthUser = Depends(require_analyst),
):
    return generate_report(period)


@router.get("/download")
def report_download(
    period: str = Query("daily", pattern="^(daily|weekly)$"),
    _: AuthUser = Depends(require_analyst),
):
    report = generate_report(period)
    html_content = render_html(report)
    filename = f"tinysiem-{period}-report-{report['generated_at'][:10]}.html"
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/send")
def report_send(
    period: str = Query("daily", pattern="^(daily|weekly)$"),
    actor: AuthUser = Depends(require_admin),
):
    _send_report_email(period)
    audit.log_event(
        "system.report", "sent", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="system",
        detail={"period": period},
    )
    return {"status": "sent"}
