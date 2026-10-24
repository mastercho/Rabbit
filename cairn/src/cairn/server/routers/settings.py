from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests
from fastapi import APIRouter

from cairn.server.activity_service import record_audit, record_notification
from cairn.server.db import get_conn
from cairn.server.models import Settings
from cairn.server.settings_models import (
    SettingsAlert,
    SettingsCleanupResult,
    SettingsHealthCheck,
    SettingsHealthResponse,
    SettingsHealthStats,
    SettingsHealthSummary,
)
from cairn.server.settings_service import load_settings
from cairn.server.routers.workers import _internal_auth_kwargs, _internal_url, _status_timeout

router = APIRouter(tags=["settings"])

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.strftime(_TIMESTAMP_FORMAT)


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _status_rank(value: str) -> int:
    return {"ok": 0, "warning": 1, "error": 2}.get(value, 2)


def _summary_status(checks: list[SettingsHealthCheck], alerts: list[SettingsAlert]) -> str:
    status = "ok"
    for check in checks:
        if _status_rank(check.status) > _status_rank(status):
            status = check.status
    for alert in alerts:
        level_status = "error" if alert.level == "danger" else "warning" if alert.level == "warning" else "ok"
        if _status_rank(level_status) > _status_rank(status):
            status = level_status
    return status


def _fetch_dispatcher_snapshot() -> tuple[dict | None, str | None]:
    try:
        health = requests.get(_internal_url("/internal/health"), timeout=_status_timeout())
        if health.status_code != 200:
            return None, f"Dispatcher health check returned {health.status_code}"
        response = requests.get(
            _internal_url("/internal/status"),
            timeout=_status_timeout(),
            **_internal_auth_kwargs(),
        )
        if response.status_code != 200:
            return None, f"Dispatcher status returned {response.status_code}"
        payload = response.json()
        if not isinstance(payload, dict):
            return None, "Dispatcher status response was not valid"
        return payload, None
    except (requests.RequestException, ValueError) as exc:
        return None, str(exc)


def _worker_counts(snapshot: dict | None) -> tuple[int, int, int]:
    if not snapshot:
        return (0, 0, 0)
    online = 0
    offline = 0
    total = 0
    for item in snapshot.get("workers", []):
        if not isinstance(item, dict):
            continue
        total += 1
        status = str(item.get("status") or "")
        enabled = bool(item.get("enabled", True))
        if not enabled or status == "disabled":
            continue
        if status in {"idle", "busy"}:
            online += 1
        elif status in {"offline", "unhealthy"}:
            offline += 1
    return (total, online, offline)


def _idle_project_alerts(conn, threshold_hours: int) -> list[SettingsAlert]:
    rows = conn.execute(
        """
        SELECT
            p.id,
            p.title,
            p.created_at,
            p.decide_last_heartbeat_at,
            MAX(s.created_at) AS last_step_created_at,
            MAX(s.concluded_at) AS last_step_concluded_at,
            MAX(h.created_at) AS last_hint_created_at
        FROM projects p
        LEFT JOIN steps s ON s.project_id = p.id
        LEFT JOIN hints h ON h.project_id = p.id
        WHERE p.status = 'active'
        GROUP BY p.id, p.title, p.created_at, p.decide_last_heartbeat_at
        ORDER BY p.created_at
        """
    ).fetchall()
    alerts: list[SettingsAlert] = []
    now = _utcnow()
    for row in rows:
        latest = max(
            (
                ts
                for ts in (
                    row["created_at"],
                    row["decide_last_heartbeat_at"],
                    row["last_step_created_at"],
                    row["last_step_concluded_at"],
                    row["last_hint_created_at"],
                )
                if ts
            ),
            default=None,
        )
        latest_at = _parse_utc(latest)
        if latest_at is None:
            continue
        idle_hours = (now - latest_at).total_seconds() / 3600
        if idle_hours >= threshold_hours:
            alerts.append(
                SettingsAlert(
                    level="warning",
                    title=f"Project {row['title']} has been idle",
                    detail=f"{row['id']} last activity was about {idle_hours:.1f} hours ago, past the {threshold_hours} hour threshold.",
                )
            )
    return alerts


@router.get("/settings", response_model=Settings)
def get_settings() -> Settings:
    with get_conn() as conn:
        return load_settings(conn)


@router.put("/settings", response_model=Settings)
def update_settings(body: Settings) -> Settings:
    payload = body.model_dump()
    assignments = ", ".join(f"{key} = ?" for key in payload)
    values = tuple(payload[key] for key in payload)
    with get_conn() as conn:
        conn.execute(f"UPDATE settings SET {assignments} WHERE rowid = 1", values)
    record_audit("settings.update", "Updated system settings", detail=", ".join(f"{key}={value}" for key, value in payload.items()))
    record_notification("System settings updated", level="success", body="The new dispatch, security, and retention policy was saved.")
    return body


@router.get("/settings/health", response_model=SettingsHealthResponse)
def health() -> SettingsHealthResponse:
    checks: list[SettingsHealthCheck] = []
    alerts: list[SettingsAlert] = []

    with get_conn() as conn:
        settings = load_settings(conn)
        stats = SettingsHealthStats(
            users=int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]),
            projects=int(conn.execute("SELECT COUNT(*) AS n FROM projects").fetchone()["n"]),
            active_projects=int(conn.execute("SELECT COUNT(*) AS n FROM projects WHERE status = 'active'").fetchone()["n"]),
            vulnerabilities=int(conn.execute("SELECT COUNT(*) AS n FROM vulnerabilities").fetchone()["n"]),
            export_records=int(conn.execute("SELECT COUNT(*) AS n FROM export_records").fetchone()["n"]),
            audit_entries=int(conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"]),
            notifications_unread=int(conn.execute("SELECT COUNT(*) AS n FROM notifications WHERE read = 0").fetchone()["n"]),
        )
        alerts.extend(_idle_project_alerts(conn, settings.project_idle_alert_hours))

    checks.append(
        SettingsHealthCheck(
            key="server",
            label="API",
            status="ok",
            summary="The product service is healthy",
            detail="Settings, projects, and reports are served by this process.",
        )
    )
    checks.append(
        SettingsHealthCheck(
            key="database",
            label="SQLite database",
            status="ok",
            summary=f"Projects {stats.projects} / vulnerabilities {stats.vulnerabilities}",
            detail=f"Users {stats.users}, audit entries {stats.audit_entries}, export records {stats.export_records}.",
        )
    )

    dispatcher_snapshot, dispatcher_error = _fetch_dispatcher_snapshot()
    worker_total, worker_online, worker_offline = _worker_counts(dispatcher_snapshot)
    if dispatcher_snapshot is None:
        checks.append(
            SettingsHealthCheck(
                key="dispatcher",
                label="Dispatcher connectivity",
                status="error" if stats.active_projects > 0 else "warning",
                summary="Dispatcher status is unavailable",
                detail=dispatcher_error or "Could not reach the dispatcher status API.",
            )
        )
        alerts.append(
            SettingsAlert(
                level="danger" if stats.active_projects > 0 else "warning",
                title="Could not read dispatcher status",
                detail=dispatcher_error or "Worker tests, live status, and health checks are unavailable.",
            )
        )
    else:
        runtime = dispatcher_snapshot.get("runtime") if isinstance(dispatcher_snapshot, dict) else {}
        checks.append(
            SettingsHealthCheck(
                key="dispatcher",
                label="Dispatcher connectivity",
                status="ok",
                summary=f"Poll interval {runtime.get('interval', '-')}s, running tasks {runtime.get('running_task_count', 0)}",
                detail=f"Max concurrency {runtime.get('max_workers', 0)}, running projects {runtime.get('running_project_count', 0)}.",
            )
        )
        worker_status = "ok" if worker_offline == 0 else "warning"
        checks.append(
            SettingsHealthCheck(
                key="workers",
                label="Worker status",
                status=worker_status,
                summary=f"Online {worker_online} / offline {worker_offline} / total {worker_total}",
                detail="Online workers can take tasks. Offline workers need attention on the Workers page.",
            )
        )
        if stats.active_projects > 0 and worker_online == 0:
            alerts.append(
                SettingsAlert(
                    level="danger",
                    title="Work is waiting but no worker is online",
                    detail=f"{stats.active_projects} projects are active, but no worker is online.",
                )
            )
        elif worker_offline > 0:
            alerts.append(
                SettingsAlert(
                    level="warning",
                    title="Some workers are offline",
                    detail=f"{worker_online} online, {worker_offline} offline.",
                )
            )

    checks.append(
        SettingsHealthCheck(
            key="auth",
            label="Authentication policy",
            status="ok",
            summary=f"{settings.max_failed_login_attempts} failures / {settings.rate_limit_window_minutes} minute window",
            detail=f"Sessions last {settings.session_duration_hours} hours. Captcha is always on.",
        )
    )
    checks.append(
        SettingsHealthCheck(
            key="retention",
            label="Retention and cleanup",
            status="ok",
            summary=f"Logs {settings.log_retention_days} days, exports {settings.export_retention_days} days",
            detail=f"Notifications are kept {settings.notification_retention_days} days. Idle-project alert threshold is {settings.project_idle_alert_hours} hours.",
        )
    )

    summary = SettingsHealthSummary(
        status=_summary_status(checks, alerts),
        server_reachable=True,
        dispatcher_reachable=dispatcher_snapshot is not None,
        active_projects=stats.active_projects,
        online_workers=worker_online,
        offline_workers=worker_offline,
    )
    return SettingsHealthResponse(
        generated_at=_utcnow().isoformat(),
        summary=summary,
        stats=stats,
        checks=checks,
        alerts=alerts,
    )


@router.post("/settings/cleanup", response_model=SettingsCleanupResult)
def cleanup() -> SettingsCleanupResult:
    now = _utcnow()
    with get_conn() as conn:
        settings = load_settings(conn)
        log_cutoff = _format_utc(now - timedelta(days=settings.log_retention_days))
        export_cutoff = _format_utc(now - timedelta(days=settings.export_retention_days))
        notification_cutoff = _format_utc(now - timedelta(days=settings.notification_retention_days))

        deleted = {
            "audit_log": conn.execute(
                "DELETE FROM audit_log WHERE created_at < ?",
                (log_cutoff,),
            ).rowcount,
            "worker_task_history": conn.execute(
                "DELETE FROM worker_task_history WHERE COALESCE(completed_at, started_at) < ?",
                (log_cutoff,),
            ).rowcount,
            "login_attempts": conn.execute(
                "DELETE FROM login_attempts WHERE attempted_at < ?",
                (log_cutoff,),
            ).rowcount,
            "export_records": conn.execute(
                "DELETE FROM export_records WHERE created_at < ?",
                (export_cutoff,),
            ).rowcount,
            "notifications": conn.execute(
                "DELETE FROM notifications WHERE read = 1 AND created_at < ?",
                (notification_cutoff,),
            ).rowcount,
            "expired_sessions": conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (_format_utc(now),),
            ).rowcount,
        }

    total_deleted = sum(int(value or 0) for value in deleted.values())
    summary = f"Removed {total_deleted} expired history records."
    record_audit("settings.cleanup", summary, detail=", ".join(f"{key}={value}" for key, value in deleted.items()))
    record_notification("Cleanup finished", level="info", body=summary)
    return SettingsCleanupResult(
        ran_at=now.isoformat(),
        deleted={key: int(value or 0) for key, value in deleted.items()},
        summary=summary,
    )
