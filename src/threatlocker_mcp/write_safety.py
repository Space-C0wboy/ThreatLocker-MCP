"""Guard rails shared by every tool that changes ThreatLocker state.

Every write tool in this server goes through the helpers here so the same
three rules apply everywhere:

1. ``dry_run`` defaults to **True**. A dry run returns the exact request(s)
   that would be sent plus the target organization, and sends nothing.
2. The target organization is either an explicit ``organization_id`` or the
   configured default (``THREATLOCKER_ORG_ID``). Write tools deliberately do
   not accept ``override_organization_id``; there is no other way to hit a
   different org.
3. Destructive operations (deploy, delete, remove) additionally require
   ``confirm=True`` when ``dry_run=False``.

Every executed write is appended to a local JSON-lines audit file. The audit
record never contains headers, the API key, or request bodies.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .client import ThreatLockerAPIError, get_client
from .config import get_config

logger = logging.getLogger(__name__)

AUDIT_LOG_ENV = "THREATLOCKER_AUDIT_LOG"
_DEFAULT_AUDIT_LOG = Path.home() / ".threatlocker-mcp" / "audit.jsonl"


class WriteBlocked(ValueError):
    """Raised before any HTTP call when a safety precondition is not met."""


@dataclass
class PlannedRequest:
    """One HTTP request a write tool intends to send."""

    method: str
    path: str
    params: dict[str, Any] | None = None
    json: Any = None
    # Human-readable id of the object being changed (policy id, app id, ...).
    target_id: str | None = None
    # Free-text label shown in dry-run output and the audit log.
    purpose: str = ""

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"method": self.method, "path": self.path}
        if self.purpose:
            out["purpose"] = self.purpose
        if self.target_id is not None:
            out["target_id"] = self.target_id
        if self.params:
            out["params"] = self.params
        if self.json is not None:
            out["json"] = self.json
        return out


@dataclass
class WritePlan:
    """Everything a write tool decided to do, before deciding whether to send it."""

    tool: str
    organization_id: str
    requests: list[PlannedRequest] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, request: PlannedRequest) -> PlannedRequest:
        self.requests.append(request)
        return request


def resolve_target_org(organization_id: str | None) -> str:
    """Return the org a write will target.

    An explicit ``organization_id`` wins. Otherwise the configured default is
    used. There is intentionally no third option.
    """
    org = (organization_id or "").strip()
    return org or get_config().default_org_id


def require_confirmation(dry_run: bool, confirm: bool, action: str) -> None:
    """Block destructive calls unless the caller passed ``confirm=True``."""
    if dry_run:
        return
    if not confirm:
        raise WriteBlocked(
            f"{action} requires confirm=true in addition to dry_run=false. "
            "Nothing was sent. Re-run with dry_run=false and confirm=true to proceed."
        )


def audit_log_path() -> Path:
    override = os.getenv(AUDIT_LOG_ENV, "").strip()
    return Path(override) if override else _DEFAULT_AUDIT_LOG


def record_audit(
    *,
    tool: str,
    organization_id: str,
    method: str,
    path: str,
    target_id: str | None,
    outcome: str,
    detail: str | None = None,
) -> None:
    """Append one audit line. Failures to write the audit file are logged, never raised."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": tool,
        "organization_id": organization_id,
        "method": method,
        "path": path,
        "target_id": target_id,
        "outcome": outcome,
    }
    if detail:
        record["detail"] = detail
    try:
        log_path = audit_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError as e:  # pragma: no cover - depends on filesystem state
        logger.warning("Could not write audit record to %s: %s", audit_log_path(), e)


def dry_run_result(plan: WritePlan) -> dict[str, Any]:
    """The payload every write tool returns when ``dry_run`` is true."""
    return {
        "dry_run": True,
        "tool": plan.tool,
        "organization_id": plan.organization_id,
        "request_count": len(plan.requests),
        "requests": [r.as_dict() for r in plan.requests],
        "notes": plan.notes
        + ["Nothing was sent. Re-run with dry_run=false to execute these requests."],
    }


async def send_one(plan: WritePlan, request: PlannedRequest) -> Any:
    """Send a single planned request and audit the outcome."""
    client = await get_client()
    try:
        result = await client.request(
            request.method,
            request.path,
            organization_id=plan.organization_id,
            params=request.params or None,
            json=request.json,
        )
    except ThreatLockerAPIError as e:
        record_audit(
            tool=plan.tool,
            organization_id=plan.organization_id,
            method=request.method,
            path=request.path,
            target_id=request.target_id,
            outcome="error",
            detail=f"HTTP {e.status_code}: {e.message}",
        )
        raise
    record_audit(
        tool=plan.tool,
        organization_id=plan.organization_id,
        method=request.method,
        path=request.path,
        target_id=request.target_id,
        outcome="ok",
        detail=request.purpose or None,
    )
    return result


async def execute_plan(plan: WritePlan, *, dry_run: bool) -> dict[str, Any]:
    """Either describe the plan (dry run) or send every request in order.

    Requests are sent sequentially; the first failure stops the run and the
    partial results are included in the raised error's context via the audit
    log. Callers that need batching semantics (bulk SHA256) implement their own
    loop on top of :func:`send_one`.
    """
    if dry_run:
        return dry_run_result(plan)
    results = []
    for request in plan.requests:
        results.append(
            {
                "method": request.method,
                "path": request.path,
                "target_id": request.target_id,
                "purpose": request.purpose or None,
                "response": await send_one(plan, request),
            }
        )
    return {
        "dry_run": False,
        "tool": plan.tool,
        "organization_id": plan.organization_id,
        "request_count": len(results),
        "results": results,
        "notes": plan.notes,
    }
