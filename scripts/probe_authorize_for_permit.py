"""Probe ApprovalRequestAuthorizeForPermitById with optional take-ownership.

Reads ThreatLocker credentials from the user's claude_desktop_config.json so
the key never has to be passed via the shell. Captures before-state, optionally
takes ownership, calls authorize-for-permit, captures after-state, prints diff.

Usage:
    python scripts/probe_authorize_for_permit.py <approvalRequestId> [--take-ownership]
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path


def load_creds_into_env() -> None:
    cfg_path = Path(os.environ["APPDATA"]) / "Claude" / "claude_desktop_config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    env = cfg["mcpServers"]["threatlocker"]["env"]
    for k in ("THREATLOCKER_API_KEY", "THREATLOCKER_ORG_ID", "THREATLOCKER_BASE_URL"):
        if k in env:
            os.environ[k] = env[k]


load_creds_into_env()

# Import after env is populated so config picks up the values.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from threatlocker_mcp.client import ThreatLockerAPIError, ThreatLockerClient  # noqa: E402, I001


INTERESTING_FIELDS = (
    "approvalRequestId",
    "statusId",
    "approvedBy",
    "approvedByTierLevel",
    "actionDate",
    "authorizeForPermit",
    "comments",
    "multiLevelApprovalStatusId",
    "pendingTierLevel",
    "assigneeUserId",
    "assigneeUsername",
    "isAssigned",
)


def slim(record: dict) -> dict:
    return {k: record.get(k) for k in INTERESTING_FIELDS}


def print_error(label: str, e: Exception) -> None:
    print(f"{label}: {type(e).__name__}: {e}")
    status = getattr(e, "status_code", None)
    body = getattr(e, "body", None)
    if status is not None:
        print(f"  status_code: {status}")
    if body is not None:
        print(f"  body: {body}")


async def main(approval_request_id: str, take_ownership: bool) -> int:
    client = ThreatLockerClient()
    await client.connect()
    try:
        print(f"=== BEFORE (approvalRequestId={approval_request_id}) ===")
        before = await client.request(
            "GET",
            "/portalapi/ApprovalRequest/ApprovalRequestGetById",
            params={"approvalRequestId": approval_request_id},
        )
        print(json.dumps(slim(before), indent=2))

        if take_ownership:
            print("\n=== STEP 1: UpdateForTakeOwnership ===")
            # Pass the full DTO back as the body; spec accepts ApprovalRequestDto.
            try:
                resp = await client.request(
                    "POST",
                    "/portalapi/ApprovalRequest/ApprovalRequestUpdateForTakeOwnership",
                    json=before,
                )
                print(
                    f"response: {json.dumps(resp, indent=2) if not isinstance(resp, str) else resp}"
                )
            except ThreatLockerAPIError as e:
                print_error("TAKE_OWNERSHIP_ERROR", e)
                return 1

            print("\n=== STATE AFTER TAKE_OWNERSHIP ===")
            after_to = await client.request(
                "GET",
                "/portalapi/ApprovalRequest/ApprovalRequestGetById",
                params={"approvalRequestId": approval_request_id},
            )
            print(json.dumps(slim(after_to), indent=2))

        print("\n=== STEP 2: ApprovalRequestAuthorizeForPermitById ===")
        body = {
            "approvalRequestId": approval_request_id,
            "message": "MCP probe: AuthorizeForPermitById after take_ownership",
        }
        print(f"body: {json.dumps(body)}")
        try:
            resp = await client.request(
                "POST",
                "/portalapi/ApprovalRequest/ApprovalRequestAuthorizeForPermitById",
                json=body,
            )
            print(f"response: {json.dumps(resp, indent=2) if not isinstance(resp, str) else resp}")
        except ThreatLockerAPIError as e:
            print_error("AUTHORIZE_ERROR", e)

        print("\n=== AFTER ===")
        after = await client.request(
            "GET",
            "/portalapi/ApprovalRequest/ApprovalRequestGetById",
            params={"approvalRequestId": approval_request_id},
        )
        print(json.dumps(slim(after), indent=2))

        print("\n=== DIFF (before → after) ===")
        b, a = slim(before), slim(after)
        changed = {k: (b.get(k), a.get(k)) for k in INTERESTING_FIELDS if b.get(k) != a.get(k)}
        if not changed:
            print("(no fields changed)")
        else:
            for k, (bv, av) in changed.items():
                print(f"  {k}: {bv!r}  ->  {av!r}")
    finally:
        await client.close()
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    take_ownership = "--take-ownership" in args
    args = [a for a in args if a != "--take-ownership"]
    if len(args) != 1:
        print(
            "usage: probe_authorize_for_permit.py <approvalRequestId> [--take-ownership]",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(asyncio.run(main(args[0], take_ownership)))
