"""End-to-end probe of the KB-aligned PermitApplication workflow.

Steps:
  1. GET ApprovalRequestGetPermitApplicationById for the target request.
  2. Call ApplicationGetMatchingList to discover candidate apps.
  3. Build a KB-aligned permit body (minimum required fields + chosen mode).
  4. Call ApprovalRequestPermitApplication.
  5. GET the request again to verify it transitioned out of statusId=1.

Defaults to the matching-app path when the request has a match, otherwise
falls back to creating a new application named after the file stem.

Usage:
    python scripts/probe_permit_application.py <approvalRequestId>
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


def load_creds_into_env() -> None:
    cfg_path = Path(os.environ["APPDATA"]) / "Claude" / "claude_desktop_config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    env = cfg["mcpServers"]["threatlocker"]["env"]
    for k in ("THREATLOCKER_API_KEY", "THREATLOCKER_ORG_ID", "THREATLOCKER_BASE_URL"):
        if k in env:
            os.environ[k] = env[k]


load_creds_into_env()

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from threatlocker_mcp.client import ThreatLockerAPIError, ThreatLockerClient  # noqa: E402, I001


SUMMARY_FIELDS = (
    "approvalRequestId",
    "statusId",
    "approvedBy",
    "approvedByTierLevel",
    "actionDate",
    "authorizeForPermit",
    "assigneeUsername",
    "comments",
)


def slim(record: dict) -> dict:
    return {k: record.get(k) for k in SUMMARY_FIELDS}


def extract_instance(portal_api_url: str | None) -> str:
    """Derive the userinstance shard ('h', 'g', etc.) from the portalApiUrl."""
    if not portal_api_url:
        return "g"
    host = urlparse(portal_api_url).hostname or ""
    # portalapi.<shard>.threatlocker.com -> <shard>
    m = re.match(r"portalapi\.([^.]+)\.threatlocker\.com", host)
    return m.group(1) if m else "g"


def derive_app_name(full_path: str) -> str:
    stem = Path(full_path or "permitted-app.exe").stem
    # Title-case for readability, e.g. "code" -> "Code", "1pass" -> "1Pass"
    return stem.title() if stem else "Permitted App"


def print_error(label: str, e: Exception) -> None:
    print(f"{label}: {type(e).__name__}: {e}")
    status = getattr(e, "status_code", None)
    body = getattr(e, "body", None)
    if status is not None:
        print(f"  status_code: {status}")
    if body is not None:
        print(f"  body: {body}")


async def main(approval_request_id: str) -> int:
    client = ThreatLockerClient()
    await client.connect()
    try:
        # ---------------------------------------------------------------
        # 0. Capture before-state via GetById
        # ---------------------------------------------------------------
        print(f"=== BEFORE (approvalRequestId={approval_request_id}) ===")
        before = await client.request(
            "GET",
            "/portalapi/ApprovalRequest/ApprovalRequestGetById",
            params={"approvalRequestId": approval_request_id},
        )
        print(json.dumps(slim(before), indent=2))

        # ---------------------------------------------------------------
        # 1. Fetch the PermitApplicationDto template
        # ---------------------------------------------------------------
        print("\n=== STEP 1: GetPermitApplicationById ===")
        permit = await client.request(
            "GET",
            "/portalapi/ApprovalRequest/ApprovalRequestGetPermitApplicationById",
            params={"approvalRequestId": approval_request_id},
        )
        ar = permit.get("approvalRequest") or {}
        fd = permit.get("fileDetails") or {}
        action_type = (
            permit.get("actionType")
            or (ar.get("threatLockerActionDto") or {}).get("actionType")
            or "execute"
        )
        full_path = fd.get("fullPath") or ar.get("path") or ""
        os_type = permit.get("osType") or fd.get("osType") or 1
        organization_id = permit.get("organizationId") or ar.get("organizationId")
        computer_id = permit.get("computerId") or ar.get("computerId")
        portal_api_url = ar.get("portalApiUrl")
        userinstance = extract_instance(portal_api_url)
        print(f"  actionType={action_type}, osType={os_type}, fullPath={full_path}")
        print(f"  userinstance={userinstance!r} (from {portal_api_url})")
        print(f"  has approvalRequest.json: {bool(ar.get('json'))}")

        # ---------------------------------------------------------------
        # 2. Discover matching applications
        # ---------------------------------------------------------------
        print("\n=== STEP 2: ApplicationGetMatchingList ===")
        tl_action = ar.get("threatLockerActionDto") or {}
        match_body = {
            "hash": tl_action.get("hash") or None,
            "sha256": tl_action.get("sha256") or None,
            "path": full_path or None,
            "processPath": tl_action.get("processName") or None,
            "organizationIds": None,
            "certs": [
                {
                    "sha": c.get("sha"),
                    "subject": c.get("subject"),
                    "validCert": c.get("validCert", True),
                }
                for c in (tl_action.get("certs") or [])
            ]
            or None,
            "createdBys": tl_action.get("installedBy") or None,
            "osType": os_type,
        }
        match_body = {k: v for k, v in match_body.items() if v is not None}
        matches = await client.request(
            "POST",
            "/portalapi/Application/ApplicationGetMatchingList",
            json=match_body,
        )
        candidates = (matches or {}).get("matchingApplications") or []
        has_matching = (matches or {}).get("hasMatching", False)
        print(f"  hasMatching={has_matching}, candidates={len(candidates)}")
        for c in candidates:
            print(
                f"    - {c.get('name')!r}"
                f" org={c.get('organizationName')!r} status={c.get('status')}"
            )

        # Prefer tenant-owned over BUILT-IN/master org.
        chosen_match = None
        is_builtin = False
        if candidates:
            tenant_matches = [c for c in candidates if c.get("organizationId") == organization_id]
            chosen_match = tenant_matches[0] if tenant_matches else candidates[0]
            is_builtin = (chosen_match.get("organizationName") or "").lower() == "master"
            print(f"  chosen: {chosen_match.get('name')!r} (built-in={is_builtin})")

        # ---------------------------------------------------------------
        # 3. Build the KB-aligned permit body
        # ---------------------------------------------------------------
        is_elevation = action_type == "elevate"

        if chosen_match:
            matching_applications = {
                "hasMatchingApplication": True,
                "useMatchingApplication": True,
                "matchingApplication": chosen_match,
                "useExistingApplication": False,
                "existingApplication": None,
                "useNewApplication": False,
                "newApplicationName": None,
            }
            mode = "useMatchingApplication"
        else:
            new_name = derive_app_name(full_path)
            matching_applications = {
                "hasMatchingApplication": False,
                "useMatchingApplication": False,
                "matchingApplication": None,
                "useExistingApplication": False,
                "existingApplication": None,
                "useNewApplication": True,
                "newApplicationName": new_name,
            }
            mode = f"useNewApplication={new_name!r}"

        # Scope selection per KB:
        # * BUILT-IN matching app  -> entire organization (KB Body 3 pattern).
        #   The KB explicitly warns: "When applying a built-in, the entire
        #   built-in application is being effectively permitted." Pairing a
        #   master-org matchingApplication with computer-only scope appears to
        #   confuse the server's dynamic permission lookup (HTTP 401 with empty
        #   permission name) on 2026-05 testing.
        # * Otherwise -> all-flags-false ("this computer", inferred from
        #   top-level computerId) per KB Body 1 pattern.
        to_entire_org = bool(chosen_match and is_builtin)
        scope_label = "entire organization (built-in)" if to_entire_org else "this computer"
        print(f"\n=== STEP 3: build body -- mode={mode}, scope={scope_label} ===")

        body = {
            "computerId": computer_id,
            "computerGroupId": "00000000-0000-0000-0000-000000000000",
            "organizationId": organization_id,
            "organizationIds": [],
            "osType": os_type,
            "userinstance": userinstance,
            "approvalRequest": {
                "approvalRequestId": approval_request_id,
                "json": ar.get("json") or "{}",
            },
            "fileDetails": {"fullPath": full_path},
            "isFromApproval": True,
            "actionType": action_type,
            "isElevationRequest": is_elevation,
            "isExtensionRequest": False,
            "edgeStoreUrl": None,
            "chromeStoreUrl": None,
            "canViewOnSystemLookup": False,
            "systemLookupUrl": None,
            "canViewVirusTotal": False,
            "virusTotalUrl": None,
            "matchingApplications": matching_applications,
            "policyConditions": {
                "useExistingPolicy": False,
                "createManualPolicy": False,
                "manualOptions": [
                    {
                        "fullPath": None,
                        "processPath": None,
                        "cert": None,
                        "hash": tl_action.get("hash"),
                        "createdBy": None,
                        "isDefaultOption": True,
                        "disabled": False,
                    }
                ],
                "ruleId": 0,
                "certSubjects": [],
                "createdByProcesses": [],
                "disableProtection": False,
            },
            "policyExpirationDate": None,
            "ringfencingOptions": {
                "ringfence": False,
                "ringfenceActionId": 0,
                "restrictNetwork": False,
                "blockRegistryWrites": False,
                "blockProtectedFiles": False,
                "blockHighRiskApps": False,
                "blockPowerShell": False,
                "blockCommandPrompt": False,
                "blockRunDLL": False,
                "blockRegSRV": False,
                "blockWscriptCscript": False,
            },
            "hasRingfencingAsProduct": permit.get("hasRingfencingAsProduct", True),
            "hasElevation": permit.get("hasElevation", False),
            "organizationHasElevation": permit.get("organizationHasElevation", True),
            "elevationStatus": 0,
            "elevationExpiration": 0,
            "elevationExpirationDate": None,
            # KB Body 1 ("create a new policy for the computer") sends all three
            # policyLevel flags as false -- the scope is inferred from top-level
            # computerId. Setting toComputer: true returns HTTP 417 'Provided
            # applies to ID does not associate with a known OS type'.
            # KB Body 3 ("matching application + new entire-org policy") uses
            # toEntireOrganization: true -- required when the chosen match is a
            # BUILT-IN/master-org application.
            "policyLevel": {
                "canUseEntireOrganization": True,
                "toEntireOrganization": to_entire_org,
                "toComputerGroup": False,
                "selectedComputerGroup": {
                    "computerGroupId": None,
                    "name": None,
                    "organizationId": None,
                    "organizationName": None,
                    "default": None,
                    "osType": 0,
                    "isGlobal": False,
                },
                "toComputer": False,
            },
            "adminNotes": {
                "ticket": "",
                "requestorEmail": ar.get("requestorEmailAddress") or "",
                "comments": "MCP probe: KB-aligned PermitApplication test",
            },
            "applicationList": [],
            "allowTMM": False,
            "hasOriginApprovalCenter": True,
        }

        # ---------------------------------------------------------------
        # 4. Submit the permit
        # ---------------------------------------------------------------
        print("\n=== STEP 4: ApprovalRequestPermitApplication ===")
        print("--- request body (sans approvalRequest.json) ---")
        debug_body = {
            **body,
            "approvalRequest": {**body["approvalRequest"], "json": "<...truncated...>"},
        }
        print(json.dumps(debug_body, indent=2, default=str))
        try:
            resp = await client.request(
                "POST",
                "/portalapi/ApprovalRequest/ApprovalRequestPermitApplication",
                json=body,
            )
            print(f"response: {json.dumps(resp, indent=2) if not isinstance(resp, str) else resp}")
        except ThreatLockerAPIError as e:
            print_error("PERMIT_ERROR", e)

        # ---------------------------------------------------------------
        # 5. Verify the request transitioned
        # ---------------------------------------------------------------
        print("\n=== AFTER ===")
        after = await client.request(
            "GET",
            "/portalapi/ApprovalRequest/ApprovalRequestGetById",
            params={"approvalRequestId": approval_request_id},
        )
        print(json.dumps(slim(after), indent=2))

        print("\n=== DIFF ===")
        b, a = slim(before), slim(after)
        changed = {k: (b.get(k), a.get(k)) for k in SUMMARY_FIELDS if b.get(k) != a.get(k)}
        if not changed:
            print("(no fields changed)")
        else:
            for k, (bv, av) in changed.items():
                print(f"  {k}: {bv!r}  ->  {av!r}")

        # Final verdict
        print("\n=== VERDICT ===")
        approved = (
            after.get("statusId") != 1
            or (after.get("approvedBy") or "") != ""
            or after.get("actionDate") is not None
        )
        print("APPROVED" if approved else "NOT APPROVED")
    finally:
        await client.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: probe_permit_application.py <approvalRequestId>", file=sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(main(sys.argv[1])))
