"""ThreatLocker MCP tools: Allowlisting (Application Control) policy management.

Hand-written (not generated). Endpoints come from the ThreatLocker KB:
https://threatlocker.kb.help/portalapipolicy/ and
https://threatlocker.kb.help/portalapideploypolicyqueue/ — they are not present
in the public Swagger document. Every write goes through ``write_safety``.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from ..client import ThreatLockerClient, get_client
from ..management_models import (
    ALL_ZEROS_GUID,
    POLICY_ACTION_NAMES,
    resolve_applies_to,
    resolve_os_type,
    resolve_policy_action,
    row_value,
)
from ..write_safety import (
    PlannedRequest,
    WriteBlocked,
    WritePlan,
    execute_plan,
    require_confirmation,
    resolve_target_org,
)
from ._params import Confirm, DryRun, OverrideOrgId, ReadOrgId, WriteOrgId

POLICY_GET_BY_ID = "/portalapi/Policy/PolicyGetById"
POLICY_GET_BY_PARAMETERS = "/portalapi/Policy/PolicyGetByParameters"
POLICY_GET_FOR_VIEW_BY_APPLICATION_ID = "/portalapi/Policy/PolicyGetForViewPoliciesByApplicationId"
POLICY_INSERT = "/portalapi/Policy/PolicyInsert"
POLICY_UPDATE_BY_ID = "/portalapi/Policy/PolicyUpdateById"
POLICY_UPDATE_FOR_DELETE_BY_IDS = "/portalapi/Policy/PolicyUpdateForDeleteByIds"
DEPLOY_POLICIES = "/portalapi/DeployPolicyQueue/DeployPolicies"
DEPLOY_POLICIES_FOR_COMPUTER = "/portalapi/DeployPolicyQueue/DeployPoliciesForComputer"

# Fields PolicyUpdateById accepts (KB). Omitted optional fields RESET on the
# server, so policy_update carries every one of these over from PolicyGetById.
POLICY_UPDATE_FIELDS: tuple[str, ...] = (
    "policyId",
    "name",
    "description",
    "osType",
    "policyActionId",
    "applicationIdList",
    "computerGroupId",
    "logAction",
    "isEnabled",
    "orderBy",
    "allDevices",
    "allUserGroups",
    "allowRequest",
    "applicationSelection",
    "comments",
    "deviceType",
    "elevationStatus",
    "endDate",
    "killRunningProcesses",
    "monitorMode",
    "networkExclusions",
    "notifyOnRequest",
    "parentProcessIdList",
    "parentRestrictionEnabled",
    "policySchedules",
    "policyScheduleStatus",
    "requestEmailAddressesList",
    "requestor",
    "ticketInfo",
    "userGroups",
    "ringfencingOptions",
)

# Alternate names the GET response may use for update-body fields.
_GET_ALIASES: dict[str, tuple[str, ...]] = {
    "computerGroupId": ("appliesToId",),
    "isEnabled": ("enabled", "isActive", "active"),
    "applicationIdList": ("applicationIds",),
}

# Keys returned by policy_list in compact mode (first match wins per group).
_COMPACT_GROUPS: dict[str, tuple[str, ...]] = {
    "policyId": ("policyId",),
    "name": ("name", "policyName"),
    "orderBy": ("orderBy",),
    "policyActionId": ("policyActionId", "actionId"),
    "isEnabled": ("isEnabled", "enabled", "isActive", "status"),
    "appliesToId": ("appliesToId", "computerGroupId"),
    "appliesToName": ("appliesToName", "appliesTo", "computerGroupName", "groupName"),
    "policyLevel": ("policyLevel", "appliesToLevel", "level", "entityType", "appliesToType"),
    "lastMatch": ("lastMatch", "lastMatched", "dateLastMatched", "lastMatchDate", "lastHit"),
    "applications": ("applicationNames", "applications", "applicationList", "applicationName"),
    "osType": ("osType",),
    "organizationId": ("organizationId",),
    "description": ("description",),
    "totalRows": ("totalRows", "totalCount"),
}

_LEVEL_NAMES = {1: "organization", 2: "computer_group", 3: "computer"}


class PolicyOrderChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str = Field(description="Policy GUID.")
    order_by: int = Field(ge=0, description="New order number (lower runs first; no negatives).")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _as_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        if data.get("_empty_response"):
            return []
        for key in ("data", "items", "result", "results", "policies"):
            value = data.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


async def _get_policy(client: ThreatLockerClient, policy_id: str, org: str) -> dict[str, Any]:
    data = await client.request(
        "GET", POLICY_GET_BY_ID, organization_id=org, params={"policyId": policy_id}
    )
    if not isinstance(data, dict) or data.get("_empty_response"):
        raise WriteBlocked(f"Policy {policy_id} was not found in organization {org}.")
    return data


def _application_id_list(current: dict[str, Any]) -> list[str] | None:
    """Derive applicationIdList from whatever shape PolicyGetById returned."""
    direct = row_value(current, "applicationIdList")
    if isinstance(direct, list):
        return [str(x) for x in direct]
    for key in ("applicationIds", "applications", "applicationList", "policyApplications"):
        value = row_value(current, key)
        if isinstance(value, list):
            ids = []
            for item in value:
                if isinstance(item, dict):
                    app_id = row_value(item, "applicationId") or row_value(item, "value")
                    if app_id:
                        ids.append(str(app_id))
                elif isinstance(item, str):
                    ids.append(item)
            return ids
    return None


def build_policy_update_body(
    current: dict[str, Any], changes: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Merge the GET response with the requested changes into a PolicyUpdateById body.

    Returns ``(body, carried_over_fields)`` so dry runs can show which existing
    settings were preserved. Fields missing from the GET response are left out
    of the body (and therefore reset server-side) — the dry run output makes
    that visible before anything is sent.
    """
    body: dict[str, Any] = {}
    carried: list[str] = []
    for field_name in POLICY_UPDATE_FIELDS:
        value = row_value(current, field_name)
        if value is None:
            for alias in _GET_ALIASES.get(field_name, ()):
                value = row_value(current, alias)
                if value is not None:
                    break
        if field_name == "applicationIdList" and value is None:
            value = _application_id_list(current)
        if value is not None:
            body[field_name] = value
            carried.append(field_name)
    body.update({k: v for k, v in changes.items() if v is not None})
    return body, carried


def _compact_policy(row: dict[str, Any], org: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for out_key, candidates in _COMPACT_GROUPS.items():
        for cand in candidates:
            value = row_value(row, cand)
            if value is not None:
                out[out_key] = value
                break
    action_id = out.get("policyActionId")
    if isinstance(action_id, int):
        out["action"] = POLICY_ACTION_NAMES.get(action_id, f"unknown({action_id})")
    level = out.get("policyLevel")
    if isinstance(level, int):
        out["policyLevel"] = _LEVEL_NAMES.get(level, level)
    elif level is None:
        applies = str(out.get("appliesToId") or "").lower()
        if applies and applies == org.lower():
            out["policyLevel"] = "organization"
    return out


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="policy_list",
        description=(
            "List Allowlisting policies with filters (POST Policy/PolicyGetByParameters, or "
            "Policy/PolicyGetForViewPoliciesByApplicationId when `application_id` is given). "
            "`applies_to`: 'organization' (entire-org policies), a computer-group GUID or a "
            "computer GUID; omit for all levels. `search_text` is a case-insensitive name search. "
            "`include_inactive` includes disabled/expired policies. `show_all_policies` also returns "
            "higher-level policies that affect the selected location. `filter`: '' | nomatch | match "
            "| oversixweeks | ringfence | noringfence | elevation | permitonly | inherit | monitor | "
            "secured. `os_type` (default 1=Windows) applies when no applies_to is given. With "
            "`compact=true` (default) each row is reduced to policyId, name, orderBy, action, "
            "isEnabled, appliesTo, policyLevel (organization/computer_group/computer), lastMatch, "
            "applications; `compact=false` returns raw rows. Read-only."
        ),
    )
    async def policy_list(
        applies_to: Annotated[str | None, Field(default=None)] = None,
        application_id: Annotated[str | None, Field(default=None)] = None,
        search_text: Annotated[str | None, Field(default=None)] = None,
        include_inactive: Annotated[bool, Field(default=False)] = False,
        show_all_policies: Annotated[bool, Field(default=False)] = False,
        filter: Annotated[str, Field(default="")] = "",
        os_type: Annotated[int | str, Field(default=1)] = 1,
        page_number: Annotated[int, Field(default=1, ge=1)] = 1,
        page_size: Annotated[int, Field(default=50, ge=1, le=1000)] = 50,
        compact: Annotated[bool, Field(default=True)] = True,
        organization_id: ReadOrgId = None,
        override_organization_id: OverrideOrgId = None,
    ) -> Any:
        org = resolve_target_org(organization_id)
        applies_to_id = resolve_applies_to(applies_to, org) if applies_to else None
        extra_headers = (
            {"OverrideManagedOrganizationId": override_organization_id}
            if override_organization_id
            else None
        )
        if application_id:
            path = POLICY_GET_FOR_VIEW_BY_APPLICATION_ID
            body: dict[str, Any] = {
                "applicationId": application_id,
                "organizationId": org,
                "pageNumber": page_number,
                "pageSize": page_size,
                "includeDenies": True,
            }
            if applies_to_id:
                body["appliesToId"] = applies_to_id
        else:
            path = POLICY_GET_BY_PARAMETERS
            body = {
                "computerGroupId": applies_to_id or ALL_ZEROS_GUID,
                "filter": filter or "",
                "pageNumber": page_number,
                "pageSize": page_size,
                "activeOnly": not include_inactive,
                "osType": resolve_os_type(os_type),
                "searchText": search_text or "",
                "showAllPolicies": show_all_policies,
            }
        client = await get_client()
        data = await client.request(
            "POST", path, organization_id=organization_id, json=body, extra_headers=extra_headers
        )
        rows = _as_rows(data)
        total = None
        if rows:
            total = row_value(rows[0], "totalRows") or row_value(rows[0], "totalCount")
        return {
            "organization_id": org,
            "endpoint": path,
            "page_number": page_number,
            "page_size": page_size,
            "returned": len(rows),
            "total": total,
            "policies": [_compact_policy(r, org) for r in rows] if compact else (rows or data),
        }

    @mcp.tool(
        name="policy_insert",
        description=(
            "Create an Allowlisting policy (POST Policy/PolicyInsert). Required: `name`, "
            "`application_ids` (GUID list), `applies_to` ('organization' for entire org, or a "
            "computer-group / computer GUID). `action`: permit (1, default) | deny (2) | "
            "permit_with_ringfencing (6). `log_action` (default true; may only be false for permit). "
            "`is_enabled` defaults to FALSE (policy created disabled) — pass true to enable. "
            "`add_to_top=true` places it first (orderBefore); default appends to the bottom. "
            "`extra_fields` passes through any other KB-documented PolicyInsert field verbatim "
            "(e.g. ringfencingOptions, monitorMode, endDate). Run policies_deploy afterwards. "
            "`dry_run` defaults to TRUE. Writes target the configured default org unless "
            "`organization_id` is given explicitly."
        ),
    )
    async def policy_insert(
        name: Annotated[str, Field(min_length=1)],
        application_ids: Annotated[list[str], Field(min_length=1)],
        applies_to: Annotated[str, Field(description="'organization' or a group/computer GUID.")],
        action: Annotated[int | str, Field(default="permit")] = "permit",
        description: Annotated[str, Field(default="")] = "",
        log_action: Annotated[bool, Field(default=True)] = True,
        is_enabled: Annotated[bool, Field(default=False)] = False,
        add_to_top: Annotated[bool, Field(default=False)] = False,
        os_type: Annotated[int | str, Field(default=1)] = 1,
        extra_fields: Annotated[dict[str, Any] | None, Field(default=None)] = None,
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
    ) -> Any:
        org = resolve_target_org(organization_id)
        action_id = resolve_policy_action(action)
        if not log_action and action_id != 1:
            raise WriteBlocked("log_action may only be false for Permit policies (KB rule).")
        body: dict[str, Any] = {
            "name": name.strip(),
            "description": description or "",
            "osType": resolve_os_type(os_type),
            "policyActionId": action_id,
            "applicationIdList": list(application_ids),
            "computerGroupId": resolve_applies_to(applies_to, org),
            "logAction": log_action,
            "isEnabled": is_enabled,
            "orderBefore": add_to_top,
            "allUserGroups": True,
        }
        if extra_fields:
            body.update(extra_fields)
        plan = WritePlan(tool="policy_insert", organization_id=org)
        plan.add(
            PlannedRequest(
                "POST", POLICY_INSERT, json=body, purpose=f"create policy {body['name']!r}"
            )
        )
        plan.notes.append("Policies take effect only after policies_deploy.")
        return await execute_plan(plan, dry_run=dry_run)

    @mcp.tool(
        name="policy_update",
        description=(
            "Update an Allowlisting policy: rename, description, enable/disable, applies-to, "
            "application list, action, log action or order. Does a read-modify-write: GET "
            "Policy/PolicyGetById, carry every existing setting over, apply the changes, then PUT "
            "Policy/PolicyUpdateById (the API resets any field that is omitted, so the full body is "
            "always sent). The dry run shows the merged body and which fields were carried over — "
            "review it before executing. `applies_to`: 'organization' or a group/computer GUID. "
            "`action`: permit | deny | permit_with_ringfencing (or 1/2/6). Run policies_deploy "
            "afterwards. `dry_run` defaults to TRUE. Writes target the configured default org "
            "unless `organization_id` is given explicitly."
        ),
    )
    async def policy_update(
        policy_id: Annotated[str, Field(description="Policy GUID.")],
        name: Annotated[str | None, Field(default=None)] = None,
        description: Annotated[str | None, Field(default=None)] = None,
        is_enabled: Annotated[bool | None, Field(default=None)] = None,
        applies_to: Annotated[str | None, Field(default=None)] = None,
        application_ids: Annotated[list[str] | None, Field(default=None)] = None,
        action: Annotated[int | str | None, Field(default=None)] = None,
        log_action: Annotated[bool | None, Field(default=None)] = None,
        order_by: Annotated[int | None, Field(default=None, ge=0)] = None,
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
    ) -> Any:
        org = resolve_target_org(organization_id)
        changes: dict[str, Any] = {
            "name": name.strip() if name else None,
            "description": description,
            "isEnabled": is_enabled,
            "computerGroupId": resolve_applies_to(applies_to, org) if applies_to else None,
            "applicationIdList": list(application_ids) if application_ids else None,
            "policyActionId": resolve_policy_action(action) if action is not None else None,
            "logAction": log_action,
            "orderBy": order_by,
        }
        if all(v is None for v in changes.values()):
            raise WriteBlocked("Nothing to do: pass at least one field to change.")
        client = await get_client()
        current = await _get_policy(client, policy_id, org)
        body, carried = build_policy_update_body(current, changes)
        body["policyId"] = policy_id
        plan = WritePlan(tool="policy_update", organization_id=org)
        plan.add(
            PlannedRequest(
                "PUT",
                POLICY_UPDATE_BY_ID,
                json=body,
                target_id=policy_id,
                purpose="update policy "
                + ", ".join(k for k, v in changes.items() if v is not None),
            )
        )
        plan.notes.append(f"Fields carried over from PolicyGetById: {carried}.")
        missing = [f for f in POLICY_UPDATE_FIELDS if f not in body]
        if missing:
            plan.notes.append(
                f"Fields NOT present in the GET response and therefore not sent (server resets "
                f"them): {missing}."
            )
        plan.notes.append("Policies take effect only after policies_deploy.")
        return await execute_plan(plan, dry_run=dry_run)

    @mcp.tool(
        name="policy_set_order",
        description=(
            "Set the order number (orderBy) for one or more policies. Lower numbers are evaluated "
            "first regardless of applies-to level; negatives are not allowed. Implemented as a "
            "read-modify-write per policy (GET Policy/PolicyGetById → PUT Policy/PolicyUpdateById "
            "with the new orderBy and every other field preserved). Run policies_deploy afterwards. "
            "`dry_run` defaults to TRUE. Writes target the configured default org unless "
            "`organization_id` is given explicitly."
        ),
    )
    async def policy_set_order(
        orders: Annotated[list[PolicyOrderChange], Field(min_length=1)],
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
    ) -> Any:
        org = resolve_target_org(organization_id)
        client = await get_client()
        plan = WritePlan(tool="policy_set_order", organization_id=org)
        for change in orders:
            current = await _get_policy(client, change.policy_id, org)
            body, _carried = build_policy_update_body(current, {"orderBy": change.order_by})
            body["policyId"] = change.policy_id
            plan.add(
                PlannedRequest(
                    "PUT",
                    POLICY_UPDATE_BY_ID,
                    json=body,
                    target_id=change.policy_id,
                    purpose=f"set orderBy={change.order_by}",
                )
            )
        plan.notes.append("Policies take effect only after policies_deploy.")
        return await execute_plan(plan, dry_run=dry_run)

    @mcp.tool(
        name="policy_delete",
        description=(
            "Delete one or more Allowlisting policies in a single organization (PUT "
            "Policy/PolicyUpdateForDeleteByIds). Each policy is read first to fill the required "
            "name / organizationId / osType. Requires `confirm=true` with `dry_run=false`. Run "
            "policies_deploy afterwards. `dry_run` defaults to TRUE. Writes target the configured "
            "default org unless `organization_id` is given explicitly."
        ),
    )
    async def policy_delete(
        policy_ids: Annotated[list[str], Field(min_length=1)],
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
        confirm: Confirm = False,
    ) -> Any:
        require_confirmation(dry_run, confirm, "Deleting policies")
        org = resolve_target_org(organization_id)
        client = await get_client()
        items = []
        for policy_id in policy_ids:
            current = await _get_policy(client, policy_id, org)
            items.append(
                {
                    "policyId": policy_id,
                    "name": row_value(current, "name") or "",
                    "organizationId": row_value(current, "organizationId") or org,
                    "osType": int(row_value(current, "osType") or 1),
                }
            )
        plan = WritePlan(tool="policy_delete", organization_id=org)
        plan.add(
            PlannedRequest(
                "PUT",
                POLICY_UPDATE_FOR_DELETE_BY_IDS,
                json=items,
                target_id=",".join(policy_ids),
                purpose=f"delete {len(items)} policy(ies)",
            )
        )
        plan.notes.append(
            "Run policies_deploy afterwards (all orgs if a global policy was deleted)."
        )
        return await execute_plan(plan, dry_run=dry_run)

    @mcp.tool(
        name="policies_deploy",
        description=(
            "The portal's 'Deploy Policies' action: POST DeployPolicyQueue/DeployPolicies pushes "
            "pending policy changes to every computer in the target organization. Pass both "
            "`computer_id` and `computer_name` to deploy to one computer instead "
            "(DeployPoliciesForComputer). One organization per call. Requires `confirm=true` with "
            "`dry_run=false`. `dry_run` defaults to TRUE. Writes target the configured default org "
            "unless `organization_id` is given explicitly."
        ),
    )
    async def policies_deploy(
        computer_id: Annotated[str | None, Field(default=None)] = None,
        computer_name: Annotated[str | None, Field(default=None)] = None,
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
        confirm: Confirm = False,
    ) -> Any:
        require_confirmation(dry_run, confirm, "Deploying policies")
        org = resolve_target_org(organization_id)
        plan = WritePlan(tool="policies_deploy", organization_id=org)
        if computer_id or computer_name:
            if not (computer_id and computer_name):
                raise WriteBlocked(
                    "Deploying to a single computer needs both computer_id and computer_name."
                )
            plan.add(
                PlannedRequest(
                    "POST",
                    DEPLOY_POLICIES_FOR_COMPUTER,
                    params={"computerId": computer_id, "computerName": computer_name},
                    target_id=computer_id,
                    purpose=f"deploy policies to computer {computer_name!r}",
                )
            )
        else:
            plan.add(
                PlannedRequest(
                    "POST",
                    DEPLOY_POLICIES,
                    target_id=org,
                    purpose="deploy policies to all computers in the organization",
                )
            )
        return await execute_plan(plan, dry_run=dry_run)
