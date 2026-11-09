"""ThreatLocker MCP tools: application and application-file-rule management.

Hand-written (not generated). The endpoints come from the ThreatLocker KB:
https://threatlocker.kb.help/portalapiapplication/ and
https://threatlocker.kb.help/portalapiapplicationfile/ — they are not present in
the public Swagger document. Every write goes through ``write_safety``.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from ..client import ThreatLockerAPIError, ThreatLockerClient, get_client
from ..management_models import (
    ApplicationFileRule,
    normalize_sha256_list,
    resolve_os_type,
    row_value,
)
from ..write_safety import (
    PlannedRequest,
    WriteBlocked,
    WritePlan,
    dry_run_result,
    execute_plan,
    require_confirmation,
    resolve_target_org,
    send_one,
)
from ._params import Confirm, DryRun, OverrideOrgId, ReadOrgId, WriteOrgId

APPLICATION_GET_BY_ID = "/portalapi/Application/ApplicationGetById"
APPLICATION_GET_BY_PARAMETERS = "/portalapi/Application/ApplicationGetByParameters"
APPLICATION_INSERT = "/portalapi/Application/ApplicationInsert"
APPLICATION_UPDATE_BY_ID = "/portalapi/Application/ApplicationUpdateById"
APPLICATION_UPDATE_FOR_DELETE = "/portalapi/Application/ApplicationUpdateForDelete"
APPLICATION_CONFIRM_UPDATE_FOR_DELETE = "/portalapi/Application/ApplicationConfirmUpdateForDelete"
APPLICATION_FILE_GET_BY_APPLICATION_ID = (
    "/portalapi/ApplicationFile/ApplicationFileGetByApplicationId"
)
APPLICATION_FILE_INSERT = "/portalapi/ApplicationFile/ApplicationFileInsert"
APPLICATION_FILE_DELETE_BY_ID = "/portalapi/ApplicationFile/ApplicationFileDeleteById"

# ApplicationFileInsert accepts one rule per call. The bulk tool sends this many
# concurrent requests per batch.
DEFAULT_BULK_BATCH_SIZE = 25
MAX_BULK_HASHES = 5000
RULE_PAGE_SIZE = 500
MAX_RULE_PAGES = 40  # 20,000 rules — well above the ~1,000-rule apps we have seen
DEFAULT_RULE_NOTES = "Added via threatlocker-mcp"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _as_rows(data: Any) -> list[dict[str, Any]]:
    """Normalise list-or-envelope responses to a list of row dicts."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        if data.get("_empty_response"):
            return []
        for key in ("data", "items", "result", "results", "applicationFiles"):
            value = data.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


async def _get_application(
    client: ThreatLockerClient, application_id: str, org: str
) -> dict[str, Any]:
    data = await client.request(
        "GET",
        APPLICATION_GET_BY_ID,
        organization_id=org,
        params={"applicationId": application_id},
    )
    if not isinstance(data, dict) or data.get("_empty_response"):
        raise WriteBlocked(
            f"Application {application_id} was not found in organization {org} "
            "(ApplicationGetById only returns custom applications)."
        )
    return data


async def _list_rules(
    client: ThreatLockerClient,
    org: str,
    application_id: str,
    *,
    hash_only: bool | None = None,
    custom_rules_only: bool | None = None,
    search_text: str | None = None,
    page_size: int = RULE_PAGE_SIZE,
    max_pages: int = MAX_RULE_PAGES,
) -> list[dict[str, Any]]:
    """Page through ApplicationFileGetByApplicationId and return every row."""
    rows: list[dict[str, Any]] = []
    page = 1
    while page <= max_pages:
        params: dict[str, Any] = {
            "applicationId": application_id,
            "pageNumber": page,
            "pageSize": page_size,
        }
        if hash_only is not None:
            params["hashOnly"] = hash_only
        if custom_rules_only is not None:
            params["isCustomRule"] = custom_rules_only
        if search_text:
            params["searchText"] = search_text
        batch = _as_rows(
            await client.request(
                "GET",
                APPLICATION_FILE_GET_BY_APPLICATION_ID,
                organization_id=org,
                params=params,
            )
        )
        rows.extend(batch)
        if len(batch) < page_size:
            break
        page += 1
    return rows


def _rule_delete_body(
    rule_row: dict[str, Any], *, application_id: str, application_name: str, os_type: int
) -> dict[str, Any]:
    """Body for ApplicationFileDeleteById — the KB wants every condition the rule uses."""
    body: dict[str, Any] = {
        "applicationFileId": row_value(rule_row, "applicationFileId"),
        "applicationId": application_id,
        "applicationName": application_name,
        "osType": os_type,
    }
    for key in ("fullPath", "processPath", "installedBy", "cert", "hash"):
        value = row_value(rule_row, key)
        if value not in (None, ""):
            body[key] = value
    return body


def _rules_with_notes(rules: list[ApplicationFileRule]) -> list[ApplicationFileRule]:
    return [r if r.notes else r.model_copy(update={"notes": DEFAULT_RULE_NOTES}) for r in rules]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="application_list",
        description=(
            "List custom (and optionally built-in) applications in an organization, paged. "
            "Use this to find an application's GUID by name before calling the other "
            "application_* or policy_* tools. Wraps POST Application/ApplicationGetByParameters. "
            "`category`: 0=All, 1=Custom (default), 2=Built-In, 4=Patch Supported. "
            "`os_type`: 0=All, 1=Windows (default), 2=Mac, 3=Linux, 5=Windows XP. "
            "`search_by`: app (default) | full | process | hash | cert | created | categories | countries. "
            "`order_by`: name (default) | date-created | review-rating | computer-count | policy. "
            "Read-only."
        ),
    )
    async def application_list(
        search_text: Annotated[str | None, Field(default=None)] = None,
        os_type: Annotated[int | str, Field(default=1)] = 1,
        category: Annotated[int, Field(default=1)] = 1,
        page_number: Annotated[int, Field(default=1, ge=1)] = 1,
        page_size: Annotated[int, Field(default=25, ge=1, le=1000)] = 25,
        order_by: Annotated[str, Field(default="name")] = "name",
        search_by: Annotated[str, Field(default="app")] = "app",
        is_ascending: Annotated[bool, Field(default=True)] = True,
        include_child_organizations: Annotated[bool, Field(default=False)] = False,
        permitted_applications: Annotated[bool, Field(default=False)] = False,
        is_hidden: Annotated[bool, Field(default=False)] = False,
        organization_id: ReadOrgId = None,
        override_organization_id: OverrideOrgId = None,
    ) -> Any:
        body = {
            "searchText": search_text or "",
            "osType": resolve_os_type(os_type),
            "category": category,
            "pageNumber": page_number,
            "pageSize": page_size,
            "orderBy": order_by,
            "searchBy": search_by,
            "isAscending": is_ascending,
            "includeChildOrganizations": include_child_organizations,
            "permittedApplications": permitted_applications,
            "isHidden": is_hidden,
        }
        extra_headers = (
            {"OverrideManagedOrganizationId": override_organization_id}
            if override_organization_id
            else None
        )
        client = await get_client()
        return await client.request(
            "POST",
            APPLICATION_GET_BY_PARAMETERS,
            organization_id=organization_id,
            json=body,
            extra_headers=extra_headers,
        )

    @mcp.tool(
        name="application_files_list",
        description=(
            "List an application's file rules, paged. `application_get_by_id` returns "
            "`applicationFiles: []` even for apps with ~1,000 rules — use this instead. "
            "Wraps GET ApplicationFile/ApplicationFileGetByApplicationId. Filters: `hash_only=true` "
            "returns only hash-only rules; `custom_rules_only=true` returns only custom (non-hash) "
            "rules (do not set both); `search_text` is a wildcard search across rule text and notes. "
            "Built-in application rules cannot be retrieved. Read-only."
        ),
    )
    async def application_files_list(
        application_id: Annotated[str, Field(description="Application GUID.")],
        page_number: Annotated[int, Field(default=1, ge=1)] = 1,
        page_size: Annotated[int, Field(default=100, ge=1, le=5000)] = 100,
        hash_only: Annotated[bool | None, Field(default=None)] = None,
        custom_rules_only: Annotated[bool | None, Field(default=None)] = None,
        search_text: Annotated[str | None, Field(default=None)] = None,
        organization_id: ReadOrgId = None,
        override_organization_id: OverrideOrgId = None,
    ) -> Any:
        if hash_only and custom_rules_only:
            raise ValueError("Set at most one of hash_only / custom_rules_only.")
        params: dict[str, Any] = {
            "applicationId": application_id,
            "pageNumber": page_number,
            "pageSize": page_size,
        }
        if hash_only is not None:
            params["hashOnly"] = hash_only
        if custom_rules_only is not None:
            params["isCustomRule"] = custom_rules_only
        if search_text:
            params["searchText"] = search_text
        extra_headers = (
            {"OverrideManagedOrganizationId": override_organization_id}
            if override_organization_id
            else None
        )
        client = await get_client()
        data = await client.request(
            "GET",
            APPLICATION_FILE_GET_BY_APPLICATION_ID,
            organization_id=organization_id,
            params=params,
            extra_headers=extra_headers,
        )
        rows = _as_rows(data)
        return {
            "application_id": application_id,
            "page_number": page_number,
            "page_size": page_size,
            "returned": len(rows),
            "has_more": len(rows) >= page_size,
            "rules": rows if rows else data,
        }

    @mcp.tool(
        name="application_insert",
        description=(
            "Create a custom application (POST Application/ApplicationInsert). Required: `name` "
            "(unique per OS type). `os_type`: 1=Windows (default), 2=Mac, 3=Linux (names accepted). "
            "Optional `description` and initial `rules` — each rule is a set of conditions "
            "(full_path / process_path / created_by / cert may be combined; hash or sha256 are "
            "standalone) plus `notes`. `dry_run` defaults to TRUE and returns the exact body "
            "without sending; pass dry_run=false to create. Writes target the configured default "
            "org unless `organization_id` is given explicitly."
        ),
    )
    async def application_insert(
        name: Annotated[str, Field(min_length=1, description="Application name.")],
        os_type: Annotated[int | str, Field(default=1)] = 1,
        description: Annotated[str, Field(default="")] = "",
        rules: Annotated[
            list[ApplicationFileRule] | None,
            Field(default=None, description="Optional initial file rules."),
        ] = None,
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
    ) -> Any:
        org = resolve_target_org(organization_id)
        os_code = resolve_os_type(os_type)
        body: dict[str, Any] = {
            "name": name.strip(),
            "osType": os_code,
            "description": description or "",
        }
        if rules:
            body["applicationFileUpdates"] = [
                r.to_application_file_dto(os_type=os_code, update_status=1)
                for r in _rules_with_notes(rules)
            ]
        plan = WritePlan(tool="application_insert", organization_id=org)
        plan.add(
            PlannedRequest(
                "POST",
                APPLICATION_INSERT,
                json=body,
                purpose=f"create application {body['name']!r}",
            )
        )
        return await execute_plan(plan, dry_run=dry_run)

    @mcp.tool(
        name="application_update",
        description=(
            "Update a custom application: rename / change description (PUT "
            "Application/ApplicationUpdateById), add file rules (POST "
            "ApplicationFile/ApplicationFileInsert, one request per rule) and/or remove rules by "
            "`applicationFileId` (POST ApplicationFile/ApplicationFileDeleteById, one request per "
            "rule). The current app is read first so an omitted `description` is preserved rather "
            "than wiped. Each rule is a list of conditions (full_path / process_path / created_by / "
            "cert combinable; hash or sha256 standalone). Removing rules requires `confirm=true`. "
            "`dry_run` defaults to TRUE and returns every request that would be sent. Writes target "
            "the configured default org unless `organization_id` is given explicitly."
        ),
    )
    async def application_update(
        application_id: Annotated[str, Field(description="Application GUID.")],
        name: Annotated[str | None, Field(default=None)] = None,
        description: Annotated[str | None, Field(default=None)] = None,
        add_rules: Annotated[list[ApplicationFileRule] | None, Field(default=None)] = None,
        remove_rule_ids: Annotated[
            list[int] | None,
            Field(default=None, description="applicationFileId values to delete."),
        ] = None,
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
        confirm: Confirm = False,
    ) -> Any:
        if not any([name, description is not None, add_rules, remove_rule_ids]):
            raise WriteBlocked(
                "Nothing to do: pass name, description, add_rules or remove_rule_ids."
            )
        if remove_rule_ids:
            require_confirmation(dry_run, confirm, "Removing application file rules")

        org = resolve_target_org(organization_id)
        client = await get_client()
        current = await _get_application(client, application_id, org)
        current_name = row_value(current, "name") or ""
        current_description = row_value(current, "description") or ""
        os_code = int(row_value(current, "osType") or 1)
        new_name = (name or current_name).strip()

        plan = WritePlan(tool="application_update", organization_id=org)
        plan.notes.append(
            f"Current application: name={current_name!r}, osType={os_code}, "
            f"description={current_description!r}."
        )

        if name is not None or description is not None:
            plan.add(
                PlannedRequest(
                    "PUT",
                    APPLICATION_UPDATE_BY_ID,
                    json={
                        "applicationId": application_id,
                        "name": new_name,
                        "description": (
                            description if description is not None else current_description
                        ),
                        "osType": os_code,
                    },
                    target_id=application_id,
                    purpose="update name/description",
                )
            )

        for rule in _rules_with_notes(add_rules or []):
            plan.add(
                PlannedRequest(
                    "POST",
                    APPLICATION_FILE_INSERT,
                    json=rule.to_application_file_dto(
                        os_type=os_code,
                        application_id=application_id,
                        application_name=new_name,
                    ),
                    target_id=application_id,
                    purpose="add file rule",
                )
            )

        if remove_rule_ids:
            wanted = {int(i) for i in remove_rule_ids}
            existing = await _list_rules(client, org, application_id)
            by_id = {
                int(row_value(r, "applicationFileId")): r
                for r in existing
                if row_value(r, "applicationFileId") is not None
            }
            missing = sorted(wanted - set(by_id))
            if missing:
                raise WriteBlocked(
                    f"applicationFileId(s) {missing} were not found on application "
                    f"{application_id}; nothing was sent."
                )
            for file_id in sorted(wanted):
                plan.add(
                    PlannedRequest(
                        "POST",
                        APPLICATION_FILE_DELETE_BY_ID,
                        json=_rule_delete_body(
                            by_id[file_id],
                            application_id=application_id,
                            application_name=new_name,
                            os_type=os_code,
                        ),
                        target_id=str(file_id),
                        purpose="remove file rule",
                    )
                )
        return await execute_plan(plan, dry_run=dry_run)

    @mcp.tool(
        name="application_add_sha256_bulk",
        description=(
            "Add many SHA256 hash-only rules to an existing custom application. Validates and "
            "de-duplicates the input (64-hex), skips hashes the app already has "
            "(`skip_existing`, default true), then sends one ApplicationFileInsert per hash in "
            "concurrent batches of `batch_size` (default 25) and reports added / failed / skipped "
            "counts. Up to 5,000 hashes per call. `dry_run` defaults to TRUE and returns the batch "
            "plan plus a sample request without sending. Writes target the configured default org "
            "unless `organization_id` is given explicitly."
        ),
    )
    async def application_add_sha256_bulk(
        application_id: Annotated[str, Field(description="Application GUID.")],
        sha256_list: Annotated[list[str], Field(min_length=1, max_length=MAX_BULK_HASHES)],
        notes: Annotated[
            str, Field(default=DEFAULT_RULE_NOTES, description="Note stored on each rule.")
        ] = DEFAULT_RULE_NOTES,
        skip_existing: Annotated[bool, Field(default=True)] = True,
        batch_size: Annotated[int, Field(default=DEFAULT_BULK_BATCH_SIZE, ge=1, le=100)] = (
            DEFAULT_BULK_BATCH_SIZE
        ),
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
    ) -> Any:
        org = resolve_target_org(organization_id)
        valid, rejected = normalize_sha256_list(sha256_list)

        client = await get_client()
        current = await _get_application(client, application_id, org)
        app_name = row_value(current, "name") or ""
        os_code = int(row_value(current, "osType") or 1)

        already_present: list[str] = []
        if skip_existing and valid:
            existing_rows = await _list_rules(client, org, application_id, hash_only=True)
            existing_hashes = {
                str(row_value(r, "hash") or "").strip().lower()
                for r in existing_rows
                if row_value(r, "hash")
            }
            already_present = [h for h in valid if h in existing_hashes]
            valid = [h for h in valid if h not in existing_hashes]

        plan = WritePlan(tool="application_add_sha256_bulk", organization_id=org)
        for sha in valid:
            rule = ApplicationFileRule(sha256=sha, notes=notes or DEFAULT_RULE_NOTES)
            plan.add(
                PlannedRequest(
                    "POST",
                    APPLICATION_FILE_INSERT,
                    json=rule.to_application_file_dto(
                        os_type=os_code,
                        application_id=application_id,
                        application_name=app_name,
                    ),
                    target_id=sha,
                    purpose="add sha256 rule",
                )
            )
        batches = [
            plan.requests[i : i + batch_size] for i in range(0, len(plan.requests), batch_size)
        ]
        summary: dict[str, Any] = {
            "tool": plan.tool,
            "organization_id": org,
            "application_id": application_id,
            "application_name": app_name,
            "input_count": len(sha256_list),
            "rejected": rejected,
            "already_present_count": len(already_present),
            "to_add_count": len(valid),
            "batch_size": batch_size,
            "batch_count": len(batches),
        }
        if dry_run:
            preview = dry_run_result(plan)
            preview["requests"] = preview["requests"][:3]
            preview["notes"].insert(
                0,
                f"Showing the first {min(3, len(valid))} of {len(valid)} planned requests "
                "(one ApplicationFileInsert per hash).",
            )
            return {**summary, **preview}

        added: list[str] = []
        failed: list[dict[str, str]] = []
        for batch in batches:
            outcomes = await asyncio.gather(
                *(send_one(plan, req) for req in batch), return_exceptions=True
            )
            for req, outcome in zip(batch, outcomes, strict=True):
                if isinstance(outcome, ThreatLockerAPIError):
                    failed.append({"sha256": req.target_id or "", "error": str(outcome)})
                elif isinstance(outcome, BaseException):
                    failed.append({"sha256": req.target_id or "", "error": repr(outcome)})
                else:
                    added.append(req.target_id or "")
        return {
            **summary,
            "dry_run": False,
            "added_count": len(added),
            "failed_count": len(failed),
            "failed": failed,
            "already_present": already_present,
        }

    @mcp.tool(
        name="application_delete",
        description=(
            "Delete a custom application. Reads the app first, then POSTs "
            "Application/ApplicationUpdateForDelete (apps with no policies). If the app still has "
            "policies attached, pass `force_with_policies=true` to use "
            "ApplicationConfirmUpdateForDelete instead (deploy policies afterwards). Requires "
            "`confirm=true` with `dry_run=false`. `dry_run` defaults to TRUE. Writes target the "
            "configured default org unless `organization_id` is given explicitly."
        ),
    )
    async def application_delete(
        application_id: Annotated[str, Field(description="Application GUID.")],
        force_with_policies: Annotated[bool, Field(default=False)] = False,
        organization_id: WriteOrgId = None,
        dry_run: DryRun = True,
        confirm: Confirm = False,
    ) -> Any:
        require_confirmation(dry_run, confirm, "Deleting an application")
        org = resolve_target_org(organization_id)
        client = await get_client()
        current = await _get_application(client, application_id, org)
        body = {
            "applications": [
                {
                    "applicationId": application_id,
                    "name": row_value(current, "name") or "",
                    "organizationId": row_value(current, "organizationId") or org,
                    "osType": int(row_value(current, "osType") or 1),
                }
            ]
        }
        path = (
            APPLICATION_CONFIRM_UPDATE_FOR_DELETE
            if force_with_policies
            else APPLICATION_UPDATE_FOR_DELETE
        )
        plan = WritePlan(tool="application_delete", organization_id=org)
        plan.add(
            PlannedRequest(
                "POST",
                path,
                json=body,
                target_id=application_id,
                purpose="delete application" + (" (has policies)" if force_with_policies else ""),
            )
        )
        if force_with_policies:
            plan.notes.append("Run policies_deploy afterwards so endpoints pick up the change.")
        return await execute_plan(plan, dry_run=dry_run)
