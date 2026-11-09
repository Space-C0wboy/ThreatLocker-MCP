"""ThreatLocker MCP tools: action-log search with projection, aggregation and explicit paging.

Hand-written companion to the generated ``action_log_get_by_parameters_v2``.
Same endpoint (POST ActionLog/ActionLogGetByParametersV2, ``usenewsearch=true``),
but:

* explicit ``page_number`` / ``page_size`` with totals read from the response
  headers (``totalItems`` / ``totalPages``) that the API only exposes there;
* ``fields`` — return only the named columns of each row;
* ``aggregate_by`` — counts instead of rows, server-side via ``groupBys`` where
  the API has an ID for the field, client-side over paged rows otherwise (e.g.
  ``fullPathFolder``).

groupBys IDs: https://threatlocker.kb.help/unified-audit-portalapiactionlog/
"""

from __future__ import annotations

from collections import Counter
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from .. import models
from ..client import get_client
from ..management_models import (
    ACTION_LOG_GROUP_BY_IDS,
    CLIENT_SIDE_AGGREGATES,
    AggregateMode,
    folder_of,
    pick_fields,
    row_value,
)
from ._params import OverrideOrgId, ReadOrgId

ACTION_LOG_GET_BY_PARAMETERS_V2 = "/portalapi/ActionLog/ActionLogGetByParametersV2"
CLIENT_PAGE_SIZE = 1000
MAX_CLIENT_ROWS_CAP = 50_000

_HEADER_KEYS = {
    "total_items": "totalitems",
    "total_pages": "totalpages",
    "current_page": "currentpage",
    "items_per_page": "itemsperpage",
}


def _as_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        if data.get("_empty_response"):
            return []
        for key in ("data", "items", "result", "results", "logs"):
            value = data.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def _paging_from_headers(headers: dict[str, str]) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for key, header in _HEADER_KEYS.items():
        raw = headers.get(header)
        try:
            out[key] = int(raw) if raw not in (None, "", "null") else None
        except ValueError:
            out[key] = None
    return out


def resolve_aggregates(names: list[str], mode: AggregateMode) -> tuple[str, list[int]]:
    """Decide server vs client aggregation and resolve groupBys IDs.

    Returns ``(mode, group_by_ids)``; ``group_by_ids`` is empty for client mode.
    """
    unknown = [
        n for n in names if n not in ACTION_LOG_GROUP_BY_IDS and n not in CLIENT_SIDE_AGGREGATES
    ]
    if unknown:
        raise ValueError(
            f"Unknown aggregate_by field(s) {unknown}. Server-side options: "
            f"{sorted(ACTION_LOG_GROUP_BY_IDS)}; client-side options: {sorted(CLIENT_SIDE_AGGREGATES)}."
        )
    server_capable = all(n in ACTION_LOG_GROUP_BY_IDS for n in names)
    if mode == "server":
        if not server_capable:
            raise ValueError(
                "aggregate_mode='server' but one of the fields has no groupBys ID; use 'client' or 'auto'."
            )
        chosen = "server"
    elif mode == "client":
        chosen = "client"
    else:
        chosen = "server" if server_capable and len(names) <= 2 else "client"
    if chosen == "server":
        return "server", [ACTION_LOG_GROUP_BY_IDS[n] for n in names]
    return "client", []


def aggregate_rows(rows: list[dict[str, Any]], names: list[str]) -> list[dict[str, Any]]:
    """Client-side group-and-count over rows; derives folder for fullPathFolder."""
    counter: Counter[tuple[Any, ...]] = Counter()
    for row in rows:
        key = []
        for name in names:
            source = CLIENT_SIDE_AGGREGATES.get(name)
            if source:
                key.append(folder_of(row_value(row, source)))
            else:
                key.append(row_value(row, name))
        counter[tuple(key)] += 1
    out = []
    for key, count in counter.most_common():
        entry = {name: value for name, value in zip(names, key, strict=True)}
        entry["count"] = count
        out.append(entry)
    return out


def _build_params(
    *,
    source_table_id: int,
    start_date: str,
    end_date: str,
    page_number: int,
    page_size: int,
    hostname: str | None,
    full_path: str | None,
    username: str | None,
    action_type: str | None,
    action_id: int | None,
    policy_id: str | None,
    show_child_organizations: bool,
    group_bys: list[int] | None,
    total_rows: int | None,
) -> dict[str, Any]:
    dto = models.ActionLogParamsDto(
        source_table_id=source_table_id,
        start_date=start_date,
        end_date=end_date,
        page_number=page_number,
        page_size=page_size,
        hostname=hostname,
        full_path=full_path,
        username=username,
        action_type=action_type,
        action_id=action_id,
        policy_id=policy_id,
        show_child_organizations=show_child_organizations,
        show_total_count=True,
        group_bys=group_bys,
        total_rows=total_rows or 0,
    )
    return dto.model_dump(by_alias=True, exclude_none=True)


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="action_log_search",
        description=(
            "Search the Unified Audit (POST ActionLog/ActionLogGetByParametersV2 with "
            "usenewsearch=true) with explicit paging and output shaping — use this instead of "
            "`action_log_get_by_parameters_v2` for anything larger than a quick look. Required: "
            "`start_date` / `end_date` (UTC, 'YYYY-MM-DDTHH:MM:SSZ'). `source_table_id`: 1=ActionLog "
            "(default), 2=DenyActionLog, 3=Baseline, 4=EventLog. Filters: hostname (wildcards), "
            "full_path (wildcards), username, action_type (execute|install|network|registry|read|"
            "write|move|delete|baseline|powershell|elevate|configuration|dns), action_id (1 Permit, "
            "2 Deny, 3 Deny-request, 6 Ringfenced, 99 any deny), policy_id. "
            "`fields`: list of column names to keep per row (case-insensitive), e.g. "
            "['dateTime','hostname','fullPath','policyName']. "
            "`aggregate_by`: return counts instead of rows — server-side groupBys (1–2 fields such "
            "as policyName, fullPath, processPath, createdByProcess, hostname, username, "
            "applicationName, actionType, sha256) or client-side over paged rows for "
            "fullPathFolder / more than two fields (bounded by `max_rows`). Paging info "
            "(page_number, page_size, total_items, total_pages) is always returned. Read-only."
        ),
    )
    async def action_log_search(
        start_date: Annotated[str, Field(description="UTC start, e.g. 2026-11-01T00:00:00Z")],
        end_date: Annotated[str, Field(description="UTC end, e.g. 2026-11-08T00:00:00Z")],
        source_table_id: Annotated[int, Field(default=1)] = 1,
        page_number: Annotated[int, Field(default=1, ge=1)] = 1,
        page_size: Annotated[int, Field(default=100, ge=1, le=10000)] = 100,
        hostname: Annotated[str | None, Field(default=None)] = None,
        full_path: Annotated[str | None, Field(default=None)] = None,
        username: Annotated[str | None, Field(default=None)] = None,
        action_type: Annotated[str | None, Field(default=None)] = None,
        action_id: Annotated[int | None, Field(default=None)] = None,
        policy_id: Annotated[str | None, Field(default=None)] = None,
        show_child_organizations: Annotated[bool, Field(default=False)] = False,
        fields: Annotated[list[str] | None, Field(default=None)] = None,
        aggregate_by: Annotated[list[str] | None, Field(default=None)] = None,
        aggregate_mode: Annotated[AggregateMode, Field(default="auto")] = "auto",
        max_rows: Annotated[int, Field(default=5000, ge=1, le=MAX_CLIENT_ROWS_CAP)] = 5000,
        total_rows: Annotated[
            int | None,
            Field(
                default=None,
                description="totalItems from a previous page; the API needs it for deep multi-page pulls.",
            ),
        ] = None,
        organization_id: ReadOrgId = None,
        override_organization_id: OverrideOrgId = None,
    ) -> Any:
        extra_headers: dict[str, str] = {"usenewsearch": "true"}
        if override_organization_id:
            extra_headers["OverrideManagedOrganizationId"] = override_organization_id
        client = await get_client()

        common = dict(
            source_table_id=source_table_id,
            start_date=start_date,
            end_date=end_date,
            hostname=hostname,
            full_path=full_path,
            username=username,
            action_type=action_type,
            action_id=action_id,
            policy_id=policy_id,
            show_child_organizations=show_child_organizations,
        )

        # ------------------------------------------------------------------ aggregate
        if aggregate_by:
            mode, group_by_ids = resolve_aggregates(aggregate_by, aggregate_mode)
            if mode == "server":
                body = _build_params(
                    **common,
                    page_number=page_number,
                    page_size=page_size,
                    group_bys=group_by_ids,
                    total_rows=total_rows,
                )
                data, headers = await client.request(
                    "POST",
                    ACTION_LOG_GET_BY_PARAMETERS_V2,
                    organization_id=organization_id,
                    json=body,
                    extra_headers=extra_headers,
                    include_headers=True,
                )
                rows = _as_rows(data)
                groups = []
                for row in rows:
                    entry = {name: row_value(row, name) for name in aggregate_by}
                    entry["count"] = row_value(row, "groupByCount")
                    groups.append(entry)
                groups.sort(key=lambda g: (g["count"] is None, -(g["count"] or 0)))
                return {
                    "aggregate_by": aggregate_by,
                    "mode": "server",
                    "group_bys": group_by_ids,
                    "paging": {
                        "page_number": page_number,
                        "page_size": page_size,
                        **_paging_from_headers(headers),
                    },
                    "groups": groups,
                }

            scanned: list[dict[str, Any]] = []
            page = 1
            truncated = False
            running_total = total_rows
            while True:
                body = _build_params(
                    **common,
                    page_number=page,
                    page_size=CLIENT_PAGE_SIZE,
                    group_bys=None,
                    total_rows=running_total,
                )
                data, headers = await client.request(
                    "POST",
                    ACTION_LOG_GET_BY_PARAMETERS_V2,
                    organization_id=organization_id,
                    json=body,
                    extra_headers=extra_headers,
                    include_headers=True,
                )
                rows = _as_rows(data)
                paging = _paging_from_headers(headers)
                running_total = paging.get("total_items") or running_total
                scanned.extend(rows)
                if len(scanned) >= max_rows:
                    truncated = len(rows) >= CLIENT_PAGE_SIZE or (
                        running_total is not None and running_total > len(scanned)
                    )
                    scanned = scanned[:max_rows]
                    break
                if len(rows) < CLIENT_PAGE_SIZE:
                    break
                page += 1
            return {
                "aggregate_by": aggregate_by,
                "mode": "client",
                "rows_scanned": len(scanned),
                "pages_scanned": page,
                "truncated": truncated,
                "total_items": running_total,
                "groups": aggregate_rows(scanned, aggregate_by),
            }

        # ------------------------------------------------------------------ rows
        body = _build_params(
            **common,
            page_number=page_number,
            page_size=page_size,
            group_bys=None,
            total_rows=total_rows,
        )
        data, headers = await client.request(
            "POST",
            ACTION_LOG_GET_BY_PARAMETERS_V2,
            organization_id=organization_id,
            json=body,
            extra_headers=extra_headers,
            include_headers=True,
        )
        rows = _as_rows(data)
        if fields:
            rows = [pick_fields(r, fields) for r in rows]
        return {
            "paging": {
                "page_number": page_number,
                "page_size": page_size,
                "returned": len(rows),
                **_paging_from_headers(headers),
            },
            "fields": fields,
            "rows": rows if rows or isinstance(data, list) else data,
        }
