# Initial-Release Tool Additions — Design

**Date:** 2026-05-22
**Status:** Approved, ready for implementation planning
**Scope:** Pre-initial-release expansion of the ThreatLocker MCP server's curated tool surface.

## Context

The ThreatLocker MCP server currently exposes 36 of the ~82 endpoints in the
Portal API OpenAPI spec. The remaining 46 endpoints break down roughly as:

- **Clear gaps in existing workflows** — storage approvals, tags, file-download
  details for approvals, maintenance-mode extras. Each completes a flow we
  already half-cover.
- **New feature surfaces** — Scheduled Agent Actions (6 endpoints, all for
  scheduled agent-version updates), ThreatLocker version visibility,
  Save Search, Upload Request, etc.
- **Higher blast-radius operations** — restart-by-organization, auth-key
  rotation, agent-version push, install-script downloads.

The "Both, balanced" persona target (analyst + admin, skip high blast-radius)
plus a "lean initial release" preference means we add only the clear-gap fillers
now and queue larger feature surfaces (Scheduled Agent Actions, agent-version
management) for v0.2 once the initial release has been shaken out.

## Goals

1. Close the most-conspicuous coverage holes in workflows the server already
   partially supports.
2. Keep the additions reviewable in a single pass — no new module-scale features.
3. Avoid expanding the destructive-action surface beyond the existing
   approval/maintenance-mode/protection-toggle baseline.

## Non-Goals

- Scheduled Agent Actions (deferred to v0.2).
- ThreatLocker version reads or pushes (deferred to v0.2).
- Computer restart, channel updates, org auth-key rotation, install-script /
  binary downloads, Save Search, Upload Request, VDI HyperV — all out of scope
  for initial release.

## The 8 Additions

Added to `CHOSEN_ENDPOINTS` in `scripts/generate_from_spec.py`. Grows the
exposed surface from 36 → 44 tools and adds one new tool module
(`src/threatlocker_mcp/tools/tag.py`).

| # | Endpoint | LLM-facing tool name | Tag module |
|---|---|---|---|
| 1 | `GET /portalapi/ApprovalRequest/ApprovalRequestGetStorageApprovalById` | `approval_request_get_storage_approval_by_id` | approval_request |
| 2 | `POST /portalapi/ApprovalRequest/ApprovalRequestPermitStorageApproval` | `approval_request_permit_storage_approval` | approval_request |
| 3 | `GET /portalapi/ApprovalRequest/ApprovalRequestGetFileDownloadDetailsById` | `approval_request_get_file_download_details_by_id` | approval_request |
| 4 | `GET /portalapi/Tag/TagGetById` | `tag_get_by_id` | tag (new) |
| 5 | `GET /portalapi/Tag/TagGetDowndownOptionsByOrganizationId` | `tag_get_dropdown_options_by_organization_id` *(typo masked)* | tag (new) |
| 6 | `POST /portalapi/Tag/TagUpdate` | `tag_update` | tag (new) |
| 7 | `POST /portalapi/MaintenanceMode/MaintenanceModeUpdateEndDateTimeForSpecificDate` | `maintenance_mode_update_end_date_time_for_specific_date` | maintenance_mode |
| 8 | `POST /portalapi/Computer/ComputerUpdateToFinishMaintenanceMode` | `computer_update_to_finish_maintenance_mode` | computer |

## Generator Override Changes

The generator's existing override tables cover everything we need; no new
override types are introduced.

### `TOOL_NAME_OVERRIDES`

Mask the spec's "Downdown" typo from the LLM-facing tool name:

```python
("/portalapi/Tag/TagGetDowndownOptionsByOrganizationId", "get"):
    "tag_get_dropdown_options_by_organization_id",
```

### `REQUIRED_PARAM_OVERRIDES`

Promote the three query params the tag-dropdown endpoint actually needs at
runtime, even though the spec marks them optional. This matches the existing
pattern (e.g. `statusId` on `ApprovalRequestGetByParameters` — spec-optional
but the API returns HTTP 500 without it):

```python
("/portalapi/Tag/TagGetDowndownOptionsByOrganizationId", "get"):
    {"includeBuiltIns", "tagType", "includeNetworkTagInMaster"},
```

*Note:* values to be confirmed during live-test. If the API tolerates omission
of one of them, demote that one.

### `DESCRIPTION_OVERRIDES`

Three new entries:

**`approval_request_permit_storage_approval`**

Storage approvals are shape-sensitive in the same way as the application
permit flow. The DTO contains:

- `approvalRequest` — copy verbatim from `approval_request_get_storage_approval_by_id`.
- `json` — verbatim copy from the get response (same role as the application
  flow's `approvalRequest.json`).
- Exclusive mode flags — `addDeviceToExisting`, `allStorageDevices`,
  `allFilePaths`, `allUserGroups`, `deviceExists`. Set exactly one mode per
  category; unset modes' companion objects (`existingStoragePolicy`,
  `newStorageDevice`) stay `null`.

The override flags this endpoint as **not yet live-tested** and points the LLM
at the related `approval_request_permit_application` quirks as a starting model.
Guidance refined once we exercise it on the dev tenant.

**`computer_update_to_finish_maintenance_mode`** + cross-reference on
**`maintenance_mode_end_by_id`**

Clarifies the verb distinction (only one new description entry; the existing
`maintenance_mode_end_by_id` summary stays as-is):

- `maintenance_mode_end_by_id` (PATCH) — ends a *scheduled* maintenance
  window identified by `maintenanceModeId`. The window may or may not be in
  progress.
- `computer_update_to_finish_maintenance_mode` (POST) — terminates *active*
  maintenance on a specific `computerId` immediately.

**`tag_update`**

Note that `tagId` is required to update an existing tag; spec marks it
nullable but absent or empty `tagId` may cause unintended new-tag creation.
To be verified on tenant; documented defensively.

### Other Override Tables

No changes required:

- **`HEADER_PARAM_DEFAULTS`** — no header tweaks needed.
- **`PROPERTY_NAME_OVERRIDES`** — no mis-cased fields observed.
- **`SEND_FULL_BODY_OVERRIDES`** — none of the new endpoints distinguish
  missing from null in a way the generator's default `exclude_none` mode would
  break.

## Risk & Destructive-Action Notes

Three of the eight tools are destructive writes:

| Tool | Blast radius |
|---|---|
| `approval_request_permit_storage_approval` | Approves storage device / path access (USB, network share, file path) for one device or scope. Equivalent caution level to the existing application-permit flow. |
| `tag_update` | Overwrites tag membership lists for an existing tag. Per-org scope. |
| `computer_update_to_finish_maintenance_mode` | Ends active maintenance on one computer, re-enabling enforcement immediately. Could break in-progress installs if used carelessly. |

The remaining five are reads.

The README's existing destructive-actions warning at the top of the file
already covers the spirit of these; no new warnings are added until the
storage-approval flow is live-tested.

## Test Plan

- The repository's 24 mocked tests in `tests/test_client.py` exercise the
  client transport, not the per-tool wrappers — they continue to pass
  unchanged after codegen.
- New tools are codegen output, so they get implicit coverage via the
  generator's idempotency. No new test files are added at codegen time.
- Verification after regeneration:
  1. `ruff check .` clean.
  2. `ruff format .` clean.
  3. `pytest` passes (24/24).
- Live-test the storage-approval flow against the dev tenant before declaring
  the description guidance settled. If the flow reveals body-shape quirks
  similar to `permit_application`, fold them into the description override and
  the README "Known API quirks" section.
- The remaining new tools are mechanical reads or low-risk writes; smoke-test
  them via the dev tenant during the same live-test pass.

## README Updates

Three areas:

1. **Counter bumps** — two places quote "36 tools": the opening blurb (line 9)
   and the Quick Start confirmation line ("you should see 36 ThreatLocker
   tools listed", line 104). Update both to 44. The separate "54 generated
   from the spec" Pydantic-model count on line 128 also needs updating once
   regeneration produces the new total (storage approval, tag, and
   maintenance-mode DTOs introduce additional schemas).
2. **Tools table** (lines 113–127) — adjust counts and capability strings:
   - Approval Requests: 8 → 11 (add storage approval read+write, file download details).
   - Maintenance Mode: 3 → 4 (update end-date for scheduled window).
   - Computers: 8 → 9 (finish active maintenance now).
   - Add a **Tag** row (3 tools — get/dropdown/update).
3. **Optional Example Prompts** — one new entry each for tag inspection and
   storage-approval review. Skip if it bloats the section.

The "Known API quirks" section gets at most one new bullet, added only after
live-testing storage approvals reveals an actual quirk worth documenting.

## Implementation Outline

A single edit pass on `scripts/generate_from_spec.py` plus a regeneration:

1. Append the 8 new `(path, method)` tuples to `CHOSEN_ENDPOINTS`, grouped
   under their existing tags (or a new `# Tag (3)` group).
2. Add the entries to `TOOL_NAME_OVERRIDES`, `REQUIRED_PARAM_OVERRIDES`, and
   `DESCRIPTION_OVERRIDES`.
3. Run `python scripts/generate_from_spec.py spec.json`.
4. `ruff format .`.
5. `pytest`.
6. Update the README counters and tools table.
7. Live-test storage approvals on the dev tenant; refine description override
   if needed; re-generate.
8. Commit.

No edits to hand-written code (`client.py`, `config.py`, `server.py`) are
expected.

## Out of Scope (Tracked for v0.2)

- Scheduled Agent Actions (6 endpoints) — bounded fleet management for agent
  version updates with batch/window control.
- ThreatLocker agent version visibility — `ComputerGetThreatlockerVersions`,
  `ThreatLockerVersionGetForDropdownList`.
- `ReportGetDynamicData` — ad-hoc report data on top of the existing
  org-level report list.
- `ComputerCheckinGetByParameters` — per-endpoint check-in history.
- Computer restart / channel updates / agent-version push.
- Computer install-script and binary downloads.
- Organization auth-key rotation.
- Save Search, Upload Request, VDI HyperV, Application network-policy
  process, computer remove-duplicate.
