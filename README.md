# ThreatLocker MCP

[![PyPI version](https://badge.fury.io/py/threatlocker-mcp.svg)](https://pypi.org/project/threatlocker-mcp/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/threatlocker-mcp)](https://pypi.org/project/threatlocker-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Space-C0wboy/ThreatLocker-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/Space-C0wboy/ThreatLocker-MCP/actions/workflows/ci.yml)

**threatlocker-mcp** is a [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI assistants such as Claude Desktop and Claude Code with the [ThreatLocker Portal API](https://portalapi.h.threatlocker.com/swagger/index.html). 57 tools — 44 generated directly from the official OpenAPI 3.0 spec plus 13 hand-written application / policy / audit-log management tools built from ThreatLocker's published API documentation — give your AI assistant programmatic access to computers, approvals, applications, policies, action logs, tags, maintenance mode, reports, and more, across single-org and parent/child tenant setups.

> [!IMPORTANT]
> **Unofficial project.** This is an independent, community-built MCP server developed against ThreatLocker's published API documentation. It is **not** an official ThreatLocker product and is not affiliated with, endorsed by, or supported by ThreatLocker, Inc. "ThreatLocker" is a trademark of ThreatLocker, Inc. For official support of the ThreatLocker platform itself, contact ThreatLocker directly.

> [!WARNING]
> **Beta software — not yet recommended for production environments.** This project is under active development. The tool surface and individual tool body shapes may still change between minor versions, and not every endpoint has been exhaustively exercised against every tenant configuration. Use against a lab or non-production tenant until you're confident in the behavior for your use case.
>
> **This server can also perform destructive actions against your ThreatLocker environment.** Tools can enable/disable endpoint protection, approve security requests, modify tag membership, end active maintenance windows, approve storage devices, move computers between organizations, and (as of 0.3) create, change, delete and deploy Allowlisting applications and policies. A hallucinated tool argument from your AI assistant could alter your ThreatLocker configuration in ways that affect endpoint security.
>
> **Recommended posture:**
> - Try the server against a non-production or lab tenant first.
> - Use a ThreatLocker API key scoped to the **minimum permissions** your use case requires.
> - Review every destructive tool call before allowing execution. Claude Desktop requires tool-call approval by default — keep that enabled.
> - Treat the API key with the same care as portal admin credentials, because functionally it is one.
> - The HTTP transport binds to `127.0.0.1` by default. Do not expose it to the public internet without adding authentication.

## Tools

| Area | Count | Capabilities |
|------|:-----:|--------------|
| **Computers** | 9 | Search, get/edit details, enable/disable protection, update maintenance mode, baseline rescan, move between orgs, finish active maintenance |
| **Approval Requests** | 11 | Search, get by ID, count pending, get permit details, approve, reject, ignore, take ownership, storage approval read/permit, file download details |
| **Application** | 11 | Get by ID, get matching list, list available apps for permit-into, list apps for maintenance mode, research details; **list apps** (`application_list`), **list file rules** paged with hash-only / custom filters (`application_files_list`), **create** (`application_insert`), **update** name/description and add/remove file rules (`application_update`), **bulk-add SHA256 rules** (`application_add_sha256_bulk`), **delete** (`application_delete`) |
| **Action Log** | 5 | Search by parameters, get by ID, file history, file download details; **`action_log_search`** with explicit paging, `fields` projection and `aggregate_by` counts (server-side `groupBys` or client-side folder roll-up) |
| **Maintenance Mode** | 4 | Get schedule by computer, insert, end by ID, reschedule end time |
| **Tag** | 3 | Get by ID, dropdown options by org, update |
| **System Audit** | 2 | Search by parameters, health center |
| **Computer Groups** | 2 | Get groups with computers, dropdown by org |
| **Policy** | 7 | Get by ID; **list/filter** by applies-to, application, name, inactive (`policy_list`), **create** (`policy_insert`), **update** name/description/enabled/applies-to/applications/action (`policy_update`), **set order** (`policy_set_order`), **delete** (`policy_delete`), **Deploy Policies** (`policies_deploy`) |
| **Online Devices** | 1 | Get by parameters |
| **Reports** | 1 | Get by organization |
| **Organization** | 1 | `list_organizations` — discover org GUIDs this API key can target |

All request bodies are typed Pydantic models (63 generated from the spec), so the AI assistant receives full schema validation and autocomplete. The wire format preserves the original camelCase field names expected by the API.

The application / policy management tools wrap endpoints that ThreatLocker documents in its [PortalAPI knowledge-base articles](https://threatlocker.kb.help/portalapiapplication/) rather than in the public Swagger document (`Application/ApplicationInsert`, `ApplicationFile/*`, `Policy/PolicyInsert`, `Policy/PolicyUpdateById`, `Policy/PolicyGetByParameters`, `DeployPolicyQueue/DeployPolicies`, ...). Field names are taken from those articles verbatim.

### Write safety (application / policy tools)

Every tool that changes applications or policies follows the same rules:

| Rule | Behaviour |
|------|-----------|
| **`dry_run` defaults to `true`** | The tool returns the exact request(s) it would send (method, path, body) plus the target org, and sends nothing. Pass `dry_run=false` to execute. |
| **Explicit org for anything but the default** | Writes go to `THREATLOCKER_ORG_ID` unless `organization_id` is given. Write tools do not accept `override_organization_id`; there is no silent fallback to another org. |
| **`confirm=true` for destructive calls** | `policies_deploy`, `policy_delete`, `application_delete`, and any `application_update` that removes rules refuse to run with `dry_run=false` unless `confirm=true` is also passed. |
| **Read-modify-write** | `policy_update` / `policy_set_order` read the policy first and resend every existing setting (the API resets omitted fields); `application_update` reads the app so an omitted description is preserved. The dry run shows exactly what was carried over. |
| **Local audit log** | Each executed write appends a JSON line (timestamp, tool, org, target id, method, path, outcome) to `THREATLOCKER_AUDIT_LOG` (default `~/.threatlocker-mcp/audit.jsonl`). API keys, headers and request bodies are never written. |

A rule for `application_insert` / `application_update` is a list of conditions, mirroring the portal: `full_path`, `process_path`, `created_by` and `cert` can be combined; `hash` (ThreatLocker hash) and `sha256` are standalone. Exercise new write tools against a throwaway application in a non-production org first.

## Quick Start

### Install

#### Using uv (recommended)

```bash
uv tool install threatlocker-mcp
```

#### Using pip

```bash
pip install threatlocker-mcp
```

### Configure

Set the required environment variables (or place them in a `.env` file in the directory where you launch the server):

```bash
export THREATLOCKER_API_KEY="your-api-key"
export THREATLOCKER_ORG_ID="your-default-org-guid"
export THREATLOCKER_BASE_URL="https://portalapi.h.threatlocker.com"
```

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `THREATLOCKER_API_KEY` | ✅ | — | API key from **ThreatLocker Portal → Modules → API** |
| `THREATLOCKER_ORG_ID` | ✅ | — | Default organization GUID. Find it in the portal URL after switching into the target org. |
| `THREATLOCKER_BASE_URL` | ✅ | — | Portal API base URL. Use the same subdomain letter shown in your portal (`.h.`, `.g.`, `.e.`, etc.) — e.g. `https://portalapi.h.threatlocker.com` |
| `THREATLOCKER_TIMEOUT` | — | `30` | Per-request timeout in seconds |
| `THREATLOCKER_AUDIT_LOG` | — | `~/.threatlocker-mcp/audit.jsonl` | JSON-lines audit file for every executed application / policy write |
| `LOG_LEVEL` | — | `INFO` | Logging verbosity: `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `MCP_HTTP_HOST` | — | `127.0.0.1` | Bind host for the HTTP transport |
| `MCP_HTTP_PORT` | — | `8765` | Bind port for the HTTP transport |

### Run

```bash
threatlocker-mcp
```

By default the server runs in **stdio** mode (the transport MCP clients like Claude Desktop expect). For HTTP transport:

```bash
threatlocker-mcp --transport http --port 8765
```

## Editor Integration

### Claude Desktop with `uvx` (recommended)

Add the following block to your Claude Desktop configuration file:

- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "threatlocker": {
      "command": "uvx",
      "args": [
        "threatlocker-mcp"
      ],
      "env": {
        "THREATLOCKER_API_KEY": "your-api-key",
        "THREATLOCKER_ORG_ID": "your-default-org-guid",
        "THREATLOCKER_BASE_URL": "https://portalapi.h.threatlocker.com"
      }
    }
  }
}
```

Fully quit Claude Desktop (tray icon → **Quit** on Windows; **⌘Q** on macOS), then reopen it. `uvx` resolves and caches the package on first launch; subsequent launches are nearly instant.

#### Pinning to a specific version

```json
"args": ["threatlocker-mcp@0.2.1"]
```

#### Forcing a refresh

```json
"args": ["--refresh", "threatlocker-mcp"]
```

## Multi-Organization Usage

Every tool accepts two optional parameters for targeting specific organizations in a parent/child tenant hierarchy:

- **`organization_id`** — overrides the `ManagedOrganizationId` request header. When omitted, `THREATLOCKER_ORG_ID` is used.
- **`override_organization_id`** — sets the `OverrideManagedOrganizationId` header for scenarios that require both headers simultaneously.

> **Finding child org GUIDs:** Call `list_organizations` first — optionally with `search_text` to filter by display name — to enumerate every org this API key can target. Org GUIDs can also be read from the portal URL while switched into each child org.

## Example Prompts

**Investigate denied activity:**
> "Search the action log for any denied executions on hostname SRV-DB-01 in the last 24 hours."

→ Calls `action_log_get_by_parameters_v2` with an `ActionLogParamsDto`.

**Review pending approvals:**
> "Show me all pending approval requests for the Cloud Services org."

→ Calls `approval_request_get_by_parameters` with `organization_id=<cloud-svc-guid>`.

**Approve a request:**
> "Approve request abc-123 at computer scope with the note 'verified vendor'."

→ Calls `approval_request_permit_application` with a `PermitApplicationDto`.

**Schedule maintenance:**
> "Put workstation WS-FINANCE-04 into maintenance mode for the next two hours."

→ Calls `maintenance_mode_insert` with a `MaintenanceModeInsertDto`.

**Manage tags:**
> "Add `corporate-vpn.example.com` to the existing 'Corporate VPN' network tag."

→ Calls `tag_get_dropdown_options_by_organization_id` and `tag_update`.

**Add launcher hashes to an application:**
> "Add these 940 SHA256s to the 'Launcher' app in our lab org — show me the plan first."

→ Calls `application_list` to find the app, then `application_add_sha256_bulk` (dry run), then again with `dry_run=false`.

**Create and order a policy:**
> "Create a disabled permit policy for app X on the Workstations group, put it above the default deny, then deploy."

→ Calls `policy_insert`, `policy_set_order`, and `policies_deploy` (each dry-run first; deploy needs `confirm=true`).

**Summarise a week of denies without a 1 MB dump:**
> "Which policies produced the most denies last week, and which folders?"

→ Calls `action_log_search` with `aggregate_by=["policyName"]` and `aggregate_by=["fullPathFolder"]`.

## License

MIT — see [LICENSE](LICENSE).
