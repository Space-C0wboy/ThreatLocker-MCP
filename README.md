# ThreatLocker MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![CI](https://github.com/Space-C0wboy/ThreatLocker-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/Space-C0wboy/ThreatLocker-MCP/actions/workflows/ci.yml)

An [MCP](https://modelcontextprotocol.io/) server that exposes the [ThreatLocker Portal API](https://portalapi.h.threatlocker.com/swagger/index.html) as callable tools for AI assistants such as Claude Desktop and Claude Code.

44 tools are generated directly from the official OpenAPI 3.0 spec, with fully-typed Pydantic request bodies, stdio and HTTP transports, and per-call organization override for parent/child tenant setups.

---

> [!WARNING]
> **This project is in early development and is not production-ready.**
>
> - Endpoint mappings come from the published OpenAPI spec but have **not been exhaustively tested** against a live tenant.
> - The server can perform **destructive actions**: enabling/disabling protection on endpoints, approving or denying security requests, and moving computers between organizations. A hallucinated tool argument from your AI assistant could alter your ThreatLocker configuration in ways that affect endpoint security.
> - There are **no built-in rate-limit protections or confirmation prompts** beyond what ThreatLocker itself records.
>
> **Recommended posture:**
> - Test against a non-production or lab tenant before deploying to a live environment.
> - Use a ThreatLocker API key scoped to the **minimum permissions** your use case requires.
> - Review every destructive tool call before allowing execution. Claude Desktop requires tool-call approval by default — keep that enabled.
> - Treat the API key with the same care as portal admin credentials, because functionally it is one.
>
> Found a bug? [Open an issue](https://github.com/Space-C0wboy/ThreatLocker-MCP/issues). Found a security bug? Contact the maintainer directly rather than filing a public issue.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Tools](#tools)
- [Configuration](#configuration)
- [Multi-Organization Usage](#multi-organization-usage)
- [Example Prompts](#example-prompts)
- [Security Notes](#security-notes)
- [Known API Limitations](#known-api-limitations)
- [Known API Quirks](#known-api-quirks)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Quick Start

The recommended installation method uses [`uvx`](https://docs.astral.sh/uv/), which handles dependency isolation automatically with no manual virtual environment setup.

### Prerequisites

**Git** — required by `uvx` to clone the repository.

| Platform | Install command |
|----------|----------------|
| Windows | `winget install --id Git.Git -e --source winget` |
| macOS | `brew install git` (or Xcode Command Line Tools) |
| Linux | `apt install git` / `dnf install git` |

Verify with `git --version` in a fresh terminal after installation.

**uv** — provides the `uvx` runner.

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Reopen your terminal after installing so `PATH` is refreshed.

### Configure Claude Desktop

Add the following block to your Claude Desktop configuration file:

- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "threatlocker": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/Space-C0wboy/ThreatLocker-MCP",
        "threatlocker-mcp"
      ],
      "env": {
        "THREATLOCKER_API_KEY": "your-api-key",
        "THREATLOCKER_ORG_ID": "your-default-org-guid",
        "THREATLOCKER_BASE_URL": "https://portalapi.h.threatlocker.com",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.PY;.PYW"
      }
    }
  }
}
```

> **Windows note:** The `PATHEXT` entry is required. Claude Desktop does not pass `PATHEXT` to child processes, which prevents `uv` from locating `git.exe` even when Git is installed. The symptom is a `Git executable not found` error in the log. Non-Windows users can omit that line.

Fully quit Claude Desktop (tray icon → **Quit** on Windows; **⌘Q** on macOS), then reopen it. The first launch takes 30–60 seconds while `uvx` clones the repository and installs dependencies. Subsequent launches are nearly instant due to caching. You should see 44 ThreatLocker tools listed in the tools menu.

**Pinning a version:** Once a release is tagged, replace the URL with `git+https://github.com/Space-C0wboy/ThreatLocker-MCP@v0.1.0` to lock to a specific version.

**Forcing a refresh:** Add `"--refresh"` as the first item in `args` to force `uvx` to re-fetch after an update has been pushed.

---

## Tools

| Area | Count | Capabilities |
|------|:-----:|--------------|
| **Computers** | 9 | Search, get/edit details, enable/disable protection, update maintenance mode, baseline rescan, move between orgs, finish active maintenance |
| **Approval Requests** | 11 | Search, get by ID, count pending, get permit details, approve, reject, ignore, take ownership, storage approval read/permit, file download details |
| **Application** | 5 | Get by ID, get matching list, list available apps for permit-into, list apps for maintenance mode, research details |
| **Action Log** | 4 | Search by parameters, get by ID, file history, file download details |
| **Maintenance Mode** | 4 | Get schedule by computer, insert, end by ID, reschedule end time |
| **Tag** | 3 | Get by ID, dropdown options by org, update |
| **System Audit** | 2 | Search by parameters, health center |
| **Computer Groups** | 2 | Get groups with computers, dropdown by org |
| **Policy** | 1 | Get by ID |
| **Online Devices** | 1 | Get by parameters |
| **Reports** | 1 | Get by organization |
| **Organization** | 1 | `list_organizations` — discover org GUIDs this API key can target |

All request bodies are typed Pydantic models (63 generated from the spec), so the AI assistant receives full schema validation and autocomplete. The wire format preserves the original camelCase field names expected by the API.

---

## Configuration

Set the following environment variables, either in your shell or in a `.env` file in the project root (see `.env.example`).

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `THREATLOCKER_API_KEY` | ✅ | — | API key from **ThreatLocker Portal → Modules → API** |
| `THREATLOCKER_ORG_ID` | ✅ | — | Default organization GUID. Find it in the portal URL after switching into the target org. |
| `THREATLOCKER_BASE_URL` | ✅ | — | Portal API base URL. Use the same subdomain letter shown in your portal (`.h.`, `.g.`, `.e.`, etc.) — e.g. `https://portalapi.h.threatlocker.com` |
| `THREATLOCKER_TIMEOUT` | — | `30` | Per-request timeout in seconds |
| `LOG_LEVEL` | — | `INFO` | Logging verbosity: `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `MCP_HTTP_HOST` | — | `127.0.0.1` | Bind host for the HTTP transport |
| `MCP_HTTP_PORT` | — | `8765` | Bind port for the HTTP transport |

---

## Multi-Organization Usage

Every tool accepts two optional parameters for targeting specific organizations in a parent/child tenant hierarchy:

- **`organization_id`** — overrides the `ManagedOrganizationId` request header. When omitted, `THREATLOCKER_ORG_ID` is used.
- **`override_organization_id`** — sets the `OverrideManagedOrganizationId` header for scenarios that require both headers simultaneously.

> **Finding child org GUIDs:** Call `list_organizations` first — optionally with `search_text` to filter by display name — to enumerate every org this API key can target. (Under the hood this hits `/portalapi/Organization/OrganizationGetForMoveComputers`, the same endpoint the portal uses to populate its move-computer org picker.) Org GUIDs can also be read from the portal URL while switched into each child org.

---

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

---

## Security Notes

- **API key handling:** Keys are read from environment variables only and are never written to logs.
- **HTTP transport:** Binds to `127.0.0.1` by default. Do not expose it to the public internet without adding authentication — FastMCP supports OAuth for this purpose.
- **Destructive operations:** This server can enable or disable endpoint protection, approve or deny security requests, and move computers between organizations. The API key should be treated with the same care as portal admin credentials.
- **Error message exposure:** ThreatLocker API error responses are surfaced verbatim in tool outputs. This aids debugging but means your AI assistant will see raw API response bodies.

---

## Known API Limitations

The following are gaps in ThreatLocker's public API, not limitations of this server:

| Limitation | Detail |
|-----------|--------|
| No network isolation | `computer_enable_protection` / `computer_disable_protection` toggle policy enforcement, not network isolation |
| Policy management is read-only | Policies can be retrieved by ID only; create, update, and delete are not available via the public API |
| Application data is read-only | The `Application` endpoints return metadata only |

---

## Known API Quirks

A few server-side behaviors worth knowing about. Detailed body-shape guidance lives inside each tool's description and is delivered to the AI assistant automatically — the items below are the ones you might notice from the outside.

- **Empty responses surface as `{"_empty_response": true, "_status_code": 200}`.** Several ThreatLocker endpoints reply with HTTP 200 + an empty body (or the JSON literal `null`) when there are no matching rows. The client converts both to this sentinel so the response isn't silently dropped.
- **HTTP 401 `"Missing the '' permission"` (empty interpolation) usually means a request-body shape problem, not a permissions problem.** ThreatLocker reuses one error template across several permission-lookup paths; when the server can't resolve which permission was needed, the placeholder ends up empty. Check the request body before re-granting roles.
- **Transient errors are retried up to 3 times.** The client retries HTTP `429`, `500`, `502`, `503`, `504`, and network errors. When the server sends a `Retry-After` header (delta-seconds or HTTP-date) the client honors it (capped at 60s); otherwise it backs off exponentially with full jitter. `4xx` responses other than `429` are surfaced immediately without retry.

## Troubleshooting

**Where are the logs?**

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\Claude\logs\mcp-server-threatlocker.log` |
| macOS | `~/Library/Logs/Claude/mcp-server-threatlocker.log` |

Most startup and connection issues are visible in plain text in these files.

---

**`Git executable not found` (Windows)**

Claude Desktop does not pass `PATHEXT` to child processes, so `uv` cannot recognize `git.exe` as an executable even when Git is on `PATH`. Add the `PATHEXT` entry shown in the [Configure Claude Desktop](#configure-claude-desktop) example to your `env` block.

---

**`Could not load app settings ... Expected ',' or '}'`**

JSON syntax error in `claude_desktop_config.json`. Every key-value pair except the last one in an object requires a trailing comma. Paste the file contents into [jsonlint.com](https://jsonlint.com/) to identify the exact location.

---

**`Configuration error: THREATLOCKER_API_KEY is required`**

The `env` block in your config is missing or contains a typo. All values must be JSON strings (quoted). Confirm each variable name matches exactly.

---

**Tools menu is empty after restart**

Confirm Claude Desktop was fully quit — on Windows the window close button is not sufficient; right-click the tray icon and choose **Quit**. Then check the log file for the underlying error.

---

**First launch hangs for 60+ seconds**

Expected behaviour. `uvx` is cloning the repository and building the dependency environment on first use. Subsequent launches are nearly instant due to the local cache.

---

**Claude still runs the old version after an update**

`uvx` caches by commit hash. Add `"--refresh"` as the first item in `args` to force a re-fetch, or pin an explicit version tag (e.g. `@v0.2.0`) so updates require a deliberate change.

---

## Contributing

The tool wrappers and Pydantic models under `src/threatlocker_mcp/tools/` and `src/threatlocker_mcp/models.py` are generated from `spec.json` by `scripts/generate_from_spec.py`. To make changes:

```bash
git clone https://github.com/Space-C0wboy/ThreatLocker-MCP
cd ThreatLocker-MCP
uv sync --extra dev          # or: pip install -e ".[dev]"
cp .env.example .env         # then fill in your credentials

# Update the spec snapshot if needed, then regenerate
curl https://portalapi.h.threatlocker.com/swagger/public/swagger.json -o spec.json
python scripts/generate_from_spec.py spec.json
ruff format .

# Verify
ruff check .
pytest                       # 24 mocked tests, no live API calls
```

The curated tool surface and per-endpoint overrides (description text, required-param promotions, name overrides) all live near the top of `scripts/generate_from_spec.py`.

Bug reports and pull requests are welcome via the [issue tracker](https://github.com/Space-C0wboy/ThreatLocker-MCP/issues). For security issues, please contact the maintainer directly rather than filing a public issue.

---

## License

[MIT](LICENSE)
