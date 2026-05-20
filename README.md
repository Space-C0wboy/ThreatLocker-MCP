# threatlocker-mcp

An [MCP](https://modelcontextprotocol.io/) server that exposes the [ThreatLocker Portal API](https://portalapi.h.threatlocker.com/swagger/index.html) as tools an AI assistant (Claude Desktop, Claude Code, custom clients) can call.

32 tools generated from the official OpenAPI 3.0 spec, with typed Pydantic request bodies, stdio + HTTP transports, and per-call organization override for parent/child tenants.

## Quick start (recommended: `uvx`)

If you don't already have `uv` installed:

**macOS / Linux:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Then add this block to your Claude Desktop config (`%APPDATA%\Claude\claude_desktop_config.json` on Windows, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "threatlocker": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/YOUR-USERNAME/threatlocker-mcp",
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

Fully quit Claude Desktop (right-click the tray icon → Quit on Windows, ⌘Q on macOS), then reopen. You'll see 32 ThreatLocker tools in the tools menu.

To pin a specific version once you tag a release, change the URL to `git+https://github.com/YOUR-USERNAME/threatlocker-mcp@v0.1.0`. To force `uvx` to re-fetch after pushing updates, add `"--refresh"` as the first item in `args`.

## Tools

| Area | Tools |
|---|---|
| **Computers** (8) | search, get/edit, enable/disable protection, maintenance mode, baseline rescan, move between orgs |
| **Approval Requests** (8) | search, get by id, count pending, permit application, reject, ignore, take ownership |
| **Action Log** (4) | search, get by id, file history, file download details |
| **System Audit** (2) | search, health center |
| **Computer Groups** (2) | get groups + computers, dropdown by org |
| **Maintenance Mode** (3) | get by computer, insert, end by id |
| **Application** (2) | get by id, get matching list |
| **Policy** (1) | get by id |
| **Online Devices** (1) | get by parameters |
| **Reports** (1) | get by organization |

All request bodies are typed Pydantic models (54 generated from the spec) so callers get autocomplete and validation; the wire format uses the original camelCase aliases.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `THREATLOCKER_API_KEY` | yes | API key from ThreatLocker Portal → Modules → API |
| `THREATLOCKER_ORG_ID` | yes | Default org GUID (parent or child). Find it in the portal URL after switching into the org you want as default. |
| `THREATLOCKER_BASE_URL` | yes | Your portal API URL (e.g. `https://portalapi.h.threatlocker.com`) |
| `THREATLOCKER_TIMEOUT` | no | Per-request timeout seconds (default 30) |
| `LOG_LEVEL` | no | DEBUG / INFO / WARNING / ERROR |
| `MCP_HTTP_HOST` | no | HTTP bind host (default 127.0.0.1) |
| `MCP_HTTP_PORT` | no | HTTP bind port (default 8765) |

The base URL is the subdomain shown in your portal — the same letter (`.h.`, `.g.`, `.e.`, etc.) the portal uses.

## Multi-organization usage

For setups with a parent org and child orgs (e.g. one child per department), every tool accepts:

- `organization_id` — optional override of the `ManagedOrganizationId` header. Without it, `THREATLOCKER_ORG_ID` from the env is used.
- `override_organization_id` — optional `OverrideManagedOrganizationId` header for scenarios that need both.

The public API has no "list organizations" endpoint, so you'll need to know your child-org GUIDs ahead of time. Find them in the portal URL while switched into each child org, or in the Organization settings page.

## Example asks

> "Search the action log for any denied executions on hostname SRV-DB-01 in the last 24 hours."

→ Claude calls `action_log_get_by_parameters_v2` with an `ActionLogParamsDto`.

> "Show me pending approval requests for the Cloud Services org."

→ Claude calls `approval_request_get_by_parameters` with `organization_id=<cloud-svc-guid>`.

> "Approve request abc-123 at computer scope with the note 'verified vendor'."

→ Claude calls `approval_request_permit_application` with a `PermitApplicationDto`.

## Local development

If you want to hack on the code instead of running it via `uvx`:

```bash
git clone https://github.com/YOUR-USERNAME/threatlocker-mcp
cd threatlocker-mcp
python -m venv .venv
. .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
cp .env.example .env          # then edit .env
pytest                        # 4 tests, all mocked
threatlocker-mcp --help
```

Run as HTTP instead of stdio:

```bash
threatlocker-mcp --transport http --port 8765
```

## Regenerating from spec

When ThreatLocker updates their API, refresh the spec and re-run codegen:

```bash
curl https://portalapi.h.threatlocker.com/swagger/public/swagger.json -o spec.json
python scripts/generate_from_spec.py spec.json
```

To add or remove tools from the curated 32, edit `CHOSEN_ENDPOINTS` at the top of `scripts/generate_from_spec.py` and regenerate.

## Project layout

```
threatlocker-mcp/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── spec.json                       # OpenAPI snapshot — input to codegen
├── scripts/
│   └── generate_from_spec.py       # Models + tools codegen
├── src/threatlocker_mcp/
│   ├── __init__.py
│   ├── config.py                   # env-var loading + validation
│   ├── client.py                   # async httpx client w/ auth + org headers
│   ├── server.py                   # FastMCP entrypoint (stdio + http)
│   ├── models.py                   # GENERATED — Pydantic models
│   └── tools/                      # GENERATED — one module per ThreatLocker tag
│       ├── __init__.py
│       ├── action_log.py
│       ├── application.py
│       ├── approval_request.py
│       ├── computer.py
│       ├── computer_group.py
│       ├── maintenance_mode.py
│       ├── online_devices.py
│       ├── policy.py
│       ├── report.py
│       └── system_audit.py
└── tests/
    └── test_client.py
```

## Security notes

- API keys are read from env vars only, never logged.
- The HTTP transport binds to `127.0.0.1` by default. **Don't** expose it to the public internet without adding authentication (FastMCP supports OAuth).
- This server can perform destructive actions (enable/disable protection, approve/deny requests, move computers between orgs). Treat the API key with the same care as portal admin credentials.
- ThreatLocker error responses are surfaced verbatim in tool outputs — handy for debugging, but your AI assistant will see them.

## Known API limitations

These are gaps in ThreatLocker's public API, not this server:

- **No "list organizations" endpoint.** Child-org GUIDs must be known out of band.
- **No isolate/release endpoints.** `computer_enable_protection`/`computer_disable_protection` control policy enforcement, not network isolation.
- **Policy support is read-only by ID.** No list, create, update, or delete via the public API.
- **No application definitions.** The `Application` endpoints are read-only metadata queries.

## License

MIT — see [LICENSE](LICENSE).
