# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2026-11-05

0.2.2 went out on PyPI by mistake before testing and was yanked; 0.2.3 is the first stable release of these changes.

### Changed
- Moved to **fastmcp 4** (mcp SDK 2.3). Tool input schemas now carry `additionalProperties: false`, so calls with unexpected arguments are rejected.
- Dependency updates: cryptography 50.0.2, cyclopts 4.25.3, websockets 16.1.1 and a grouped minor/patch batch; pytest allowed up to 9.x.

### CI
- Workflows run with a read-only token by default; jobs that publish get only the grants they need.
- ruff pinned at 0.17.3 with a `ruff format --check` step; the codebase is formatted.
- The release workflow refuses to publish unless the tag matches the `pyproject.toml` version.

## [0.2.2] - 2026-06-25

### Security

- **[High] Pinned `cryptography>=48.0.1`** to address CVE-2026-34180 (out-of-bounds read). Previously resolved to 48.0.0 as a transitive dependency.
- **[Medium] Pinned `idna>=3.15`** to address CVE-2026-45409 (ReDoS). Previously resolved to 3.11 as a transitive dependency.
- Removed hardcoded test credential in `tests/test_client.py`; `api_key` now reads from the `THREATLOCKER_API_KEY` environment variable set at the top of the test module (CWE-547).
- Added path validation in `scripts/generate_from_spec.py`: CLI argument is resolved via `os.path.realpath()` and validated as an existing file before use (CWE-23).
- Added `requirements.txt` (generated via `pip-compile`) to lock transitive dependency versions for reproducible installs.

## [0.2.1] - Initial release baseline

See [GitHub releases](https://github.com/Space-C0wboy/ThreatLocker-MCP/releases) for earlier history.
