"""Tests for the ThreatLocker HTTP client (mocked, no live API calls)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("THREATLOCKER_API_KEY", "test-key")
os.environ.setdefault("THREATLOCKER_ORG_ID", "00000000-0000-0000-0000-000000000000")
os.environ.setdefault("THREATLOCKER_BASE_URL", "https://api.example.test")

from threatlocker_mcp.client import ThreatLockerAPIError, ThreatLockerClient  # noqa: E402
from threatlocker_mcp.config import Config  # noqa: E402


@pytest.fixture
def config() -> Config:
    return Config(
        api_key="test-key",
        default_org_id="default-org",
        base_url="https://api.example.test",
        timeout=5.0,
        log_level="WARNING",
        http_host="127.0.0.1",
        http_port=8765,
    )


# ---------------------------------------------------------------------------
# Basic request behaviour
# ---------------------------------------------------------------------------


async def test_get_sends_auth_and_default_org(httpx_mock, config):
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        json=[{"id": "abc"}],
        match_headers={
            "Authorization": "test-key",
            "ManagedOrganizationId": "default-org",
        },
    )
    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == [{"id": "abc"}]


async def test_org_override(httpx_mock, config):
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        json=[],
        match_headers={"ManagedOrganizationId": "child-org-1"},
    )
    async with ThreatLockerClient(config) as c:
        await c.get("/portalApi/Computer", organization_id="child-org-1")


async def test_empty_body_returns_sentinel(httpx_mock, config):
    """200 OK with no body should surface a clear marker, not silent None.

    Some ThreatLocker endpoints (action log / approval-request searches) reply with
    HTTP 200 + empty body when there are no rows. We want callers to see *something*
    instead of MCP's bare "no output" message.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        content=b"",
        status_code=200,
    )
    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == {"_empty_response": True, "_status_code": 200}


async def test_error_is_raised(httpx_mock, config):
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        status_code=403,
        json={"message": "forbidden"},
    )
    async with ThreatLockerClient(config) as c:
        with pytest.raises(ThreatLockerAPIError) as exc_info:
            await c.get("/portalApi/Computer")
    assert exc_info.value.status_code == 403
    assert "forbidden" in str(exc_info.value)


async def test_empty_body_204_returns_sentinel(httpx_mock, config):
    """204 No Content should also surface the sentinel so MCP doesn't drop it silently."""
    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalApi/Foo",
        status_code=204,
        content=b"",
    )
    async with ThreatLockerClient(config) as c:
        result = await c.post("/portalApi/Foo")
    assert result == {"_empty_response": True, "_status_code": 204}


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


async def test_retries_on_503_then_succeeds(httpx_mock, config):
    """A 503 on the first attempt should be retried; success on second."""
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        status_code=503,
    )
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        json=[{"id": "ok"}],
    )
    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == [{"id": "ok"}]


async def test_raises_after_all_retries_exhausted(httpx_mock, config):
    """Three consecutive 503s should eventually raise ThreatLockerAPIError."""
    for _ in range(3):
        httpx_mock.add_response(
            method="GET",
            url="https://api.example.test/portalApi/Computer",
            status_code=503,
        )
    async with ThreatLockerClient(config) as c:
        with pytest.raises(ThreatLockerAPIError) as exc_info:
            await c.get("/portalApi/Computer")
    assert exc_info.value.status_code == 503


async def test_4xx_is_not_retried(httpx_mock, config):
    """A 404 should raise immediately without retrying."""
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        status_code=404,
        json={"message": "not found"},
    )
    async with ThreatLockerClient(config) as c:
        with pytest.raises(ThreatLockerAPIError) as exc_info:
            await c.get("/portalApi/Computer")
    assert exc_info.value.status_code == 404
    # Only one request should have been made
    assert len(httpx_mock.get_requests()) == 1


# ---------------------------------------------------------------------------
# Generated tool — camelCase serialisation
# ---------------------------------------------------------------------------


async def test_generated_tool_serializes_body_with_aliases(httpx_mock, monkeypatch, config):
    """End-to-end: a generated tool packs a Pydantic model into camelCase JSON."""
    from threatlocker_mcp import client as client_module
    from threatlocker_mcp import models

    # Inject our test client as the process-wide client
    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalapi/Computer/ComputerGetByAllParameters",
        json=[{"computerId": "abc"}],
    )

    from fastmcp import FastMCP

    from threatlocker_mcp.tools.computer import register

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("computer_get_by_all_parameters")
    await tool.run({"body": models.ComputerParameterDto(search_text="srv-01", page_size=50)})

    request = httpx_mock.get_request()
    import json as _json

    sent = _json.loads(request.content)
    assert sent == {"searchText": "srv-01", "pageSize": 50}
    assert request.headers["Authorization"] == "test-key"
    assert request.headers["ManagedOrganizationId"] == "default-org"

    await test_client.close()


async def test_approval_request_tool_camel_case(httpx_mock, monkeypatch, config):
    """approval_request_get_by_parameters serialises ApprovalRequestParametersDto correctly."""
    from threatlocker_mcp import client as client_module
    from threatlocker_mcp import models

    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalapi/ApprovalRequest/ApprovalRequestGetByParameters",
        json=[],
    )

    from fastmcp import FastMCP

    from threatlocker_mcp.tools.approval_request import register

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("approval_request_get_by_parameters")
    await tool.run(
        {
            "body": models.ApprovalRequestParametersDto(
                status_id=1, page_size=25, show_child_organizations=True
            )
        }
    )

    import json as _json

    sent = _json.loads(httpx_mock.get_request().content)
    assert sent == {"statusId": 1, "pageSize": 25, "showChildOrganizations": True}

    await test_client.close()


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_config_rejects_missing_api_key(monkeypatch):
    monkeypatch.delenv("THREATLOCKER_API_KEY", raising=False)
    monkeypatch.setenv("THREATLOCKER_API_KEY", "")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_API_KEY"):
        Config.from_env()


def test_config_rejects_missing_org_id(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_ORG_ID"):
        Config.from_env()


def test_config_rejects_invalid_base_url(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "ftp://bad.example.com")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_BASE_URL"):
        Config.from_env()


def test_config_rejects_non_numeric_timeout(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "https://api.example.test")
    monkeypatch.setenv("THREATLOCKER_TIMEOUT", "not-a-number")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_TIMEOUT"):
        Config.from_env()


def test_config_rejects_non_integer_port(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "https://api.example.test")
    monkeypatch.setenv("MCP_HTTP_PORT", "abc")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="MCP_HTTP_PORT"):
        Config.from_env()


def test_config_strips_trailing_slash_from_base_url(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "https://api.example.test/")
    from threatlocker_mcp.config import Config

    config = Config.from_env()
    assert not config.base_url.endswith("/")
