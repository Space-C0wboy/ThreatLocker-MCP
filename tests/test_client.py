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

    # Call the generated tool function directly
    from threatlocker_mcp.tools.computer import register
    from fastmcp import FastMCP

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("computer_get_by_all_parameters")
    result = await tool.run(
        {"body": models.ComputerParameterDto(search_text="srv-01", page_size=50)}
    )

    # Verify the request went out with camelCase keys
    request = httpx_mock.get_request()
    import json as _json
    sent = _json.loads(request.content)
    assert sent == {"searchText": "srv-01", "pageSize": 50}
    assert request.headers["Authorization"] == "test-key"
    assert request.headers["ManagedOrganizationId"] == "default-org"

    await test_client.close()
