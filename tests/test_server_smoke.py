"""Proves the server still builds and registers its tools after a dependency bump (no network calls)."""

import pytest

from threatlocker_mcp import config as config_module
from threatlocker_mcp.config import ConfigError
from threatlocker_mcp.server import build_server


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "test-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setattr(config_module, "_config", None)
    yield
    config_module._config = None


async def test_build_server_registers_tools(env):
    mcp = build_server()
    tools = await mcp.get_tools()
    assert "list_organizations" in tools
    assert len(tools) >= 13  # one module per area under tools/; each adds at least one


def test_missing_api_key_fails_early(monkeypatch):
    monkeypatch.delenv("THREATLOCKER_API_KEY", raising=False)
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setattr(config_module, "_config", None)
    with pytest.raises(ConfigError):
        build_server()
    config_module._config = None
