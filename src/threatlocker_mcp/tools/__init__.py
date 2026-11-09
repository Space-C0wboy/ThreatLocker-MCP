"""Tool registry (generated modules plus the hand-written management modules)."""

from fastmcp import FastMCP

from . import (
    action_log,
    action_log_analytics,
    application,
    application_management,
    approval_request,
    computer,
    computer_group,
    maintenance_mode,
    online_devices,
    organization,
    policy,
    policy_management,
    report,
    system_audit,
    tag,
)


def register_all(mcp: FastMCP) -> None:
    action_log.register(mcp)
    action_log_analytics.register(mcp)
    application.register(mcp)
    application_management.register(mcp)
    approval_request.register(mcp)
    computer.register(mcp)
    computer_group.register(mcp)
    maintenance_mode.register(mcp)
    online_devices.register(mcp)
    organization.register(mcp)
    policy.register(mcp)
    policy_management.register(mcp)
    report.register(mcp)
    system_audit.register(mcp)
    tag.register(mcp)
