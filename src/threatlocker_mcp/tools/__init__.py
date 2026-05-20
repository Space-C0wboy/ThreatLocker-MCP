"""Generated tool registry."""
from fastmcp import FastMCP

from . import action_log
from . import application
from . import approval_request
from . import computer
from . import computer_group
from . import maintenance_mode
from . import online_devices
from . import policy
from . import report
from . import system_audit


def register_all(mcp: FastMCP) -> None:
    action_log.register(mcp)
    application.register(mcp)
    approval_request.register(mcp)
    computer.register(mcp)
    computer_group.register(mcp)
    maintenance_mode.register(mcp)
    online_devices.register(mcp)
    policy.register(mcp)
    report.register(mcp)
    system_audit.register(mcp)
