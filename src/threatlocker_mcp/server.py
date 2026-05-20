"""ThreatLocker MCP server — entrypoint."""
from __future__ import annotations

import argparse
import logging
import sys

from fastmcp import FastMCP

from .client import shutdown_client
from .config import ConfigError, get_config
from .tools import register_all


def build_server() -> FastMCP:
    config = get_config()  # validates env early; raises ConfigError if bad

    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,  # stdio transport uses stdout for the protocol
    )

    mcp = FastMCP(
        name="threatlocker-mcp",
        instructions=(
            "MCP server for the ThreatLocker Portal API. Use `list_organizations` "
            "first to discover org IDs, then pass `organization_id` to other tools "
            "to target a specific child org. Without `organization_id`, the server's "
            "default org is used."
        ),
    )

    register_all(mcp)
    return mcp


def main() -> int:
    parser = argparse.ArgumentParser(prog="threatlocker-mcp")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport mode (default: stdio for local Claude Desktop use).",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="HTTP bind host (overrides MCP_HTTP_HOST). Only used with --transport http.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP bind port (overrides MCP_HTTP_PORT). Only used with --transport http.",
    )
    args = parser.parse_args()

    try:
        mcp = build_server()
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2

    config = get_config()

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            host = args.host or config.http_host
            port = args.port or config.http_port
            # FastMCP's HTTP transport is "streamable-http" (modern spec).
            mcp.run(transport="http", host=host, port=port)
    finally:
        # Best-effort shutdown of the shared HTTP client.
        import asyncio

        try:
            asyncio.run(shutdown_client())
        except RuntimeError:
            # Event loop already closed by the transport runner — fine.
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
