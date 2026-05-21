"""Async HTTP client for the ThreatLocker Portal API."""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .config import Config, get_config

logger = logging.getLogger(__name__)


class ThreatLockerAPIError(RuntimeError):
    """Raised when the ThreatLocker API returns a non-2xx response."""

    def __init__(self, status_code: int, message: str, body: Any = None):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.body = body


class ThreatLockerClient:
    """Thin async wrapper around the ThreatLocker Portal API.

    Authentication: every request sends the API key in the `Authorization` header.
    Org targeting: the `ManagedOrganizationId` header selects which child/parent org
    the request applies to. A default is set from config; individual calls can
    override it.
    """

    def __init__(self, config: Optional[Config] = None):
        self._config = config or get_config()
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ThreatLockerClient":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def connect(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._config.base_url,
                timeout=self._config.timeout,
                headers={
                    "Authorization": self._config.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": "threatlocker-mcp/0.1.0",
                },
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _build_headers(
        self,
        organization_id: Optional[str],
        extra_headers: Optional[dict[str, str]] = None,
    ) -> dict[str, str]:
        org = organization_id or self._config.default_org_id
        headers = {"ManagedOrganizationId": org}
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        organization_id: Optional[str] = None,
        params: Optional[dict[str, Any]] = None,
        json: Optional[Any] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> Any:
        """Send a request and return parsed JSON (or raw text if not JSON)."""
        if self._client is None:
            await self.connect()
        assert self._client is not None

        headers = self._build_headers(organization_id, extra_headers)
        logger.debug("%s %s params=%s org=%s", method, path, params, headers.get("ManagedOrganizationId"))

        try:
            response = await self._client.request(
                method,
                path,
                params=params,
                json=json,
                headers=headers,
            )
        except httpx.HTTPError as e:
            raise ThreatLockerAPIError(0, f"Network error: {e}") from e

        if response.status_code >= 400:
            body: Any
            try:
                body = response.json()
            except ValueError:
                body = response.text
            message = (
                body.get("message") or body.get("error") or str(body)
                if isinstance(body, dict)
                else str(body)
            )
            raise ThreatLockerAPIError(response.status_code, message, body)

        if not response.content:
            # Some ThreatLocker endpoints (e.g. ActionLog/ApprovalRequest searches with no
            # matching rows) return HTTP 200 with an empty body. Surface that explicitly
            # so callers can distinguish "no results" from a missing tool response.
            logger.info(
                "empty response body from %s %s (HTTP %d)", method, path, response.status_code
            )
            return {"_empty_response": True, "_status_code": response.status_code}

        ctype = response.headers.get("content-type", "")
        if "application/json" in ctype:
            return response.json()
        return response.text

    # ------------------------------------------------------------------
    # Verb-specific shortcuts (kept for tool-module readability)
    # ------------------------------------------------------------------
    async def get(self, path: str, **kwargs) -> Any:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> Any:
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs) -> Any:
        return await self.request("PUT", path, **kwargs)

    async def patch(self, path: str, **kwargs) -> Any:
        return await self.request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs) -> Any:
        return await self.request("DELETE", path, **kwargs)


_client: Optional[ThreatLockerClient] = None


async def get_client() -> ThreatLockerClient:
    """Return a process-wide shared client (one connection pool)."""
    global _client
    if _client is None:
        _client = ThreatLockerClient()
        await _client.connect()
    return _client


async def shutdown_client() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None
