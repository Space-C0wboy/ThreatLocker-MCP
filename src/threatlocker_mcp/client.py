"""Async HTTP client for the ThreatLocker Portal API."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .config import Config, get_config

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_MAX_RETRIES = 3


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

    def __init__(self, config: Config | None = None):
        self._config = config or get_config()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> ThreatLockerClient:
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
        organization_id: str | None,
        extra_headers: dict[str, str] | None = None,
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
        organization_id: str | None = None,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        """Send a request and return parsed JSON (or raw text if not JSON).

        Retries up to _MAX_RETRIES times on transient errors (network failures
        and 5xx / 429 responses) with exponential backoff (1 s, 2 s, …).
        """
        if self._client is None:
            await self.connect()
        assert self._client is not None

        headers = self._build_headers(organization_id, extra_headers)
        logger.debug(
            "%s %s params=%s org=%s", method, path, params, headers.get("ManagedOrganizationId")
        )

        for attempt in range(_MAX_RETRIES):
            if attempt:
                backoff = 2 ** (attempt - 1)  # 1 s, 2 s
                logger.warning(
                    "Retry %d/%d for %s %s — backing off %.0fs",
                    attempt,
                    _MAX_RETRIES - 1,
                    method,
                    path,
                    backoff,
                )
                await asyncio.sleep(backoff)

            try:
                response = await self._client.request(
                    method,
                    path,
                    params=params,
                    json=json,
                    headers=headers,
                )
            except httpx.HTTPError as e:
                if attempt == _MAX_RETRIES - 1:
                    raise ThreatLockerAPIError(0, f"Network error: {e}") from e
                logger.warning("Network error on attempt %d: %s", attempt + 1, e)
                continue

            # Retry on transient server-side errors unless this is the last attempt.
            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < _MAX_RETRIES - 1:
                logger.warning(
                    "HTTP %d on attempt %d — will retry", response.status_code, attempt + 1
                )
                continue

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
                    "empty response body from %s %s (HTTP %d)",
                    method,
                    path,
                    response.status_code,
                )
                return {"_empty_response": True, "_status_code": response.status_code}

            ctype = response.headers.get("content-type", "")
            if "application/json" in ctype:
                return response.json()
            return response.text

        # Unreachable — the last iteration always raises or returns.
        raise ThreatLockerAPIError(0, "Max retries exceeded")  # pragma: no cover

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


_client: ThreatLockerClient | None = None
_client_lock = asyncio.Lock()


async def get_client() -> ThreatLockerClient:
    """Return a process-wide shared client (one connection pool)."""
    global _client
    async with _client_lock:
        if _client is None:
            _client = ThreatLockerClient()
            await _client.connect()
    return _client


async def shutdown_client() -> None:
    global _client
    async with _client_lock:
        if _client is not None:
            await _client.close()
            _client = None
