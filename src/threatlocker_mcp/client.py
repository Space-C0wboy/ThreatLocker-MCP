"""Async HTTP client for the ThreatLocker Portal API."""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from .config import Config, get_config

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_MAX_RETRIES = 3
# Cap any server-suggested Retry-After at this value (seconds) so a misbehaving
# upstream can't park us indefinitely.
_MAX_RETRY_AFTER_SECONDS = 60.0


def _parse_retry_after(header_value: str | None) -> float | None:
    """Parse a Retry-After header (RFC 7231 §7.1.3).

    Accepts either an integer/float seconds value or an HTTP-date. Returns None
    if the header is absent or unparseable.
    """
    if not header_value:
        return None
    value = header_value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = (when - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, delta)


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
        # Guards lazy connect inside request() against concurrent first-callers.
        self._connect_lock = asyncio.Lock()

    async def __aenter__(self) -> ThreatLockerClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def connect(self) -> None:
        async with self._connect_lock:
            if self._client is None:
                # ThreatLocker uses a bare API key as the Authorization value
                # (no "Bearer " scheme prefix) -- intentional, do not change.
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

        # Next sleep duration is set by the previous iteration when it decides to
        # retry — driven by Retry-After if present, else exponential backoff + jitter.
        next_backoff: float | None = None
        for attempt in range(_MAX_RETRIES):
            if next_backoff is not None:
                logger.warning(
                    "Retry %d/%d for %s %s — backing off %.2fs",
                    attempt,
                    _MAX_RETRIES - 1,
                    method,
                    path,
                    next_backoff,
                )
                await asyncio.sleep(next_backoff)
                next_backoff = None

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
                # Exponential backoff with full jitter (AWS-style): pick uniformly
                # from [0, base * 2^attempt] to spread out concurrent retriers.
                next_backoff = random.uniform(0, 2**attempt)
                continue

            # Retry on transient server-side errors unless this is the last attempt.
            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < _MAX_RETRIES - 1:
                logger.warning(
                    "HTTP %d on attempt %d — will retry", response.status_code, attempt + 1
                )
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                if retry_after is not None:
                    next_backoff = min(retry_after, _MAX_RETRY_AFTER_SECONDS)
                else:
                    next_backoff = random.uniform(0, 2**attempt)
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
                parsed = response.json()
                # Some endpoints (OnlineDevicesGetByParameters,
                # ApprovalRequestGetByParameters) return the JSON literal `null` instead of
                # an empty body when there are no rows. Treat that the same as an empty body
                # so callers don't see a silent None in MCP.
                if parsed is None:
                    logger.info(
                        "json-null response body from %s %s (HTTP %d)",
                        method,
                        path,
                        response.status_code,
                    )
                    return {"_empty_response": True, "_status_code": response.status_code}
                return parsed
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
