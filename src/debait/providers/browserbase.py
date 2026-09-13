"""Narrow Browserbase adapter for reading and releasing allowlisted sessions."""

import asyncio
import json
import math
import re
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from debait.protection.broker import Action
from debait.providers.base import Observation, ProviderStateChanged, Receipt, RetryAfter


class BrowserbaseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    project_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    controlled_session_ids: frozenset[str] = Field(min_length=1)
    timeout_seconds: float = Field(default=5, gt=0, le=15)
    maximum_response_bytes: int = Field(default=131072, ge=4096, le=1048576)


class BrowserbaseAdapter:
    BASE_URL = "https://api.browserbase.com"
    TERMINAL = frozenset({"COMPLETED", "TIMED_OUT", "ERROR"})
    ACTIVE = frozenset({"PENDING", "RUNNING"})
    _IDENTITY = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

    def __init__(
        self,
        config: BrowserbaseConfig,
        key: SecretStr,
        *,
        transport=None,
        allow_network: bool = False,
    ):
        if not key.get_secret_value():
            raise PermissionError("Browserbase API key is required")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Browserbase network access is disabled until explicitly enabled")
        if any(not self._IDENTITY.fullmatch(item) for item in config.controlled_session_ids):
            raise PermissionError("Browserbase session allowlist contains an invalid identity")
        self.config = config
        self._key = key
        self._transport = transport

    def _session(self, session_id: str):
        if session_id not in self.config.controlled_session_ids:
            raise PermissionError("Browserbase session is outside configured scope")
        return session_id

    async def _request(self, method: str, path: str, *, body=None):
        try:
            async with (
                asyncio.timeout(self.config.timeout_seconds),
                httpx.AsyncClient(
                    base_url=self.BASE_URL,
                    transport=self._transport,
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
            ):
                async with client.stream(
                    method,
                    path,
                    json=body,
                    headers={"X-BB-API-Key": self._key.get_secret_value()},
                ) as response:
                    if response.status_code == 429:
                        try:
                            hint = float(response.headers.get("retry-after", "1"))
                        except ValueError:
                            hint = 1
                        if not math.isfinite(hint):
                            hint = 1
                        raise RetryAfter(min(max(hint, 0), 30))
                    if response.status_code in {401, 403}:
                        raise PermissionError("Browserbase denied the scoped session request")
                    if response.status_code in {400, 404, 409}:
                        raise ProviderStateChanged("Browserbase session is unavailable or changed state")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ConnectionError(f"Browserbase request failed with HTTP {response.status_code}")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Browserbase response exceeded the configured size")
                    request_id = response.headers.get("x-request-id")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            return payload, request_id
        except (RetryAfter, PermissionError, ProviderStateChanged, ConnectionError):
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            raise ConnectionError("Browserbase transport or response validation failed") from None

    def _validate(self, payload, session_id):
        if payload.get("id") != session_id:
            raise PermissionError("Browserbase session response identity mismatch")
        if payload.get("projectId") != self.config.project_id:
            raise PermissionError("Browserbase project response identity mismatch")
        status = payload.get("status")
        if status not in self.ACTIVE | self.TERMINAL:
            raise ConnectionError("Browserbase session status is unavailable")
        return payload

    async def _retrieve(self, session_id):
        session_id = self._session(session_id)
        payload, _ = await self._request("GET", f"/v1/sessions/{session_id}")
        return self._validate(payload, session_id)

    async def read(self, resource_id: str) -> Observation:
        session = await self._retrieve(resource_id)
        return Observation(
            provider="browserbase",
            resource_id=session["id"],
            account_id=self.config.project_id,
            state="terminated" if session["status"] in self.TERMINAL else "active",
            level="read_back",
            observed_at=datetime.now(timezone.utc),
            source="browserbase.get_session",
            details={
                "provider_status": session["status"],
                "keep_alive": session.get("keepAlive"),
                "ended_at": session.get("endedAt"),
            },
        )

    async def act(self, action: Action) -> Receipt:
        if action.target.provider != "browserbase" or action.target.operation != "release":
            raise PermissionError("Browserbase adapter only permits session release")
        session_id = self._session(action.target.resource_id)
        before = await self._retrieve(session_id)
        if before["status"] in self.TERMINAL:
            raise ProviderStateChanged("Browserbase session already reached a terminal state")
        released, request_id = await self._request(
            "POST",
            f"/v1/sessions/{session_id}",
            body={"status": "REQUEST_RELEASE", "projectId": self.config.project_id},
        )
        self._validate(released, session_id)
        return Receipt(
            request_id=request_id or f"browserbase:{action.action_id}",
            acknowledged=True,
        )
