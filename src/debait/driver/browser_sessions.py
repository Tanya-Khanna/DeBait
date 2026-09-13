"""Create and prove one bounded Browserbase session for the controlled demo."""

import asyncio
import json
import re
import time

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.browserbase import BrowserbaseAdapter, BrowserbaseConfig


class BrowserbaseDriverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    session_timeout_seconds: int = Field(default=60, ge=60, le=300)
    request_timeout_seconds: float = Field(default=8, gt=0, le=15)
    maximum_response_bytes: int = Field(default=131072, ge=4096, le=1048576)


class BrowserbaseSessionDriver:
    BASE_URL = "https://api.browserbase.com"
    _IDENTITY = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

    def __init__(
        self,
        config: BrowserbaseDriverConfig,
        key: SecretStr,
        *,
        transport=None,
        allow_network: bool = False,
    ):
        if not key.get_secret_value():
            raise PermissionError("Browserbase API key is required")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Browserbase session creation is disabled until explicitly enabled")
        self.config = config
        self._key = key
        self._transport = transport

    async def create(self, run_id: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
            raise ValueError("Bound Browserbase run identity is required")
        body = {
            "timeout": self.config.session_timeout_seconds,
            "keepAlive": False,
            "userMetadata": {"debait_run": run_id},
        }
        try:
            async with (
                asyncio.timeout(self.config.request_timeout_seconds),
                httpx.AsyncClient(
                    base_url=self.BASE_URL,
                    transport=self._transport,
                    timeout=self.config.request_timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
            ):
                async with client.stream(
                    "POST",
                    "/v1/sessions",
                    json=body,
                    headers={"X-BB-API-Key": self._key.get_secret_value()},
                ) as response:
                    if response.status_code in {401, 403}:
                        raise PermissionError("Browserbase denied session creation")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ConnectionError(
                            f"Browserbase session creation failed with HTTP {response.status_code}"
                        )
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Browserbase create response exceeded the configured size")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            session_id = payload.get("id")
            project_id = payload.get("projectId")
            if (
                not isinstance(session_id, str)
                or not self._IDENTITY.fullmatch(session_id)
                or not isinstance(project_id, str)
                or not self._IDENTITY.fullmatch(project_id)
                or payload.get("status") not in BrowserbaseAdapter.ACTIVE
                or payload.get("userMetadata") != body["userMetadata"]
            ):
                raise PermissionError("Browserbase returned an unbound or nonactive session")
            return payload
        except (PermissionError, ConnectionError):
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            raise ConnectionError("Browserbase create transport or response validation failed") from None


async def run_browserbase_smoke(
    key: SecretStr,
    *,
    run_id: str,
    transport=None,
    allow_network: bool = False,
    poll_interval_seconds: float = 0.5,
    maximum_poll_seconds: float = 20,
) -> dict:
    if not 0 <= poll_interval_seconds <= 2 or not 1 <= maximum_poll_seconds <= 30:
        raise ValueError("Browserbase smoke polling bounds are invalid")
    driver = BrowserbaseSessionDriver(
        BrowserbaseDriverConfig(), key, transport=transport, allow_network=allow_network
    )
    created = await driver.create(run_id)
    session_id = created["id"]
    project_id = created["projectId"]
    adapter = BrowserbaseAdapter(
        BrowserbaseConfig(
            project_id=project_id,
            controlled_session_ids=frozenset({session_id}),
        ),
        key,
        transport=transport,
        allow_network=allow_network,
    )
    before = await adapter.read(session_id)
    action = Action(
        action_id=f"browserbase-smoke-{run_id}",
        episode_id=run_id,
        target=Target(provider="browserbase", resource_id=session_id, operation="release"),
        policy_version="browserbase_live_smoke_v1",
    )
    receipt = await adapter.act(action)
    deadline = time.monotonic() + maximum_poll_seconds
    after = await adapter.read(session_id)
    while after.state != "terminated" and time.monotonic() < deadline:
        await asyncio.sleep(poll_interval_seconds)
        after = await adapter.read(session_id)
    if after.state != "terminated":
        raise ConnectionError("Browserbase session release was not verified before the poll deadline")
    return {
        "run_id": run_id,
        "project_id": project_id,
        "session_id": session_id,
        "before_state": before.state,
        "release_acknowledged": receipt.acknowledged,
        "after_state": after.state,
        "provider_status": after.details["provider_status"],
        "session_url": f"https://www.browserbase.com/sessions/{session_id}",
    }
