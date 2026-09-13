"""Narrow Twilio adapter for reading and ending an allowlisted controlled call."""

import asyncio
import json
import math
import re
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from debait.protection.broker import Action
from debait.providers.base import Observation, ProviderStateChanged, Receipt, RetryAfter


class TwilioConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    account_sid: str = Field(pattern=r"^AC[0-9a-fA-F]{32}$")
    controlled_call_sids: frozenset[str] = Field(min_length=1)
    allowed_callers: frozenset[str] = Field(min_length=1)
    allowed_recipients: frozenset[str] = Field(min_length=1)
    timeout_seconds: float = Field(default=5, gt=0, le=15)
    maximum_response_bytes: int = Field(default=131072, ge=4096, le=1048576)


class TwilioAdapter:
    BASE_URL = "https://api.twilio.com"
    ACTIVE = frozenset({"queued", "ringing", "in-progress"})
    TERMINAL = frozenset({"completed", "busy", "failed", "no-answer", "canceled"})
    _CALL_SID = re.compile(r"^CA[0-9a-fA-F]{32}$")
    _PHONE = re.compile(r"^\+[1-9]\d{7,14}$")

    def __init__(
        self,
        config: TwilioConfig,
        auth_token: SecretStr,
        *,
        transport=None,
        allow_network: bool = False,
    ):
        if not auth_token.get_secret_value():
            raise PermissionError("Twilio auth token is required")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Twilio network access is disabled until explicitly enabled")
        if any(not self._CALL_SID.fullmatch(item) for item in config.controlled_call_sids):
            raise PermissionError("Twilio call allowlist contains an invalid SID")
        parties = config.allowed_callers | config.allowed_recipients
        if any(not self._PHONE.fullmatch(item) for item in parties):
            raise PermissionError("Twilio party allowlist contains an invalid phone number")
        self.config = config
        self._auth_token = auth_token
        self._transport = transport

    def _call_sid(self, call_sid: str):
        if call_sid not in self.config.controlled_call_sids:
            raise PermissionError("Twilio call is outside configured scope")
        return call_sid

    async def _request(self, method: str, path: str, *, data=None):
        try:
            async with (
                asyncio.timeout(self.config.timeout_seconds),
                httpx.AsyncClient(
                    base_url=self.BASE_URL,
                    transport=self._transport,
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    auth=httpx.BasicAuth(
                        self.config.account_sid,
                        self._auth_token.get_secret_value(),
                    ),
                ) as client,
            ):
                async with client.stream(method, path, data=data) as response:
                    if response.status_code == 429:
                        try:
                            hint = float(response.headers.get("retry-after", "1"))
                        except ValueError:
                            hint = 1
                        if not math.isfinite(hint):
                            hint = 1
                        raise RetryAfter(min(max(hint, 0), 30))
                    if response.status_code in {401, 403}:
                        raise PermissionError("Twilio denied the scoped call request")
                    if response.status_code in {400, 404, 409}:
                        raise ProviderStateChanged("Twilio call is unavailable or changed state")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ConnectionError(f"Twilio request failed with HTTP {response.status_code}")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Twilio response exceeded the configured size")
                    request_id = response.headers.get("twilio-request-id")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            return payload, request_id
        except (RetryAfter, PermissionError, ProviderStateChanged, ConnectionError):
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            raise ConnectionError("Twilio transport or response validation failed") from None

    def _validate(self, payload, call_sid):
        if payload.get("sid") != call_sid:
            raise PermissionError("Twilio Call response identity mismatch")
        if payload.get("account_sid") != self.config.account_sid:
            raise PermissionError("Twilio account response identity mismatch")
        if payload.get("from") not in self.config.allowed_callers:
            raise PermissionError("Twilio caller is outside configured scope")
        if payload.get("to") not in self.config.allowed_recipients:
            raise PermissionError("Twilio recipient is outside configured scope")
        status = payload.get("status")
        if status not in self.ACTIVE | self.TERMINAL:
            raise ConnectionError("Twilio call status is unavailable")
        return payload

    async def _retrieve(self, call_sid):
        call_sid = self._call_sid(call_sid)
        path = f"/2010-04-01/Accounts/{self.config.account_sid}/Calls/{call_sid}.json"
        payload, _ = await self._request("GET", path)
        return self._validate(payload, call_sid)

    async def read(self, resource_id: str) -> Observation:
        call = await self._retrieve(resource_id)
        return Observation(
            provider="twilio",
            resource_id=call["sid"],
            account_id=self.config.account_sid,
            state=call["status"],
            level="read_back",
            observed_at=datetime.now(timezone.utc),
            source="twilio.fetch_call",
            details={
                "from": call["from"],
                "to": call["to"],
                "duration": call.get("duration"),
            },
        )

    async def act(self, action: Action) -> Receipt:
        if action.target.provider != "twilio" or action.target.operation != "end":
            raise PermissionError("Twilio adapter only permits ending a call")
        call_sid = self._call_sid(action.target.resource_id)
        before = await self._retrieve(call_sid)
        if before["status"] not in self.ACTIVE:
            raise ProviderStateChanged(f"Twilio call state {before['status']} is not active")
        path = f"/2010-04-01/Accounts/{self.config.account_sid}/Calls/{call_sid}.json"
        ended, request_id = await self._request("POST", path, data={"Status": "completed"})
        ended = self._validate(ended, call_sid)
        if ended["status"] not in self.TERMINAL:
            raise ProviderStateChanged("Twilio did not return a terminal call state")
        return Receipt(
            request_id=request_id or f"twilio:{action.action_id}",
            acknowledged=True,
        )
