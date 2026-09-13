"""Scoped Telegram Bot API adapter with explicit acknowledgment/read-back levels."""

import asyncio
import json
import math
import re
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from debait.protection.broker import Action
from debait.providers.base import Observation, ProviderStateChanged, Receipt, RetryAfter


def message_resource(chat_id: int, message_id: int) -> str:
    if message_id <= 0:
        raise ValueError("Telegram message ID must be positive")
    return f"message:{chat_id}:{message_id}"


def member_resource(chat_id: int, user_id: int) -> str:
    if user_id <= 0:
        raise ValueError("Telegram user ID must be positive")
    return f"member:{chat_id}:{user_id}"


class TelegramConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    bot_id: int = Field(gt=0)
    controlled_chat_ids: frozenset[int] = Field(min_length=1)
    controlled_attacker_ids: frozenset[int] = Field(min_length=1)
    protected_user_ids: frozenset[int] = Field(min_length=1)
    timeout_seconds: float = Field(default=5, gt=0, le=15)
    maximum_response_bytes: int = Field(default=131072, ge=4096, le=1048576)

    @model_validator(mode="after")
    def disjoint_actors(self):
        protected = self.protected_user_ids | {self.bot_id}
        if self.controlled_attacker_ids & protected:
            raise ValueError("Controlled attacker and protected user IDs overlap")
        return self


class TelegramAdapter:
    _TOKEN = re.compile(r"^(?P<bot_id>[1-9]\d*):[A-Za-z0-9_-]{5,}$")
    _RESOURCE = re.compile(r"^(message|member):(-?\d+):([1-9]\d*)$")

    def __init__(
        self,
        config: TelegramConfig,
        token: SecretStr,
        *,
        transport=None,
        allow_network: bool = False,
    ):
        secret = token.get_secret_value()
        match = self._TOKEN.fullmatch(secret)
        if not match or int(match.group("bot_id")) != config.bot_id:
            raise PermissionError("Telegram token identity does not match the configured bot")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Telegram network access is disabled until explicitly enabled")
        self.config = config
        self._token = token
        self._transport = transport
        self._message_observations: dict[str, Observation] = {}

    def _parse_resource(self, resource_id: str):
        match = self._RESOURCE.fullmatch(resource_id)
        if not match:
            raise PermissionError("Invalid Telegram resource identity")
        kind, chat_id, subject_id = match.groups()
        chat_id, subject_id = int(chat_id), int(subject_id)
        if chat_id not in self.config.controlled_chat_ids:
            raise PermissionError("Telegram chat is outside configured scope")
        return kind, chat_id, subject_id

    async def _request(self, method: str, data=None):
        try:
            async with (
                asyncio.timeout(self.config.timeout_seconds),
                httpx.AsyncClient(
                    base_url=f"https://api.telegram.org/bot{self._token.get_secret_value()}",
                    transport=self._transport,
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
            ):
                async with client.stream("POST", f"/{method}", data=data) as response:
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Telegram response exceeded the configured size")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            if response.status_code == 429:
                hint = payload.get("parameters", {}).get("retry_after", 1)
                if type(hint) not in {int, float} or not math.isfinite(hint):
                    hint = 1
                raise RetryAfter(min(max(float(hint), 0), 30))
            if response.status_code in {401, 403}:
                raise PermissionError("Telegram denied the scoped bot request")
            if response.status_code in {400, 404, 409}:
                raise ProviderStateChanged("Telegram resource is unavailable or changed state")
            if response.status_code < 200 or response.status_code >= 300 or payload.get("ok") is not True:
                raise ConnectionError(f"Telegram request failed with HTTP {response.status_code}")
            return payload.get("result")
        except (RetryAfter, PermissionError, ProviderStateChanged, ConnectionError):
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError, AttributeError):
            raise ConnectionError("Telegram transport or response validation failed") from None

    async def _verify_bot(self):
        bot = await self._request("getMe")
        if not isinstance(bot, dict) or bot.get("id") != self.config.bot_id or bot.get("is_bot") is not True:
            raise PermissionError("Telegram bot response identity mismatch")

    def record_message_update(self, resource_id: str, evidence_path: str, observed_at: datetime):
        kind, _, _ = self._parse_resource(resource_id)
        if kind != "message" or observed_at.tzinfo is None or not evidence_path:
            raise ValueError("A dated message update and evidence path are required")
        observation = Observation(
            provider="telegram",
            resource_id=resource_id,
            account_id=f"bot:{self.config.bot_id}",
            state="present",
            level="provider_event",
            observed_at=observed_at,
            source=evidence_path,
        )
        self._message_observations[resource_id] = observation
        return observation

    def record_client_observation(self, resource_id: str, observed_state: str, evidence_path: str):
        kind, _, _ = self._parse_resource(resource_id)
        if kind != "message" or observed_state not in {"present", "removed"} or not evidence_path:
            raise ValueError("A scoped client observation and evidence path are required")
        observation = Observation(
            provider="telegram",
            resource_id=resource_id,
            account_id=f"bot:{self.config.bot_id}",
            state=observed_state,
            level="client_observed",
            observed_at=datetime.now(timezone.utc),
            source=evidence_path,
        )
        self._message_observations[resource_id] = observation
        return observation

    async def read(self, resource_id: str) -> Observation:
        kind, chat_id, subject_id = self._parse_resource(resource_id)
        if kind == "message":
            return self._message_observations.get(
                resource_id,
                Observation(
                    provider="telegram",
                    resource_id=resource_id,
                    account_id=f"bot:{self.config.bot_id}",
                    state="unknown",
                    level="requested",
                    observed_at=datetime.now(timezone.utc),
                    source="telegram.no_message_readback",
                ),
            )
        await self._verify_bot()
        member = await self._request("getChatMember", {"chat_id": chat_id, "user_id": subject_id})
        if not isinstance(member, dict) or member.get("user", {}).get("id") != subject_id:
            raise PermissionError("Telegram member response identity mismatch")
        status = member.get("status")
        if status == "kicked":
            state = "banned"
        elif status == "left":
            state = "absent"
        elif not isinstance(status, str):
            raise ConnectionError("Telegram member state is unavailable")
        else:
            state = "present"
        return Observation(
            provider="telegram",
            resource_id=resource_id,
            account_id=f"bot:{self.config.bot_id}",
            state=state,
            level="read_back",
            observed_at=datetime.now(timezone.utc),
            source="telegram.getChatMember",
            details={"member_status": status},
        )

    async def act(self, action: Action) -> Receipt:
        if action.target.provider != "telegram" or action.target.operation not in {"delete", "ban"}:
            raise PermissionError("Telegram adapter only permits message deletion or chat ban")
        kind, chat_id, subject_id = self._parse_resource(action.target.resource_id)
        if action.target.operation == "delete" and kind != "message":
            raise PermissionError("Telegram delete requires a message resource")
        if action.target.operation == "delete" and (
            action.target.resource_id not in self._message_observations
            or self._message_observations[action.target.resource_id].state != "present"
        ):
            raise PermissionError("Telegram deletion requires observed message evidence")
        if action.target.operation == "ban" and (
            kind != "member"
            or subject_id not in self.config.controlled_attacker_ids
            or subject_id in self.config.protected_user_ids
            or subject_id == self.config.bot_id
        ):
            raise PermissionError("Telegram member is outside controlled attacker scope")
        await self._verify_bot()
        if kind == "message":
            result = await self._request("deleteMessage", {"chat_id": chat_id, "message_id": subject_id})
        else:
            result = await self._request(
                "banChatMember",
                {"chat_id": chat_id, "user_id": subject_id, "revoke_messages": False},
            )
        if result is not True:
            raise ProviderStateChanged("Telegram did not acknowledge the scoped operation")
        return Receipt(request_id=f"telegram:{action.action_id}", acknowledged=True)
