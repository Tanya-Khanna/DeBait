"""Scoped Gmail adapter: read a message's labels and reversibly quarantine it.

Quarantine = remove the INBOX label and add a DeBait/Quarantined label. This is a
reversible label change, never a permanent delete. Live network is gated; the
adapter acts only on the exact supplied message id.

Reliability contract:
- After mutating, it performs an **independent read-back** and treats *that*, not
  the modify response, as proof of the final world state.
- The operation is **reconciliation-friendly / idempotent**: if the message is
  already in the desired quarantined state (label present, INBOX absent), it
  returns success without mutating again — so a lost response after a successful
  quarantine is resolved by reading real state, not by repeating the action.
"""

import asyncio
import base64
import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from debait.protection.broker import Action
from debait.providers.base import Observation, ProviderStateChanged, Receipt, RetryAfter

QUARANTINE_LABEL_NAME = "DeBait/Quarantined"


class GmailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    user_id: str = Field(default="me", pattern=r"^(me|[^@\s]+@[^@\s]+)$", max_length=256)
    quarantine_label_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$", max_length=128)
    timeout_seconds: float = Field(default=8, gt=0, le=15)
    maximum_response_bytes: int = Field(default=1048576, ge=4096, le=4194304)


class GmailAdapter:
    BASE_URL = "https://gmail.googleapis.com"
    _RESOURCE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

    def __init__(self, config: GmailConfig, token: SecretStr, *, transport=None, allow_network: bool = False):
        if not token.get_secret_value():
            raise PermissionError("Gmail OAuth access token is required")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Gmail network access is disabled until explicitly enabled")
        self.config = config
        self._token = token
        self._transport = transport
        # URL-encode the mailbox segment ("me", or a literal email address).
        self._user = quote(config.user_id, safe="")

    def _resource(self, resource_id: str) -> str:
        if not self._RESOURCE.fullmatch(resource_id):
            raise PermissionError("Invalid Gmail message resource identity")
        return resource_id

    async def _request(self, method: str, path: str, *, json_body=None):
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
                    json=json_body,
                    headers={"Authorization": f"Bearer {self._token.get_secret_value()}"},
                ) as response:
                    if response.status_code == 429:
                        try:
                            retry_after = float(response.headers.get("retry-after", "1"))
                        except ValueError:
                            retry_after = 1
                        raise RetryAfter(min(max(retry_after, 0), 30))
                    if response.status_code in {401, 403}:
                        raise PermissionError("Gmail denied the scoped request")
                    if response.status_code in {400, 404, 409}:
                        raise ProviderStateChanged("Gmail resource is unavailable or changed state")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ConnectionError(f"Gmail request failed with HTTP {response.status_code}")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Gmail response exceeded the configured size")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except (RetryAfter, PermissionError, ProviderStateChanged, ConnectionError):
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            raise ConnectionError("Gmail transport or response validation failed") from None

    def _state(self, label_ids: list[str]) -> str:
        labels = set(label_ids)
        if self.config.quarantine_label_id in labels and "INBOX" not in labels:
            return "quarantined"
        if "INBOX" in labels:
            return "inbox"
        return "archived"

    async def _retrieve(self, resource_id: str) -> dict:
        resource_id = self._resource(resource_id)
        message = await self._request(
            "GET", f"/gmail/v1/users/{self._user}/messages/{resource_id}?format=full"
        )
        if message.get("id") != resource_id or not isinstance(message.get("labelIds"), list):
            raise PermissionError("Gmail message response identity mismatch")
        return message

    @staticmethod
    def _content(message: dict) -> dict:
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        headers = {}
        for header in payload.get("headers", []):
            if isinstance(header, dict) and isinstance(header.get("name"), str):
                headers[header["name"].lower()] = str(header.get("value", ""))
        bodies = []
        pending = [payload]
        while pending:
            part = pending.pop(0)
            if not isinstance(part, dict):
                continue
            pending.extend(part.get("parts", []))
            data = part.get("body", {}).get("data")
            if isinstance(data, str) and data:
                try:
                    bodies.append(
                        base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode(
                            "utf-8", errors="replace"
                        )
                    )
                except (ValueError, TypeError):
                    continue
        return {
            "from": headers.get("from", ""),
            "subject": headers.get("subject", ""),
            "snippet": str(message.get("snippet", "")),
            "body": "\n".join(bodies)[:32768],
        }

    def _quarantined(self, labels) -> bool:
        labels = set(labels)
        return self.config.quarantine_label_id in labels and "INBOX" not in labels

    async def read(self, resource_id: str) -> Observation:
        message = await self._retrieve(resource_id)
        labels = [str(x) for x in message["labelIds"]]
        return Observation(
            provider="gmail",
            resource_id=self._resource(resource_id),
            account_id=self.config.user_id,
            state=self._state(labels),
            level="read_back",
            observed_at=datetime.now(timezone.utc),
            source="gmail.messages.get",
            details={"label_ids": labels, **self._content(message)},
        )

    async def act(self, action: Action) -> Receipt:
        if action.target.provider != "gmail" or action.target.operation != "quarantine":
            raise PermissionError("Gmail adapter only permits reversible quarantine")
        resource_id = self._resource(action.target.resource_id)
        current = [str(x) for x in (await self._retrieve(resource_id))["labelIds"]]
        # Reconcile: already in the desired state is success, not an error. This makes a
        # lost response after a successful quarantine safe to retry without mutating again.
        if self._quarantined(current):
            return Receipt(request_id=f"gmail:{action.action_id}", acknowledged=True)
        if "INBOX" not in set(current):
            raise ProviderStateChanged("Gmail message is neither in the inbox nor quarantined")
        # Mutate, then IGNORE the modify response as proof and verify by independent read-back.
        await self._request(
            "POST",
            f"/gmail/v1/users/{self._user}/messages/{resource_id}/modify",
            json_body={"removeLabelIds": ["INBOX"], "addLabelIds": [self.config.quarantine_label_id]},
        )
        verified = [str(x) for x in (await self._retrieve(resource_id))["labelIds"]]
        if not self._quarantined(verified):
            raise ProviderStateChanged("Gmail quarantine not confirmed by independent read-back")
        return Receipt(request_id=f"gmail:{action.action_id}", acknowledged=True)
