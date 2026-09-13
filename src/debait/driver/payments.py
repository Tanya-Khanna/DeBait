"""Driver-only creation of two bounded Stripe test PaymentIntents."""

import asyncio
import json
import re

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr


class StripeDriverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    account_id: str = Field(pattern=r"^acct_[A-Za-z0-9_]+$", max_length=128)
    api_version: str = Field(pattern=r"^20\d{2}-\d{2}-\d{2}\.[a-z]+$", max_length=64)
    timeout_seconds: float = Field(default=5, gt=0, le=15)
    maximum_response_bytes: int = Field(default=131072, ge=4096, le=1048576)


class ScenarioPayments:
    def __init__(
        self,
        config: StripeDriverConfig,
        key: SecretStr,
        *,
        episode_id: str,
        source_event_id: str,
        transport=None,
        allow_network: bool = False,
    ):
        if not key.get_secret_value().startswith("sk_test_"):
            raise PermissionError("Scenario payment creation requires a Stripe test secret")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Stripe scenario networking is disabled until explicitly enabled")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", episode_id) or not source_event_id:
            raise ValueError("Bound episode and source event are required")
        self.config = config
        self._key = key
        self._episode_id = episode_id
        self._source_event_id = source_event_id
        self._transport = transport

    async def _request(self, path, *, data=None, idempotency_key=None):
        headers = {
            "Authorization": f"Bearer {self._key.get_secret_value()}",
            "Stripe-Version": self.config.api_version,
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            async with (
                asyncio.timeout(self.config.timeout_seconds),
                httpx.AsyncClient(
                    base_url="https://api.stripe.com",
                    transport=self._transport,
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
            ):
                method = "POST" if data is not None else "GET"
                async with client.stream(method, path, data=data, headers=headers) as response:
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ConnectionError(
                            f"Stripe driver request failed with HTTP {response.status_code}"
                        )
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Stripe driver response exceeded the configured size")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except ConnectionError:
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            raise ConnectionError("Stripe driver transport or response validation failed") from None

    async def _verify_account(self):
        account = await self._request("/v1/account")
        if account.get("object") != "account" or account.get("id") != self.config.account_id:
            raise PermissionError("Stripe driver account identity mismatch")

    def _validate(self, payment, role, origin, amount, currency):
        metadata = payment.get("metadata")
        if (
            payment.get("object") != "payment_intent"
            or not isinstance(payment.get("id"), str)
            or not payment["id"].startswith("pi_")
            or payment.get("livemode") is not False
            or payment.get("amount") != amount
            or payment.get("currency") != currency
            or payment.get("status") != "requires_confirmation"
            or not isinstance(metadata, dict)
            or metadata.get("debait_role") != role
            or metadata.get("debait_episode") != self._episode_id
            or metadata.get("debait_origin_event") != origin
        ):
            raise PermissionError("Stripe driver returned an unexpected test PaymentIntent")
        return payment["id"]

    async def create_pair(self, amount_minor: int, currency: str) -> tuple[str, str]:
        if type(amount_minor) is not int or not 50 <= amount_minor <= 99999999:
            raise ValueError("Scenario amount is outside Stripe test bounds")
        if not re.fullmatch(r"[a-z]{3}", currency):
            raise ValueError("Scenario currency must be a lowercase three-letter code")
        await self._verify_account()
        ids = []
        for role, origin in [
            ("scam-linked", self._source_event_id),
            ("control", "control:no-scam-origin"),
        ]:
            payment = await self._request(
                "/v1/payment_intents",
                data={
                    "amount": amount_minor,
                    "currency": currency,
                    "payment_method": "pm_card_visa",
                    "confirmation_method": "manual",
                    "metadata[debait_role]": role,
                    "metadata[debait_episode]": self._episode_id,
                    "metadata[debait_origin_event]": origin,
                },
                idempotency_key=f"debait-{self._episode_id}-{role}",
            )
            ids.append(self._validate(payment, role, origin, amount_minor, currency))
        if ids[0] == ids[1]:
            raise PermissionError("Stripe driver did not return two distinct PaymentIntents")
        return ids[0], ids[1]
