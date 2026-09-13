"""Narrow Stripe test-mode adapter for retrieving and canceling one PaymentIntent."""

import asyncio
import json
import re
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from debait.protection.broker import Action
from debait.providers.base import Observation, ProviderStateChanged, Receipt, RetryAfter


class StripeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    account_id: str = Field(pattern=r"^acct_[A-Za-z0-9_]+$", max_length=128)
    api_version: str = Field(pattern=r"^20\d{2}-\d{2}-\d{2}\.[a-z]+$", max_length=64)
    timeout_seconds: float = Field(default=5, gt=0, le=15)
    maximum_response_bytes: int = Field(default=131072, ge=4096, le=1048576)


class StripeAdapter:
    BASE_URL = "https://api.stripe.com"
    CANCELABLE = frozenset(
        {
            "requires_payment_method",
            "requires_capture",
            "requires_confirmation",
            "requires_action",
            "processing",
        }
    )
    _RESOURCE = re.compile(r"^pi_[A-Za-z0-9_]{1,120}$")

    def __init__(
        self,
        config: StripeConfig,
        key: SecretStr,
        *,
        transport=None,
        allow_network: bool = False,
    ):
        secret = key.get_secret_value()
        if not secret.startswith("sk_test_"):
            raise PermissionError("Stripe adapter requires a test secret key")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Stripe network access is disabled until explicitly enabled")
        self.config = config
        self._key = key
        self._transport = transport

    def _resource(self, resource_id: str) -> str:
        if not self._RESOURCE.fullmatch(resource_id):
            raise PermissionError("Invalid Stripe PaymentIntent resource identity")
        return resource_id

    async def _request(self, method: str, path: str, *, data=None, idempotency_key=None):
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
                    base_url=self.BASE_URL,
                    transport=self._transport,
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
            ):
                async with client.stream(method, path, data=data, headers=headers) as response:
                    if response.status_code == 429:
                        try:
                            retry_after = float(response.headers.get("retry-after", "1"))
                        except ValueError:
                            retry_after = 1
                        raise RetryAfter(min(max(retry_after, 0), 30))
                    if response.status_code in {401, 403}:
                        raise PermissionError("Stripe denied the scoped test-mode request")
                    if response.status_code in {400, 404, 409}:
                        raise ProviderStateChanged("Stripe resource is unavailable or changed state")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ConnectionError(f"Stripe request failed with HTTP {response.status_code}")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Stripe response exceeded the configured size")
                    request_id = response.headers.get("request-id")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            return payload, request_id
        except (RetryAfter, PermissionError, ProviderStateChanged, ConnectionError):
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            raise ConnectionError("Stripe transport or response validation failed") from None

    async def _verify_account(self):
        account, _ = await self._request("GET", "/v1/account")
        if account.get("object") != "account" or account.get("id") != self.config.account_id:
            raise PermissionError("Stripe account identity mismatch")

    async def _retrieve(self, resource_id: str):
        resource_id = self._resource(resource_id)
        await self._verify_account()
        payment, _ = await self._request("GET", f"/v1/payment_intents/{resource_id}")
        if payment.get("object") != "payment_intent" or payment.get("id") != resource_id:
            raise PermissionError("Stripe PaymentIntent response identity mismatch")
        if payment.get("livemode") is not False:
            raise PermissionError("Stripe live-mode resources are forbidden")
        if not isinstance(payment.get("status"), str):
            raise ConnectionError("Stripe PaymentIntent status is unavailable")
        return payment

    async def read(self, resource_id: str) -> Observation:
        payment = await self._retrieve(resource_id)
        details = {
            "amount": payment.get("amount"),
            "amount_received": payment.get("amount_received"),
            "currency": payment.get("currency"),
            "livemode": payment["livemode"],
        }
        return Observation(
            provider="stripe",
            resource_id=payment["id"],
            account_id=self.config.account_id,
            state=payment["status"],
            level="read_back",
            observed_at=datetime.now(timezone.utc),
            source="stripe.retrieve",
            details=details,
        )

    async def act(self, action: Action) -> Receipt:
        if action.target.provider != "stripe" or action.target.operation != "cancel":
            raise PermissionError("Stripe adapter only permits PaymentIntent cancellation")
        resource_id = self._resource(action.target.resource_id)
        payment = await self._retrieve(resource_id)
        if payment["status"] not in self.CANCELABLE:
            raise ProviderStateChanged(f"PaymentIntent state {payment['status']} is not cancelable")
        canceled, request_id = await self._request(
            "POST",
            f"/v1/payment_intents/{resource_id}/cancel",
            data={"cancellation_reason": "fraudulent"},
            idempotency_key=action.action_id,
        )
        if (
            canceled.get("object") != "payment_intent"
            or canceled.get("id") != resource_id
            or canceled.get("livemode") is not False
            or canceled.get("status") != "canceled"
        ):
            raise ProviderStateChanged("Stripe cancellation response identity or state mismatch")
        if not request_id:
            raise ConnectionError("Stripe cancellation request ID is unavailable")
        return Receipt(request_id=request_id, acknowledged=True)
