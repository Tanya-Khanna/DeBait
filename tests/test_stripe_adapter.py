import json

import httpx
import pytest
from pydantic import SecretStr

from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.base import ProviderStateChanged, RetryAfter
from debait.providers.stripe import StripeAdapter, StripeConfig


def action(resource_id="pi_scam"):
    return Action(
        action_id="act-sc1-cancel",
        episode_id="sc1",
        target=Target(provider="stripe", resource_id=resource_id, operation="cancel"),
        policy_version="critical_cross_app_scam_v1",
    )


def payment(status="requires_confirmation", *, payment_id="pi_scam", livemode=False):
    return {
        "id": payment_id,
        "object": "payment_intent",
        "status": status,
        "livemode": livemode,
        "amount": 980000,
        "amount_received": 0,
        "currency": "usd",
    }


def adapter(handler):
    return StripeAdapter(
        StripeConfig(account_id="acct_test_owner", api_version="2026-08-26.dahlia"),
        SecretStr("sk_test_local_fixture"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_reads_exact_account_then_cancels_exact_payment_with_idempotency():
    requests = []
    state = {"payment": payment()}

    def handler(request):
        requests.append(request)
        assert request.headers["authorization"].startswith("Bearer sk_test_")
        assert request.headers["stripe-version"] == "2026-08-26.dahlia"
        if request.url.path == "/v1/account":
            return httpx.Response(200, json={"id": "acct_test_owner", "object": "account"})
        if request.method == "GET":
            return httpx.Response(200, json=state["payment"])
        assert request.method == "POST"
        assert request.headers["idempotency-key"] == "act-sc1-cancel"
        assert request.content == b"cancellation_reason=fraudulent"
        state["payment"] = payment("canceled")
        return httpx.Response(200, json=state["payment"], headers={"request-id": "req_cancel"})

    client = adapter(handler)
    before = await client.read("pi_scam")
    receipt = await client.act(action())
    after = await client.read("pi_scam")

    assert before.state == "requires_confirmation"
    assert before.details == {
        "amount": 980000,
        "amount_received": 0,
        "currency": "usd",
        "livemode": False,
    }
    assert receipt.request_id == "req_cancel" and receipt.acknowledged
    assert after.state == "canceled" and after.level == "read_back"
    assert [r.url.path for r in requests].count("/v1/payment_intents/pi_scam/cancel") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("unsafe_payment", "message"),
    [
        (payment(livemode=True), "live-mode"),
        (payment(payment_id="pi_other"), "identity"),
    ],
)
async def test_refuses_live_mode_or_response_identity_mismatch(unsafe_payment, message):
    posted = False

    def handler(request):
        nonlocal posted
        if request.url.path == "/v1/account":
            return httpx.Response(200, json={"id": "acct_test_owner", "object": "account"})
        if request.method == "POST":
            posted = True
        return httpx.Response(200, json=unsafe_payment, headers={"request-id": "req_unsafe"})

    with pytest.raises(PermissionError, match=message):
        await adapter(handler).act(action())
    assert not posted


@pytest.mark.asyncio
async def test_succeeded_payment_is_too_late_and_is_never_canceled():
    posted = False

    def handler(request):
        nonlocal posted
        if request.url.path == "/v1/account":
            return httpx.Response(200, json={"id": "acct_test_owner", "object": "account"})
        if request.method == "POST":
            posted = True
        return httpx.Response(200, json=payment("succeeded"))

    client = adapter(handler)
    observed = await client.read("pi_scam")
    assert observed.state == "succeeded"
    with pytest.raises(ProviderStateChanged, match="succeeded"):
        await client.act(action())
    assert not posted


@pytest.mark.asyncio
async def test_rate_limit_is_bounded_and_does_not_leak_provider_body():
    def handler(request):
        return httpx.Response(429, json={"error": {"message": "sensitive"}}, headers={"retry-after": "3"})

    with pytest.raises(RetryAfter) as exc:
        await adapter(handler).read("pi_scam")
    assert exc.value.seconds == 3
    assert "sensitive" not in str(exc.value)


def test_real_network_needs_explicit_enable_and_test_key():
    config = StripeConfig(account_id="acct_test_owner", api_version="2026-08-26.dahlia")
    with pytest.raises(PermissionError, match="disabled"):
        StripeAdapter(config, SecretStr("sk_test_fixture"))
    with pytest.raises(PermissionError, match="test secret"):
        StripeAdapter(config, SecretStr("sk_live_forbidden"), transport=httpx.MockTransport(lambda r: None))


def test_error_payload_is_not_embedded_in_exception():
    secret_body = json.dumps({"error": {"message": "cardholder-private-data"}})

    def handler(request):
        return httpx.Response(500, content=secret_body)

    with pytest.raises(ConnectionError) as exc:
        import asyncio

        asyncio.run(adapter(handler).read("pi_scam"))
    assert "cardholder-private-data" not in str(exc.value)
