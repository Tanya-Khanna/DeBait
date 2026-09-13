import json
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

import httpx
import pytest
from pydantic import SecretStr

from debait.driver.bindings import BindingNotFound, BindingStore
from debait.driver.payments import ScenarioPayments, StripeDriverConfig

SECRET = SecretStr("driver-signing-secret-is-long-enough")


def test_binding_export_and_reset_operate_only_on_driver_store(tmp_path):
    store = BindingStore(tmp_path / "driver.sqlite", SECRET)
    token = store.issue(
        "sc1",
        "pi_scam",
        "telegram:message:91",
        datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    rows = store.export()
    assert len(rows) == 1
    assert rows[0]["episode_id"] == "sc1" and rows[0]["payment_id"] == "pi_scam"
    assert "signing_secret" not in json.dumps(rows)
    assert store.reset() == 1
    with pytest.raises(BindingNotFound):
        store.lookup(token)


@pytest.mark.asyncio
async def test_scenario_driver_creates_two_equal_pending_payments_with_distinct_roles():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/v1/account":
            return httpx.Response(200, json={"id": "acct_test_owner", "object": "account"})
        form = dict(parse_qsl(request.content.decode()))
        role = form["metadata[debait_role]"]
        payment_id = "pi_scam" if role == "scam-linked" else "pi_control"
        return httpx.Response(
            200,
            json={
                "id": payment_id,
                "object": "payment_intent",
                "amount": 980000,
                "currency": "usd",
                "status": "requires_confirmation",
                "livemode": False,
                "metadata": {
                    "debait_role": role,
                    "debait_episode": "sc1",
                    "debait_origin_event": form["metadata[debait_origin_event]"],
                },
            },
        )

    driver = ScenarioPayments(
        StripeDriverConfig(account_id="acct_test_owner", api_version="2026-08-26.dahlia"),
        SecretStr("sk_test_fixture"),
        episode_id="sc1",
        source_event_id="telegram:message:91",
        transport=httpx.MockTransport(handler),
    )
    assert await driver.create_pair(980000, "usd") == ("pi_scam", "pi_control")
    creates = [request for request in requests if request.url.path == "/v1/payment_intents"]
    assert len(creates) == 2
    assert {request.headers["idempotency-key"] for request in creates} == {
        "debait-sc1-scam-linked",
        "debait-sc1-control",
    }
    assert all(b"amount=980000" in request.content for request in creates)
    assert all("confirm" not in dict(parse_qsl(request.content.decode())) for request in creates)


@pytest.mark.asyncio
async def test_scenario_driver_rejects_live_or_duplicate_payment_objects():
    responses = iter(
        [
            {
                "id": "pi_same",
                "object": "payment_intent",
                "amount": 500,
                "currency": "usd",
                "status": "requires_confirmation",
                "livemode": False,
                "metadata": {
                    "debait_role": "scam-linked",
                    "debait_episode": "sc1",
                    "debait_origin_event": "e1",
                },
            },
            {
                "id": "pi_same",
                "object": "payment_intent",
                "amount": 500,
                "currency": "usd",
                "status": "requires_confirmation",
                "livemode": False,
                "metadata": {
                    "debait_role": "control",
                    "debait_episode": "sc1",
                    "debait_origin_event": "control:no-scam-origin",
                },
            },
        ]
    )

    def handler(request):
        if request.url.path == "/v1/account":
            return httpx.Response(200, json={"id": "acct_test_owner", "object": "account"})
        return httpx.Response(200, json=next(responses))

    driver = ScenarioPayments(
        StripeDriverConfig(account_id="acct_test_owner", api_version="2026-08-26.dahlia"),
        SecretStr("sk_test_fixture"),
        episode_id="sc1",
        source_event_id="e1",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PermissionError, match="distinct"):
        await driver.create_pair(500, "usd")


def test_driver_cli_can_seed_export_and_explicitly_reset(tmp_path):
    workspace = str(tmp_path)
    seed = subprocess.run(
        [
            "uv",
            "run",
            "debait",
            "driver-bind",
            "--workspace",
            workspace,
            "--episode",
            "sc1",
            "--payment",
            "pi_scam",
            "--source",
            "telegram:message:91",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert seed.returncode == 0 and json.loads(seed.stdout)["token"]
    exported = subprocess.run(
        ["uv", "run", "debait", "driver-export", "--workspace", workspace],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(exported.stdout)[0]["payment_id"] == "pi_scam"
    reset = subprocess.run(
        ["uv", "run", "debait", "driver-reset", "--workspace", workspace, "--yes"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(reset.stdout) == {"deleted_bindings": 1}
    empty = subprocess.run(
        ["uv", "run", "debait", "driver-export", "--workspace", workspace],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(empty.stdout) == []
