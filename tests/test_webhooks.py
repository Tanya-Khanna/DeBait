import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi.testclient import TestClient
from pydantic import SecretStr

from debait.app import create_app
from debait.episodes.models import Event
from debait.protection.policy import Target
from debait.settings import Settings

STRIPE_SECRET = "whsec_local_fixture"
TWILIO_TOKEN = "twilio-local-auth-token"
CALL_SID = "CA0123456789abcdef0123456789abcdef"


def callback_client(tmp_path):
    settings = Settings(
        database_path=tmp_path / "db.sqlite",
        operator_token=SecretStr("test-operator-token-is-long-enough"),
        stripe_webhook_secret=SecretStr(STRIPE_SECRET),
        twilio_token=SecretStr(TWILIO_TOKEN),
        callback_base_url="http://localhost:8000",
    )
    app = create_app(settings)
    now = datetime.now(timezone.utc)
    for provider, resource_id, operation in [
        ("stripe", "pi_bound", "cancel"),
        ("twilio", CALL_SID, "end"),
    ]:
        source = Event(
            event_id=f"source:{provider}",
            provider=provider,
            provider_event_id=f"source:{provider}",
            episode_id="sc-callback",
            observed_at=now,
            received_at=now,
            payload={"resource_id": resource_id, "account_id": f"acct:{provider}"},
        )
        app.state.store.ingest(source)
        app.state.store.bind_resource(
            "sc-callback",
            Target(provider=provider, resource_id=resource_id, operation=operation),
            f"acct:{provider}",
            [source.event_id],
        )
    return TestClient(app, base_url="http://localhost:8000"), app


def stripe_header(raw: bytes, timestamp: int) -> str:
    digest = hmac.new(
        STRIPE_SECRET.encode(), str(timestamp).encode() + b"." + raw, hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={digest}"


def twilio_header(url: str, params: dict[str, str]) -> str:
    canonical = url + "".join(key + value for key, value in sorted(params.items()))
    digest = hmac.new(TWILIO_TOKEN.encode(), canonical.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def stripe_payload(payment_id: str = "pi_bound") -> bytes:
    return json.dumps(
        {
            "id": "evt_callback_1",
            "type": "payment_intent.canceled",
            "created": int(time.time()),
            "data": {"object": {"id": payment_id, "status": "canceled", "livemode": False}},
        },
        separators=(",", ":"),
    ).encode()


def test_stripe_callback_verifies_exact_raw_body_before_persistence(tmp_path):
    client, app = callback_client(tmp_path)
    raw = stripe_payload()
    timestamp = int(time.time())

    response = client.post(
        "/callbacks/stripe",
        content=raw,
        headers={"Stripe-Signature": stripe_header(raw, timestamp), "Content-Type": "application/json"},
    )

    assert response.status_code == 202
    assert response.json() == {"accepted": True, "inserted": True}
    stored = app.state.store.events("sc-callback")[-1]
    assert stored.provider_event_id == "evt_callback_1"
    assert stored.payload == {
        "resource_id": "pi_bound",
        "event_type": "payment_intent.canceled",
        "status": "canceled",
        "livemode": False,
        "signature_verified": True,
    }


def test_stripe_callback_rejects_tampering_staleness_and_unbound_objects(tmp_path):
    client, app = callback_client(tmp_path)
    raw = stripe_payload()
    before = len(app.state.store.events("sc-callback"))
    valid = stripe_header(raw, int(time.time()))

    assert (
        client.post("/callbacks/stripe", content=raw + b" ", headers={"Stripe-Signature": valid}).status_code
        == 401
    )
    stale = stripe_header(raw, int(time.time()) - 301)
    assert (
        client.post("/callbacks/stripe", content=raw, headers={"Stripe-Signature": stale}).status_code == 401
    )

    other = stripe_payload("pi_not_bound")
    response = client.post(
        "/callbacks/stripe",
        content=other,
        headers={"Stripe-Signature": stripe_header(other, int(time.time()))},
    )
    assert response.status_code == 202
    assert response.json() == {"accepted": False, "reason": "unbound_resource"}
    assert len(app.state.store.events("sc-callback")) == before


def test_stripe_callback_rejects_an_unrepresentable_event_timestamp(tmp_path):
    client, _ = callback_client(tmp_path)
    body = json.loads(stripe_payload())
    body["created"] = 10**100
    raw = json.dumps(body, separators=(",", ":")).encode()

    response = client.post(
        "/callbacks/stripe",
        content=raw,
        headers={"Stripe-Signature": stripe_header(raw, int(time.time()))},
    )

    assert response.status_code == 400


def test_twilio_callback_verifies_configured_public_url_and_form_before_persistence(tmp_path):
    client, app = callback_client(tmp_path)
    params = {"CallSid": CALL_SID, "CallStatus": "completed"}
    url = "http://localhost:8000/callbacks/twilio"
    body = urlencode(params)

    response = client.post(
        "/callbacks/twilio",
        content=body,
        headers={
            "X-Twilio-Signature": twilio_header(url, params),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    assert response.status_code == 202
    assert response.json() == {"accepted": True, "inserted": True}
    stored = app.state.store.events("sc-callback")[-1]
    assert stored.provider == "twilio"
    assert stored.payload["resource_id"] == CALL_SID
    assert stored.payload["status"] == "completed"
    assert stored.payload["signature_verified"] is True


def test_twilio_callback_rejects_invalid_signature_and_duplicate_form_keys(tmp_path):
    client, app = callback_client(tmp_path)
    before = len(app.state.store.events("sc-callback"))
    headers = {
        "X-Twilio-Signature": "invalid",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    assert client.post("/callbacks/twilio", content=f"CallSid={CALL_SID}", headers=headers).status_code == 401

    duplicate = f"CallSid={CALL_SID}&CallSid={CALL_SID}&CallStatus=completed"
    assert client.post("/callbacks/twilio", content=duplicate, headers=headers).status_code == 400
    assert len(app.state.store.events("sc-callback")) == before
