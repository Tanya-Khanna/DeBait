import httpx
import pytest
from pydantic import SecretStr

from debait.ingest.twilio import normalize_call
from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.base import ProviderStateChanged, RetryAfter
from debait.providers.twilio import TwilioAdapter, TwilioConfig

ACCOUNT = "AC" + "1" * 32
CALL = "CA" + "2" * 32
OTHER = "CA" + "3" * 32
TO = "+12025550123"
FROM = "+12025550124"


def call(status="in-progress", *, sid=CALL, account=ACCOUNT, to=TO):
    return {
        "sid": sid,
        "account_sid": account,
        "status": status,
        "to": to,
        "from": FROM,
        "duration": None if status == "in-progress" else "12",
    }


def action(call_sid=CALL):
    return Action(
        action_id="act-end-sc1",
        episode_id="sc1",
        target=Target(provider="twilio", resource_id=call_sid, operation="end"),
        policy_version="critical_cross_app_scam_v1",
    )


def adapter(handler):
    return TwilioAdapter(
        TwilioConfig(
            account_sid=ACCOUNT,
            controlled_call_sids=frozenset({CALL}),
            allowed_callers=frozenset({FROM}),
            allowed_recipients=frozenset({TO}),
        ),
        SecretStr("local_auth_token"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_ends_exact_active_call_then_retrieves_terminal_state():
    requests = []
    state = {"status": "in-progress"}

    def handler(request):
        requests.append(request)
        assert request.url.path.endswith(f"/Accounts/{ACCOUNT}/Calls/{CALL}.json")
        assert request.headers["authorization"].startswith("Basic ")
        if request.method == "POST":
            assert request.content == b"Status=completed"
            state["status"] = "completed"
            return httpx.Response(200, json=call("completed"), headers={"twilio-request-id": "RQ1"})
        return httpx.Response(200, json=call(state["status"]))

    client = adapter(handler)
    assert (await client.read(CALL)).state == "in-progress"
    receipt = await client.act(action())
    ended = await client.read(CALL)
    assert receipt.request_id == "RQ1" and receipt.acknowledged
    assert ended.state == "completed" and ended.level == "read_back"
    assert len([r for r in requests if r.method == "POST"]) == 1
    assert all(OTHER not in str(r.url) for r in requests)


@pytest.mark.asyncio
async def test_already_ended_call_is_reported_without_update():
    posted = False

    def handler(request):
        nonlocal posted
        posted |= request.method == "POST"
        return httpx.Response(200, json=call("no-answer"))

    client = adapter(handler)
    assert (await client.read(CALL)).state == "no-answer"
    with pytest.raises(ProviderStateChanged, match="no-answer"):
        await client.act(action())
    assert not posted


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe",
    [call(sid=OTHER), call(account="AC" + "4" * 32), call(to="+12025550999")],
)
async def test_rejects_response_identity_or_unapproved_party(unsafe):
    with pytest.raises(PermissionError):
        await adapter(lambda r: httpx.Response(200, json=unsafe)).read(CALL)


@pytest.mark.asyncio
async def test_uncontrolled_call_is_rejected_before_http():
    with pytest.raises(PermissionError, match="scope"):
        await adapter(lambda r: (_ for _ in ()).throw(AssertionError("HTTP reached"))).act(action(OTHER))


@pytest.mark.asyncio
async def test_rate_limit_has_bounded_retry_hint():
    response = httpx.Response(429, json={"message": "private"}, headers={"retry-after": "5"})
    with pytest.raises(RetryAfter) as exc:
        await adapter(lambda r: response).read(CALL)
    assert exc.value.seconds == 5
    assert "private" not in str(exc.value)


def test_supplied_script_keeps_explicit_provenance_and_bound_episode():
    event = normalize_call(CALL, "I am your bank fraud team", "supplied_script", lambda sid: "sc1")
    assert event.episode_id == "sc1"
    assert event.payload["transcript_source"] == "supplied_script"
    assert event.payload["claimed_identity"] == "unverified"
    with pytest.raises(ValueError, match="provenance"):
        normalize_call(CALL, "text", "live", lambda sid: "sc1")


def test_network_requires_explicit_enable_and_nonempty_token():
    config = TwilioConfig(
        account_sid=ACCOUNT,
        controlled_call_sids=frozenset({CALL}),
        allowed_callers=frozenset({FROM}),
        allowed_recipients=frozenset({TO}),
    )
    with pytest.raises(PermissionError, match="disabled"):
        TwilioAdapter(config, SecretStr("fixture"))
    with pytest.raises(PermissionError, match="token"):
        TwilioAdapter(config, SecretStr(""), transport=httpx.MockTransport(lambda r: None))
