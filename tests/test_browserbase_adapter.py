import httpx
import pytest
from pydantic import SecretStr

from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.base import RetryAfter
from debait.providers.browserbase import BrowserbaseAdapter, BrowserbaseConfig

SESSION = "sess_scam_123"
OTHER = "sess_other_456"


def action(session_id=SESSION):
    return Action(
        action_id="act-release-sc1",
        episode_id="sc1",
        target=Target(provider="browserbase", resource_id=session_id, operation="release"),
        policy_version="critical_cross_app_scam_v1",
    )


def session(status="RUNNING", *, session_id=SESSION, project_id="proj_test_owner"):
    return {
        "id": session_id,
        "projectId": project_id,
        "status": status,
        "keepAlive": True,
        "endedAt": None if status == "RUNNING" else "2026-09-13T12:00:00Z",
    }


def adapter(handler):
    return BrowserbaseAdapter(
        BrowserbaseConfig(project_id="proj_test_owner", controlled_session_ids=frozenset({SESSION})),
        SecretStr("bb_fixture_secret"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_release_request_stays_active_until_terminal_state_is_retrieved():
    requests = []
    state = {"status": "RUNNING"}

    def handler(request):
        requests.append(request)
        assert request.headers["x-bb-api-key"] == "bb_fixture_secret"
        assert request.url.path == f"/v1/sessions/{SESSION}"
        if request.method == "GET":
            return httpx.Response(200, json=session(state["status"]))
        assert request.method == "POST"
        assert request.read() == b'{"status":"REQUEST_RELEASE","projectId":"proj_test_owner"}'
        return httpx.Response(200, json=session("RUNNING"), headers={"x-request-id": "req_release"})

    client = adapter(handler)
    assert (await client.read(SESSION)).state == "active"
    receipt = await client.act(action())
    still_running = await client.read(SESSION)
    state["status"] = "COMPLETED"
    ended = await client.read(SESSION)

    assert receipt.request_id == "req_release" and receipt.acknowledged
    assert still_running.state == "active"
    assert ended.state == "terminated" and ended.level == "read_back"
    assert len([r for r in requests if r.method == "POST"]) == 1
    assert all(OTHER not in str(r.url) for r in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", ["COMPLETED", "TIMED_OUT", "ERROR"])
async def test_provider_terminal_states_are_read_back_as_terminated(terminal):
    client = adapter(lambda r: httpx.Response(200, json=session(terminal)))
    observation = await client.read(SESSION)
    assert observation.state == "terminated"
    assert observation.details["provider_status"] == terminal


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe",
    [session(session_id=OTHER), session(project_id="proj_other")],
)
async def test_response_identity_or_project_mismatch_is_rejected(unsafe):
    with pytest.raises(PermissionError):
        await adapter(lambda r: httpx.Response(200, json=unsafe)).read(SESSION)


@pytest.mark.asyncio
async def test_uncontrolled_session_is_rejected_before_http():
    def handler(request):
        raise AssertionError("Uncontrolled session reached Browserbase")

    with pytest.raises(PermissionError, match="scope"):
        await adapter(handler).act(action(OTHER))


@pytest.mark.asyncio
async def test_rate_limit_has_bounded_retry_hint():
    def handler(request):
        return httpx.Response(429, json={"secret": "private"}, headers={"retry-after": "6"})

    with pytest.raises(RetryAfter) as exc:
        await adapter(handler).read(SESSION)
    assert exc.value.seconds == 6
    assert "private" not in str(exc.value)


def test_real_network_requires_explicit_enable_and_nonempty_key():
    config = BrowserbaseConfig(project_id="proj_test_owner", controlled_session_ids=frozenset({SESSION}))
    with pytest.raises(PermissionError, match="disabled"):
        BrowserbaseAdapter(config, SecretStr("bb_fixture_secret"))
    with pytest.raises(PermissionError, match="key"):
        BrowserbaseAdapter(config, SecretStr(""), transport=httpx.MockTransport(lambda r: None))
