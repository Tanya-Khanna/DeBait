import json
import subprocess

import httpx
import pytest
from pydantic import SecretStr

from debait.driver.browser_sessions import run_browserbase_smoke


@pytest.mark.asyncio
async def test_smoke_creates_one_bounded_session_and_verifies_release():
    requests = []
    state = {"status": "RUNNING"}

    def handler(request):
        requests.append(request)
        assert request.headers["x-bb-api-key"] == "bb_fixture_secret"
        if request.method == "POST" and request.url.path == "/v1/sessions":
            body = json.loads(request.content)
            assert body == {
                "timeout": 60,
                "keepAlive": False,
                "userMetadata": {"debait_run": "browserbase-smoke-test"},
            }
            return httpx.Response(
                201,
                json={
                    "id": "sess_owned_123",
                    "projectId": "proj_owned_123",
                    "status": "RUNNING",
                    "keepAlive": False,
                    "userMetadata": body["userMetadata"],
                },
            )
        if request.method == "POST":
            state["status"] = "COMPLETED"
        return httpx.Response(
            200,
            headers={"x-request-id": "req_release"},
            json={
                "id": "sess_owned_123",
                "projectId": "proj_owned_123",
                "status": state["status"],
                "keepAlive": False,
                "endedAt": "2026-09-13T14:00:00Z" if state["status"] == "COMPLETED" else None,
            },
        )

    report = await run_browserbase_smoke(
        SecretStr("bb_fixture_secret"),
        run_id="browserbase-smoke-test",
        transport=httpx.MockTransport(handler),
        poll_interval_seconds=0,
    )

    assert report["project_id"] == "proj_owned_123"
    assert report["session_id"] == "sess_owned_123"
    assert report["before_state"] == "active"
    assert report["release_acknowledged"] is True
    assert report["after_state"] == "terminated"
    assert report["provider_status"] == "COMPLETED"
    assert report["session_url"].endswith("/sess_owned_123")
    assert len([r for r in requests if r.method == "POST" and r.url.path == "/v1/sessions"]) == 1
    assert len([r for r in requests if r.method == "POST" and r.url.path != "/v1/sessions"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe",
    [
        {"id": "", "projectId": "proj_owned", "status": "RUNNING"},
        {"id": "sess_owned", "projectId": "", "status": "RUNNING"},
        {"id": "sess_owned", "projectId": "proj_owned", "status": "COMPLETED"},
        {
            "id": "sess_owned",
            "projectId": "proj_owned",
            "status": "RUNNING",
            "userMetadata": {"debait_run": "wrong-run"},
        },
    ],
)
async def test_smoke_rejects_unbound_or_nonactive_created_session(unsafe):
    def handler(request):
        if request.url.path == "/v1/sessions":
            return httpx.Response(201, json=unsafe)
        raise AssertionError("Unsafe created session reached the scoped adapter")

    with pytest.raises((PermissionError, ConnectionError)):
        await run_browserbase_smoke(
            SecretStr("bb_fixture_secret"),
            run_id="browserbase-smoke-test",
            transport=httpx.MockTransport(handler),
            poll_interval_seconds=0,
        )


def test_browserbase_smoke_cli_requires_explicit_live_confirmation():
    result = subprocess.run(
        ["uv", "run", "debait", "browserbase-smoke"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "requires --confirm-live-test" in result.stderr
