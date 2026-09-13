import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from pydantic import SecretStr

from debait.app import create_app
from debait.episodes.consent import Consent, permits
from debait.reasoning.budget import Budget
from debait.settings import Settings


def test_consent_exact_resource_and_expiry():
    now = datetime.now(timezone.utc)
    c = Consent(
        episode_id="sc1",
        scope=frozenset({("stripe", "pi_scam", "cancel")}),
        expires_at=now + timedelta(minutes=5),
    )
    assert permits(c, "stripe", "pi_scam", "cancel", now)
    assert not permits(c, "stripe", "pi_other", "cancel", now)
    assert not permits(c, "stripe", "pi_scam", "capture", now)
    assert not permits(c, "stripe", "pi_scam", "cancel", now + timedelta(minutes=6))


def client(tmp_path):
    return TestClient(
        create_app(
            Settings(
                database_path=tmp_path / "db.sqlite",
                operator_token=SecretStr("test-operator-token-is-long-enough"),
            )
        ),
        base_url="http://localhost:8000",
    )


def unlock(c):
    return c.post(
        "/api/session",
        json={"token": "test-operator-token-is-long-enough"},
        headers={"Origin": "http://localhost:8000"},
    )


def test_api_cannot_be_read_without_session(tmp_path):
    c = client(tmp_path)
    assert c.get("/api/episodes").status_code == 401
    assert c.get("/api/evaluations").status_code == 401
    assert c.get("/api/health").status_code == 200
    assert unlock(c).status_code == 200
    assert c.get("/api/episodes").json() == []


def test_evaluation_reports_are_read_from_local_workspace(tmp_path):
    directory = tmp_path / "evaluations"
    directory.mkdir()
    (directory / "run-1.json").write_text(
        '{"run_id":"run-1","created_at":"2026-09-13T12:00:00+00:00","metrics":{"total_runs":15}}'
    )
    c = client(tmp_path)
    assert unlock(c).status_code == 200
    assert c.get("/api/evaluations").json()[0]["metrics"]["total_runs"] == 15


def test_usage_api_returns_persisted_measured_and_reserved_costs(tmp_path):
    c = client(tmp_path)
    c.app.state.store.set_budget_limit(3_000_000)
    budget = Budget(c.app.state.store)
    assert budget.reserve("pending-request", 400_000)
    assert budget.reserve("measured-request", 300_000)
    budget.settle("measured-request", 125_000)

    assert unlock(c).status_code == 200
    response = c.get("/api/usage")

    assert response.status_code == 200
    assert response.json() == {
        "mode": "local",
        "fresh_model_enabled": False,
        "currency": "USD",
        "model": {
            "limit_microdollars": 3_000_000,
            "spent_microdollars": 125_000,
            "reserved_microdollars": 400_000,
            "available_microdollars": 2_475_000,
        },
    }


def test_cross_origin_cannot_unlock_even_with_correct_token(tmp_path):
    c = client(tmp_path)
    r = c.post(
        "/api/session",
        json={"token": "test-operator-token-is-long-enough"},
        headers={"Origin": "https://attacker.test"},
    )
    assert r.status_code == 403
    assert c.get("/api/episodes").status_code == 401


def test_cookie_is_http_only_and_logout_requires_csrf(tmp_path):
    c = client(tmp_path)
    r = unlock(c)
    assert "httponly" in r.headers["set-cookie"].lower()
    assert "samesite=strict" in r.headers["set-cookie"].lower()
    assert c.delete("/api/session", headers={"Origin": "http://localhost:8000"}).status_code == 403
    assert (
        c.delete(
            "/api/session",
            headers={"Origin": "http://localhost:8000", "X-CSRF-Token": r.json()["csrf_token"]},
        ).status_code
        == 200
    )
    assert c.get("/api/episodes").status_code == 401


def test_dns_rebinding_host_is_rejected(tmp_path):
    c = client(tmp_path)
    assert c.get("/api/health", headers={"Host": "attacker.test"}).status_code == 400


def test_local_scenario_requires_session_and_csrf(tmp_path):
    c = client(tmp_path)
    assert (
        c.post(
            "/api/local-runs",
            json={"case": "four_app_two_payments"},
            headers={"Origin": "http://localhost:8000"},
        ).status_code
        == 401
    )
    session = unlock(c)
    assert (
        c.post(
            "/api/local-runs",
            json={"case": "four_app_two_payments"},
            headers={"Origin": "http://localhost:8000"},
        ).status_code
        == 403
    )
    r = c.post(
        "/api/local-runs",
        json={"case": "four_app_two_payments"},
        headers={"Origin": "http://localhost:8000", "X-CSRF-Token": session.json()["csrf_token"]},
    )
    assert r.status_code == 200
    assert r.json()["world"]["pi_unrelated"] == "requires_confirmation"
    assert r.json()["mode"] == "local"
    assert c.get("/api/episodes").json()[0]["id"] == r.json()["episode_id"]


def test_episode_endpoint_exposes_the_durable_agent_decision_trace(tmp_path):
    c = client(tmp_path)
    session = unlock(c)
    headers = {"Origin": "http://localhost:8000", "X-CSRF-Token": session.json()["csrf_token"]}
    run = c.post("/api/local-runs", json={"case": "four_app_two_payments"}, headers=headers).json()
    snapshot = c.get(f"/api/episodes/{run['episode_id']}").json()
    trace = snapshot["agent_trace"]
    assert [step["phase"] for step in trace[:1]] == ["observe"]
    assert any(step["phase"] == "reason" for step in trace)
    assert any(step["phase"] == "verify" for step in trace)
    assert trace[-1]["phase"] == "stop" and trace[-1]["data"]["state"] == "CONTAINED"
    # The trace is durable: indices are contiguous and match what the run reported.
    assert [step["index"] for step in trace] == list(range(len(trace)))
    assert len(trace) == len(run["agent_trace"])


def test_episode_event_feed_uses_durable_sequence_for_reconnect(tmp_path):
    c = client(tmp_path)
    session = unlock(c)
    headers = {"Origin": "http://localhost:8000", "X-CSRF-Token": session.json()["csrf_token"]}
    run = c.post("/api/local-runs", json={"case": "four_app_two_payments"}, headers=headers).json()

    response = c.get(f"/api/episodes/{run['episode_id']}/events")
    blocks = [block for block in response.text.strip().split("\n\n") if block]
    ids = [int(next(line[4:] for line in block.splitlines() if line.startswith("id: "))) for block in blocks]
    payloads = [
        json.loads(next(line[6:] for line in block.splitlines() if line.startswith("data: ")))
        for block in blocks
    ]

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert ids == sorted(ids) and len(ids) == len(set(ids))
    assert {payload["provider"] for payload in payloads} >= {"twilio", "telegram", "browserbase", "stripe"}

    resumed = c.get(
        f"/api/episodes/{run['episode_id']}/events",
        headers={"Last-Event-ID": str(ids[-2])},
    )
    assert f"id: {ids[-1]}\n" in resumed.text
    assert f"id: {ids[-2]}\n" not in resumed.text
    assert (
        c.get(
            f"/api/episodes/{run['episode_id']}/events", headers={"Last-Event-ID": "not-a-number"}
        ).status_code
        == 400
    )


def test_local_hunter_runs_only_after_containment_in_fixture_decoy(tmp_path):
    c = client(tmp_path)
    session = unlock(c)
    headers = {
        "Origin": "http://localhost:8000",
        "X-CSRF-Token": session.json()["csrf_token"],
    }
    episode = c.post("/api/local-runs", json={"case": "four_app_two_payments"}, headers=headers).json()

    response = c.post(f"/api/local-hunter/{episode['episode_id']}", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "completed"
    assert payload["sent_messages"] == 1
    assert {item["value"] for item in payload["indicators"]} == {
        "@mule_demo",
        "pay.example.test",
    }
    assert all(item["claim_status"] == "attacker_supplied" for item in payload["indicators"])
