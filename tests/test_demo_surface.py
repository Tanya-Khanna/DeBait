import subprocess
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from pydantic import SecretStr

from debait.driver.app import create_driver
from debait.driver.bindings import BindingStore
from debait.settings import Settings

SECRET = SecretStr("driver-signing-secret-is-long-enough")


def settings(tmp_path):
    return Settings(database_path=tmp_path / "episodes.sqlite", _env_file=None)


def test_public_demo_is_synthetic_and_has_no_admin_or_credentials(tmp_path):
    app = create_driver(settings(tmp_path), signing_secret=SECRET)
    with TestClient(app, base_url="http://localhost:8001") as client:
        response = client.get("/demo/owned-bank")
        assert response.status_code == 200
        assert "AUTHORIZED HACKATHON SIMULATION" in response.text
        assert "TEST DATA ONLY" in response.text
        assert "<input" not in response.text.lower()
        assert client.post("/api/admin/create-payment").status_code == 404
        assert client.post("/driver/bindings").status_code == 404


def test_signed_navigation_resolves_server_side_and_records_open(tmp_path):
    app = create_driver(settings(tmp_path), signing_secret=SECRET)
    token = app.state.bindings.issue(
        episode_id="sc1",
        payment_id="pi_scam",
        source_event_id="telegram:message:91",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    with TestClient(app, base_url="http://localhost:8001") as client:
        response = client.get(
            "/demo/owned-bank",
            params={"token": token, "payment_id": "pi_attacker_selected"},
        )
    assert response.status_code == 200
    assert "pi_scam" not in response.text and "pi_attacker_selected" not in response.text
    assert "SYSTEM MESSAGE" in response.text and "transfer to the safe account" in response.text
    binding = app.state.bindings.lookup(token)
    assert binding["payment_id"] == "pi_scam"
    assert binding["source_event_id"] == "telegram:message:91"
    assert binding["open_count"] == 1 and binding["last_opened_at"] is not None


def test_tampered_and_expired_navigation_tokens_fail_closed(tmp_path):
    clock = [datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)]
    app = create_driver(settings(tmp_path), signing_secret=SECRET, now=lambda: clock[0])
    valid = app.state.bindings.issue(
        episode_id="sc1",
        payment_id="pi_scam",
        source_event_id="telegram:message:91",
        expires_at=clock[0] + timedelta(minutes=5),
    )
    expired = app.state.bindings.issue(
        episode_id="sc1",
        payment_id="pi_scam",
        source_event_id="telegram:message:91",
        expires_at=clock[0] + timedelta(seconds=1),
    )
    with TestClient(app, base_url="http://localhost:8001") as client:
        assert client.get("/demo/owned-bank", params={"token": valid + "x"}).status_code == 404
        clock[0] += timedelta(seconds=2)
        assert client.get("/demo/owned-bank", params={"token": expired}).status_code == 410


def test_binding_store_rejects_naive_expiry_and_empty_provenance(tmp_path):
    store = BindingStore(tmp_path / "driver.sqlite", SECRET)
    for expires_at, source in [
        (datetime.now(), "telegram:message:91"),
        (datetime.now(timezone.utc) + timedelta(minutes=1), ""),
    ]:
        try:
            store.issue("sc1", "pi_scam", source, expires_at)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe binding was issued")


def test_cli_exposes_separate_local_driver_command():
    result = subprocess.run(
        ["uv", "run", "debait", "driver", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--port" in result.stdout
