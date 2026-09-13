import pytest
from fastapi.testclient import TestClient

from debait.app import create_app
from debait.settings import Settings


def test_health_is_honest(tmp_path):
    with TestClient(
        create_app(Settings(database_path=tmp_path / "db.sqlite")), base_url="http://localhost:8000"
    ) as client:
        assert client.get("/api/health").json() == {"status": "ok", "mode": "local"}


def test_no_live_mode_without_credentials(tmp_path):
    with pytest.raises(ValueError, match="Live-test mode"):
        Settings(mode="live-test", database_path=tmp_path / "db.sqlite", _env_file=None)


def test_empty_episode_list_does_not_fabricate_activity(tmp_path):
    with TestClient(
        create_app(Settings(database_path=tmp_path / "db.sqlite")), base_url="http://localhost:8000"
    ) as client:
        token = (tmp_path / "operator.token").read_text().strip()
        client.post("/api/session", json={"token": token}, headers={"Origin": "http://localhost:8000"})
        assert client.get("/api/episodes").json() == []
