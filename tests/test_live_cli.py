import os
import subprocess


def test_demo_live_dry_run_reports_readiness_without_credentials_or_mutations(tmp_path):
    env = {key: value for key, value in os.environ.items() if not key.startswith("DEBAIT_")}
    env["DEBAIT_DATABASE_PATH"] = str(tmp_path / "live.sqlite")
    result = subprocess.run(
        ["uv", "run", "debait", "demo-live", "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0
    for provider in ["OpenAI", "Gmail", "Twilio", "Telegram", "Browserbase", "Stripe TEST"]:
        assert f"{provider}" in result.stdout
        assert "NOT CONFIGURED" in result.stdout
    assert "provider_mutations: 0" in result.stdout
    assert "stripe.observe:None" not in result.stdout
    assert not (tmp_path / "live.sqlite").exists()


def test_demo_live_confirmation_fails_closed_when_any_provider_is_unconfigured(tmp_path):
    env = {key: value for key, value in os.environ.items() if not key.startswith("DEBAIT_")}
    database = tmp_path / "live.sqlite"
    env["DEBAIT_DATABASE_PATH"] = str(database)

    result = subprocess.run(
        ["uv", "run", "debait", "demo-live", "--confirm-live-test"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode != 0
    assert "providers not configured" in result.stderr
    assert not database.exists()
