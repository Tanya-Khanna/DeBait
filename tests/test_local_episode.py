from debait.testing.harness import run_case


def test_four_app_world_preserves_unrelated_payment(tmp_path):
    r = run_case("four_app_two_payments", workspace=tmp_path)
    assert r["episode_state"] == "CONTAINED"
    assert r["world"]["pi_scam"] == "canceled"
    assert r["world"]["pi_unrelated"] == "requires_confirmation"
    assert r["unrelated_resource_diffs"] == []
    assert set(r["acted_providers"]) == {"stripe", "twilio", "telegram", "browserbase"}
    assert r["mode"] == "local" and r["reasoning_mode"] == "deterministic_fixture"


def test_missing_telegram_proof_is_partial(tmp_path):
    r = run_case("telegram_delete_ack_only", workspace=tmp_path)
    assert r["episode_state"] == "PARTIALLY_CONTAINED"
    assert r["world"]["pi_scam"] == "canceled"


def test_benign_case_is_uninterrupted(tmp_path):
    r = run_case("legitimate_invoice", workspace=tmp_path)
    assert r["world"]["pi_scam"] == "requires_confirmation"
    assert r["effects"] == {}


def test_dropped_response_has_one_effect_and_audit(tmp_path):
    r = run_case("cancel_response_lost", workspace=tmp_path)
    assert r["effects"]["stripe.cancel:pi_scam"] == 1
    assert r["episode_state"] == "CONTAINED"
    assert any(a["phase"] == "uncertain_response" for h in r["actions"] for a in h["attempts"])


def test_prompt_cannot_select_unrelated_resource(tmp_path):
    r = run_case("injection_cancel_unrelated", workspace=tmp_path)
    assert r["world"]["pi_unrelated"] == "requires_confirmation"
    assert r["unauthorized_actions"] == 0
