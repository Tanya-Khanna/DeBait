"""Behavioural proof that DeBait runs as a self-directed agent, not a fixed sequence."""

from debait.testing.harness import run_case


def _phases(trace):
    return [step["phase"] for step in trace]


def test_loop_is_multi_step_observe_reason_act_verify(tmp_path):
    r = run_case("four_app_two_payments", workspace=tmp_path)
    phases = _phases(r["agent_trace"])
    # A real loop: it reasons several times, reads more evidence, acts, and verifies.
    assert phases[0] == "observe"
    assert phases.count("reason") >= 3
    assert phases.count("read") >= 2
    assert "decide" in phases and "verify" in phases
    assert phases[-1] == "stop"
    # Verification comes from re-reading provider state, not from the act acknowledgement.
    assert r["episode_state"] == "CONTAINED"


def test_agent_gathers_evidence_incrementally_before_it_is_sure(tmp_path):
    r = run_case("four_app_two_payments", workspace=tmp_path)
    reason_steps = [s for s in r["agent_trace"] if s["phase"] == "reason"]
    # It only reaches "sufficient" after accumulating markers across reads.
    assert reason_steps[0]["data"]["sufficient"] is False
    assert any(s["data"]["sufficient"] for s in reason_steps)
    # The first decision to act happens strictly after at least one evidence read.
    first_decide = next(i for i, s in enumerate(r["agent_trace"]) if s["phase"] == "decide")
    assert any(s["phase"] == "read" for s in r["agent_trace"][:first_decide])


def test_agent_discovers_and_acts_across_all_four_apps(tmp_path):
    r = run_case("four_app_two_payments", workspace=tmp_path)
    acted = set()
    for step in r["agent_trace"]:
        for action in step["data"].get("actions", []):
            acted.add(action.split(".")[0])
    assert acted == {"twilio", "telegram", "browserbase", "stripe"}


def test_agent_ignores_injected_instructions_and_never_targets_unrelated(tmp_path):
    r = run_case("injection_cancel_unrelated", workspace=tmp_path)
    blob = str(r["agent_trace"])
    # The injected "cancel pi_unrelated" instruction never becomes an action or a read.
    assert "pi_unrelated" not in blob
    assert r["world"]["pi_unrelated"] == "requires_confirmation"
    assert r["unauthorized_actions"] == 0
    # It still correctly contains the genuinely scam-linked payment.
    assert r["world"]["pi_scam"] == "canceled"


def test_benign_episode_is_investigated_but_never_acted_on(tmp_path):
    r = run_case("legitimate_invoice", workspace=tmp_path)
    phases = _phases(r["agent_trace"])
    assert "read" in phases  # the agent still investigates
    assert "decide" not in phases  # but it chooses not to intervene
    assert r["effects"] == {}
    assert r["episode_state"] == "OBSERVING"


def test_agent_contains_live_channels_when_no_payment_exists_yet(tmp_path):
    # Proof this is an agent, not a Twilio->Telegram->Browserbase->Stripe pipeline:
    # the attack is clear before any payment exists, so it acts now and never waits on Stripe.
    r = run_case("attack_before_payment", workspace=tmp_path)
    assert r["episode_state"] == "CONTAINED"
    assert set(r["acted_providers"]) == {"twilio", "telegram", "browserbase"}
    assert "stripe" not in r["acted_providers"]
    assert r["world"]["pi_scam"] == "requires_confirmation"
    blob = str(r["agent_trace"])
    assert "pi_scam" not in blob  # it never even reads a payment that isn't there


def test_agent_withholds_cancel_and_escalates_when_payment_already_settled(tmp_path):
    # It observes real state, distinguishes a settled payment from a preventable one,
    # withholds a pointless cancel, and reports the failure honestly instead of faking success.
    r = run_case("payment_already_settled", workspace=tmp_path)
    assert r["episode_state"] == "PREVENTION_FAILED"
    assert set(r["acted_providers"]) == {"twilio", "telegram", "browserbase"}
    assert r["world"]["pi_scam"] == "succeeded"
    assert r["effects"].get("stripe.cancel:pi_scam") is None
    assert any(s["phase"] == "decide" and "withholding cancel" in s["summary"] for s in r["agent_trace"])


def test_five_surface_episode_quarantines_gmail_as_part_of_the_flow(tmp_path):
    # The same agent runs one episode across all five surfaces, starting at the email hook.
    r = run_case("five_app_gmail", workspace=tmp_path)
    assert r["episode_state"] == "CONTAINED"
    assert set(r["acted_providers"]) == {"gmail", "twilio", "telegram", "browserbase", "stripe"}
    assert r["world"]["scam_email"] == "quarantined"
    assert r["world"]["unrelated_email"] == "inbox"  # unrelated mail untouched
    assert r["world"]["pi_unrelated"] == "requires_confirmation"
    assert r["unauthorized_actions"] == 0
    assert r["agent_trace"][0]["data"]["resource"] == "scam_email"  # episode starts at the email


def test_agent_reconciles_a_lost_response_by_rereading(tmp_path):
    r = run_case("cancel_response_lost", workspace=tmp_path)
    # Exactly one real effect despite the dropped response, confirmed by re-read.
    assert r["effects"]["stripe.cancel:pi_scam"] == 1
    assert r["episode_state"] == "CONTAINED"
    assert any(a["phase"] == "uncertain_response" for h in r["actions"] for a in h["attempts"])
