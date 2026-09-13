"""Step 15: a genuinely branching next-read decision.

These tests prove the paired branching experiment holds at the level the claim
requires: at one reasoning step the agent is offered at least two legitimate,
already-authorized reads bound to the same episode; an unbound resource can never be
selected; the two paired cases differ only in where the missing payment-coercion
instruction lives; and the useful next read therefore flips between them. They assert
against the structure and the authored ground truth — never by weakening the loop's
security invariants — and they document that the content-blind deterministic fixture
picks the same read in both cases, which is exactly why the fresh-model proof matters.
"""

from pathlib import Path

import pytest

from debait.agent.loop import ContainmentAgent
from debait.agent.reasoner import FixtureReasoner
from debait.agent.scenario import BRANCHING_CASES, build_scenario
from debait.episodes.store import EpisodeStore
from debait.evaluation.branching import BRANCHING_GROUND_TRUTH, branch_summary
from debait.evaluation.runner import evaluate
from debait.reasoning.assess import validate_assessment
from debait.reasoning.schema import Assessment, ReadRequest, Signal
from debait.testing.harness import run_case
from debait.testing.world import FixtureWorld

PAIR = ("branch_payment_on_web", "branch_payment_in_email")
MANIFEST = Path(__file__).resolve().parents[1] / "evals" / "manifests" / "branching-local.json"


def _agent_at_branch(case: str, tmp_path) -> ContainmentAgent:
    """Drive an agent to the chat step, where both onward reads are authorized."""
    store = EpisodeStore(tmp_path / f"{case}.sqlite")
    agent = ContainmentAgent(
        store, FixtureWorld(), build_scenario(case), FixtureReasoner(), episode_id="ep-branch"
    )
    agent.observe("scam_call")
    agent.observe("scam_message")
    return agent


def _authorized_reads(agent: ContainmentAgent) -> frozenset:
    """Reproduce exactly what the loop passes to the reasoner as allowed_reads."""
    pending = agent.allowed - agent.observed
    return frozenset((agent.scenario.provider_of(r), r) for r in pending)


@pytest.mark.parametrize("case", PAIR)
def test_branch_point_offers_at_least_two_authorized_reads(case, tmp_path):
    agent = _agent_at_branch(case, tmp_path)
    reads = _authorized_reads(agent)
    assert reads == {("browserbase", "scam_browser"), ("gmail", "scam_email")}
    assert len(reads) >= 2


@pytest.mark.parametrize("case", PAIR)
def test_both_candidate_reads_belong_to_the_same_episode(case, tmp_path):
    agent = _agent_at_branch(case, tmp_path)
    pending = agent.allowed - agent.observed
    # Both leads were reached by a trusted link from this episode's chat message,
    # and every recorded event carries this episode's id.
    for resource in pending:
        assert agent.link_parent[resource] == "scam_message"
    episode_ids = {event.episode_id for event in agent.store.events(agent.episode_id)}
    assert episode_ids == {agent.episode_id}
    reached = {event.payload["resource_id"] for event in agent.store.events(agent.episode_id)}
    assert {"scam_call", "scam_message"} <= reached


@pytest.mark.parametrize("case", PAIR)
def test_unbound_third_resource_cannot_be_selected(case, tmp_path):
    agent = _agent_at_branch(case, tmp_path)
    reads = _authorized_reads(agent)
    events = agent.store.events(agent.episode_id)
    # A control resource that was never linked into this episode is not authorized.
    assert ("stripe", "pi_unrelated") not in reads
    # pi_scam is a real resource but only becomes authorized after the browser session
    # is read; it is not selectable at the branch step.
    assert ("stripe", "pi_scam") not in reads
    # The loop's validation layer refuses any next read outside the authorized set,
    # whether the id is fabricated or merely not-yet-authorized.
    for bad in (
        ReadRequest(provider="gmail", resource_id="unrelated_email"),
        ReadRequest(provider="stripe", resource_id="pi_scam"),
        ReadRequest(provider="browserbase", resource_id="does_not_exist"),
    ):
        with pytest.raises(ValueError, match="outside authorized resources"):
            validate_assessment(
                Assessment(episode_id=agent.episode_id, next_read=bad),
                events,
                allowed_reads=reads,
            )
    # A read that IS in the authorized set validates.
    ok = validate_assessment(
        Assessment(
            episode_id=agent.episode_id,
            next_read=ReadRequest(provider="gmail", resource_id="scam_email"),
        ),
        events,
        allowed_reads=reads,
    )
    assert ok.next_read.resource_id == "scam_email"


def test_signals_must_cite_real_episode_evidence(tmp_path):
    # Guards the other half of the invariant: fabricated evidence ids are rejected too.
    agent = _agent_at_branch("branch_payment_on_web", tmp_path)
    events = agent.store.events(agent.episode_id)
    with pytest.raises(ValueError, match="unknown or cross-episode evidence"):
        validate_assessment(
            Assessment(
                episode_id=agent.episode_id,
                signals=[Signal(kind="payment_coercion", evidence_ids=["ghost"], confidence=1)],
            ),
            events,
        )


def test_case_a_missing_information_is_payment_on_the_web(tmp_path):
    result = run_case("branch_payment_on_web", workspace=tmp_path)
    summary = branch_summary("branch_payment_on_web", result)
    assert summary["missing_evidence"] == ["payment_coercion"]
    assert summary["useful_read"] == {"provider": "browserbase", "resource_id": "scam_browser"}
    assert "web page" in summary["missing_information_note"]
    # The browser session carries the coercion instruction; the email follow-up does not.
    web = build_scenario("branch_payment_on_web")
    assert "safe account" in web.node("scam_browser").text
    assert "safe account" not in web.node("scam_email").text


def test_case_b_missing_information_is_payment_in_the_email(tmp_path):
    result = run_case("branch_payment_in_email", workspace=tmp_path)
    summary = branch_summary("branch_payment_in_email", result)
    assert summary["missing_evidence"] == ["payment_coercion"]
    assert summary["useful_read"] == {"provider": "gmail", "resource_id": "scam_email"}
    assert "email" in summary["missing_information_note"]
    # Flipped: the email follow-up carries the coercion instruction; the browser does not.
    email = build_scenario("branch_payment_in_email")
    assert "safe account" in email.node("scam_email").text
    assert "safe account" not in email.node("scam_browser").text


@pytest.mark.parametrize("case", PAIR)
def test_structured_trace_exposes_the_branching_decision(case, tmp_path):
    result = run_case(case, workspace=tmp_path)
    summary = branch_summary(case, result)
    for field in (
        "goal",
        "missing_evidence",
        "authorized_reads",
        "selected_next_read",
        "resulting_observation",
        "replan",
    ):
        assert field in summary and summary[field] not in (None, [], "")
    assert len(summary["authorized_reads"]) >= 2
    assert summary["selected_next_read"] in summary["authorized_reads"]
    assert summary["resulting_observation"]  # the observation the chosen read revealed
    assert "missing_evidence" in summary["replan"]


def test_paired_cases_expect_different_useful_reads():
    # The core experimental claim: changing where the missing information lives changes
    # the genuinely useful next read. Asserted on authored ground truth so it holds
    # without any model call.
    useful = {c: BRANCHING_GROUND_TRUTH[c]["useful_read"] for c in PAIR}
    assert useful["branch_payment_on_web"] != useful["branch_payment_in_email"]
    assert useful["branch_payment_on_web"]["provider"] == "browserbase"
    assert useful["branch_payment_in_email"]["provider"] == "gmail"
    assert set(BRANCHING_CASES) == set(PAIR)


@pytest.mark.parametrize("case", PAIR)
def test_deterministic_fixture_is_content_blind(case, tmp_path):
    # Documents the baseline the experiment contrasts against: the deterministic
    # fixture reasoner picks the first unseen-provider read (the browser session) in
    # BOTH cases, regardless of where the payment instruction actually lives. In case B
    # that read is not the useful one, which is precisely why a real model is needed to
    # demonstrate content-driven branching.
    result = run_case(case, workspace=tmp_path)
    summary = branch_summary(case, result)
    assert summary["selected_next_read"] == {"provider": "browserbase", "resource_id": "scam_browser"}


def test_both_paired_cases_contain_the_payment_safely(tmp_path):
    for case in PAIR:
        result = run_case(case, workspace=tmp_path / case)
        assert result["episode_state"] == "CONTAINED"
        assert result["world"]["pi_scam"] == "canceled"
        assert result["world"]["pi_unrelated"] == "requires_confirmation"
        assert result["unrelated_resource_diffs"] == []
        assert result["unauthorized_actions"] == 0


def test_branching_manifest_runs_through_existing_evaluation_machinery(tmp_path):
    # The paired cases are valid evaluation cases in the reviewed manifest schema and
    # score as correct through the unchanged fixture evaluation runner.
    report = evaluate(MANIFEST, workspace=tmp_path, repeats=1, seed=0)
    assert report.run_mode == "local_fixture"
    assert report.metrics["unique_case_count"] == 2
    assert report.metrics["total_runs"] == 2
    assert report.metrics["attacks_contained"] == 2
    assert all(row["correct"] for row in report.results)
