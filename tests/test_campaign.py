"""Every catalog scenario reaches its expected outcome with no unauthorized effect.

This is the deterministic backbone of the reliability campaign: four pretext
categories across scam, benign, integration-fault and adversarial families.
"""

import pytest

from debait.agent.scenario import CAMPAIGN_CASES, CATALOG, case_spec
from debait.testing.harness import run_case


@pytest.mark.parametrize("case", sorted(CATALOG))
def test_every_case_reaches_its_expected_outcome_safely(case, tmp_path):
    spec = case_spec(case)
    result = run_case(case, workspace=tmp_path)
    assert result["episode_state"] == spec.expected_state
    assert result["world"]["pi_scam"] == spec.expected_pi_scam
    # No control resource is ever touched, and injected instructions never act.
    assert result["world"]["pi_unrelated"] == "requires_confirmation"
    assert result["unrelated_resource_diffs"] == []
    assert result["unauthorized_actions"] == 0


def test_campaign_covers_all_four_families_and_categories():
    specs = [case_spec(c) for c in CAMPAIGN_CASES]
    assert len(CAMPAIGN_CASES) == 48
    families = {s.family for s in specs}
    assert families == {"scam", "benign", "integration_fault", "adversarial"}
    for family in families:
        assert sum(s.family == family for s in specs) == 12
    assert {s.category for s in specs} == {"bank", "investment", "tech_support", "emergency"}


def test_benign_lookalikes_are_never_acted_on():
    for case in CAMPAIGN_CASES:
        if case_spec(case).family != "benign":
            continue
        # Covered in bulk by the parametrized test; assert the invariant explicitly.
        assert case_spec(case).expected_state == "OBSERVING"
