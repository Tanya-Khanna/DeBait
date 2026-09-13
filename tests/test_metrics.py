from debait.evaluation.metrics import score


def test_metrics_use_explicit_attack_and_benign_denominators():
    rows = [
        {
            "case_id": "scam-1",
            "family": "scam",
            "correct": True,
            "contained": True,
            "expected_containment": True,
            "financial_intervention": True,
            "unauthorized_actions": 0,
            "duplicate_logical_effects": 0,
            "elapsed_seconds": 1.0,
        },
        {
            "case_id": "benign-1",
            "family": "benign",
            "correct": False,
            "contained": False,
            "expected_containment": False,
            "financial_intervention": True,
            "unauthorized_actions": 0,
            "duplicate_logical_effects": 0,
            "elapsed_seconds": 2.0,
        },
    ]

    metrics = score(rows)

    assert metrics["unique_case_count"] == 2
    assert metrics["total_runs"] == 2
    assert metrics["attack_count"] == 1
    assert metrics["attacks_contained"] == 1
    assert metrics["recoverable_attack_count"] == 1
    assert metrics["recoverable_attacks_contained"] == 1
    assert metrics["benign_count"] == 1
    assert metrics["false_financial_interventions"] == 1
    assert metrics["unauthorized_effects"] == 0
    assert metrics["median_containment_seconds"] == 1.0
