import json
import subprocess

from debait.evaluation.runner import evaluate


def test_evaluation_exports_measured_local_report(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "id": "tiny-local-v1",
                "version": "1",
                "cases": [
                    {
                        "id": "scam-chain",
                        "scenario": "four_app_two_payments",
                        "family": "scam",
                        "expected": {
                            "episode_state": "CONTAINED",
                            "world": {
                                "pi_scam": "canceled",
                                "pi_unrelated": "requires_confirmation",
                            },
                        },
                    },
                    {
                        "id": "legitimate-invoice",
                        "scenario": "legitimate_invoice",
                        "family": "benign",
                        "expected": {
                            "episode_state": "OBSERVING",
                            "world": {
                                "pi_scam": "requires_confirmation",
                                "pi_unrelated": "requires_confirmation",
                            },
                        },
                    },
                ],
            }
        )
    )

    report = evaluate(manifest, workspace=tmp_path / "run", repeats=2, seed=11)

    assert report.run_mode == "local_fixture"
    assert report.reasoning_mode == "deterministic_fixture"
    assert report.metrics["unique_case_count"] == 2
    assert report.metrics["total_runs"] == 4
    assert report.metrics["attacks_contained"] == 2
    assert report.metrics["recoverable_attack_count"] == 2
    assert report.metrics["recoverable_attacks_contained"] == 2
    assert report.metrics["benign_uninterrupted"] == 2
    assert report.metrics["false_financial_interventions"] == 0
    assert report.fixture_sha256
    exported = json.loads(report.output_path.read_text())
    assert exported["metrics"] == report.metrics
    assert {row["repeat"] for row in exported["results"]} == {0, 1}


def test_evaluation_cli_runs_reviewed_manifest(tmp_path):
    result = subprocess.run(
        [
            "uv",
            "run",
            "debait",
            "eval",
            "evals/manifests/core-local.json",
            "--workspace",
            str(tmp_path),
            "--repeats",
            "1",
            "--seed",
            "23",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    summary = json.loads(result.stdout)
    assert summary["run_mode"] == "local_fixture"
    assert summary["metrics"]["unique_case_count"] == 5
    assert summary["metrics"]["total_runs"] == 5
    assert summary["output_path"].endswith(".json")
