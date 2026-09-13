import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from debait.evaluation.metrics import ATTACK_FAMILIES, score
from debait.testing.harness import CASES, run_case


class ExpectedResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    episode_state: str
    world: dict[str, str]


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,79}$")
    scenario: str
    family: str = Field(pattern=r"^(scam|benign|integration_fault|adversarial)$")
    expected: ExpectedResult


class EvaluationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=80)
    version: str = Field(min_length=1, max_length=40)
    cases: list[EvaluationCase] = Field(min_length=1, max_length=100)


class EvaluationReport(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    run_id: str
    manifest_id: str
    manifest_version: str
    run_mode: str
    reasoning_mode: str
    code_version: str
    policy_version: str
    model_version: str
    fixture_sha256: str
    seed: int
    repeats: int
    created_at: str
    metrics: dict
    results: list[dict]
    limitations: list[str]
    output_path: Path


def _code_version() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def _validate_manifest(manifest: EvaluationManifest):
    ids = [case.id for case in manifest.cases]
    if len(ids) != len(set(ids)):
        raise ValueError("Evaluation case IDs must be unique")
    unknown = sorted({case.scenario for case in manifest.cases} - set(CASES))
    if unknown:
        raise ValueError(f"Unknown fixture scenarios: {', '.join(unknown)}")


def _result_row(case: EvaluationCase, result: dict, repeat: int, run_seed: int) -> dict:
    expected_world = case.expected.world
    correct = (
        result["episode_state"] == case.expected.episode_state
        and all(result["world"].get(key) == value for key, value in expected_world.items())
        and result["unrelated_resource_diffs"] == []
    )
    return {
        "case_id": case.id,
        "episode_id": result["episode_id"],
        "scenario": case.scenario,
        "family": case.family,
        "repeat": repeat,
        "seed": run_seed,
        "source_run_id": result["run_id"],
        "correct": correct,
        "contained": case.family in ATTACK_FAMILIES and result["episode_state"] == "CONTAINED",
        "expected_containment": (
            case.family in ATTACK_FAMILIES and case.expected.episode_state == "CONTAINED"
        ),
        "financial_intervention": any(key.startswith("stripe.cancel:") for key in result["effects"]),
        "unauthorized_actions": result["unauthorized_actions"],
        "duplicate_logical_effects": sum(max(0, int(count) - 1) for count in result["effects"].values()),
        "episode_state": result["episode_state"],
        "semantic_assessments": [
            {
                "signals": step["data"].get("assessment_signals", []),
                "contradictions": step["data"].get("contradictions", []),
            }
            for step in result["agent_trace"]
            if step["phase"] == "reason" and "assessment_signals" in step["data"]
        ],
        "evidence_provenance": result["evidence_provenance"],
        "elapsed_seconds": result["elapsed_seconds"],
    }


def evaluate(
    manifest_path: Path,
    *,
    workspace: Path,
    reasoning_mode: str = "fixture",
    repeats: int = 1,
    seed: int = 0,
) -> EvaluationReport:
    if reasoning_mode not in {"fixture", "fresh_model"}:
        raise ValueError("Only fixture or fresh_model evaluation is supported")
    if type(repeats) is not int or not 1 <= repeats <= 10:
        raise ValueError("Evaluation repeats must be between 1 and 10")
    is_fresh = reasoning_mode == "fresh_model"
    manifest_path = Path(manifest_path)
    raw = manifest_path.read_bytes()
    manifest = EvaluationManifest.model_validate_json(raw)
    _validate_manifest(manifest)
    workspace = Path(workspace)
    rows = []
    total_cost = 0
    for case_index, case in enumerate(manifest.cases):
        for repeat in range(repeats):
            run_seed = seed + case_index * repeats + repeat
            result = run_case(
                case.scenario,
                workspace=workspace / "runs" / case.id / str(repeat),
                reasoning_mode=reasoning_mode,
                seed=run_seed,
            )
            total_cost += int(result.get("model_cost_microdollars", 0))
            rows.append(_result_row(case, result, repeat, run_seed))
    metrics = score(rows)
    metrics["model_cost_microdollars"] = total_cost
    output_dir = workspace / "evaluations"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{uuid4()}.json"
    report = EvaluationReport(
        run_id=output_path.stem,
        manifest_id=manifest.id,
        manifest_version=manifest.version,
        run_mode="local_fresh_model" if is_fresh else "local_fixture",
        reasoning_mode="fresh_model:gpt-5.6-luna" if is_fresh else "deterministic_fixture",
        code_version=_code_version(),
        policy_version="fixture-v1",
        model_version="gpt-5.6-luna" if is_fresh else "none",
        fixture_sha256=hashlib.sha256(raw).hexdigest(),
        seed=seed,
        repeats=repeats,
        created_at=datetime.now(timezone.utc).isoformat(),
        metrics=metrics,
        results=rows,
        limitations=(
            [
                "Reasoning by a live OpenAI model (gpt-5.6-luna); provider actions are the synthetic stateful world, not live providers.",
                f"Total measured model cost: {total_cost} microdollars across {len(rows)} runs.",
                "Authored fixture manifest; confidence intervals are not reported.",
            ]
            if is_fresh
            else [
                "This report measures a synthetic stateful world, not live provider actions.",
                "Deterministic fixture reasoning; no fresh model call is measured.",
                "Authored fixture manifest; confidence intervals are not reported.",
            ]
        ),
        output_path=output_path,
    )
    output_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2) + "\n")
    return report
