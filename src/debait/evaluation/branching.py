"""Project the branching next-read decision out of an existing per-case agent trace.

This is a read-only *view* over the trace the containment loop already records in
`result["agent_trace"]` (see agent/loop.py) plus the scenario topology — it is not a
second tracing system and it never runs the agent itself. It exists so the paired
Step-15 experiment can point at one structured object per case that makes the branch
visible: the goal, what evidence is still missing, the two (or more) authorized reads
available at the same reasoning step, which one was actually selected, what that read
revealed, and how the agent re-planned afterwards.

The "useful read" for each paired case is authored ground truth: the read that
resolves the missing payment-coercion instruction given where that instruction lives
(a web page vs. an emailed reply). A deterministic fixture reasoner is content-blind
and picks the same read in both cases; a fresh model that reads the chat pointer is
expected to pick the useful read, which flips between the pair. Comparing the actual
`selected_next_read` against `useful_read` is what the experiment measures.
"""

from debait.agent.scenario import build_scenario

# The standing containment objective for these episodes (see agent/loop.py docstring).
GOAL = "Prevent scam-linked financial loss without disrupting legitimate activity"

# Authored ground truth for the paired branching cases. `useful_read` is the read that
# actually resolves the missing payment-coercion instruction for that case.
BRANCHING_GROUND_TRUTH: dict[str, dict] = {
    "branch_payment_on_web": {
        "pointer": "the coercion instruction is on a linked web page",
        "useful_read": {"provider": "browserbase", "resource_id": "scam_browser"},
    },
    "branch_payment_in_email": {
        "pointer": "the coercion instruction is in a follow-up email",
        "useful_read": {"provider": "gmail", "resource_id": "scam_email"},
    },
}


def _read(step: dict) -> dict:
    """Compact projection of a reason step's re-plan."""
    data = step.get("data", {})
    return {
        "summary": step.get("summary", ""),
        "signals": data.get("signals", []),
        "missing_evidence": data.get("missing", []),
        "sufficient": data.get("sufficient"),
    }


def branch_summary(scenario_name: str, result: dict) -> dict:
    """Return the structured branching decision for a completed run.

    `result` is the dict returned by `testing.harness.run_case`. The scenario supplies
    provider/link topology; the trace supplies the actual, ordered decisions. Raises
    ValueError if the run never reached a step with two or more authorized reads.
    """
    scenario = build_scenario(scenario_name)
    trace = result["agent_trace"]
    ground_truth = BRANCHING_GROUND_TRUTH.get(scenario_name, {})

    observed: list[str] = []
    allowed: set[str] = set()
    last_reason: dict | None = None
    branch: dict | None = None

    for step in trace:
        phase = step["phase"]
        if phase == "reason":
            if branch is not None and branch.get("replan") is None:
                branch["replan"] = _read(step)
            last_reason = step
            continue
        if phase in ("observe", "read"):
            rid = step["data"].get("resource")
            if rid is None:
                continue
            pending = allowed - set(observed)
            if branch is None and phase == "read" and rid in pending and len(pending) >= 2:
                branch = {
                    "reason_step": last_reason,
                    "authorized_reads": sorted(pending),
                    "selected": rid,
                    "replan": None,
                }
            observed.append(rid)
            for linked in scenario.node(rid).links:
                allowed.add(linked)

    if branch is None:
        raise ValueError(f"Run for {scenario_name!r} never reached a branching step")

    reason_data = (branch["reason_step"] or {}).get("data", {})
    selected = branch["selected"]

    def _ref(rid: str) -> dict:
        return {"provider": scenario.node(rid).provider, "resource_id": rid}

    return {
        "scenario": scenario_name,
        "goal": GOAL,
        "current_evidence": {
            "observed_resources": [_ref(r) for r in observed[: observed.index(selected)]],
            "signals": reason_data.get("signals", []),
        },
        "missing_evidence": reason_data.get("missing", []),
        "authorized_reads": [_ref(r) for r in branch["authorized_reads"]],
        "selected_next_read": _ref(selected),
        "resulting_observation": scenario.node(selected).text,
        "replan": branch["replan"],
        # Authored ground truth for the paired experiment (not derived from the run).
        "useful_read": ground_truth.get("useful_read"),
        "missing_information_note": ground_truth.get("pointer"),
    }
