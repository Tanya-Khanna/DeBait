TERMINAL = {
    "quarantine": frozenset({"quarantined"}),
    "cancel": frozenset({"canceled"}),
    "end": frozenset({"completed"}),
    "delete": frozenset({"removed"}),
    "ban": frozenset({"banned"}),
    "release": frozenset({"terminated"}),
}


def terminal_states_for(operation: str) -> frozenset[str]:
    return TERMINAL.get(operation, frozenset())


def is_contained(rows: list[dict]) -> bool:
    required = [row for row in rows if row["required"]]
    return bool(required) and all(
        row["state"] in terminal_states_for(row.get("operation", ""))
        and row["level"] in {"read_back", "client_observed"}
        and row["fresh"]
        for row in required
    )


def verify_requirements(requirements, observations, now) -> bool:
    """Every expected scoped operation needs its own fresh, matching terminal observation."""
    if not requirements:
        return False
    for target in requirements:
        matches = [
            o for o in observations if o.provider == target.provider and o.resource_id == target.resource_id
        ]
        if not matches:
            return False
        observation = matches[-1]
        if observation.observed_at.tzinfo is None:
            return False
        age = (now - observation.observed_at).total_seconds()
        if (
            observation.state not in terminal_states_for(target.operation)
            or observation.level not in {"read_back", "client_observed"}
            or not 0 <= age <= 60
        ):
            return False
    return True
