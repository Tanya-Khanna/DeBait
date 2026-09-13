"""Resolve payment targets from stored, trusted origin edges, never amount or model prose."""

from debait.protection.policy import Target


def payment_target(store, episode_id: str, event_id: str) -> Target | None:
    events = {e.event_id: e for e in store.events(episode_id)}
    event = events.get(event_id)
    if event is None or event.provider != "stripe":
        return None
    resource = event.payload.get("resource_id")
    account = event.payload.get("account_id")
    if not isinstance(resource, str) or not isinstance(account, str):
        return None
    target = Target(provider="stripe", resource_id=resource, operation="cancel")
    binding = store.binding(episode_id, target)
    if not binding or binding["account_id"] != account:
        return None
    for edge in store.edges(episode_id):
        source = events.get(edge.source_id)
        if (
            edge.target_id == event_id
            and edge.kind == "observed_payment_origin"
            and edge.confidence == 1
            and source is not None
            and source.provider in {"browserbase", "telegram"}
            and {edge.source_id, event_id} <= set(edge.provenance_event_ids)
        ):
            return target
    return None
