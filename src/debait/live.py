"""Thin live composition layer for one pre-registered multi-provider episode."""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from debait.episodes.consent import Consent, permits
from debait.episodes.linking import payment_target
from debait.episodes.models import Edge, Event
from debait.protection.broker import Action, Broker
from debait.protection.policy import PolicyContext, Target, assess_semantic_evidence, decide
from debait.protection.verify import verify_requirements
from debait.protection.worker import Worker
from debait.providers.base import Observation, ProviderStateChanged, RetryAfter
from debait.reasoning.assess import validate_assessment
from debait.reasoning.client import ModelUnavailable

ProviderName = Literal["gmail", "twilio", "telegram", "browserbase", "stripe"]
EdgeKind = Literal["inferred_actor", "observed_navigation", "observed_payment_origin", "channel_migration"]
ResourceRole = Literal["target", "control"]


class LiveResource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    provider: ProviderName
    resource_id: str = Field(min_length=1, max_length=200)
    account_id: str = Field(min_length=1, max_length=256)
    operation: str = Field(min_length=1, max_length=40)
    parent_provider: ProviderName | None = None
    parent_resource_id: str | None = None
    edge_kind: EdgeKind | None = None
    role: ResourceRole = "target"

    @model_validator(mode="after")
    def complete_parent(self):
        values = (self.parent_provider, self.parent_resource_id, self.edge_kind)
        if any(value is not None for value in values) and not all(value is not None for value in values):
            raise ValueError("Live resource parent provenance must be complete")
        if self.role == "control" and self.operation != "observe":
            raise ValueError("Control resources must use operation 'observe'")
        return self

    @property
    def key(self) -> tuple[str, str]:
        return self.provider, self.resource_id

    @property
    def parent_key(self) -> tuple[str, str] | None:
        if self.parent_provider is None:
            return None
        return self.parent_provider, self.parent_resource_id

    @property
    def target(self) -> Target:
        return Target(provider=self.provider, resource_id=self.resource_id, operation=self.operation)


class LiveRunResult(BaseModel):
    state: str
    episode_id: str
    observed_resources: list[str]
    actions: list[dict]
    verification: dict[str, str]
    control_payment_before: str | None = None
    control_payment_after: str | None = None
    control_payment_unchanged: bool | None = None
    failure_reason: str | None = None


class LiveEpisodeRunner:
    """Compose existing adapters, policy, durable worker and verifier for live resources."""

    def __init__(
        self,
        store,
        router,
        resources: list[LiveResource],
        reasoner,
        *,
        episode_id: str,
        clock=time.time,
        max_iterations: int = 32,
        drain_timeout_seconds: float = 20,
    ):
        if not resources:
            raise ValueError("At least one live resource is required")
        if not 1 <= max_iterations <= 64 or not 0 <= drain_timeout_seconds <= 30:
            raise ValueError("Live runner bounds are invalid")
        self.store = store
        self.router = router
        self.reasoner = reasoner
        self.episode_id = episode_id
        self.clock = clock
        self.max_iterations = max_iterations
        self.drain_timeout_seconds = drain_timeout_seconds
        self.worker = Worker(store, router, clock=clock)
        self.resources = list(resources)
        self._resources = {resource.key: resource for resource in resources}
        if len(self._resources) != len(resources):
            raise ValueError("Live resource identities must be unique per provider")
        roots = [
            resource for resource in resources if resource.parent_key is None and resource.role != "control"
        ]
        if len(roots) != 1:
            raise ValueError("A live episode requires exactly one entry resource")
        self.entry = roots[0].key
        for resource in resources:
            if resource.provider not in router.providers():
                raise PermissionError(f"No adapter is registered for {resource.provider!r}")
            if resource.role == "control":
                if resource.operation != "observe":
                    raise PermissionError("Live control resource must specify 'observe' operation")
            elif resource.operation not in Broker.ALLOWED.get(resource.provider, set()):
                raise PermissionError("Live resource operation is outside broker policy")
            if resource.parent_key is not None and resource.parent_key not in self._resources:
                raise ValueError("Live resource parent is not registered")
        self.observed: set[tuple[str, str]] = set()
        self.event_ids: dict[tuple[str, str], str] = {}
        self.eligible_targets: set[Target] = set()
        self.acted_targets: set[Target] = set()
        self.trace: list[dict] = []
        prior_trace = self.store.agent_trace(self.episode_id)
        self.trace_offset = prior_trace[-1]["index"] + 1 if prior_trace else 0
        self.registered = False
        self.prevention_failed = False

    def _step(self, phase: str, summary: str, **data):
        step = {
            "index": self.trace_offset + len(self.trace),
            "phase": phase,
            "summary": summary,
            "data": data,
        }
        self.trace.append(step)
        self.store.record_agent_step(self.episode_id, step)

    def _registration_event(self, resource: LiveResource) -> Event:
        identity = json.dumps(
            [self.episode_id, resource.provider, resource.resource_id, resource.operation],
            separators=(",", ":"),
        )
        digest = hashlib.sha256(identity.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        return Event(
            event_id=f"{self.episode_id}:binding:{digest[:24]}",
            provider="driver",
            provider_event_id=f"live-binding:{digest}",
            episode_id=self.episode_id,
            observed_at=now,
            received_at=now,
            payload={
                "resource_id": resource.resource_id,
                "account_id": resource.account_id,
                "registered_provider": resource.provider,
                "operation": resource.operation,
                "provenance": "trusted_live_registration",
            },
        )

    async def register(self):
        if self.registered:
            return
        for resource in self.resources:
            event = self._registration_event(resource)
            self.store.ingest(event)
            self.store.bind_resource(
                self.episode_id,
                resource.target,
                resource.account_id,
                [event.event_id],
            )
        scope = frozenset(
            (resource.provider, resource.resource_id, resource.operation)
            for resource in self.resources
            if resource.role != "control"
        )
        current = self.store.consent(self.episode_id)
        now = datetime.now(timezone.utc)
        if current is None or current.scope != scope or current.expires_at <= now:
            self.store.save_consent(
                Consent(
                    episode_id=self.episode_id,
                    scope=scope,
                    expires_at=now + timedelta(hours=1),
                )
            )
        for history in self.store.action_history(self.episode_id):
            self.acted_targets.add(Target.model_validate(history["target"]))
        self.registered = True

    def _normalized_payload(self, observation) -> dict:
        details = observation.details
        text_parts = []
        text_fields = ("subject", "snippet", "body", "text")
        for field in text_fields:
            value = details.get(field)
            if isinstance(value, str) and value.strip():
                text_parts.append(value.strip())
        return {
            "resource_id": observation.resource_id,
            "account_id": observation.account_id,
            "state": observation.state,
            "level": observation.level,
            "text": "\n".join(text_parts)[:16384],
            "provider_metadata": {key: value for key, value in details.items() if key not in text_fields},
            "observation_source": observation.source,
            "provenance": "provider_read",
        }

    async def read_registered(self, provider: str, resource_id: str) -> Observation:
        if not self.registered:
            await self.register()
        key = (provider, resource_id)
        resource = self._resources.get(key)
        if resource is None or self.store.binding(self.episode_id, resource.target) is None:
            raise PermissionError("Live reads require an exact registered and bound resource")
        observation = await self.router.read(provider, resource_id)
        self._validate_observation(resource, observation)
        return observation

    async def observe(self, provider: str, resource_id: str) -> Event:
        observation = await self.read_registered(provider, resource_id)
        key = (provider, resource_id)
        resource = self._resources[key]
        payload = self._normalized_payload(observation)
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        event = Event(
            event_id=f"{self.episode_id}:{provider}:{digest[:24]}",
            provider=provider,
            provider_event_id=f"provider-read:{digest}",
            episode_id=self.episode_id,
            observed_at=observation.observed_at,
            received_at=datetime.now(timezone.utc),
            payload=payload,
        )
        self.store.ingest(event)
        self.observed.add(key)
        self.event_ids[key] = event.event_id
        if resource.parent_key is not None:
            parent_event_id = self.event_ids.get(resource.parent_key)
            if parent_event_id is None:
                raise PermissionError("Live resource was read before its trusted parent")
            self.store.add_edge(
                Edge(
                    source_id=parent_event_id,
                    target_id=event.event_id,
                    kind=resource.edge_kind,
                    confidence=1,
                    provenance_event_ids=[parent_event_id, event.event_id],
                )
            )
        if resource.role != "control":
            if provider == "stripe":
                if payment_target(self.store, self.episode_id, event.event_id) == resource.target:
                    self.eligible_targets.add(resource.target)
            else:
                self.eligible_targets.add(resource.target)
        self._step(
            "observe",
            f"Read bound {provider} resource from provider",
            provider=provider,
            resource_id=resource_id,
            event_id=event.event_id,
            source=observation.source,
            state=observation.state,
        )
        return event

    @staticmethod
    def _validate_observation(resource: LiveResource, observation: Observation) -> None:
        if (
            observation.provider != resource.provider
            or observation.resource_id != resource.resource_id
            or observation.account_id != resource.account_id
            or observation.observed_at.tzinfo is None
        ):
            raise PermissionError("Live provider observation identity mismatch")

    async def _preflight(self) -> None:
        """Prove every configured resource is readable before any live mutation."""
        for resource in self.resources:
            observation = await self.read_registered(resource.provider, resource.resource_id)
            if resource.target in self.acted_targets:
                action_id = (
                    f"{self.episode_id}:{resource.provider}:{resource.resource_id}:{resource.operation}"
                )
                self.store.record_observation(action_id, observation)

    def _ready_reads(self) -> frozenset[tuple[str, str]]:
        return frozenset(
            resource.key
            for resource in self.resources
            if resource.role != "control"
            and resource.key not in self.observed
            and (resource.parent_key is None or resource.parent_key in self.observed)
        )

    async def _payment_state(self) -> str | None:
        for target in self.eligible_targets:
            if target.provider == "stripe":
                return (await self.read_registered(target.provider, target.resource_id)).state
        return None

    def _enqueue(self, targets: list[Target]) -> list[str]:
        enqueued = []
        for target in targets:
            if target in self.acted_targets:
                continue
            action_id = f"{self.episode_id}:{target.provider}:{target.resource_id}:{target.operation}"
            self.worker.queue.enqueue(
                Action(
                    action_id=action_id,
                    episode_id=self.episode_id,
                    target=target,
                    policy_version="critical_cross_app_scam_v1",
                ),
                now=self.clock(),
            )
            self.acted_targets.add(target)
            enqueued.append(f"{target.provider}.{target.operation}:{target.resource_id}")
        return enqueued

    async def _drain(self):
        deadline = time.monotonic() + self.drain_timeout_seconds
        for _ in range(128):
            if await self.worker.run_once():
                continue
            statuses = self._job_statuses()
            if any(status in {"pending", "retry", "running"} for status in statuses):
                if time.monotonic() < deadline:
                    await asyncio.sleep(min(0.25, max(0, deadline - time.monotonic())))
                    continue
            break

    def _job_statuses(self) -> list[str]:
        with self.store.connection() as db:
            rows = db.execute(
                "SELECT j.status FROM action_jobs j JOIN actions a USING(action_id) "
                "WHERE a.episode_id=? ORDER BY a.action_id",
                (self.episode_id,),
            ).fetchall()
        return [row["status"] for row in rows]

    def _verification(self) -> dict[str, str]:
        result = {}
        for action in self.store.action_history(self.episode_id):
            if action["observations"]:
                target = action["target"]
                result[f"{target['provider']}:{target['resource_id']}"] = action["observations"][-1]["state"]
        return result

    def _final_state(self, review: bool) -> str:
        statuses = self._job_statuses()
        history = self.store.action_history(self.episode_id)
        observations = [action["observations"][-1] for action in history if action["observations"]]
        parsed = [Observation.model_validate(observation) for observation in observations]
        if review:
            state = "REVIEW_REQUIRED"
        elif self.prevention_failed or "prevention_failed" in statuses:
            state = "PREVENTION_FAILED"
        elif (
            statuses
            and all(status == "verified" for status in statuses)
            and verify_requirements(
                [resource.target for resource in self.resources if resource.role != "control"],
                parsed,
                datetime.now(timezone.utc),
            )
        ):
            state = "CONTAINED"
        elif statuses:
            state = "PARTIALLY_CONTAINED"
        else:
            state = "REVIEW_REQUIRED"
        self.store.set_state(self.episode_id, state)
        return state

    async def run(self, *, control_payment: tuple[str, str] | None = None) -> LiveRunResult:
        await self.register()
        review = False
        failure_reason = None
        control_before = None
        control_after = None
        target_keys = {resource.key for resource in self.resources if resource.role != "control"}
        try:
            if control_payment is not None:
                resource = self._resources.get(control_payment)
                if resource is None or resource.role != "control":
                    raise PermissionError("Control payment must be a registered control resource")
                control_before = (await self.read_registered(*control_payment)).state
            await self._preflight()
            await self.observe(*self.entry)
            for _ in range(self.max_iterations):
                events = self.store.events(self.episode_id)
                allowed_reads = self._ready_reads()
                try:
                    assessment = await self.reasoner.assess(events, allowed_reads=allowed_reads)
                    assessment = validate_assessment(
                        assessment,
                        events,
                        allowed_reads=allowed_reads,
                    )
                except ModelUnavailable as exc:
                    review = True
                    failure_reason = str(exc)
                    self._step(
                        "reason",
                        "Model reasoning unavailable or invalid; autonomous writes withheld",
                        outcome="model_unavailable",
                        reason_code="model_reasoning_unavailable",
                        error_type=type(exc).__name__,
                        detail=str(exc),
                        newly_authorized_actions=0,
                    )
                    break
                except (ValueError, TypeError, AttributeError) as exc:
                    review = True
                    failure_reason = "Model assessment failed deterministic scope validation"
                    self._step(
                        "reason",
                        failure_reason,
                        outcome="invalid_assessment",
                        error_type=type(exc).__name__,
                        newly_authorized_actions=0,
                    )
                    break
                semantic = assess_semantic_evidence(assessment, events)
                self._step(
                    "reason",
                    semantic.reason,
                    assessment_signals=[signal.model_dump() for signal in assessment.signals],
                    contradictions=list(assessment.contradictions),
                    semantic_evidence=semantic.model_dump(),
                    sufficient=semantic.sufficient,
                )
                if semantic.sufficient and self.eligible_targets:
                    consent = self.store.consent(self.episode_id)
                    now = datetime.now(timezone.utc)
                    targets = sorted(
                        self.eligible_targets,
                        key=lambda target: (target.provider != "stripe", target.provider, target.resource_id),
                    )
                    decision = decide(
                        PolicyContext(
                            phase="HIGH_RISK",
                            sufficient_evidence=True,
                            consent_valid=bool(
                                consent
                                and all(
                                    permits(
                                        consent,
                                        target.provider,
                                        target.resource_id,
                                        target.operation,
                                        now,
                                    )
                                    for target in targets
                                )
                            ),
                            trusted_targets=targets,
                            payment_state=await self._payment_state(),
                        )
                    )
                    if decision.next_state == "REVIEW_REQUIRED":
                        review = True
                        failure_reason = decision.reason
                        self._step("decide", "Policy withheld action: " + decision.reason, actions=[])
                        break
                    if decision.next_state == "PREVENTION_FAILED":
                        self.prevention_failed = True
                    self.store.set_state(self.episode_id, decision.next_state)
                    enqueued = self._enqueue(decision.actions)
                    pending = any(
                        status in {"pending", "retry", "running"} for status in self._job_statuses()
                    )
                    if enqueued or pending:
                        self._step("decide", decision.reason, actions=enqueued)
                        await self._drain()
                        self._step(
                            "verify",
                            "Loaded persisted provider read-back observations",
                            verification=self._verification(),
                            job_statuses=self._job_statuses(),
                        )
                ready = self._ready_reads()
                if ready:
                    choice = None
                    if assessment.next_read is not None:
                        proposed = (assessment.next_read.provider, assessment.next_read.resource_id)
                        if proposed in ready:
                            choice = proposed
                    if choice is None:
                        choice = sorted(ready)[0]
                    await self.observe(*choice)
                    continue
                if not target_keys <= self.observed:
                    review = True
                    failure_reason = "No authorized read can advance the registered evidence graph"
                elif not semantic.sufficient:
                    review = True
                    failure_reason = semantic.reason
                break
        except (PermissionError, ConnectionError, ProviderStateChanged, RetryAfter) as exc:
            review = True
            failure_reason = f"Live provider observation failed: {type(exc).__name__}"
            self._step(
                "observe",
                failure_reason,
                provider_error=type(exc).__name__,
                newly_authorized_actions=0,
            )
        if control_payment is not None:
            try:
                control_after = (await self.read_registered(*control_payment)).state
                if control_before is not None and control_after != control_before:
                    review = True
                    failure_reason = "Control payment state changed unexpectedly"
            except (PermissionError, ConnectionError, ProviderStateChanged, RetryAfter) as exc:
                review = True
                failure_reason = f"Control-payment verification failed: {type(exc).__name__}"
        state = self._final_state(review)
        self._step("stop", f"Episode {state}", state=state, failure_reason=failure_reason)
        return LiveRunResult(
            state=state,
            episode_id=self.episode_id,
            observed_resources=[
                f"{provider}:{resource_id}" for provider, resource_id in sorted(self.observed)
            ],
            actions=self.store.action_history(self.episode_id),
            verification=self._verification(),
            control_payment_before=control_before,
            control_payment_after=control_after,
            control_payment_unchanged=(
                control_before == control_after if control_payment is not None else None
            ),
            failure_reason=failure_reason,
        )
