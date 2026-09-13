"""The goal-directed containment loop.

Goal: contain a social-engineering episode without disrupting legitimate activity.

Each iteration the agent decides for itself whether to gather more evidence or to
intervene, based on what it currently knows and what it is still missing. It follows
only trusted cross-app links, gates every intervention through the deterministic
policy, executes through the scoped broker/worker, verifies by re-reading provider
state, and repeats until the episode is contained or must be escalated for review.
"""

import time
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict, Field

from debait.agent.reasoner import REQUIRED_MARKERS, Reasoner
from debait.agent.scenario import EDGE_KINDS, Scenario
from debait.episodes.consent import Consent
from debait.episodes.linking import payment_target
from debait.episodes.models import Edge, Event
from debait.episodes.store import EpisodeStore
from debait.protection.broker import Action
from debait.protection.policy import PolicyContext, Target, assess_semantic_evidence, decide
from debait.protection.verify import verify_requirements
from debait.protection.worker import Worker
from debait.providers.base import Observation
from debait.reasoning.client import ModelUnavailable


class AgentStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    index: int
    phase: str  # observe | reason | read | decide | act | verify | stop
    summary: str
    data: dict = Field(default_factory=dict)


class ContainmentAgent:
    def __init__(
        self,
        store: EpisodeStore,
        world,
        scenario: Scenario,
        reasoner: Reasoner,
        *,
        episode_id: str,
        account_id: str = "test",
        clock=time.time,
        max_iterations: int = 16,
    ):
        if not 1 <= max_iterations <= 64:
            raise ValueError("max_iterations must be between 1 and 64")
        self.store = store
        self.world = world
        self.scenario = scenario
        self.reasoner = reasoner
        self.episode_id = episode_id
        self.account_id = account_id
        self.clock = clock
        self.max_iterations = max_iterations
        self.worker = Worker(store, world)
        self.observed: set[str] = set()
        self.allowed: set[str] = set()
        self.link_parent: dict[str, str] = {}
        self.event_ids: dict[str, str] = {}
        self.scam_targets: list[Target] = []
        self.acted: set[str] = set()
        self.prevention_failed = False
        self.trace: list[AgentStep] = []
        self._base = datetime.now(timezone.utc)
        self._offset = 0

    # -- trace helpers -----------------------------------------------------

    def _step(self, phase: str, summary: str, **data) -> None:
        step = AgentStep(index=len(self.trace), phase=phase, summary=summary, data=data)
        self.trace.append(step)
        self.store.record_agent_step(self.episode_id, step.model_dump())

    def _next_time(self) -> datetime:
        self._offset += 1
        return self._base + timedelta(seconds=self._offset)

    # -- observation / evidence gathering ----------------------------------

    def _ingest(self, provider: str, resource_id: str, payload: dict) -> str:
        event_id = f"{self.episode_id}:{resource_id}"
        self.store.ingest(
            Event(
                event_id=event_id,
                provider=provider,
                provider_event_id=event_id,
                episode_id=self.episode_id,
                observed_at=self._next_time(),
                received_at=datetime.now(timezone.utc),
                payload={"resource_id": resource_id, "account_id": self.account_id, **payload},
            )
        )
        self.event_ids[resource_id] = event_id
        return event_id

    def _edge(self, source: str, target: str, kind: str) -> None:
        self.store.add_edge(
            Edge(
                source_id=self.event_ids[source],
                target_id=self.event_ids[target],
                kind=kind,
                confidence=1,
                provenance_event_ids=[self.event_ids[source], self.event_ids[target]],
            )
        )

    def _grant_consent(self) -> None:
        # Represents the owner's standing opt-in for their own resources. An attacker
        # cannot reach this path; scope only ever contains agent-bound trusted targets.
        self.store.save_consent(
            Consent(
                episode_id=self.episode_id,
                scope=frozenset((t.provider, t.resource_id, t.operation) for t in self.scam_targets),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )

    def observe(self, resource_id: str) -> None:
        node = self.scenario.node(resource_id)
        payload = {"text": node.text, "scenario_mode": "local"}
        if node.transcript_source:
            payload["transcript_source"] = node.transcript_source
        payload.update(node.extra_payload)
        self._ingest(node.provider, resource_id, payload)
        parent = self.link_parent.get(resource_id)
        if parent is not None:
            self._edge(parent, resource_id, EDGE_KINDS[node.provider])
        target = Target(provider=node.provider, resource_id=resource_id, operation=node.operation)
        self.store.bind_resource(self.episode_id, target, self.account_id, [self.event_ids[resource_id]])
        if node.provider == "stripe":
            if payment_target(self.store, self.episode_id, self.event_ids[resource_id]) == target:
                self.scam_targets.append(target)
        else:
            self.scam_targets.append(target)
        if node.ban_actor:
            self._ingest("driver", node.ban_actor, {"role": "designated_test_actor"})
            self._edge(resource_id, node.ban_actor, "inferred_actor")
            actor = Target(provider="telegram", resource_id=node.ban_actor, operation="ban")
            self.store.bind_resource(
                self.episode_id, actor, self.account_id, [self.event_ids[node.ban_actor]]
            )
            self.scam_targets.append(actor)
        self._grant_consent()
        self.observed.add(resource_id)
        for linked in node.links:
            self.allowed.add(linked)
            self.link_parent.setdefault(linked, resource_id)

    # -- state / verification ----------------------------------------------

    def _last_observations(self) -> dict[str, Observation]:
        latest: dict[str, Observation] = {}
        for history in self.store.action_history(self.episode_id):
            if history["observations"]:
                obs = Observation.model_validate(history["observations"][-1])
                latest[obs.resource_id] = obs
        return latest

    async def _payment_state(self) -> str | None:
        """Observe the live state of any bound payment before deciding to cancel it.

        This is what lets the agent withhold a pointless cancel when the money has
        already moved, and escalate honestly instead of claiming a false success.
        """
        for target in self.scam_targets:
            if target.provider == "stripe" and target.resource_id in self.observed:
                observation = await self.world.read(target.resource_id)
                return observation.state
        return None

    def _job_statuses(self) -> list[str]:
        with self.store.connection() as db:
            rows = db.execute(
                "SELECT j.status FROM action_jobs j JOIN actions a USING(action_id) WHERE a.episode_id=?",
                (self.episode_id,),
            ).fetchall()
        return [row["status"] for row in rows]

    def _finalize_state(self, signals: set[str], escalate: bool) -> str:
        statuses = self._job_statuses()
        observations = list(self._last_observations().values())
        if escalate:
            state = "REVIEW_REQUIRED"
        elif self.prevention_failed or "prevention_failed" in statuses:
            state = "PREVENTION_FAILED"
        elif (
            self.scam_targets
            and statuses
            and all(status == "verified" for status in statuses)
            and verify_requirements(self.scam_targets, observations, datetime.now(timezone.utc))
        ):
            state = "CONTAINED"
        elif statuses:
            state = "PARTIALLY_CONTAINED"
        elif REQUIRED_MARKERS <= signals or signals:
            state = "SUSPICIOUS"
        else:
            state = "OBSERVING"
        self.store.set_state(self.episode_id, state)
        return state

    async def _drain(self, budget: int = 12) -> None:
        for _ in range(budget):
            if await self.worker.run_once() == 0:
                break

    def _contain(self, actions: list[Target]) -> list[str]:
        enqueued = []
        for target in actions:
            action_id = f"{self.episode_id}:{target.resource_id}:{target.operation}"
            if action_id in self.acted:
                continue
            self.worker.queue.enqueue(
                Action(
                    action_id=action_id,
                    episode_id=self.episode_id,
                    target=target,
                    policy_version="fixture-v1",
                ),
                now=self.clock(),
            )
            self.acted.add(action_id)
            enqueued.append(f"{target.provider}.{target.operation}:{target.resource_id}")
        return enqueued

    # -- the loop ----------------------------------------------------------

    async def run(self) -> list[AgentStep]:
        self.observe(self.scenario.entry)
        entry_node = self.scenario.node(self.scenario.entry)
        self._step(
            "observe", f"Observed {entry_node.provider} {self.scenario.entry}", resource=self.scenario.entry
        )
        signals: set[str] = set()
        escalate = False
        for _ in range(self.max_iterations):
            events = self.store.events(self.episode_id)
            pending = self.allowed - self.observed
            allowed_reads = frozenset((self.scenario.provider_of(r), r) for r in pending)
            try:
                assessment = await self.reasoner.assess(events, allowed_reads=allowed_reads)
            except ModelUnavailable as exc:
                # A failed semantic step grants no authority. Preserve observed evidence and
                # any earlier verified effects, then stop before policy or queue dispatch.
                self.store.set_state(self.episode_id, "REVIEW_REQUIRED")
                self._step(
                    "reason",
                    "Model reasoning unavailable or invalid; autonomous writes withheld",
                    outcome="model_unavailable",
                    reason_code="model_reasoning_unavailable",
                    error_type=type(exc).__name__,
                    detail=str(exc),
                    newly_authorized_actions=0,
                )
                escalate = True
                break
            signals = {signal.kind for signal in assessment.signals}
            semantic_evidence = assess_semantic_evidence(assessment, events)
            sufficient = semantic_evidence.sufficient
            self._step(
                "reason",
                f"{len(signals)}/{len(REQUIRED_MARKERS)} markers; {'sufficient' if sufficient else 'insufficient'} to intervene",
                signals=sorted(signals),
                assessment_signals=[signal.model_dump() for signal in assessment.signals],
                contradictions=list(assessment.contradictions),
                missing=assessment.missing_evidence,
                sufficient=sufficient,
                semantic_evidence=semantic_evidence.model_dump(),
            )
            if sufficient and self.scam_targets:
                payment_state = await self._payment_state()
                decision = decide(
                    PolicyContext(
                        phase="HIGH_RISK",
                        sufficient_evidence=True,
                        consent_valid=True,
                        trusted_targets=list(self.scam_targets),
                        payment_state=payment_state,
                    )
                )
                if decision.next_state == "PREVENTION_FAILED":
                    self.prevention_failed = True
                if decision.next_state == "REVIEW_REQUIRED":
                    escalate = True
                    self._step("decide", "Policy withheld action: " + decision.reason)
                else:
                    self.store.set_state(self.episode_id, decision.next_state)
                    enqueued = self._contain(decision.actions)
                    if enqueued:
                        self._step(
                            "decide",
                            f"Policy authorized {len(enqueued)} scoped action(s): " + decision.reason,
                            actions=enqueued,
                        )
                        await self._drain()
                        verified = {rid: obs.level for rid, obs in self._last_observations().items()}
                        self._step(
                            "verify",
                            "Re-read provider state after intervention",
                            verification=verified,
                            effects=dict(self.world.effects),
                        )
                    elif self.prevention_failed:
                        self._step(
                            "decide",
                            "Payment already settled; withholding cancel: " + decision.reason,
                            payment_state=payment_state,
                        )
            else:
                await self._drain()

            pending = self.allowed - self.observed
            if pending and not escalate:
                choice = None
                if assessment.next_read and assessment.next_read.resource_id in pending:
                    choice = assessment.next_read.resource_id
                else:
                    choice = sorted(pending)[0]
                self.observe(choice)
                node = self.scenario.node(choice)
                self._step(
                    "read",
                    f"Retrieved {node.provider} {choice} to resolve missing evidence",
                    resource=choice,
                )
                continue
            if REQUIRED_MARKERS <= signals and not sufficient:
                decision = decide(
                    PolicyContext(
                        phase="HIGH_RISK",
                        sufficient_evidence=False,
                        consent_valid=True,
                        trusted_targets=list(self.scam_targets),
                    )
                )
                escalate = decision.next_state == "REVIEW_REQUIRED"
                self._step(
                    "decide",
                    "Policy withheld action: " + semantic_evidence.reason,
                    semantic_evidence=semantic_evidence.model_dump(),
                    actions=[],
                )
            break
        state = self._finalize_state(signals, escalate)
        self._step("stop", f"Episode {state}", state=state)
        return self.trace
