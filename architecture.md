# DeBait architecture

DeBait is one goal-directed agent that owns a self-directed loop — observe evidence, reason, decide whether to gather more evidence or intervene, gate each action through deterministic policy, verify by re-reading provider state, and adapt until the incident is contained or escalated. The local system implementing this loop is built: the DeBait agent, durable episode store, semantic reasoner, deterministic policy and scoped broker, independent verifier, four provider adapters (behind mock transports), the decoy investigator and the evaluation harness all run and are tested. Not yet implemented: live provider actions against real test accounts, and a fresh (paid) model reasoning run — both are gated on credentials and are called out honestly wherever they appear. All payloads in the companion interactive diagram are illustrative; no provider requests are executed by the diagram.

Open `architecture.html` directly in a browser. Select a flow, use Previous/Next or the arrow keys, click a participating node to jump to its first step, or press Space to play the sequence. Theme, fullscreen, and node dragging are supported. There are no external font, script, or API requests.

## Components

| Component | Responsibility |
|---|---|
| **DeBait agent (incident orchestrator)** | Owns the self-directed loop; on each iteration decides whether to retrieve more evidence or intervene, invokes the reasoner, policy, broker and verifier as tools, and continues until contained or escalated. It never selects targets from attacker content — that authority lives in policy and trusted-edge linking |
| Twilio adapter | Ingest authorized call evidence, end the bound call, retrieve status |
| Telegram adapter | Observe an authorized test chat, preserve evidence, delete designated messages, enforce separately authorized membership actions |
| Browserbase adapter | Open a message-linked owned test page, record navigation, release and inspect the managed session |
| Stripe adapter | Inspect and cancel the bound eligible sandbox PaymentIntent; never create or capture payments from the defender |
| Event intake | Authenticate source scope, normalize events, and persist before acknowledgment |
| Episode store | SQLite event log, source provenance, observed/inferred relationships, decisions, action ledger, and verification observations |
| Reasoner | Structured evidence interpretation and bounded recommendations without write credentials |
| Action broker | Deterministic authorization, trusted target resolution, state checks, and durable action dispatch |
| Verifier | Independent retrieval and reconciliation, including uncertain and partial results |
| Workspace | Local operator interface for episodes, evidence, explanations, actions, and evaluation results |
| Decoy investigator | Separate controlled investigation after victim-facing containment |
| ScamGym | Stateful evaluation worlds, fault injection, adaptive adversaries, reviewed expectations, ablations, and regression comparisons |

## Walkthroughs

### Agent decision loop

This is the loop the DeBait agent actually runs; the other walkthroughs are views of it.

1. **Observe** — pull the next authorized piece of evidence the agent is still missing, following only trusted cross-app links. This is a decision, not a fixed provider order.
2. **Reason** — interpret the accumulated evidence; surface contradictions, missing evidence, and a bounded next read. Content is treated as data and can never grant authority.
3. **Decide** — choose to gather more evidence, intervene now, or escalate for review, based on whether the evidence threshold is met.
4. **Policy gate** — authorize each proposed action against trusted scope and exact bindings; an injected or unlinked target is refused.
5. **Act** — contain the exact linked resources. If the attack is clear before a payment exists, act on the live call/chat/browser and do not wait on Stripe.
6. **Verify** — re-read external state; an API acknowledgment is not a verified outcome. Levels: requested, acknowledged, read-back, client-observed.
7. **Adapt** — reconcile uncertain or partial results and repeat until the episode is CONTAINED, PARTIALLY_CONTAINED, PREVENTION_FAILED, or REVIEW_REQUIRED.

Every step is persisted as a per-episode decision trace, so the loop the agent followed is inspectable rather than implied.

### Connect the episode

1. Receive a call event within the authenticated account scope.
2. Store the claim and its provider identifiers without treating the claim as verified identity.
3. Receive a Telegram message containing a page link.
4. Observe the managed browser's navigation and the actual payment-flow binding.
5. Persist evidence-backed edges. Equal amounts and nearby timestamps are insufficient links.
6. Request structured interpretation of the accumulated evidence.
7. Validate the recommended action against trusted scope and exact resource bindings.
8. Present the decision and its evidence to the operator.

### Contain and verify

After authorization and persistence, prioritize the bound payment and independently dispatch scoped call, message, and browser actions. The diagram displays dispatches in sequence for explanation; the runtime should not delay payment protection until other actions finish.

Retrieve fresh Stripe, Twilio, and Browserbase state. For Telegram deletion, distinguish API acknowledgment from independent observation in the client. Report complete containment only when all required checks meet their declared evidence level. Otherwise show partial containment or uncertainty.

### Recover an uncertain action

A controlled fault transport drops the cancellation response after the provider processes the action. Persist the uncertain result. Reconciliation, including after restart, retrieves the same object before deciding whether another write is necessary. Preserve the operation key and distinguish logical effects from network attempts.

### Investigate after containment

Authorize a separate decoy context after the protected flow is contained. The decoy asks the controlled test adversary for payment instructions, receives a synthetic indicator, and attaches its source quotation to the episode. This does not establish that a supplied account belongs to a criminal. The victim-facing session remains closed.

### Challenge and improve

Create a candidate regression from an episode trace. Generate bounded variations and review expected behavior independently. Compare payment-only, flattened-context, and provenance-aware inputs against the same policy. Assert resulting resource state, non-interference, and action counts. Record actual results and failures; evaluate proposed improvements against a frozen baseline before promotion.

Adaptive adversary support uses a provider-neutral interface. The proposed Grok adapter remains access-dependent and is not currently implemented.

### Preserve unrelated activity

Present competing payment origins, including equal amounts. Resolve the proposed target through trusted code and deny an unrelated target. Compare unrelated resource state with its initial state and display non-interference alongside the intended intervention.

## Execution modes

| Mode | Provider surface | Model surface | Purpose |
|---|---|---|---|
| Local worlds | Stateful local adapters | Recorded fixtures for deterministic tests | Reproducible policies, targeting, and fault/restart behavior |
| Provider sandbox | Authorized provider APIs and Stripe test objects | Real structured model calls | Separate semantic evaluations and live integration checks |

These toggles change the depicted deployment only. Clicking them does not start services or spend credits. Local model fixtures are not fresh semantic evaluations; local adapter checks are not real provider checks.

## Trust and control boundaries

The operator workspace binds to loopback for the initial local deployment. Protect mutation routes with an authenticated local session or explicit session token, origin checks, and appropriate CSRF controls. A future callback tunnel must expose only the required authenticated or signature-verified routes, not administrative controls.

Keep provider keys server-side. Validate callback signatures and event freshness where applicable. A separate demo driver owns scenario creation and payment setup; it must not share those capabilities with the defender. Model output cannot choose an arbitrary payment, destination, secret, or executable operation.

An external identity provider is not required by this single-operator design. Hosted multi-user operation would require an appropriate identity/session system and authorization model. The action broker remains necessary regardless of the identity vendor.

Containment applies to the specific authorized resources. It does not establish safety across ordinary cellular calls, unrelated private messages, unmanaged browsers, or arbitrary bank transfers. If a payment has already completed or verification is unavailable, show the limitation explicitly.

## Required implementation evidence

- Fresh provider state for every supported read-back verification.
- Separate verification levels for requested, acknowledged, retrieved, and client-observed outcomes.
- Evidence-backed relationships and explicit uncertainty for inferred links.
- Unrelated payments and conversations unchanged by targeted actions.
- Stable logical actions through duplicates, timeouts, and restart.
- Test results with model/policy versions, denominators, failures, and trace references.

No passing results or measured prevention claims are asserted by this design document.
