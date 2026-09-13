# Model reasoning boundary

The app still runs its deterministic local fixture baseline. A separate `ModelClient` now implements a text-only Responses request and structured assessment validation. Its local HTTP-transport tests are not live model evaluations.

The request uses `text.format` with strict JSON schema, no tools, an output-token ceiling and `store: false`. Incomplete output and refusals produce unavailable/review outcomes. The transport format follows the [official Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).

Paid networking is disabled by default. To enable it in a controlled caller, provide an explicit API key, exact model snapshot, verified input/output rate configuration, an authorized budget and `allow_network=True`. This is not exposed as a website toggle. Account access and live schema/model compatibility still require verification.

Before sending, the client reserves a conservative text-input estimate plus the configured maximum output cost. It bounds input bytes, response bytes and request duration, and performs no automatic retry. Unknown usage, timeouts, HTTP failures and unexpected models retain their reservations. Observed token counts settle an estimate using configured standard rates; this is not an invoice or an unconditional billing guarantee. Cached-input discounts are not assumed. Recheck pricing and calibrate reservation overhead before live use.

Validated extractions are cached durably by a SHA-256 digest of the canonical evidence and permitted-read set, the exact configured model, and an explicit prompt version. An identical request after restart returns the validated assessment without a provider request or another budget reservation. The result is labeled `mode=cache`, `cache_hit=true`, zero new tokens/cost and `cost_basis=cache_hit_no_new_request`; the original request and response IDs remain available as provenance. Any cached assessment that no longer validates against the supplied episode and read scope fails closed.

The model returns evidence-backed signals, contradictions, missing evidence and an optional permitted next-read request. It receives attacker content only as evidence data. Returned episode IDs and evidence citations must match the supplied episode; out-of-scope reads are rejected. No model output can create resource bindings or authorize a financial operation.

Autonomous intervention applies a deterministic semantic gate after assessment validation. Every required signal class must have confidence of at least `0.60`, and the qualifying citations must resolve to at least two canonical persisted events across at least two trusted external providers. Canonical identity is `(provider, provider_event_id)`, so repeated citations or duplicate representations of one artifact cannot create corroboration. Driver and Hunter records do not count as independent external surfaces. The `0.60` prototype threshold was selected from a one-repeat, 48-case fresh-model calibration run: benign signal confidence reached at most `0.35`, while `0.60` preserved every episode that satisfied the previous label-only authorization rule; the next tested cutoff, `0.65`, routed one additional recoverable attack to review. This authored fixture sample is limited and the threshold must be recalibrated before production use.

Evaluation reports retain structured signal confidences, evidence citations and sanitized provider provenance for each reasoning step. To rerun the calibration without placing a key in the command or repository, set `DEBAIT_OPENAI_KEY` in an ignored `.env` and run:

```sh
uv run debait eval evals/manifests/full-campaign.json --workspace runtime/calibration --repeats 1 --seed 13 --reasoning-mode fresh_model
```

Insufficient confidence or corroboration never reaches the action queue. Once bounded evidence gathering is exhausted, the existing policy sends the episode to `REVIEW_REQUIRED` with zero newly authorized writes.

`payment_target` resolves only an existing account-bound Stripe object with an observed origin edge from messaging or managed browsing. Equal amounts, uncertain edges and another episode cannot establish this relationship. Observer integrations remain responsible for authenticating the source of stored events and origin edges.
