# Model reasoning boundary

The app still runs its deterministic local fixture baseline. A separate `ModelClient` now implements a text-only Responses request and structured assessment validation. Its local HTTP-transport tests are not live model evaluations.

The request uses `text.format` with strict JSON schema, no tools, an output-token ceiling and `store: false`. Incomplete output and refusals produce unavailable/review outcomes. The transport format follows the [official Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).

Paid networking is disabled by default. To enable it in a controlled caller, provide an explicit API key, exact model snapshot, verified input/output rate configuration, an authorized budget and `allow_network=True`. This is not exposed as a website toggle. Account access and live schema/model compatibility still require verification.

Before sending, the client reserves a conservative text-input estimate plus the configured maximum output cost. It bounds input bytes, response bytes and request duration, and performs no automatic retry. Unknown usage, timeouts, HTTP failures and unexpected models retain their reservations. Observed token counts settle an estimate using configured standard rates; this is not an invoice or an unconditional billing guarantee. Cached-input discounts are not assumed. Recheck pricing and calibrate reservation overhead before live use.

Validated extractions are cached durably by a SHA-256 digest of the canonical evidence and permitted-read set, the exact configured model, and an explicit prompt version. An identical request after restart returns the validated assessment without a provider request or another budget reservation. The result is labeled `mode=cache`, `cache_hit=true`, zero new tokens/cost and `cost_basis=cache_hit_no_new_request`; the original request and response IDs remain available as provenance. Any cached assessment that no longer validates against the supplied episode and read scope fails closed.

The model returns evidence-backed signals, contradictions, missing evidence and an optional permitted next-read request. It receives attacker content only as evidence data. Returned episode IDs and evidence citations must match the supplied episode; out-of-scope reads are rejected. No model output can create resource bindings or authorize a financial operation.

`payment_target` resolves only an existing account-bound Stripe object with an observed origin edge from messaging or managed browsing. Equal amounts, uncertain edges and another episode cannot establish this relationship. Observer integrations remain responsible for authenticating the source of stored events and origin edges.
