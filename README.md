# DeBait

Follow the scam. Protect the right payment. Verify the outcome.

DeBait connects evidence across calls, messages, managed browsing and a payment checkpoint. It targets resources linked to an episode and preserves unrelated activity.

## Run locally

Requirements: Python 3.12+, [uv](https://docs.astral.sh/uv/), Node.js 22+ and npm. Run these commands from this repository directory:

```sh
uv sync --frozen
npm --prefix frontend ci
npm --prefix frontend run build
uv run debait serve --port 8000
```

Open **http://127.0.0.1:8000** for the landing page and `/app` for the local workspace. On first start, DeBait creates `runtime/operator.token` with owner-only permissions. Open that local file and enter its value into the workspace unlock form. Do not share or commit it. Restarting the backend expires sessions; unlock again with the same local token.

To run a synthetic scenario from another terminal:

```sh
uv run debait run four_app_two_payments --mode local
uv run debait run cancel_response_lost --mode local
```

To run the authored zero-cost core baseline or the complete local reliability campaign and export a measured report:

```sh
uv run debait eval evals/manifests/core-local.json --workspace runtime --repeats 3 --seed 13
uv run debait eval evals/manifests/full-campaign.json --workspace runtime --repeats 3 --seed 13
```

The report is stored under `runtime/evaluations/` and appears on `/evaluations` after the local workspace has been unlocked. It is labeled as deterministic fixture evidence, with separate case and execution counts and explicit limitations.

The controlled fake-site driver is a separate localhost process with no defender API or payment-creation route:

```sh
uv run debait driver --port 8001
```

Its public demonstration page is `/demo/owned-bank`. Signed navigation bindings are created server-side by the driver runtime; the page accepts no credentials or payment identifier.

The local-only operator commands seed a short-lived binding, inspect the driver state and reset only that state. Reset requires an explicit flag, and none of these controls are exposed over HTTP:

```sh
uv run debait driver-bind --episode sc1 --payment pi_test --source telegram:message:91
uv run debait driver-export
uv run debait driver-reset --yes
```

Each run persists its episode to `runtime/episodes.sqlite` and its evidence to `runtime/reports/`. The catalog contains 55 deterministic local scenarios: 48 campaign cases spanning four scam pretexts and four test families, plus seven focused core and adaptive scenarios.

For frontend development, run the backend and `npm --prefix frontend run dev`. The Vite server proxies `/api` to the local backend. The production backend serves the architecture walkthrough at `/architecture`.

## Current implementation

- Responsive landing page and local session unlock.
- Immutable SQLite evidence, provenance edges and exact resource bindings.
- Consent-scoped action dispatch, append-only authority history and independent observation records.
- Narrow Stripe and Twilio callback endpoints that verify provider signatures before resolving a trusted binding and persisting sanitized evidence.
- Transactional budget reservations with conservative handling of unknown costs.
- A disabled-by-default structured model client with strict evidence citations, bounded requests and no action tools.
- Trusted payment-origin linking that rejects amount-only, uncertain and cross-episode matches.
- A disabled-by-default Stripe test-mode adapter for exact account/read/cancel/read-back operations.
- A disabled-by-default Telegram adapter for scoped message deletion and controlled-chat membership bans.
- A disabled-by-default Browserbase adapter that separates release acknowledgment from terminal read-back.
- A disabled-by-default Twilio adapter for exact controlled-call retrieval and termination.
- A separate local demonstration driver with short-lived signed navigation-to-payment provenance, explicit reset/export controls and a test-key-only creator for two equal pending Stripe test objects.
- A runnable synthetic four-app world, unrelated-payment controls, durable worker recovery and dropped-response reconciliation.
- A self-directed incident loop that persists each observe/reason/read/act/verify decision and adapts when payment is absent or already settled.
- A bounded post-containment Hunter fixture in a separate decoy context, with attacker-supplied indicator extraction and no payment tool or real contact.
- A protected usage endpoint and workspace panel that separate settled model cost, outstanding reservations and remaining configured budget without implying a live model run.
- A session-protected, replayable episode-event feed with durable sequence IDs and `Last-Event-ID` recovery; each response materializes a bounded batch before streaming.
- Authored 5-case core, 2-case adaptive and 48-case campaign manifests, repeatable world reset, explicit attack/benign/fault denominators and exported measured reports.

**The running app still uses a deterministic fixture baseline, and no fresh AI-model call has been measured.** Local-world observations are labeled as such. The structured model client has only been tested through a local HTTP transport and remains disconnected from the application until access, pricing and model behavior are verified. One narrow real-provider checkpoint has been verified in Stripe test mode: the exact scam-linked PaymentIntent was canceled and read back while an equal-value control remained pending. Telegram, Browserbase and Twilio remain transport-tested only. The Hunter panel is a local deterministic decoy demonstration, not outreach to a real person. The interactive architecture distinguishes implemented local behavior from gated live-provider paths.

## Verification

```sh
uv run pytest -q
uv run ruff check src tests
npm --prefix frontend run build
npm --prefix frontend run test:e2e
```

Browser tests use Playwright. On macOS they can use installed Google Chrome; set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to another Chromium path, or install Playwright Chromium with `npx --prefix frontend playwright install chromium` if Chrome is unavailable.

## Boundaries

The local scenario driver has synthetic creation privileges; the defender has only read/end/delete/ban/release/cancel operations. It has no send-money, capture or arbitrary recipient-creation tool. Simulation success is not proof of real losses prevented. A Stripe PaymentIntent is an object controlled by an integration, not an arbitrary outgoing bank transfer.

Keep keys in an ignored `.env`, using `.env.example` for variable names. Runtime data, tokens and raw recordings do not belong in source control. See [storage](docs/storage.md) for persistence and migration boundaries and [architecture](architecture.md) for intended flows.

Auth0 is intentionally omitted from this single-operator localhost prototype. Any public multi-user deployment would need a separate identity, tenant-isolation and authorization design before these controls could be exposed.

## Attribution

The architecture walkthrough uses the MIT-licensed [architecture-diagram-skill](https://github.com/konraddzbik/architecture-diagram-skill) template. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
