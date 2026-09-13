# Browserbase managed-session boundary

DeBait has a narrow Browserbase adapter for reading and requesting release of an exact allowlisted managed session. The running application does not enable it yet, and no Browserbase project or live managed session has been verified.

The adapter requires a configured project ID and session allowlist before networking. It retrieves `GET /v1/sessions/:id`, checks both response identities, and maps `COMPLETED`, `TIMED_OUT` and `ERROR` to DeBait's terminal `terminated` state. `PENDING` and `RUNNING` remain active. It exposes no session creation, arbitrary browser connection, credential access or general-purpose request method.

Release follows Browserbase's [Update a Session reference](https://docs.browserbase.com/reference/api/update-a-session) by posting `status=REQUEST_RELEASE` with the exact project ID. Browserbase can still return a nonterminal session immediately after that request, so DeBait records only an acknowledgment until a later [Get a Session](https://docs.browserbase.com/reference/api/get-a-session) response supplies terminal read-back state. This distinction is required for the containment contract.

Mock transport tests prove exact request construction, project/session validation, terminal-state normalization, rate-limit handling and preservation of an unrelated session ID. Approved-link inspection, redirect and private-network controls, minute budgeting, orphan cleanup and a real managed-session release remain incomplete.
