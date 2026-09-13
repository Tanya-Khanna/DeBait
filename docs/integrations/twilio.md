# Twilio controlled-call boundary

DeBait has a narrow Twilio adapter for retrieving and ending an exact allowlisted controlled call. The running application does not enable it yet, and no Twilio account, trial eligibility, phone number or live call has been verified.

The adapter requires a configured Account SID, Call SID allowlist, caller allowlist and recipient allowlist. Every fetched or updated Call must match all four identities. It uses HTTP Basic authentication server-side and exposes only Call retrieval and the `Status=completed` update. It cannot originate calls, dial a new recipient, play audio, access recordings or invoke arbitrary Twilio endpoints.

The behavior follows Twilio's [Call resource reference](https://www.twilio.com/docs/voice/api/call-resource): active `queued`, `ringing` and `in-progress` calls may receive the supported end transition, while `completed`, `busy`, `failed`, `no-answer` and `canceled` are reported as already terminal without claiming DeBait ended them. A successful update is followed by exact Call retrieval through the broker before containment can be verified.

Call text is normalized with explicit provenance: `supplied_script`, `recorded_transcription` or `live_transcription`. Supplied scenario text is never labeled as live audio, and any identity mentioned in it remains an unverified actor claim.

Twilio requires signature validation over the exact webhook URL and all submitted parameters, as described in its [secure webhooks guide](https://www.twilio.com/docs/usage/webhooks/webhooks-security). DeBait now has a narrow `/callbacks/twilio` endpoint that reads a bounded form body, rejects duplicate keys, validates `X-Twilio-Signature` against the explicitly configured callback base URL, resolves the Call SID through the trusted resource registry and only then stores sanitized status evidence. Local transport tests cover valid, invalid and ambiguous forms. A live callback, trial eligibility, call-duration enforcement and a real controlled call remain incomplete.
