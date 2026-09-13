# Episode storage

SQLite stores immutable source events separately from inferred relationships, assessments, consent, exact resource bindings, action attempts and provider observations. Source-event identity is unique per provider. Conflicting replacements are rejected; event updates/deletes are rejected by database triggers. Observed and received timestamps are UTC-aware. Payloads are capped at 64 KiB.

Each write uses a transaction with foreign keys enabled; evidence ingestion and budget admission use an immediate transaction. WAL permits concurrent readers. SQLite is the initial local store. The local worker now claims actions with durable leases, prioritizes payment jobs, fences stale owners and bounds provider I/O below the lease duration. Action and job persistence commit atomically. Rate limits, consent changes, uncertain outcomes and exhausted retries remain explicit. Live multi-worker operation still requires provider-specific idempotency and integration verification.

For PostgreSQL migration, preserve textual object IDs and provider/event uniqueness, convert UTC fields to timestamptz and JSON bodies to jsonb, retain immutability triggers, and replace SQLite immediate transactions with row locking for reservations and action leases. Run the same persistence, identity-conflict, concurrency and recovery cases against the migrated store before use. No PostgreSQL deployment is currently required.

Runtime files remain local and ignored. The current schema stores synthetic evidence only. Before handling personal evidence, implement explicit retention/deletion workflows rather than bypassing immutability with application updates.

The restart test runs a separate process, persists a cancellation in an independent synthetic provider database, exits before recording success in the defender, and restarts the worker after lease expiry. The restarted worker re-reads the resource and verifies the existing effect. This demonstrates local process recovery, not a live provider guarantee or distributed exactly-once delivery.
