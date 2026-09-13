PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES(1);
CREATE TABLE IF NOT EXISTS episodes(id TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'OBSERVING', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
 provider TEXT NOT NULL, provider_event_id TEXT NOT NULL, episode_id TEXT NOT NULL REFERENCES episodes(id),
 observed_at TEXT NOT NULL, received_at TEXT NOT NULL, payload TEXT NOT NULL,
 retention_class TEXT NOT NULL DEFAULT 'local-synthetic', redaction_status TEXT NOT NULL DEFAULT 'not-exported',
 UNIQUE(provider,provider_event_id));
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are immutable'); END;
CREATE TABLE IF NOT EXISTS edges(
 episode_id TEXT NOT NULL REFERENCES episodes(id), source_id TEXT NOT NULL REFERENCES events(event_id),
 target_id TEXT NOT NULL REFERENCES events(event_id), kind TEXT NOT NULL, confidence REAL NOT NULL,
 provenance TEXT NOT NULL, UNIQUE(source_id,target_id,kind));
CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY,episode_id TEXT NOT NULL REFERENCES episodes(id),body TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bindings(episode_id TEXT NOT NULL REFERENCES episodes(id),provider TEXT NOT NULL,resource_id TEXT NOT NULL,account_id TEXT NOT NULL,
 operation TEXT NOT NULL,evidence_ids TEXT NOT NULL,PRIMARY KEY(episode_id,provider,resource_id,operation));
CREATE TABLE IF NOT EXISTS consents(id TEXT PRIMARY KEY,episode_id TEXT NOT NULL REFERENCES episodes(id),scope TEXT NOT NULL,expires_at TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS actions(action_id TEXT PRIMARY KEY,episode_id TEXT NOT NULL REFERENCES episodes(id),provider TEXT NOT NULL,
 resource_id TEXT NOT NULL,operation TEXT NOT NULL,policy_version TEXT NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',
 UNIQUE(episode_id,provider,resource_id,operation,policy_version));
CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,action_id TEXT NOT NULL REFERENCES actions(action_id),request_id TEXT,body TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY AUTOINCREMENT,action_id TEXT NOT NULL REFERENCES actions(action_id),body TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_steps(
 id INTEGER PRIMARY KEY AUTOINCREMENT, episode_id TEXT NOT NULL REFERENCES episodes(id),
 step_index INTEGER NOT NULL, phase TEXT NOT NULL, summary TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL,
 UNIQUE(episode_id,step_index));
CREATE TABLE IF NOT EXISTS budget_config(id INTEGER PRIMARY KEY CHECK(id=1),limit_microdollars INTEGER NOT NULL CHECK(limit_microdollars>=0));
INSERT OR IGNORE INTO budget_config VALUES(1,0);
CREATE TABLE IF NOT EXISTS usage_reservations(request_id TEXT PRIMARY KEY,amount INTEGER NOT NULL CHECK(amount>=0),actual INTEGER CHECK(actual>=0),state TEXT NOT NULL DEFAULT 'reserved');
CREATE TABLE IF NOT EXISTS extraction_cache(
 cache_key TEXT PRIMARY KEY, episode_id TEXT NOT NULL, evidence_hash TEXT NOT NULL,
 model TEXT NOT NULL, prompt_version TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS consent_history(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, episode_id TEXT NOT NULL REFERENCES episodes(id),
 kind TEXT NOT NULL CHECK(kind IN ('grant','revoke')), scope TEXT NOT NULL,expires_at TEXT,created_at TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS consent_history_no_update BEFORE UPDATE ON consent_history BEGIN SELECT RAISE(ABORT,'consent history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS consent_history_no_delete BEFORE DELETE ON consent_history BEGIN SELECT RAISE(ABORT,'consent history is immutable'); END;
INSERT INTO consent_history(episode_id,kind,scope,expires_at,created_at)
 SELECT episode_id,'grant',scope,expires_at,created_at FROM consents c
 WHERE NOT EXISTS(SELECT 1 FROM consent_history h WHERE h.episode_id=c.episode_id);
