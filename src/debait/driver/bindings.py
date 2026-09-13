import base64
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from pydantic import SecretStr


class BindingNotFound(ValueError):
    pass


class BindingExpired(ValueError):
    pass


class BindingStore:
    def __init__(self, path, signing_secret: SecretStr, now=None):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._secret = signing_secret.get_secret_value().encode()
        if len(self._secret) < 24:
            raise ValueError("Driver signing secret must contain at least 24 characters")
        self._now = now or (lambda: datetime.now(timezone.utc))
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS navigation_bindings (
                    nonce TEXT PRIMARY KEY,
                    episode_id TEXT NOT NULL,
                    payment_id TEXT NOT NULL,
                    source_event_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    open_count INTEGER NOT NULL DEFAULT 0,
                    last_opened_at TEXT
                )"""
            )

    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _sign(self, value):
        digest = hmac.new(self._secret, value.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def issue(self, episode_id, payment_id, source_event_id, expires_at):
        now = self._now()
        if expires_at.tzinfo is None:
            raise ValueError("Binding expiry must be timezone-aware")
        if not all(
            isinstance(item, str) and item and len(item) <= 256
            for item in [episode_id, payment_id, source_event_id]
        ):
            raise ValueError("Binding identity and provenance are required")
        if not now < expires_at <= now + timedelta(minutes=15):
            raise ValueError("Binding must expire within fifteen minutes")
        nonce = secrets.token_urlsafe(24)
        expiry = int(expires_at.timestamp())
        unsigned = f"{nonce}.{expiry}"
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO navigation_bindings(nonce,episode_id,payment_id,source_event_id,expires_at) VALUES (?,?,?,?,?)",
                (nonce, episode_id, payment_id, source_event_id, expires_at.isoformat()),
            )
        return f"{unsigned}.{self._sign(unsigned)}"

    def _resolve(self, token):
        try:
            nonce, expiry_text, signature = token.split(".")
            expiry = int(expiry_text)
        except (AttributeError, ValueError):
            raise BindingNotFound("Unknown navigation") from None
        unsigned = f"{nonce}.{expiry_text}"
        if not hmac.compare_digest(signature, self._sign(unsigned)):
            raise BindingNotFound("Unknown navigation")
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM navigation_bindings WHERE nonce=?", (nonce,)).fetchone()
        if row is None:
            raise BindingNotFound("Unknown navigation")
        if self._now().timestamp() >= expiry:
            raise BindingExpired("Navigation expired")
        return dict(row)

    def lookup(self, token):
        return self._resolve(token)

    def record_open(self, token):
        row = self._resolve(token)
        opened_at = self._now().isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE navigation_bindings SET open_count=open_count+1,last_opened_at=? WHERE nonce=?",
                (opened_at, row["nonce"]),
            )
        return self._resolve(token)

    def export(self):
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT episode_id,payment_id,source_event_id,expires_at,
                          open_count,last_opened_at
                   FROM navigation_bindings ORDER BY rowid"""
            ).fetchall()
        return [dict(row) for row in rows]

    def reset(self):
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute("SELECT COUNT(*) FROM navigation_bindings").fetchone()[0]
            connection.execute("DELETE FROM navigation_bindings")
        return count
