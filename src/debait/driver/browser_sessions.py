"""Create and prove one bounded Browserbase session for the controlled demo."""

import asyncio
import hashlib
import json
import re
import time
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from debait.episodes.models import Edge, Event
from debait.episodes.store import EpisodeStore
from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.browserbase import BrowserbaseAdapter, BrowserbaseConfig

# Bounded page text keeps attacker-controlled page content from flooding the model or
# the evidence store; only a small, capped excerpt is ever persisted.
DEFAULT_MAX_PAGE_TEXT_BYTES = 4096
# The scam-linked payment reference is a bound TEST identifier (pi_...), never a live one.
PAYMENT_REFERENCE_PATTERN = re.compile(r"pi_[A-Za-z0-9_]{1,120}")


def _bounded_utf8_text(value: str, maximum_bytes: int) -> str:
    """Return a UTF-8-safe prefix, never exceeding the explicit byte boundary."""
    if not isinstance(value, str):
        raise ValueError("Page text must be a string")
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 16 * 1024:
        raise ValueError("Page text byte limit must be between 1 and 16384")
    return value.encode("utf-8")[:maximum_bytes].decode("utf-8", errors="ignore").strip()


class BrowserbaseDriverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    session_timeout_seconds: int = Field(default=60, ge=60, le=300)
    request_timeout_seconds: float = Field(default=8, gt=0, le=15)
    maximum_response_bytes: int = Field(default=131072, ge=4096, le=1048576)


class BrowserbaseSessionDriver:
    BASE_URL = "https://api.browserbase.com"
    _IDENTITY = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

    def __init__(
        self,
        config: BrowserbaseDriverConfig,
        key: SecretStr,
        *,
        transport=None,
        allow_network: bool = False,
    ):
        if not key.get_secret_value():
            raise PermissionError("Browserbase API key is required")
        if not allow_network and not isinstance(transport, httpx.MockTransport):
            raise PermissionError("Browserbase session creation is disabled until explicitly enabled")
        self.config = config
        self._key = key
        self._transport = transport

    async def create(self, run_id: str, *, keep_alive: bool = False) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
            raise ValueError("Bound Browserbase run identity is required")
        # keep_alive=True lets the session survive a CDP disconnect so the scoped adapter
        # release remains the single terminator; the lifecycle smoke keeps the default.
        body = {
            "timeout": self.config.session_timeout_seconds,
            "keepAlive": keep_alive,
            "userMetadata": {"debait_run": run_id},
        }
        try:
            async with (
                asyncio.timeout(self.config.request_timeout_seconds),
                httpx.AsyncClient(
                    base_url=self.BASE_URL,
                    transport=self._transport,
                    timeout=self.config.request_timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
            ):
                async with client.stream(
                    "POST",
                    "/v1/sessions",
                    json=body,
                    headers={"X-BB-API-Key": self._key.get_secret_value()},
                ) as response:
                    if response.status_code in {401, 403}:
                        raise PermissionError("Browserbase denied session creation")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ConnectionError(
                            f"Browserbase session creation failed with HTTP {response.status_code}"
                        )
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self.config.maximum_response_bytes:
                            raise ConnectionError("Browserbase create response exceeded the configured size")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError
            session_id = payload.get("id")
            project_id = payload.get("projectId")
            if (
                not isinstance(session_id, str)
                or not self._IDENTITY.fullmatch(session_id)
                or not isinstance(project_id, str)
                or not self._IDENTITY.fullmatch(project_id)
                or payload.get("status") not in BrowserbaseAdapter.ACTIVE
                or payload.get("userMetadata") != body["userMetadata"]
            ):
                raise PermissionError("Browserbase returned an unbound or nonactive session")
            return payload
        except (PermissionError, ConnectionError):
            raise
        except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            raise ConnectionError("Browserbase create transport or response validation failed") from None


async def run_browserbase_smoke(
    key: SecretStr,
    *,
    run_id: str,
    transport=None,
    allow_network: bool = False,
    poll_interval_seconds: float = 0.5,
    maximum_poll_seconds: float = 20,
) -> dict:
    if not 0 <= poll_interval_seconds <= 2 or not 1 <= maximum_poll_seconds <= 30:
        raise ValueError("Browserbase smoke polling bounds are invalid")
    driver = BrowserbaseSessionDriver(
        BrowserbaseDriverConfig(), key, transport=transport, allow_network=allow_network
    )
    created = await driver.create(run_id)
    session_id = created["id"]
    project_id = created["projectId"]
    adapter = BrowserbaseAdapter(
        BrowserbaseConfig(
            project_id=project_id,
            controlled_session_ids=frozenset({session_id}),
        ),
        key,
        transport=transport,
        allow_network=allow_network,
    )
    before = await adapter.read(session_id)
    action = Action(
        action_id=f"browserbase-smoke-{run_id}",
        episode_id=run_id,
        target=Target(provider="browserbase", resource_id=session_id, operation="release"),
        policy_version="browserbase_live_smoke_v1",
    )
    receipt = await adapter.act(action)
    deadline = time.monotonic() + maximum_poll_seconds
    after = await adapter.read(session_id)
    while after.state != "terminated" and time.monotonic() < deadline:
        await asyncio.sleep(poll_interval_seconds)
        after = await adapter.read(session_id)
    if after.state != "terminated":
        raise ConnectionError("Browserbase session release was not verified before the poll deadline")
    return {
        "run_id": run_id,
        "project_id": project_id,
        "session_id": session_id,
        "before_state": before.state,
        "release_acknowledged": receipt.acknowledged,
        "after_state": after.state,
        "provider_status": after.details["provider_status"],
        "session_url": f"https://www.browserbase.com/sessions/{session_id}",
    }


async def capture_page(
    connect_url: str,
    target_url: str,
    *,
    max_text_bytes: int = DEFAULT_MAX_PAGE_TEXT_BYTES,
    timeout_seconds: float = 30,
) -> dict:
    """Connect to a remote Browserbase browser over CDP, navigate once, capture evidence.

    Returns the final URL and a bounded text excerpt only. Playwright is an optional
    live-only dependency, imported lazily so the rest of the module and all offline
    tests keep working without it. Page content is untrusted data: it is never parsed
    for instructions and never widens any scope.
    """
    if not isinstance(connect_url, str) or not connect_url.startswith("wss://"):
        raise PermissionError("Browserbase CDP endpoint must be a wss:// URL")
    _bounded_utf8_text("", max_text_bytes)
    try:
        from playwright.async_api import async_playwright
    except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
        raise ConnectionError("Playwright is required for Browserbase page capture") from exc
    async with async_playwright() as pw:
        browser = await pw.chromium.connect_over_cdp(connect_url, timeout=timeout_seconds * 1000)
        try:
            context = browser.contexts[0] if browser.contexts else await browser.new_context()
            page = context.pages[0] if context.pages else await context.new_page()
            await page.goto(target_url, wait_until="load", timeout=timeout_seconds * 1000)
            final_url = page.url
            # Bound inside the remote browser before transferring untrusted page text.
            body_text = await page.locator("body").evaluate(
                "(body, maximumChars) => (body.innerText || body.textContent || '').slice(0, maximumChars)",
                max_text_bytes,
            )
        finally:
            await browser.close()
    bounded = _bounded_utf8_text(body_text, max_text_bytes)
    return {"final_url": final_url, "page_text": bounded}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def persist_browser_evidence(
    store: EpisodeStore,
    *,
    episode_id: str,
    project_id: str,
    session_id: str,
    final_url: str,
    page_text: str,
    payment_reference: str | None,
) -> tuple[str, str]:
    """Persist Browserbase web evidence into the episode store using the existing
    provider-aware Event/Edge representation, with a trusted navigation provenance edge.

    The page text is stored purely as evidence data (provenance="provider_read"); it
    creates no binding, consent, or actionable target, so it can carry zero authority.
    Returns (source_event_id, evidence_event_id).
    """
    now = _now()
    source_identity = f"browserbase-navigation:{episode_id}:{session_id}"
    source_event = Event(
        event_id=f"{episode_id}:driver:{hashlib.sha256(source_identity.encode()).hexdigest()[:24]}",
        provider="driver",
        provider_event_id=f"browserbase-navigation:{session_id}",
        episode_id=episode_id,
        observed_at=now,
        received_at=now,
        payload={
            "resource_id": session_id,
            "account_id": project_id,
            "provenance": "trusted_live_navigation",
            "navigation_source": "browserbase.session.connect_over_cdp",
        },
    )
    store.ingest(source_event)

    evidence_payload = {
        "resource_id": session_id,
        "account_id": project_id,
        "state": "active",
        "level": "read_back",
        # Bounded, untrusted page excerpt kept as evidence only.
        "text": _bounded_utf8_text(page_text, DEFAULT_MAX_PAGE_TEXT_BYTES),
        "provider_metadata": {
            "session_id": session_id,
            "final_url": final_url,
            "payment_reference": payment_reference,
        },
        "observation_source": "browserbase.page.capture",
        "provenance": "provider_read",
    }
    canonical = json.dumps(evidence_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    evidence_event = Event(
        event_id=f"{episode_id}:browserbase:{digest[:24]}",
        provider="browserbase",
        provider_event_id=f"provider-read:{digest}",
        episode_id=episode_id,
        observed_at=now,
        received_at=_now(),
        payload=evidence_payload,
    )
    store.ingest(evidence_event)
    store.add_edge(
        Edge(
            source_id=source_event.event_id,
            target_id=evidence_event.event_id,
            kind="observed_navigation",
            confidence=1,
            provenance_event_ids=[source_event.event_id, evidence_event.event_id],
        )
    )
    return source_event.event_id, evidence_event.event_id


async def run_browserbase_evidence_smoke(
    key: SecretStr,
    *,
    run_id: str,
    page_url: str,
    workspace,
    transport=None,
    allow_network: bool = False,
    poll_interval_seconds: float = 0.5,
    maximum_poll_seconds: float = 20,
    max_text_bytes: int = DEFAULT_MAX_PAGE_TEXT_BYTES,
) -> dict:
    """Create a managed session, navigate one controlled page, persist bounded web
    evidence into a real episode, then release and independently verify termination.

    This proves actual web observation (URL + bounded text + payment reference) with
    provenance, without granting the observed page any authority and without touching
    any other provider.
    """
    from pathlib import Path

    driver = BrowserbaseSessionDriver(
        BrowserbaseDriverConfig(), key, transport=transport, allow_network=allow_network
    )
    created = await driver.create(run_id, keep_alive=True)
    session_id = created["id"]
    project_id = created["projectId"]
    connect_url = created.get("connectUrl")
    if not isinstance(connect_url, str) or not connect_url:
        raise ConnectionError("Browserbase did not return a CDP connect URL for the session")

    capture = await capture_page(connect_url, page_url, max_text_bytes=max_text_bytes)
    match = PAYMENT_REFERENCE_PATTERN.search(capture["page_text"])
    payment_reference = match.group(0) if match else None
    observed_payment_references = {match.group(0) for match in PAYMENT_REFERENCE_PATTERN.finditer(capture["page_text"])}

    adapter = BrowserbaseAdapter(
        BrowserbaseConfig(project_id=project_id, controlled_session_ids=frozenset({session_id})),
        key,
        transport=transport,
        allow_network=allow_network,
    )
    before = await adapter.read(session_id)

    store = EpisodeStore(Path(workspace) / "episodes.sqlite")
    source_event_id, evidence_event_id = persist_browser_evidence(
        store,
        episode_id=run_id,
        project_id=project_id,
        session_id=session_id,
        final_url=capture["final_url"],
        page_text=capture["page_text"],
        payment_reference=payment_reference,
    )
    # Prove zero authority: persisting page evidence created no consent and no binding,
    # so no page instruction could become an actionable target.
    consent = store.consent(run_id)
    injected_binding = None
    if payment_reference is not None:
        injected_binding = store.binding(
            run_id, Target(provider="stripe", resource_id=payment_reference, operation="cancel")
        )
    injection_created_authority = consent is not None or injected_binding is not None
    unbound_payment_became_actionable = any(
        store.binding(
            run_id,
            Target(provider="stripe", resource_id=reference, operation="cancel"),
        )
        is not None
        for reference in observed_payment_references - {payment_reference}
    )

    action = Action(
        action_id=f"browserbase-evidence-{run_id}",
        episode_id=run_id,
        target=Target(provider="browserbase", resource_id=session_id, operation="release"),
        policy_version="browserbase_evidence_smoke_v1",
    )
    receipt = await adapter.act(action)
    deadline = time.monotonic() + maximum_poll_seconds
    after = await adapter.read(session_id)
    while after.state != "terminated" and time.monotonic() < deadline:
        await asyncio.sleep(poll_interval_seconds)
        after = await adapter.read(session_id)
    if after.state != "terminated":
        raise ConnectionError("Browserbase session release was not verified before the poll deadline")

    stored = {event.event_id for event in store.events(run_id)}
    return {
        "run_id": run_id,
        "project_id": project_id,
        "session_id": session_id,
        "final_url": capture["final_url"],
        "page_text_bytes": len(capture["page_text"].encode("utf-8")),
        "payment_reference": payment_reference,
        "before_state": before.state,
        "evidence_event_id": evidence_event_id,
        "evidence_persisted": evidence_event_id in stored and source_event_id in stored,
        "injection_created_authority": injection_created_authority,
        "unbound_payment_became_actionable": unbound_payment_became_actionable,
        "release_acknowledged": receipt.acknowledged,
        "after_state": after.state,
        "provider_status": after.details["provider_status"],
    }
