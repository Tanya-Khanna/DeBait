"""Follow a controlled Gmail inbox and prove one reversible scam-email quarantine.

Discovers (or creates) the DeBait/Quarantined label, follows inbox messages,
flags the scam-marked email, quarantines it via the scoped adapter, verifies by
read-back, and confirms an unrelated inbox message is untouched. Live network is
gated; message content is treated as untrusted data.
"""

import asyncio
import json
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.base import ProviderStateChanged
from debait.providers.gmail import QUARANTINE_LABEL_NAME, GmailAdapter, GmailConfig

BASE_URL = "https://gmail.googleapis.com"
DEFAULT_MARKERS = (
    "compromised",
    "verify immediately",
    "verify your account",
    "suspicious activity",
    "fraud department",
    "secure verification",
    "safe account",
)


async def _request(token, method, path, *, json_body=None, transport=None, allow_network=False, timeout=8.0):
    if not allow_network and not isinstance(transport, httpx.MockTransport):
        raise PermissionError("Gmail inbox networking is disabled until explicitly enabled")
    try:
        async with (
            asyncio.timeout(timeout),
            httpx.AsyncClient(
                base_url=BASE_URL,
                transport=transport,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client,
        ):
            async with client.stream(
                method, path, json=json_body, headers={"Authorization": f"Bearer {token.get_secret_value()}"}
            ) as response:
                if response.status_code in {401, 403}:
                    raise PermissionError("Gmail denied the inbox request")
                if response.status_code < 200 or response.status_code >= 300:
                    raise ConnectionError(f"Gmail inbox request failed with HTTP {response.status_code}")
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 1048576:
                        raise ConnectionError("Gmail inbox response exceeded the configured size")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError
        return payload
    except (PermissionError, ConnectionError):
        raise
    except (httpx.HTTPError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
        raise ConnectionError("Gmail inbox transport or response validation failed") from None


async def ensure_quarantine_label(token, *, user="me", transport=None, allow_network=False) -> str:
    user = quote(user, safe="")
    listing = await _request(
        token, "GET", f"/gmail/v1/users/{user}/labels", transport=transport, allow_network=allow_network
    )
    for label in listing.get("labels", []):
        if isinstance(label, dict) and label.get("name") == QUARANTINE_LABEL_NAME and label.get("id"):
            return str(label["id"])
    created = await _request(
        token,
        "POST",
        f"/gmail/v1/users/{user}/labels",
        json_body={
            "name": QUARANTINE_LABEL_NAME,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        },
        transport=transport,
        allow_network=allow_network,
    )
    if not created.get("id"):
        raise ConnectionError("Gmail did not return a quarantine label id")
    return str(created["id"])


async def follow_inbox(token, *, user="me", limit=25, transport=None, allow_network=False) -> list[dict]:
    user = quote(user, safe="")
    listing = await _request(
        token,
        "GET",
        f"/gmail/v1/users/{user}/messages?labelIds=INBOX&maxResults={limit}",
        transport=transport,
        allow_network=allow_network,
    )
    messages = []
    for ref in listing.get("messages", []):
        if not isinstance(ref, dict) or not ref.get("id"):
            continue
        message = await _request(
            token,
            "GET",
            f"/gmail/v1/users/{user}/messages/{ref['id']}?format=metadata"
            "&metadataHeaders=From&metadataHeaders=Subject",
            transport=transport,
            allow_network=allow_network,
        )
        headers = {
            h.get("name", "").lower(): h.get("value", "")
            for h in message.get("payload", {}).get("headers", [])
            if isinstance(h, dict)
        }
        messages.append(
            {
                "id": str(message.get("id")),
                "from": headers.get("from", ""),
                "subject": headers.get("subject", ""),
                "snippet": str(message.get("snippet", "")),
            }
        )
    return messages


def _select_scam(messages: list[dict], markers: tuple[str, ...]) -> dict:
    for message in messages:
        blob = f"{message['subject']} {message['snippet']}".lower()
        if any(marker in blob for marker in markers):
            return message
    raise ValueError("No scam-marked email was found in the followed inbox")


async def run_gmail_smoke(
    token: SecretStr,
    *,
    run_id: str,
    user: str = "me",
    markers: tuple[str, ...] = DEFAULT_MARKERS,
    transport=None,
    allow_network: bool = False,
) -> dict:
    label_id = await ensure_quarantine_label(
        token, user=user, transport=transport, allow_network=allow_network
    )
    inbox = await follow_inbox(token, user=user, transport=transport, allow_network=allow_network)
    if not inbox:
        raise ConnectionError("No inbox messages were visible")
    scam = _select_scam(inbox, markers)
    control = next((m for m in inbox if m["id"] != scam["id"]), None)

    adapter = GmailAdapter(
        GmailConfig(user_id=user, quarantine_label_id=label_id),
        token,
        transport=transport,
        allow_network=allow_network,
    )
    before = await adapter.read(scam["id"])
    receipt = await adapter.act(
        Action(
            action_id=f"gmail-smoke-{run_id}",
            episode_id=run_id,
            target=Target(provider="gmail", resource_id=scam["id"], operation="quarantine"),
            policy_version="gmail_live_smoke_v1",
        )
    )
    after = await adapter.read(scam["id"])
    control_state = None
    if control is not None:
        try:
            control_state = (await adapter.read(control["id"])).state
        except ProviderStateChanged:
            control_state = "unavailable"
    return {
        "run_id": run_id,
        "quarantine_label_id": label_id,
        "followed_messages": len(inbox),
        "scam_message_id": scam["id"],
        "scam_subject": scam["subject"][:80],
        "before_state": before.state,
        "quarantine_acknowledged": receipt.acknowledged,
        "after_state": after.state,
        "quarantine_verified": after.state == "quarantined",
        "control_message_id": control["id"] if control else None,
        "control_state": control_state,
    }
