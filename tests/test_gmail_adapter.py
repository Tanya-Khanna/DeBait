import json

import httpx
import pytest
from pydantic import SecretStr

from debait.driver.gmail_inbox import run_gmail_smoke
from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.base import ProviderStateChanged
from debait.providers.gmail import GmailAdapter, GmailConfig

TOKEN = SecretStr("ya29.mock-oauth-access-token")
LABEL = "Label_DB"


class FakeGmail:
    """Stateful Gmail mock: tracks per-message labels across read/modify."""

    def __init__(self, labels=None, has_quarantine_label=False, modify_noop=False):
        self.labels = labels or {"m_scam": {"INBOX"}, "m_ctrl": {"INBOX"}}
        self.meta = {
            "m_scam": ("Bank <fraud@x>", "Your account has been compromised", "verify immediately"),
            "m_ctrl": ("Alice <a@x>", "Lunch tomorrow?", "see you at noon"),
        }
        self.has_quarantine_label = has_quarantine_label
        self.created_label = False
        self.modify_noop = modify_noop  # POST modify returns 200 but does not mutate
        self.modify_count = 0

    def transport(self):
        return httpx.MockTransport(self._handle)

    def _handle(self, request):
        path, query = request.url.path, request.url.query.decode()
        if path.endswith("/labels") and request.method == "GET":
            labels = [{"id": "CHAT", "name": "CHAT"}]
            if self.has_quarantine_label:
                labels.append({"id": LABEL, "name": "DeBait/Quarantined"})
            return httpx.Response(200, json={"labels": labels})
        if path.endswith("/labels") and request.method == "POST":
            self.created_label = True
            return httpx.Response(200, json={"id": LABEL, "name": "DeBait/Quarantined"})
        if path.endswith("/messages") and request.method == "GET":
            ids = [{"id": mid} for mid, labs in self.labels.items() if "INBOX" in labs]
            return httpx.Response(200, json={"messages": ids})
        if path.endswith("/modify") and request.method == "POST":
            mid = path.split("/messages/")[1].split("/modify")[0]
            self.modify_count += 1
            body = json.loads(request.content)
            if not self.modify_noop:
                self.labels[mid] -= set(body.get("removeLabelIds", []))
                self.labels[mid] |= set(body.get("addLabelIds", []))
            return httpx.Response(200, json={"id": mid, "labelIds": sorted(self.labels[mid])})
        if "/messages/" in path and request.method == "GET":
            mid = path.split("/messages/")[1]
            if "format=metadata" in query:
                frm, subj, snip = self.meta[mid]
                return httpx.Response(
                    200,
                    json={
                        "id": mid,
                        "snippet": snip,
                        "payload": {
                            "headers": [{"name": "From", "value": frm}, {"name": "Subject", "value": subj}]
                        },
                    },
                )
            return httpx.Response(200, json={"id": mid, "labelIds": sorted(self.labels[mid])})
        raise AssertionError(f"unexpected gmail call: {request.method} {path}?{query}")


def _adapter(fake):
    return GmailAdapter(GmailConfig(quarantine_label_id=LABEL), TOKEN, transport=fake.transport())


def _quarantine(mid):
    return Action(
        action_id=f"q-{mid}",
        episode_id="ep",
        policy_version="v1",
        target=Target(provider="gmail", resource_id=mid, operation="quarantine"),
    )


@pytest.mark.asyncio
async def test_read_maps_labels_to_state():
    fake = FakeGmail(labels={"m_scam": {"INBOX"}, "m_ctrl": {LABEL}, "m_arch": {"CHAT"}})
    a = _adapter(fake)
    assert (await a.read("m_scam")).state == "inbox"
    assert (await a.read("m_ctrl")).state == "quarantined"
    assert (await a.read("m_arch")).state == "archived"


@pytest.mark.asyncio
async def test_quarantine_is_reversible_and_verified_by_readback():
    fake = FakeGmail()
    a = _adapter(fake)
    assert (await a.read("m_scam")).state == "inbox"
    receipt = await a.act(_quarantine("m_scam"))
    assert receipt.acknowledged is True
    after = await a.read("m_scam")
    assert after.state == "quarantined"
    assert "INBOX" not in after.details["label_ids"] and LABEL in after.details["label_ids"]


@pytest.mark.asyncio
async def test_quarantine_is_idempotent_when_already_quarantined():
    # Lost-response-after-success: already in the desired state = success, no re-mutation.
    fake = FakeGmail(labels={"m_scam": {LABEL}})
    receipt = await _adapter(fake).act(_quarantine("m_scam"))
    assert receipt.acknowledged is True
    assert fake.modify_count == 0  # it did NOT mutate again


@pytest.mark.asyncio
async def test_quarantine_refuses_when_neither_inbox_nor_quarantined():
    fake = FakeGmail(labels={"m_scam": {"CHAT"}})
    with pytest.raises(ProviderStateChanged):
        await _adapter(fake).act(_quarantine("m_scam"))


@pytest.mark.asyncio
async def test_quarantine_requires_independent_readback_not_the_modify_response():
    # modify returns 200 but does not actually change state; the read-back must catch it.
    fake = FakeGmail(modify_noop=True)
    with pytest.raises(ProviderStateChanged, match="read-back"):
        await _adapter(fake).act(_quarantine("m_scam"))
    assert fake.modify_count == 1  # it tried, then verified independently and failed closed


@pytest.mark.asyncio
async def test_adapter_rejects_wrong_operation():
    fake = FakeGmail()
    bad = Action(
        action_id="x",
        episode_id="ep",
        policy_version="v1",
        target=Target(provider="gmail", resource_id="m_scam", operation="delete"),
    )
    with pytest.raises(PermissionError):
        await _adapter(fake).act(bad)


@pytest.mark.asyncio
async def test_network_disabled_without_transport():
    with pytest.raises(PermissionError, match="disabled"):
        GmailAdapter(GmailConfig(quarantine_label_id=LABEL), TOKEN)


@pytest.mark.asyncio
async def test_smoke_follows_inbox_creates_label_quarantines_and_preserves_control():
    fake = FakeGmail(has_quarantine_label=False)
    result = await run_gmail_smoke(TOKEN, run_id="gmail-smoke-1", transport=fake.transport())
    assert fake.created_label is True  # label was created on the fly
    assert result["scam_message_id"] == "m_scam"
    assert result["before_state"] == "inbox"
    assert result["quarantine_acknowledged"] is True
    assert result["after_state"] == "quarantined"
    assert result["quarantine_verified"] is True
    assert result["control_message_id"] == "m_ctrl"
    assert result["control_state"] == "inbox"  # unrelated mail untouched


@pytest.mark.asyncio
async def test_smoke_refuses_when_no_scam_marker():
    fake = FakeGmail()
    fake.meta["m_scam"] = ("Bank <b@x>", "Monthly statement", "your statement is ready")
    with pytest.raises(ValueError, match="scam-marked"):
        await run_gmail_smoke(TOKEN, run_id="gmail-smoke-2", transport=fake.transport())
