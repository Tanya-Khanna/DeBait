import json
from base64 import urlsafe_b64encode

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
            if "format=full" in query:
                frm, subj, snip = self.meta.get(mid, ("", "", ""))
                return httpx.Response(
                    200,
                    json={
                        "id": mid,
                        "labelIds": sorted(self.labels[mid]),
                        "snippet": snip,
                        "payload": {
                            "headers": [
                                {"name": "From", "value": frm},
                                {"name": "Subject", "value": subj},
                            ],
                            "body": {
                                "data": urlsafe_b64encode(b"Do not call your bank. Pay the safe account.")
                                .decode()
                                .rstrip("=")
                            },
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
async def test_read_normalizes_exact_message_content_for_live_reasoning():
    observation = await _adapter(FakeGmail()).read("m_scam")

    assert observation.details["from"] == "Bank <fraud@x>"
    assert observation.details["subject"] == "Your account has been compromised"
    assert observation.details["snippet"] == "verify immediately"
    assert observation.details["body"] == "Do not call your bank. Pay the safe account."


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


def test_build_authorization_url():
    from debait.driver.gmail_auth import GMAIL_MODIFY_SCOPE, build_authorization_url

    url = build_authorization_url("my-client-id")
    assert "client_id=my-client-id" in url
    assert "access_type=offline" in url
    assert "prompt=consent" in url
    assert "response_type=code" in url
    assert GMAIL_MODIFY_SCOPE in url.replace("%3A", ":").replace("%2F", "/")


@pytest.mark.asyncio
async def test_exchange_code_for_tokens():
    from debait.driver.gmail_auth import exchange_code_for_tokens

    def handler(request):
        assert request.method == "POST"
        assert request.url.path == "/token"
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.test-access-token",
                "refresh_token": "1//test-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/gmail.modify",
            },
        )

    transport = httpx.MockTransport(handler)
    tokens = await exchange_code_for_tokens(
        "test-id",
        SecretStr("test-secret"),
        "test-code",
        transport=transport,
    )
    assert tokens["access_token"] == "ya29.test-access-token"
    assert tokens["refresh_token"] == "1//test-refresh-token"


@pytest.mark.asyncio
async def test_refresh_access_token():
    from debait.driver.gmail_auth import refresh_access_token

    def handler(request):
        assert request.method == "POST"
        assert request.url.path == "/token"
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.fresh-access-token",
                "expires_in": 3600,
                "token_type": "Bearer",
            },
        )

    transport = httpx.MockTransport(handler)
    tokens = await refresh_access_token(
        "test-id",
        SecretStr("test-secret"),
        SecretStr("test-refresh-token"),
        transport=transport,
    )
    assert tokens["access_token"] == "ya29.fresh-access-token"


@pytest.mark.asyncio
async def test_verify_gmail_read_and_scope():
    from debait.driver.gmail_auth import verify_gmail_read_and_scope

    def handler(request):
        if request.url.path.endswith("/profile"):
            return httpx.Response(200, json={"emailAddress": "demo@gmail.com", "messagesTotal": 42})
        if request.url.path.endswith("/labels"):
            return httpx.Response(
                200,
                json={
                    "labels": [
                        {"id": "INBOX", "name": "INBOX"},
                        {"id": "Label_12345", "name": "DeBait/Quarantined"},
                    ]
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    transport = httpx.MockTransport(handler)
    report = await verify_gmail_read_and_scope(TOKEN, transport=transport)
    assert report["email"] == "demo@gmail.com"
    assert report["quarantine_label_id"] == "Label_12345"
    assert report["verified"] is True


def test_update_local_env(tmp_path):
    from debait.driver.gmail_auth import update_local_env

    env_file = tmp_path / ".env"
    env_file.write_text("DEBAIT_MODE=local\n# Comment\nDEBAIT_DATABASE_PATH=runtime/test.sqlite\n")

    update_local_env(
        env_file,
        {
            "DEBAIT_GMAIL_TOKEN": "token123",
            "DEBAIT_GMAIL_QUARANTINE_LABEL_ID": "Label_999",
        },
    )

    content = env_file.read_text()
    assert "DEBAIT_MODE=local" in content
    assert "DEBAIT_GMAIL_TOKEN=token123" in content
    assert "DEBAIT_GMAIL_QUARANTINE_LABEL_ID=Label_999" in content
    assert "# Comment" in content

    # Test update existing
    update_local_env(env_file, {"DEBAIT_GMAIL_TOKEN": "token456"})
    content2 = env_file.read_text()
    assert "DEBAIT_GMAIL_TOKEN=token456" in content2
    assert "DEBAIT_GMAIL_TOKEN=token123" not in content2
