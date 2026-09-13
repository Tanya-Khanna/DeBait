from datetime import datetime, timezone

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from debait.protection.broker import Action
from debait.protection.policy import Target
from debait.providers.base import RetryAfter
from debait.providers.telegram import (
    TelegramAdapter,
    TelegramConfig,
    member_resource,
    message_resource,
)

CHAT = -100123456
ATTACKER = 731
BOT = 500
OWNER = 900


def action(operation, resource_id):
    return Action(
        action_id=f"act-{operation}",
        episode_id="sc1",
        target=Target(provider="telegram", resource_id=resource_id, operation=operation),
        policy_version="critical_cross_app_scam_v1",
    )


def adapter(handler):
    return TelegramAdapter(
        TelegramConfig(
            bot_id=BOT,
            controlled_chat_ids=frozenset({CHAT}),
            controlled_attacker_ids=frozenset({ATTACKER}),
            protected_user_ids=frozenset({OWNER}),
        ),
        SecretStr("500:local_fixture_token"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_delete_ack_is_not_read_back_until_client_observes_removal():
    calls = []

    def handler(request):
        calls.append(request.url.path.rsplit("/", 1)[-1])
        method = calls[-1]
        if method == "getMe":
            return httpx.Response(200, json={"ok": True, "result": {"id": BOT, "is_bot": True}})
        assert method == "deleteMessage"
        assert request.content == f"chat_id={CHAT}&message_id=91".encode()
        return httpx.Response(200, json={"ok": True, "result": True})

    client = adapter(handler)
    resource = message_resource(CHAT, 91)
    client.record_message_update(resource, "event:telegram:update:81", datetime.now(timezone.utc))
    before = await client.read(resource)
    receipt = await client.act(action("delete", resource))
    after_ack = await client.read(resource)
    client_observed = client.record_client_observation(resource, "removed", "capture:telegram:91")

    assert before.state == "present" and before.level == "provider_event"
    assert receipt.acknowledged
    assert after_ack.state == "present" and after_ack.level == "provider_event"
    assert client_observed.state == "removed" and client_observed.level == "client_observed"
    assert calls == ["getMe", "deleteMessage"]


@pytest.mark.asyncio
async def test_ban_targets_controlled_actor_and_reads_membership_back():
    state = {"status": "member"}
    called_users = []

    def handler(request):
        method = request.url.path.rsplit("/", 1)[-1]
        if method == "getMe":
            return httpx.Response(200, json={"ok": True, "result": {"id": BOT, "is_bot": True}})
        form = dict(item.split("=") for item in request.content.decode().split("&"))
        called_users.append(int(form["user_id"]))
        if method == "getChatMember":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "result": {"status": state["status"], "user": {"id": ATTACKER}},
                },
            )
        assert method == "banChatMember" and form["revoke_messages"] == "false"
        state["status"] = "kicked"
        return httpx.Response(200, json={"ok": True, "result": True})

    client = adapter(handler)
    resource = member_resource(CHAT, ATTACKER)
    assert (await client.read(resource)).state == "present"
    await client.act(action("ban", resource))
    assert (await client.read(resource)).state == "banned"
    assert called_users == [ATTACKER, ATTACKER, ATTACKER]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        Target(provider="telegram", resource_id=message_resource(-999, 1), operation="delete"),
        Target(provider="telegram", resource_id=member_resource(CHAT, 999), operation="ban"),
        Target(provider="telegram", resource_id=member_resource(CHAT, BOT), operation="ban"),
    ],
)
async def test_refuses_uncontrolled_chat_or_actor_before_http(target):
    def handler(request):
        raise AssertionError("Unauthorized target reached Telegram")

    with pytest.raises(PermissionError):
        await adapter(handler).act(
            Action(action_id="blocked", episode_id="sc1", target=target, policy_version="v1")
        )


@pytest.mark.asyncio
async def test_delete_requires_observed_message_evidence_before_http():
    def handler(request):
        raise AssertionError("A message without evidence reached Telegram")

    resource = message_resource(CHAT, 91)
    with pytest.raises(PermissionError, match="observed message evidence"):
        await adapter(handler).act(action("delete", resource))


@pytest.mark.asyncio
async def test_rate_limit_uses_bounded_provider_retry_hint():
    def handler(request):
        return httpx.Response(
            429,
            json={"ok": False, "parameters": {"retry_after": 7}, "description": "private"},
        )

    with pytest.raises(RetryAfter) as exc:
        await adapter(handler).read(member_resource(CHAT, ATTACKER))
    assert exc.value.seconds == 7
    assert "private" not in str(exc.value)


def test_network_and_non_bot_token_are_disabled():
    config = TelegramConfig(
        bot_id=BOT,
        controlled_chat_ids=frozenset({CHAT}),
        controlled_attacker_ids=frozenset({ATTACKER}),
        protected_user_ids=frozenset({OWNER}),
    )
    with pytest.raises(PermissionError, match="disabled"):
        TelegramAdapter(config, SecretStr("500:fixture"))
    with pytest.raises(PermissionError, match="token"):
        TelegramAdapter(config, SecretStr("invalid"), transport=httpx.MockTransport(lambda r: None))


def test_owner_cannot_be_configured_as_controlled_attacker():
    valid = TelegramConfig(
        bot_id=BOT,
        controlled_chat_ids=frozenset({CHAT}),
        controlled_attacker_ids=frozenset({ATTACKER}),
        protected_user_ids=frozenset({OWNER}),
    )
    assert valid.protected_user_ids == frozenset({OWNER})
    with pytest.raises(ValidationError, match="overlap"):
        TelegramConfig(
            bot_id=BOT,
            controlled_chat_ids=frozenset({CHAT}),
            controlled_attacker_ids=frozenset({ATTACKER}),
            protected_user_ids=frozenset({ATTACKER}),
        )
