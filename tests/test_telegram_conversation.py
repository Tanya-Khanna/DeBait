import httpx
import pytest
from pydantic import SecretStr

from debait.driver.telegram_conversation import poll_conversation, run_telegram_smoke

TOKEN = SecretStr("8974283680:AAtesttoken1234567890")
BOT_ID = 8974283680
CHAT = -1001234567890
ATTACKER = 555
OWNER = 111


def _updates():
    return {
        "ok": True,
        "result": [
            {
                "update_id": 1,
                "message": {
                    "message_id": 41,
                    "from": {"id": OWNER, "is_bot": False},
                    "chat": {"id": CHAT, "type": "group"},
                    "text": "hello",
                    "date": 1000,
                },
            },
            {
                "update_id": 2,
                "message": {
                    "message_id": 42,
                    "from": {"id": ATTACKER, "is_bot": False},
                    "chat": {"id": CHAT, "type": "group"},
                    "text": "URGENT: transfer to the safe account now",
                    "date": 1001,
                },
            },
            {
                "update_id": 3,
                "message": {
                    "message_id": 43,
                    "from": {"id": BOT_ID, "is_bot": True},
                    "chat": {"id": CHAT, "type": "group"},
                    "text": "/start",
                    "date": 1002,
                },
            },
        ],
    }


def _handler(*, member_status="kicked", updates=None):
    def handle(request):
        path = request.url.path
        if path.endswith("/getUpdates"):
            return httpx.Response(200, json=updates or _updates())
        if path.endswith("/getMe"):
            return httpx.Response(200, json={"ok": True, "result": {"id": BOT_ID, "is_bot": True}})
        if path.endswith("/deleteMessage"):
            return httpx.Response(200, json={"ok": True, "result": True})
        if path.endswith("/banChatMember"):
            return httpx.Response(200, json={"ok": True, "result": True})
        if path.endswith("/getChatMember"):
            return httpx.Response(
                200, json={"ok": True, "result": {"user": {"id": ATTACKER}, "status": member_status}}
            )
        raise AssertionError(f"unexpected telegram call: {path}")

    return httpx.MockTransport(handle)


@pytest.mark.asyncio
async def test_smoke_follows_conversation_then_deletes_and_bans():
    result = await run_telegram_smoke(TOKEN, run_id="tg-smoke-1", transport=_handler())
    assert result["followed_messages"] == 2  # the two human messages, bot message excluded
    assert result["attacker_id"] == ATTACKER
    assert result["protected_user_ids"] == [OWNER]
    assert result["scam_message_id"] == 42
    assert result["delete_acknowledged"] is True
    assert result["ban_acknowledged"] is True
    assert result["attacker_member_state"] == "banned"
    assert result["ban_verified"] is True


@pytest.mark.asyncio
async def test_poll_ignores_bot_and_malformed_messages():
    messages = await poll_conversation(TOKEN, transport=_handler())
    assert [m["from_id"] for m in messages] == [OWNER, ATTACKER]
    assert all(m["chat_id"] == CHAT for m in messages)


@pytest.mark.asyncio
async def test_no_scam_marker_refuses_to_act():
    benign = {
        "ok": True,
        "result": [
            {
                "update_id": 1,
                "message": {
                    "message_id": 7,
                    "from": {"id": OWNER, "is_bot": False},
                    "chat": {"id": CHAT, "type": "group"},
                    "text": "see you at lunch",
                    "date": 5,
                },
            },
        ],
    }
    with pytest.raises(ValueError, match="scam-marked"):
        await run_telegram_smoke(TOKEN, run_id="tg-smoke-2", transport=_handler(updates=benign))


@pytest.mark.asyncio
async def test_requires_a_distinct_protected_owner():
    only_attacker = {
        "ok": True,
        "result": [
            {
                "update_id": 1,
                "message": {
                    "message_id": 9,
                    "from": {"id": ATTACKER, "is_bot": False},
                    "chat": {"id": CHAT, "type": "group"},
                    "text": "pay the support fee now",
                    "date": 5,
                },
            },
        ],
    }
    with pytest.raises(ValueError, match="protected sender"):
        await run_telegram_smoke(TOKEN, run_id="tg-smoke-3", transport=_handler(updates=only_attacker))


@pytest.mark.asyncio
async def test_live_network_is_disabled_without_transport():
    with pytest.raises(PermissionError, match="disabled"):
        await poll_conversation(TOKEN, allow_network=False)


@pytest.mark.asyncio
async def test_ban_not_verified_when_member_still_present():
    result = await run_telegram_smoke(TOKEN, run_id="tg-smoke-4", transport=_handler(member_status="member"))
    assert result["ban_acknowledged"] is True
    assert result["attacker_member_state"] == "present"
    assert result["ban_verified"] is False
