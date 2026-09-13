"""Construct the explicitly configured live runtime without fixture fallbacks."""

from datetime import datetime, timezone
from decimal import Decimal

from debait.agent.reasoner import ModelReasoner
from debait.driver.telegram_conversation import poll_conversation
from debait.episodes.store import EpisodeStore
from debait.live import LiveEpisodeRunner, LiveResource
from debait.protection.router import ProviderRouter
from debait.providers.browserbase import BrowserbaseAdapter, BrowserbaseConfig
from debait.providers.gmail import GmailAdapter, GmailConfig
from debait.providers.stripe import StripeAdapter, StripeConfig
from debait.providers.telegram import (
    TelegramAdapter,
    TelegramConfig,
    member_resource,
    message_resource,
)
from debait.providers.twilio import TwilioAdapter, TwilioConfig
from debait.reasoning.budget import Budget
from debait.reasoning.client import ModelClient, ModelConfig

READINESS_ORDER = ("OpenAI", "Gmail", "Twilio", "Telegram", "Browserbase", "Stripe TEST")


def _present(*values) -> bool:
    return all(value is not None and value != "" for value in values)


def live_readiness(settings) -> dict[str, bool]:
    return {
        "OpenAI": settings.openai_key is not None,
        "Gmail": _present(
            settings.gmail_token,
            settings.gmail_user_id,
            settings.gmail_quarantine_label_id,
            settings.gmail_message_id,
        ),
        "Twilio": _present(
            settings.twilio_token,
            settings.twilio_account_sid,
            settings.twilio_call_sid,
            settings.twilio_allowed_caller,
            settings.twilio_allowed_recipient,
        ),
        "Telegram": _present(
            settings.telegram_token,
            settings.telegram_chat_id,
            settings.telegram_message_id,
            settings.telegram_attacker_id,
            settings.telegram_protected_user_id,
        ),
        "Browserbase": _present(
            settings.browserbase_key,
            settings.browserbase_project_id,
            settings.browserbase_session_id,
        ),
        "Stripe TEST": _present(
            settings.stripe_key,
            settings.stripe_account_id,
            settings.stripe_scam_payment_id,
            settings.stripe_control_payment_id,
        )
        and settings.stripe_key.get_secret_value().startswith("sk_test_"),
    }


def configured_bindings(settings) -> list[dict]:
    """Return non-secret exact bindings for dry-run review."""
    return [
        {
            "provider": "gmail",
            "resource_id": settings.gmail_message_id,
            "account_id": settings.gmail_user_id,
            "operation": "quarantine",
        },
        {
            "provider": "twilio",
            "resource_id": settings.twilio_call_sid,
            "account_id": settings.twilio_account_sid,
            "operation": "end",
        },
        {
            "provider": "telegram",
            "resource_id": (
                message_resource(settings.telegram_chat_id, settings.telegram_message_id)
                if _present(settings.telegram_chat_id, settings.telegram_message_id)
                else None
            ),
            "account_id": (
                f"bot:{settings.telegram_token.get_secret_value().split(':', 1)[0]}"
                if settings.telegram_token is not None
                else None
            ),
            "operation": "delete",
        },
        {
            "provider": "telegram",
            "resource_id": (
                member_resource(settings.telegram_chat_id, settings.telegram_attacker_id)
                if _present(settings.telegram_chat_id, settings.telegram_attacker_id)
                else None
            ),
            "account_id": (
                f"bot:{settings.telegram_token.get_secret_value().split(':', 1)[0]}"
                if settings.telegram_token is not None
                else None
            ),
            "operation": "ban",
        },
        {
            "provider": "browserbase",
            "resource_id": settings.browserbase_session_id,
            "account_id": settings.browserbase_project_id,
            "operation": "release",
        },
        {
            "provider": "stripe",
            "resource_id": settings.stripe_scam_payment_id,
            "account_id": settings.stripe_account_id,
            "operation": "cancel",
        },
        {
            "provider": "stripe",
            "resource_id": settings.stripe_control_payment_id,
            "account_id": settings.stripe_account_id,
            "operation": "observe",
            "role": "control",
        },
    ]


def _resources(settings, bot_id: int) -> list[LiveResource]:
    telegram_message = message_resource(settings.telegram_chat_id, settings.telegram_message_id)
    telegram_member = member_resource(settings.telegram_chat_id, settings.telegram_attacker_id)
    telegram_account = f"bot:{bot_id}"
    return [
        LiveResource(
            provider="gmail",
            resource_id=settings.gmail_message_id,
            account_id=settings.gmail_user_id,
            operation="quarantine",
        ),
        LiveResource(
            provider="twilio",
            resource_id=settings.twilio_call_sid,
            account_id=settings.twilio_account_sid,
            operation="end",
            parent_provider="gmail",
            parent_resource_id=settings.gmail_message_id,
            edge_kind="channel_migration",
        ),
        LiveResource(
            provider="telegram",
            resource_id=telegram_message,
            account_id=telegram_account,
            operation="delete",
            parent_provider="twilio",
            parent_resource_id=settings.twilio_call_sid,
            edge_kind="channel_migration",
        ),
        LiveResource(
            provider="telegram",
            resource_id=telegram_member,
            account_id=telegram_account,
            operation="ban",
            parent_provider="telegram",
            parent_resource_id=telegram_message,
            edge_kind="inferred_actor",
        ),
        LiveResource(
            provider="browserbase",
            resource_id=settings.browserbase_session_id,
            account_id=settings.browserbase_project_id,
            operation="release",
            parent_provider="telegram",
            parent_resource_id=telegram_message,
            edge_kind="observed_navigation",
        ),
        LiveResource(
            provider="stripe",
            resource_id=settings.stripe_scam_payment_id,
            account_id=settings.stripe_account_id,
            operation="cancel",
            parent_provider="browserbase",
            parent_resource_id=settings.browserbase_session_id,
            edge_kind="observed_payment_origin",
        ),
        LiveResource(
            provider="stripe",
            resource_id=settings.stripe_control_payment_id,
            account_id=settings.stripe_account_id,
            operation="observe",
            role="control",
        ),
    ]


async def build_live_runtime(settings):
    readiness = live_readiness(settings)
    unavailable = [name for name in READINESS_ORDER if not readiness[name]]
    if unavailable:
        raise ValueError("Live providers not configured: " + ", ".join(unavailable))

    token_value = settings.telegram_token.get_secret_value()
    try:
        bot_id = int(token_value.split(":", 1)[0])
    except (ValueError, IndexError):
        raise PermissionError("Telegram bot token identity is invalid") from None
    telegram = TelegramAdapter(
        TelegramConfig(
            bot_id=bot_id,
            controlled_chat_ids=frozenset({settings.telegram_chat_id}),
            controlled_attacker_ids=frozenset({settings.telegram_attacker_id}),
            protected_user_ids=frozenset({settings.telegram_protected_user_id}),
        ),
        settings.telegram_token,
        allow_network=True,
    )
    updates = await poll_conversation(settings.telegram_token, allow_network=True)
    exact = next(
        (
            update
            for update in updates
            if update["chat_id"] == settings.telegram_chat_id
            and update["message_id"] == settings.telegram_message_id
        ),
        None,
    )
    if exact is None or exact["from_id"] != settings.telegram_attacker_id:
        raise PermissionError("Configured Telegram message/attacker binding was not observed")
    telegram.record_message_update(
        message_resource(settings.telegram_chat_id, settings.telegram_message_id),
        evidence_path="telegram:getUpdates:live-binding",
        observed_at=datetime.fromtimestamp(exact["date"] or 1, tz=timezone.utc),
        text=exact["text"],
        actor_id=exact["from_id"],
    )

    adapters = {
        "gmail": GmailAdapter(
            GmailConfig(
                user_id=settings.gmail_user_id,
                quarantine_label_id=settings.gmail_quarantine_label_id,
            ),
            settings.gmail_token,
            allow_network=True,
        ),
        "twilio": TwilioAdapter(
            TwilioConfig(
                account_sid=settings.twilio_account_sid,
                controlled_call_sids=frozenset({settings.twilio_call_sid}),
                allowed_callers=frozenset({settings.twilio_allowed_caller}),
                allowed_recipients=frozenset({settings.twilio_allowed_recipient}),
            ),
            settings.twilio_token,
            allow_network=True,
        ),
        "telegram": telegram,
        "browserbase": BrowserbaseAdapter(
            BrowserbaseConfig(
                project_id=settings.browserbase_project_id,
                controlled_session_ids=frozenset({settings.browserbase_session_id}),
            ),
            settings.browserbase_key,
            allow_network=True,
        ),
        "stripe": StripeAdapter(
            StripeConfig(
                account_id=settings.stripe_account_id,
                api_version=settings.stripe_api_version,
            ),
            settings.stripe_key,
            allow_network=True,
        ),
    }
    store = EpisodeStore(settings.database_path)
    store.set_budget_limit(settings.live_model_budget_microdollars)
    model_config = ModelConfig(
        model="gpt-5.6-luna",
        input_usd_per_million=Decimal("0.20"),
        output_usd_per_million=Decimal("1.20"),
    )
    reasoner = ModelReasoner(
        ModelClient(
            model_config,
            settings.openai_key,
            Budget(store),
            allow_network=True,
        )
    )
    runner = LiveEpisodeRunner(
        store,
        ProviderRouter(adapters),
        _resources(settings, bot_id),
        reasoner,
        episode_id=settings.live_episode_id,
    )
    return runner, ("stripe", settings.stripe_control_payment_id)
