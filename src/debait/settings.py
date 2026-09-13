from pathlib import Path
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DEBAIT_", env_file=".env", extra="ignore")
    mode: Literal["local", "live-test"] = "local"
    database_path: Path = Path("runtime/episodes.sqlite")
    frontend_path: Path = Path("frontend/dist")
    operator_token: SecretStr | None = None
    stripe_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    telegram_token: SecretStr | None = None
    browserbase_key: SecretStr | None = None
    browserbase_project_id: str | None = None
    gmail_token: SecretStr | None = None
    twilio_token: SecretStr | None = None
    callback_base_url: str | None = None
    openai_key: SecretStr | None = None
    live_episode_id: str = "debait-live-demo"
    live_model_budget_microdollars: int = 300_000
    gmail_user_id: str = "me"
    gmail_quarantine_label_id: str | None = None
    gmail_message_id: str | None = None
    twilio_account_sid: str | None = None
    twilio_call_sid: str | None = None
    twilio_allowed_caller: str | None = None
    twilio_allowed_recipient: str | None = None
    telegram_chat_id: int | None = None
    telegram_message_id: int | None = None
    telegram_attacker_id: int | None = None
    telegram_protected_user_id: int | None = None
    browserbase_session_id: str | None = None
    stripe_account_id: str | None = None
    stripe_api_version: str = "2026-08-26.dahlia"
    stripe_scam_payment_id: str | None = None
    stripe_control_payment_id: str | None = None

    @model_validator(mode="after")
    def live_credentials(self):
        if self.mode == "live-test":
            # Live mode remains fail-closed until real adapters and scope are configured.
            raise ValueError(
                "Live-test mode is not enabled: provider setup and scoped smoke checks are required"
            )
        return self
