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

    @model_validator(mode="after")
    def live_credentials(self):
        if self.mode == "live-test":
            # Live mode remains fail-closed until real adapters and scope are configured.
            raise ValueError(
                "Live-test mode is not enabled: provider setup and scoped smoke checks are required"
            )
        return self
