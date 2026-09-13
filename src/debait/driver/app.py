import os
import secrets

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import SecretStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from debait.driver.bindings import BindingExpired, BindingNotFound, BindingStore
from debait.driver.pages import demo_page
from debait.settings import Settings


def _secret(settings):
    path = settings.database_path.parent / "driver.token"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        value = path.read_text().strip()
    else:
        value = secrets.token_urlsafe(32)
        with os.fdopen(fd, "w") as output:
            output.write(value + "\n")
    return SecretStr(value)


def open_binding_store(settings, signing_secret=None, now=None):
    return BindingStore(
        settings.database_path.parent / "driver.sqlite",
        signing_secret or _secret(settings),
        now=now,
    )


def create_driver(settings: Settings | None = None, *, signing_secret=None, now=None):
    settings = settings or Settings()
    app = FastAPI(title="DeBait controlled demo driver", docs_url=None, redoc_url=None)
    app.state.bindings = open_binding_store(settings, signing_secret, now)

    @app.middleware("http")
    async def secure_response(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/demo/owned-bank", response_class=HTMLResponse)
    def owned_bank(token: str | None = None):
        if token:
            try:
                app.state.bindings.record_open(token)
            except BindingExpired:
                raise HTTPException(410, "This demonstration link expired") from None
            except BindingNotFound:
                raise HTTPException(404, "Demonstration link not found") from None
        return demo_page()

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
    return app
