"""Local OAuth 2.0 bootstrap and verification for Gmail.

Implements the standard Google OAuth 2.0 authorization-code flow with loopback
redirect for local hackathon demo setup. Exchanges the code for access and refresh
tokens, discovers the DeBait/Quarantined label ID, and stores credentials only
in the ignored local .env.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse

import httpx
from pydantic import SecretStr

from debait.providers.gmail import QUARANTINE_LABEL_NAME

GMAIL_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GMAIL_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
DEFAULT_REDIRECT_PORT = 8085
DEFAULT_REDIRECT_URI = f"http://localhost:{DEFAULT_REDIRECT_PORT}/callback"


def build_authorization_url(
    client_id: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    *,
    scope: str = GMAIL_MODIFY_SCOPE,
    state: str = "debait-gmail-auth",
) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return f"{GMAIL_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_tokens(
    client_id: str,
    client_secret: SecretStr,
    code: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    *,
    transport=None,
    timeout: float = 15.0,
) -> dict:
    """Exchange authorization code for access and refresh tokens."""
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret.get_secret_value(),
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        response = await client.post(GMAIL_TOKEN_URL, data=data)
        if response.status_code != 200:
            raise ConnectionError(f"OAuth token exchange failed with HTTP {response.status_code}")
        payload = response.json()
    if not payload.get("access_token"):
        raise ConnectionError("OAuth response missing access_token")
    return payload


async def refresh_access_token(
    client_id: str,
    client_secret: SecretStr,
    refresh_token: SecretStr,
    *,
    transport=None,
    timeout: float = 15.0,
) -> dict:
    """Obtain a fresh access token using a refresh token."""
    data = {
        "client_id": client_id,
        "client_secret": client_secret.get_secret_value(),
        "refresh_token": refresh_token.get_secret_value(),
        "grant_type": "refresh_token",
    }
    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        response = await client.post(GMAIL_TOKEN_URL, data=data)
        if response.status_code != 200:
            raise ConnectionError(f"OAuth token refresh failed with HTTP {response.status_code}")
        payload = response.json()
    if not payload.get("access_token"):
        raise ConnectionError("OAuth refresh response missing access_token")
    return payload


async def verify_gmail_read_and_scope(
    token: SecretStr,
    user_id: str = "me",
    *,
    transport=None,
    allow_network: bool = False,
    timeout: float = 10.0,
) -> dict:
    """Perform read-only verification: check profile and discover quarantine label ID."""
    if not allow_network and not isinstance(transport, httpx.MockTransport):
        raise PermissionError("Gmail network access is disabled until explicitly enabled")

    headers = {"Authorization": f"Bearer {token.get_secret_value()}"}
    async with httpx.AsyncClient(
        base_url="https://gmail.googleapis.com",
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        # 1. Verify user profile
        user_enc = quote(user_id, safe="")
        profile_resp = await client.get(f"/gmail/v1/users/{user_enc}/profile", headers=headers)
        if profile_resp.status_code in {401, 403}:
            raise PermissionError(f"Gmail denied profile request (HTTP {profile_resp.status_code})")
        if profile_resp.status_code != 200:
            raise ConnectionError(f"Gmail profile request failed (HTTP {profile_resp.status_code})")
        profile = profile_resp.json()

        # 2. List labels and search for DeBait/Quarantined
        labels_resp = await client.get(f"/gmail/v1/users/{user_enc}/labels", headers=headers)
        if labels_resp.status_code != 200:
            raise ConnectionError(f"Gmail label listing failed (HTTP {labels_resp.status_code})")
        labels_data = labels_resp.json().get("labels", [])
        quarantine_id = None
        for lbl in labels_data:
            if lbl.get("name") == QUARANTINE_LABEL_NAME:
                quarantine_id = lbl.get("id")
                break

    return {
        "email": profile.get("emailAddress"),
        "messages_total": profile.get("messagesTotal"),
        "labels_found": len(labels_data),
        "quarantine_label_name": QUARANTINE_LABEL_NAME,
        "quarantine_label_id": quarantine_id,
        "verified": True,
    }


def update_local_env(env_path: Path, updates: dict[str, str]) -> None:
    """Safely update or add key-value pairs to local .env without overwriting unrelated lines."""
    lines = []
    existing_keys = set()
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _ = stripped.split("=", 1)
            key = key.strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                existing_keys.add(key)
                continue
        new_lines.append(line)

    for key, value in updates.items():
        if key not in existing_keys:
            new_lines.append(f"{key}={value}")

    content = "\n".join(new_lines)
    if not content.endswith("\n"):
        content += "\n"
    env_path.write_text(content, encoding="utf-8")
    try:
        env_path.chmod(0o600)
    except OSError:
        pass


class _LoopbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/callback":
            params = parse_qs(parsed.query)
            if "code" in params:
                self.server.code = params["code"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                html = (
                    "<html><body style='font-family: sans-serif; text-align: center; padding: 40px;'>"
                    "<h2>DeBait Gmail Authentication Complete</h2>"
                    "<p>You can close this tab and return to the terminal.</p>"
                    "</body></html>"
                )
                self.wfile.write(html.encode("utf-8"))
            elif "error" in params:
                self.server.error = params["error"][0]
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                html = f"<html><body><h2>Authentication Error: {self.server.error}</h2></body></html>"
                self.wfile.write(html.encode("utf-8"))
            else:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def capture_auth_code_loopback(port: int = DEFAULT_REDIRECT_PORT, timeout_seconds: float = 120.0) -> str:
    """Run a temporary local HTTP server to receive the OAuth redirect callback."""
    server = HTTPServer(("127.0.0.1", port), _LoopbackHandler)
    server.code = None
    server.error = None
    server.timeout = 2.0

    def serve():
        while server.code is None and server.error is None and not stop_event.is_set():
            server.handle_request()

    stop_event = threading.Event()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)
    stop_event.set()
    server.server_close()

    if server.error:
        raise PermissionError(f"OAuth authorization denied: {server.error}")
    if not server.code:
        raise TimeoutError("Timed out waiting for OAuth callback authorization code")
    return server.code
