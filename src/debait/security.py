import os
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from debait.settings import Settings


class Unlock(BaseModel):
    token: str = Field(min_length=1, max_length=512)


def install_security(app: FastAPI, settings: Settings):
    if settings.operator_token:
        token = settings.operator_token.get_secret_value()
    else:
        path = settings.database_path.parent / "operator.token"
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            token = path.read_text().strip()
        else:
            token = secrets.token_urlsafe(32)
            with os.fdopen(fd, "w") as out:
                out.write(token + "\n")
    if len(token) < 24:
        raise ValueError("Operator token must contain at least 24 characters")
    sessions: dict[str, tuple[str, float]] = {}

    def same_origin(request: Request):
        return request.headers.get("origin") == str(request.base_url).rstrip("/")

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if request.url.path.startswith("/api/") and request.url.path != "/api/health":
            write = request.method not in {"GET", "HEAD", "OPTIONS"}
            if write and not same_origin(request):
                return JSONResponse({"detail": "Same-origin request required"}, status_code=403)
            if not (request.url.path == "/api/session" and request.method == "POST"):
                sid = request.cookies.get("debait_session", "")
                session = sessions.get(sid)
                if not session or session[1] < time.monotonic():
                    sessions.pop(sid, None)
                    return JSONResponse({"detail": "Unlock the local workspace"}, status_code=401)
                if write and not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session[0]):
                    return JSONResponse({"detail": "CSRF token required"}, status_code=403)
                request.state.csrf = session[0]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/session")
    def unlock(body: Unlock):
        if not secrets.compare_digest(body.token, token):
            return JSONResponse({"detail": "Invalid local token"}, status_code=401)
        now = time.monotonic()
        for key in list(sessions):
            if sessions[key][1] < now:
                sessions.pop(key, None)
        if len(sessions) >= 32:
            return JSONResponse({"detail": "Session limit reached"}, status_code=429)
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        sessions[sid] = (csrf, now + 8 * 3600)
        response = JSONResponse({"csrf_token": csrf})
        response.set_cookie(
            "debait_session", sid, httponly=True, samesite="strict", max_age=8 * 3600, path="/api"
        )
        return response

    @app.get("/api/session")
    def session(request: Request):
        return {"csrf_token": request.state.csrf}

    @app.delete("/api/session")
    def logout(request: Request):
        sessions.pop(request.cookies.get("debait_session", ""), None)
        response = JSONResponse({"logged_out": True})
        response.delete_cookie("debait_session", path="/api")
        return response

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
