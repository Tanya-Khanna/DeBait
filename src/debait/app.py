import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from debait.episodes.models import Event
from debait.episodes.store import EpisodeStore
from debait.hunter.fixture import FixtureDecoy
from debait.hunter.runner import start_hunter
from debait.ingest.webhooks import (
    InvalidWebhook,
    parse_twilio_form,
    verify_stripe_signature,
    verify_twilio_signature,
)
from debait.reasoning.budget import Budget
from debait.security import install_security
from debait.settings import Settings
from debait.testing.harness import CASES, run_case


class LocalRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="DeBait", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.store = EpisodeStore(settings.database_path)

    install_security(app, settings)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": settings.mode}

    @app.get("/api/episodes")
    def episodes():
        return app.state.store.summaries()

    @app.get("/api/episodes/{episode_id}")
    def episode(episode_id: str):
        value = app.state.store.episode_snapshot(episode_id)
        if value is None:
            raise HTTPException(404, "Episode not found")
        value["actions"] = app.state.store.action_history(episode_id)
        value["mode"] = "local"
        value["reasoning_mode"] = "deterministic_fixture"
        return value

    @app.get("/api/episodes/{episode_id}/events")
    def episode_events(episode_id: str, request: Request):
        if app.state.store.episode_snapshot(episode_id) is None:
            raise HTTPException(404, "Episode not found")
        cursor = request.headers.get("last-event-id", "0")
        if not cursor.isdigit():
            raise HTTPException(400, "Last-Event-ID must be a nonnegative integer")
        rows = app.state.store.event_feed_after(episode_id, int(cursor))

        def stream():
            for row in rows:
                yield (
                    f"id: {row['sequence']}\n"
                    "event: episode-event\n"
                    f"data: {json.dumps(row, separators=(',', ':'))}\n\n"
                )

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"},
        )

    @app.get("/api/reports")
    def reports():
        directory = settings.database_path.parent / "reports"
        return (
            [json.loads(p.read_text()) for p in sorted(directory.glob("*.json"))]
            if directory.exists()
            else []
        )

    @app.get("/api/evaluations")
    def evaluations():
        directory = settings.database_path.parent / "evaluations"
        if not directory.exists():
            return []
        values = []
        for path in directory.glob("*.json"):
            if path.stat().st_size > 2_000_000:
                continue
            try:
                value = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and isinstance(value.get("created_at"), str):
                values.append(value)
        return sorted(values, key=lambda value: value["created_at"], reverse=True)

    @app.get("/api/usage")
    def usage():
        return {
            "mode": settings.mode,
            "fresh_model_enabled": False,
            "currency": "USD",
            "model": Budget(app.state.store).snapshot(),
        }

    @app.post("/api/local-runs")
    def local_run(body: LocalRunRequest):
        if body.case not in CASES:
            raise HTTPException(422, "Unknown local scenario")
        return run_case(
            body.case, workspace=settings.database_path.parent, database_path=settings.database_path
        )

    @app.post("/api/local-hunter/{episode_id}")
    async def local_hunter(episode_id: str):
        if app.state.store.episode_snapshot(episode_id) is None:
            raise HTTPException(404, "Episode not found")
        context_id = f"fixture-decoy:{episode_id}"
        run = await start_hunter(
            episode_id,
            context_id,
            app.state.store,
            FixtureDecoy(context_id),
            victim_context_ids={f"victim:{episode_id}"},
            allowed_actor_id="controlled-attacker",
        )
        indicator_ids = set(run.indicator_event_ids)
        indicators = [
            {
                key: event.payload[key]
                for key in [
                    "kind",
                    "value",
                    "source_event_id",
                    "source_start",
                    "source_end",
                    "observed_at",
                    "claim_status",
                ]
            }
            for event in app.state.store.events(episode_id)
            if event.event_id in indicator_ids
        ]
        return {**run.model_dump(mode="json"), "indicators": indicators}

    @app.post("/callbacks/stripe", status_code=202)
    async def stripe_callback(request: Request):
        secret = settings.stripe_webhook_secret
        if secret is None:
            raise HTTPException(503, "Stripe callback is not configured")
        content_length = request.headers.get("content-length")
        if content_length and (not content_length.isdigit() or int(content_length) > 65_536):
            raise HTTPException(413, "Callback body is too large")
        raw = await request.body()
        try:
            verify_stripe_signature(
                raw,
                request.headers.get("stripe-signature", ""),
                secret.get_secret_value(),
            )
        except InvalidWebhook as exc:
            raise HTTPException(401, "Invalid Stripe signature") from exc
        try:
            body = json.loads(raw)
            object_body = body["data"]["object"]
            event_id = body["id"]
            event_type = body["type"]
            resource_id = object_body["id"]
            status = object_body["status"]
            livemode = object_body["livemode"]
            created = body["created"]
            if type(created) is not int:
                raise ValueError("Stripe event creation time must be an integer")
            observed_at = datetime.fromtimestamp(created, timezone.utc)
        except (KeyError, TypeError, ValueError, OverflowError, json.JSONDecodeError, OSError) as exc:
            raise HTTPException(400, "Malformed Stripe event") from exc
        if (
            not isinstance(event_id, str)
            or not event_id.startswith("evt_")
            or not isinstance(event_type, str)
            or not event_type.startswith("payment_intent.")
            or not isinstance(resource_id, str)
            or not resource_id.startswith("pi_")
            or not isinstance(status, str)
            or type(livemode) is not bool
            or livemode
        ):
            raise HTTPException(400, "Unsupported Stripe event")
        episode_id = app.state.store.episode_for_resource("stripe", resource_id)
        if episode_id is None:
            return {"accepted": False, "reason": "unbound_resource"}
        event = Event(
            event_id=str(uuid4()),
            provider="stripe",
            provider_event_id=event_id,
            episode_id=episode_id,
            observed_at=observed_at,
            received_at=datetime.now(timezone.utc),
            payload={
                "resource_id": resource_id,
                "event_type": event_type,
                "status": status,
                "livemode": livemode,
                "signature_verified": True,
            },
        )
        return {"accepted": True, "inserted": app.state.store.ingest(event)}

    @app.post("/callbacks/twilio", status_code=202)
    async def twilio_callback(request: Request):
        token = settings.twilio_token
        if token is None:
            raise HTTPException(503, "Twilio callback is not configured")
        content_length = request.headers.get("content-length")
        if content_length and (not content_length.isdigit() or int(content_length) > 65_536):
            raise HTTPException(413, "Callback body is too large")
        raw = await request.body()
        try:
            params = parse_twilio_form(raw)
        except InvalidWebhook as exc:
            raise HTTPException(400, "Malformed Twilio callback") from exc
        base = settings.callback_base_url.rstrip("/") if settings.callback_base_url else ""
        callback_url = f"{base}{request.url.path}" if base else str(request.url)
        if request.url.query:
            callback_url += f"?{request.url.query}"
        try:
            verify_twilio_signature(
                callback_url,
                params,
                request.headers.get("x-twilio-signature", ""),
                token.get_secret_value(),
            )
        except InvalidWebhook as exc:
            raise HTTPException(401, "Invalid Twilio signature") from exc
        call_sid = params.get("CallSid", "")
        call_status = params.get("CallStatus", "")
        if not re.fullmatch(r"CA[0-9a-fA-F]{32}", call_sid) or call_status not in {
            "queued",
            "ringing",
            "in-progress",
            "completed",
            "busy",
            "failed",
            "no-answer",
            "canceled",
        }:
            raise HTTPException(400, "Unsupported Twilio callback")
        episode_id = app.state.store.episode_for_resource("twilio", call_sid)
        if episode_id is None:
            return {"accepted": False, "reason": "unbound_resource"}
        digest = hashlib.sha256(raw).hexdigest()
        event = Event(
            event_id=str(uuid4()),
            provider="twilio",
            provider_event_id=f"{call_sid}:callback:{digest}",
            episode_id=episode_id,
            observed_at=datetime.now(timezone.utc),
            received_at=datetime.now(timezone.utc),
            payload={
                "resource_id": call_sid,
                "status": call_status,
                "signature_verified": True,
                "transcript_source": "none",
                "claimed_identity": "unverified",
            },
        )
        return {"accepted": True, "inserted": app.state.store.ingest(event)}

    @app.get("/debait-mark.svg")
    def mark():
        path = settings.frontend_path / "debait-mark.svg"
        if not path.is_file():
            raise HTTPException(404, "Brand asset not built")
        return FileResponse(path, media_type="image/svg+xml")

    @app.get("/architecture")
    def architecture():
        path = Path("architecture.html")
        if not path.exists():
            raise HTTPException(404, "Architecture file unavailable")
        return FileResponse(path)

    assets = settings.frontend_path / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{path:path}")
    def frontend(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "API route not found")
        index = settings.frontend_path / "index.html"
        if index.is_file():
            return FileResponse(index)
        return {
            "name": "DeBait",
            "mode": settings.mode,
            "message": "Frontend not built; run npm --prefix frontend run build.",
        }

    return app
