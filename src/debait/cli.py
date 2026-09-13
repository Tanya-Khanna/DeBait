import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn
from pydantic import SecretStr

from debait.driver.app import open_binding_store
from debait.driver.browser_sessions import run_browserbase_smoke
from debait.driver.gmail_auth import (
    DEFAULT_REDIRECT_PORT,
    build_authorization_url,
    capture_auth_code_loopback,
    exchange_code_for_tokens,
    refresh_access_token,
    update_local_env,
    verify_gmail_read_and_scope,
)
from debait.driver.gmail_inbox import run_gmail_smoke
from debait.driver.telegram_conversation import run_telegram_smoke
from debait.evaluation.runner import evaluate
from debait.live_config import (
    READINESS_ORDER,
    build_live_runtime,
    configured_bindings,
    live_readiness,
)
from debait.settings import Settings
from debait.testing.harness import CASES, run_case


def main():
    parser = argparse.ArgumentParser(description="DeBait local protection workspace")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8000)
    driver = sub.add_parser("driver")
    driver.add_argument("--port", type=int, default=8001)
    run = sub.add_parser("run")
    run.add_argument("case", choices=sorted(CASES))
    run.add_argument("--mode", choices=["local"], default="local")
    run.add_argument("--workspace", type=Path, default=Path("runtime"))
    bind = sub.add_parser("driver-bind")
    bind.add_argument("--workspace", type=Path, default=Path("runtime"))
    bind.add_argument("--episode", required=True)
    bind.add_argument("--payment", required=True)
    bind.add_argument("--source", required=True)
    bind.add_argument("--ttl-seconds", type=int, choices=range(1, 901), default=300)
    export = sub.add_parser("driver-export")
    export.add_argument("--workspace", type=Path, default=Path("runtime"))
    reset = sub.add_parser("driver-reset")
    reset.add_argument("--workspace", type=Path, default=Path("runtime"))
    reset.add_argument("--yes", action="store_true")
    evaluation = sub.add_parser("eval")
    evaluation.add_argument("manifest", type=Path)
    evaluation.add_argument("--workspace", type=Path, default=Path("runtime"))
    evaluation.add_argument("--repeats", type=int, choices=range(1, 11), default=1)
    evaluation.add_argument("--seed", type=int, default=0)
    evaluation.add_argument("--reasoning-mode", choices=["fixture", "fresh_model"], default="fixture")
    gmail_auth = sub.add_parser("gmail-auth", help="OAuth authentication helper for Gmail")
    gmail_auth.add_argument("--client-id", help="Google OAuth Client ID")
    gmail_auth.add_argument("--client-secret", help="Google OAuth Client Secret")
    gmail_auth.add_argument("--port", type=int, default=DEFAULT_REDIRECT_PORT, help="Loopback redirect port")
    gmail_auth.add_argument("--code", help="Manual authorization code")
    gmail_auth.add_argument(
        "--refresh", action="store_true", help="Refresh access token using stored refresh token"
    )
    gmail_auth.add_argument("--check", action="store_true", help="Verify current Gmail authentication")
    gmail_smoke = sub.add_parser("gmail-smoke", help="Controlled Gmail inbox smoke test")
    gmail_smoke.add_argument("--confirm-live-test", action="store_true")
    gmail_smoke.add_argument("--workspace", type=Path, default=Path("runtime/integrations"))
    browserbase_smoke = sub.add_parser("browserbase-smoke")
    browserbase_smoke.add_argument("--confirm-live-test", action="store_true")
    browserbase_smoke.add_argument("--workspace", type=Path, default=Path("runtime/integrations"))
    telegram_smoke = sub.add_parser("telegram-smoke")
    telegram_smoke.add_argument("--confirm-live-test", action="store_true")
    telegram_smoke.add_argument("--workspace", type=Path, default=Path("runtime/integrations"))
    live = sub.add_parser("demo-live")
    live_mode = live.add_mutually_exclusive_group(required=True)
    live_mode.add_argument("--dry-run", action="store_true")
    live_mode.add_argument("--confirm-live-test", action="store_true")
    args = parser.parse_args()
    if args.command == "serve":
        uvicorn.run("debait.app:create_app", factory=True, host="127.0.0.1", port=args.port)
    elif args.command == "driver":
        uvicorn.run("debait.driver.app:create_driver", factory=True, host="127.0.0.1", port=args.port)
    elif args.command == "run":
        print(json.dumps(run_case(args.case, workspace=args.workspace, mode=args.mode), indent=2))
    elif args.command == "eval":
        report = evaluate(
            args.manifest,
            workspace=args.workspace,
            repeats=args.repeats,
            seed=args.seed,
            reasoning_mode=args.reasoning_mode,
        )
        print(
            json.dumps(
                {
                    "run_id": report.run_id,
                    "run_mode": report.run_mode,
                    "metrics": report.metrics,
                    "output_path": str(report.output_path),
                },
                indent=2,
            )
        )
    elif args.command == "browserbase-smoke":
        if not args.confirm_live_test:
            parser.error("browserbase-smoke requires --confirm-live-test")
        settings = Settings()
        if settings.browserbase_key is None:
            parser.error("DEBAIT_BROWSERBASE_KEY is required")
        run_id = datetime.now(timezone.utc).strftime("browserbase-smoke-%Y%m%dT%H%M%SZ")
        report = asyncio.run(
            run_browserbase_smoke(
                settings.browserbase_key,
                run_id=run_id,
                allow_network=True,
            )
        )
        args.workspace.mkdir(parents=True, exist_ok=True)
        output_path = args.workspace / f"{run_id}.json"
        output_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({**report, "output_path": str(output_path)}, indent=2))
    elif args.command == "telegram-smoke":
        if not args.confirm_live_test:
            parser.error("telegram-smoke requires --confirm-live-test")
        settings = Settings()
        if settings.telegram_token is None:
            parser.error("DEBAIT_TELEGRAM_TOKEN is required")
        run_id = datetime.now(timezone.utc).strftime("telegram-smoke-%Y%m%dT%H%M%SZ")
        report = asyncio.run(run_telegram_smoke(settings.telegram_token, run_id=run_id, allow_network=True))
        args.workspace.mkdir(parents=True, exist_ok=True)
        output_path = args.workspace / f"{run_id}.json"
        output_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({**report, "output_path": str(output_path)}, indent=2))
    elif args.command == "gmail-auth":
        settings = Settings()
        env_path = Path(".env")
        if args.check:
            if not settings.gmail_token:
                parser.error("DEBAIT_GMAIL_TOKEN is not configured in .env or environment")
            report = asyncio.run(
                verify_gmail_read_and_scope(
                    settings.gmail_token,
                    user_id=settings.gmail_user_id,
                    allow_network=True,
                )
            )
            if report.get("quarantine_label_id"):
                update_local_env(
                    env_path,
                    {"DEBAIT_GMAIL_QUARANTINE_LABEL_ID": report["quarantine_label_id"]},
                )
            print(json.dumps(report, indent=2))
        elif args.refresh:
            client_id = args.client_id or settings.gmail_client_id
            client_secret = (
                SecretStr(args.client_secret) if args.client_secret else settings.gmail_client_secret
            )
            refresh_token = settings.gmail_refresh_token
            if not client_id or not client_secret or not refresh_token:
                parser.error("client_id, client_secret, and refresh_token are required to refresh")
            tokens = asyncio.run(refresh_access_token(client_id, client_secret, refresh_token))
            update_local_env(env_path, {"DEBAIT_GMAIL_TOKEN": tokens["access_token"]})
            print(
                json.dumps(
                    {"status": "refreshed", "token_type": tokens.get("token_type", "Bearer")},
                    indent=2,
                )
            )
        else:
            client_id = args.client_id or settings.gmail_client_id
            client_secret = (
                SecretStr(args.client_secret) if args.client_secret else settings.gmail_client_secret
            )
            if not client_id or not client_secret:
                parser.error(
                    "Google OAuth Client ID and Client Secret are required. "
                    "Provide via --client-id / --client-secret or set DEBAIT_GMAIL_CLIENT_ID / DEBAIT_GMAIL_CLIENT_SECRET in .env"
                )
            redirect_uri = f"http://localhost:{args.port}/callback"
            if args.code:
                code = args.code
            else:
                auth_url = build_authorization_url(client_id, redirect_uri=redirect_uri)
                print(
                    f"\nOpen the following URL in your browser to authorize DeBait with the demo Gmail account:\n\n{auth_url}\n"
                )
                print(f"Waiting for authorization callback on {redirect_uri} ...")
                code = capture_auth_code_loopback(port=args.port)
                print("Authorization code received successfully.")

            tokens = asyncio.run(
                exchange_code_for_tokens(client_id, client_secret, code, redirect_uri=redirect_uri)
            )
            access_token = tokens["access_token"]
            refresh_tok = tokens.get("refresh_token")

            report = asyncio.run(
                verify_gmail_read_and_scope(
                    SecretStr(access_token),
                    user_id=settings.gmail_user_id,
                    allow_network=True,
                )
            )

            updates = {
                "DEBAIT_GMAIL_TOKEN": access_token,
                "DEBAIT_GMAIL_CLIENT_ID": client_id,
                "DEBAIT_GMAIL_CLIENT_SECRET": client_secret.get_secret_value(),
            }
            if refresh_tok:
                updates["DEBAIT_GMAIL_REFRESH_TOKEN"] = refresh_tok
            if report.get("quarantine_label_id"):
                updates["DEBAIT_GMAIL_QUARANTINE_LABEL_ID"] = report["quarantine_label_id"]

            update_local_env(env_path, updates)
            print(
                json.dumps(
                    {
                        "status": "authenticated",
                        "email": report.get("email"),
                        "quarantine_label_id": report.get("quarantine_label_id"),
                        "refresh_token_saved": bool(refresh_tok),
                    },
                    indent=2,
                )
            )
    elif args.command == "gmail-smoke":
        if not args.confirm_live_test:
            parser.error("gmail-smoke requires --confirm-live-test")
        settings = Settings()
        if settings.gmail_token is None:
            parser.error("DEBAIT_GMAIL_TOKEN is required")
        run_id = datetime.now(timezone.utc).strftime("gmail-smoke-%Y%m%dT%H%M%SZ")
        report = asyncio.run(
            run_gmail_smoke(
                settings.gmail_token,
                run_id=run_id,
                user=settings.gmail_user_id,
                allow_network=True,
            )
        )
        args.workspace.mkdir(parents=True, exist_ok=True)
        output_path = args.workspace / f"{run_id}.json"
        output_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({**report, "output_path": str(output_path)}, indent=2))
    elif args.command == "demo-live":
        settings = Settings()
        readiness = live_readiness(settings)
        for name in READINESS_ORDER:
            print(f"{name:<13} {'READY' if readiness[name] else 'NOT CONFIGURED'}")
        if args.dry_run:
            print("provider_mutations: 0")
        bindings = configured_bindings(settings)
        print(
            json.dumps(
                {
                    "episode_id": settings.live_episode_id,
                    "bindings": bindings,
                    "eligible_actions_if_all_gates_pass": [
                        f"{item['provider']}.{item['operation']}:{item['resource_id']}"
                        for item in bindings
                        if item.get("role") != "control"
                    ],
                    "provider_mutations": 0 if args.dry_run else "explicitly enabled",
                    "stripe_mode": "TEST ONLY",
                },
                indent=2,
            )
        )
        if args.confirm_live_test:
            unavailable = [name for name in READINESS_ORDER if not readiness[name]]
            if unavailable:
                parser.error("demo-live providers not configured: " + ", ".join(unavailable))

            async def execute_live():
                runner, control_payment = await build_live_runtime(settings)
                return await runner.run(control_payment=control_payment)

            result = asyncio.run(execute_live())
            print(result.model_dump_json(indent=2))
    elif args.command in {"driver-bind", "driver-export", "driver-reset"}:
        settings = Settings(
            database_path=args.workspace / "episodes.sqlite",
            _env_file=None,
        )
        store = open_binding_store(settings)
        if args.command == "driver-bind":
            token = store.issue(
                args.episode,
                args.payment,
                args.source,
                datetime.now(timezone.utc) + timedelta(seconds=args.ttl_seconds),
            )
            print(json.dumps({"token": token}))
        elif args.command == "driver-export":
            print(json.dumps(store.export(), indent=2))
        elif not args.yes:
            parser.error("driver-reset requires --yes")
        else:
            print(json.dumps({"deleted_bindings": store.reset()}))


if __name__ == "__main__":
    main()
