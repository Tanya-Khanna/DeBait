import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn

from debait.driver.app import open_binding_store
from debait.driver.browser_sessions import run_browserbase_smoke
from debait.driver.telegram_conversation import run_telegram_smoke
from debait.evaluation.runner import evaluate
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
    browserbase_smoke = sub.add_parser("browserbase-smoke")
    browserbase_smoke.add_argument("--confirm-live-test", action="store_true")
    browserbase_smoke.add_argument("--workspace", type=Path, default=Path("runtime/integrations"))
    telegram_smoke = sub.add_parser("telegram-smoke")
    telegram_smoke.add_argument("--confirm-live-test", action="store_true")
    telegram_smoke.add_argument("--workspace", type=Path, default=Path("runtime/integrations"))
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
