from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from human_codex.app_server import AppServerError, run_initialize_thread_smoke, run_turn_smoke
from human_codex.codex_runtime import CodexRuntime, CodexRuntimeError
from human_codex.core_server import serve as serve_core
from human_codex.diagnostics import collect_diagnostics
from human_codex.paths import PortablePaths
from human_codex.schema import generate_version_matched_schema, verify_pinned_schema
from human_codex.skills import SkillError, SkillManager


def _write_json(payload: object, output: Path | None = None) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(json.dumps({"status": "written", "output": str(output)}))
        return
    # Keep stdout machine-readable even when the active Windows code page is cp949.
    print(json.dumps(payload, ensure_ascii=True, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="human-codex-m0")
    commands = parser.add_subparsers(dest="command", required=True)

    diagnostics = commands.add_parser("diagnostics", help="run Gate 0 diagnostics")
    diagnostics.add_argument("--json", action="store_true", help="emit JSON")
    diagnostics.add_argument("--output", type=Path)

    codex = commands.add_parser("codex", help="Codex runtime and login")
    codex_commands = codex.add_subparsers(dest="codex_command", required=True)
    codex_status = codex_commands.add_parser("status")
    codex_status.add_argument("--json", action="store_true")
    codex_login = codex_commands.add_parser("login")
    codex_login.add_argument("--device-auth", action="store_true")

    schema = commands.add_parser("schema", help="version-matched App Server schema")
    schema_commands = schema.add_subparsers(dest="schema_command", required=True)
    schema_commands.add_parser("generate")
    schema_commands.add_parser("verify")

    app_server = commands.add_parser("app-server", help="App Server integration checks")
    app_commands = app_server.add_subparsers(dest="app_command", required=True)
    smoke = app_commands.add_parser("smoke")
    smoke.add_argument("--json", action="store_true")
    smoke.add_argument("--output", type=Path)
    smoke.add_argument("--timeout", type=float, default=30.0)
    turn_smoke = app_commands.add_parser("turn-smoke")
    turn_smoke.add_argument("--json", action="store_true")
    turn_smoke.add_argument("--output", type=Path)
    turn_smoke.add_argument("--timeout", type=float, default=120.0)

    core = commands.add_parser("core", help="Human Codex Core IPC")
    core_commands = core.add_subparsers(dest="core_command", required=True)
    core_commands.add_parser("serve", help="serve hc-ipc/1 NDJSON on stdin/stdout")

    skills = commands.add_parser("skills", help="portable Codex skill management")
    skill_commands = skills.add_subparsers(dest="skill_command", required=True)
    skill_commands.add_parser("list", help="list installation-local skills")
    skill_search = skill_commands.add_parser(
        "search", help="search OpenAI and public GitHub skills"
    )
    skill_search.add_argument("query")
    skill_install = skill_commands.add_parser(
        "install", help="install one skill into the portable Codex home"
    )
    skill_install.add_argument("source")
    skill_install.add_argument("--approved", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = PortablePaths.discover()
    runtime = CodexRuntime(paths)
    try:
        if args.command == "core" and args.core_command == "serve":
            return serve_core(sys.stdin, sys.stdout, paths)

        if args.command == "skills":
            manager = SkillManager(paths)
            if args.skill_command == "list":
                _write_json(
                    {
                        "skills": manager.list_installed(),
                        "install_root": str(paths.skills_root),
                    }
                )
                return 0
            if args.skill_command == "search":
                _write_json({"skills": manager.catalog(args.query)})
                return 0
            if args.skill_command == "install":
                _write_json(
                    {"skill": manager.install(args.source, approved=args.approved)}
                )
                return 0

        if args.command == "diagnostics":
            report = collect_diagnostics(paths)
            if args.json or args.output:
                _write_json(report, args.output)
            else:
                print(f"Gate 0 status: {report['status']}")
                print(f"Blocking: {', '.join(report['blocking_issues']) or 'none'}")
                print(f"Limits: {', '.join(report['limits']) or 'none'}")
            return 2 if report["status"] == "blocked" else 0

        if args.command == "codex" and args.codex_command == "status":
            payload = asdict(runtime.inspect())
            if args.json:
                _write_json(payload)
            else:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0 if payload["executable"] else 2

        if args.command == "codex" and args.codex_command == "login":
            return runtime.login(device_auth=args.device_auth)

        if args.command == "schema" and args.schema_command == "generate":
            destination = generate_version_matched_schema(runtime)
            _write_json({"status": "pass", "destination": str(destination)})
            return 0

        if args.command == "schema" and args.schema_command == "verify":
            result = verify_pinned_schema(runtime)
            _write_json(result)
            return 0 if result["status"] == "pass" else 2

        if args.command == "app-server" and args.app_command == "smoke":
            result = asdict(
                run_initialize_thread_smoke(
                    runtime, cwd=paths.repository_root, timeout=args.timeout
                )
            )
            result["checked_at"] = datetime.now(UTC).isoformat()
            if args.json or args.output:
                _write_json(result, args.output)
            else:
                print(
                    f"PASS: app-server initialized and thread {result['thread']['id']} started"
                )
            return 0
        if args.command == "app-server" and args.app_command == "turn-smoke":
            result = asdict(
                run_turn_smoke(runtime, cwd=paths.repository_root, timeout=args.timeout)
            )
            result["checked_at"] = datetime.now(UTC).isoformat()
            if args.json or args.output:
                _write_json(result, args.output)
            else:
                print(f"{result['status'].upper()}: turn {result['turn_id']} ended {result['completed_status']}")
            return 0 if result["status"] == "pass" else 2
    except (CodexRuntimeError, AppServerError, SkillError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2
