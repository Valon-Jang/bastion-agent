"""Validate the managed policy with the installed strict Codex App Server."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "source" / "core"))

from human_codex.app_server import run_initialize_thread_smoke
from human_codex.codex_runtime import CodexRuntime
from human_codex.paths import PortablePaths
from human_codex.secret_guard import redact_text


def main() -> int:
    result: dict[str, object] = {
        "schema": "human-codex-security-config-smoke/1",
        "status": "fail",
        "strict_config": False,
        "dynamic_thread_config": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="human-codex-security-config-") as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            paths = PortablePaths(ROOT, root / "data")
            runtime = CodexRuntime(paths)
            runtime.ensure_home()
            # AppServerClient starts the installed binary with --strict-config;
            # a successful initialize + thread/start proves both the base file
            # and the per-thread root overlay are accepted by this exact build.
            smoke = run_initialize_thread_smoke(runtime, cwd=workspace, timeout=30)
            result["strict_config"] = smoke.status == "pass"
            result["dynamic_thread_config"] = smoke.status == "pass"
            result["codex_version"] = smoke.codex_version
            result["status"] = (
                "pass" if result["dynamic_thread_config"] else "fail"
            )
    except Exception as exc:
        result["failure_type"] = type(exc).__name__
        result["diagnostic"] = redact_text(str(exc))[:2_000]
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
