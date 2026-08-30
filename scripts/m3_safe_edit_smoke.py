from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "source" / "core"))

from human_codex.codex_runtime import CodexRuntime
from human_codex.database import MetadataDatabase
from human_codex.paths import PortablePaths
from human_codex.sessions import CodexSessionManager


def main() -> int:
    artifact = ROOT / "artifacts" / "test" / "m3-safe-edit-smoke.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    actual_paths = PortablePaths.discover(ROOT)
    result = {
        "status": "fail",
        "codex_version": CodexRuntime(actual_paths).version(),
        "completed_status": "not_started",
        "approval_count": 0,
        "snapshot_count": 0,
        "file_verified": False,
    }
    try:
        with tempfile.TemporaryDirectory(dir=artifact.parent, prefix="m3-smoke-") as temp:
            temp_root = Path(temp)
            project_root = temp_root / "project"
            project_root.mkdir()
            paths = PortablePaths(ROOT, temp_root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("M3 smoke")
            chat = database.create_chat(project.id, "Safe edit")
            manager = CodexSessionManager(
                database,
                paths,
                runtime=CodexRuntime(actual_paths),
                ephemeral_threads=True,
            )
            try:
                manager.workspace.ensure_project_roots(project.id, str(project_root))
                manager.open_chat(chat.id)
                manager.start_turn(
                    chat.id,
                    "Inside this project only, create m3_probe.py containing exactly VALUE = 3 followed by a newline. "
                    "Run py -3.12 -c \"import m3_probe; assert m3_probe.VALUE == 3\". "
                    "Do not access any other path or network. When done, reply exactly M3_SAFE_OK.",
                )
                deadline = time.monotonic() + 150
                approved_ids: set[str] = set()
                while time.monotonic() < deadline:
                    for approval in manager.approvals.list_pending(project.id):
                        if approval["id"] not in approved_ids:
                            decision = "approve" if approval["risk_level"] in {"R1", "R2"} else "deny"
                            manager.approvals.decide(approval["id"], decision, "once")
                            approved_ids.add(approval["id"])
                    timeline = manager.timeline(chat.id)
                    terminal = [
                        turn for turn in timeline["turns"]
                        if turn["status"] in {"completed", "failed", "interrupted"}
                    ]
                    if terminal:
                        result["completed_status"] = terminal[-1]["status"]
                        assistant = [
                            message["content"].get("text", "")
                            for message in timeline["messages"] if message["role"] == "assistant"
                        ]
                        result["assistant_ok"] = bool(assistant and assistant[-1].strip() == "M3_SAFE_OK")
                        break
                    time.sleep(0.1)
                result["approval_count"] = len(approved_ids)
                result["snapshot_count"] = len(manager.snapshots.list(project.id))
                probe = project_root / "m3_probe.py"
                result["file_verified"] = probe.is_file() and probe.read_text(encoding="utf-8") == "VALUE = 3\n"
                result["status"] = "pass" if (
                    result["completed_status"] == "completed"
                    and result.get("assistant_ok") is True
                    and result["file_verified"]
                    and result["snapshot_count"] >= 1
                ) else "fail"
            finally:
                manager.close()
    except Exception as exc:
        result["failure_type"] = type(exc).__name__
    artifact.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
