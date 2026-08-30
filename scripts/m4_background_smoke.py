"""Controlled App Server protocol smoke for M4 background jobs and recovery."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from human_codex.app_server import wait_until
from human_codex.codex_runtime import CodexRuntime
from human_codex.database import MetadataDatabase
from human_codex.jobs import BackgroundJobManager
from human_codex.paths import PortablePaths
from human_codex.sessions import CodexSessionManager
from human_codex.vault import AesGcmVault


FAKE_SERVER = r'''import json
import sys
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        print(json.dumps({"id": request["id"], "result": {"userAgent": "m4-smoke"}}), flush=True)
    elif method == "windowsSandbox/readiness":
        print(json.dumps({"id": request["id"], "result": {"status": "ready"}}), flush=True)
    elif method == "thread/start":
        print(json.dumps({"id": request["id"], "result": {"thread": {"id": "thr_m4_smoke"}}}), flush=True)
    elif method == "turn/start":
        prompt = request["params"]["input"][0]["text"]
        thread_id = request["params"]["threadId"]
        if "background test or build command completed" in prompt:
            safe = request["params"]["approvalPolicy"] == "never" and "sandboxPolicy" not in request["params"] and "sandbox" not in request["params"]
            if not safe:
                print(json.dumps({"id": request["id"], "error": {"message": "unsafe followup"}}), flush=True)
                continue
            turn_id = "turn_followup"
            print(json.dumps({"id": request["id"], "result": {"turn": {"id": turn_id, "status": "inProgress"}}}), flush=True)
            print(json.dumps({"method": "turn/started", "params": {"threadId": thread_id, "turn": {"id": turn_id, "status": "inProgress"}}}), flush=True)
            print(json.dumps({"method": "item/completed", "params": {"threadId": thread_id, "turnId": turn_id, "item": {"type": "agentMessage", "id": "item_summary", "text": "M4_BACKGROUND_OK"}}}), flush=True)
            print(json.dumps({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": turn_id, "status": "completed"}}}), flush=True)
        else:
            turn_id = "turn_primary"
            print(json.dumps({"id": request["id"], "result": {"turn": {"id": turn_id, "status": "inProgress"}}}), flush=True)
            print(json.dumps({"method": "turn/started", "params": {"threadId": thread_id, "turn": {"id": turn_id, "status": "inProgress"}}}), flush=True)
            print(json.dumps({"method": "item/started", "params": {"threadId": thread_id, "turnId": turn_id, "item": {"type": "commandExecution", "id": "item_test", "command": "py -m unittest"}}}), flush=True)
            print(json.dumps({"method": "item/commandExecution/outputDelta", "params": {"threadId": thread_id, "turnId": turn_id, "itemId": "item_test", "delta": "passed"}}), flush=True)
            print(json.dumps({"method": "item/completed", "params": {"threadId": thread_id, "turnId": turn_id, "item": {"type": "commandExecution", "id": "item_test", "status": "completed"}}}), flush=True)
            print(json.dumps({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": turn_id, "status": "completed"}}}), flush=True)
'''


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    artifact = repo / "artifacts" / "test" / "m4-background-recovery-smoke.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
        project_root = root / "project"
        project_root.mkdir()
        paths = PortablePaths(root, root / "data")
        database = MetadataDatabase.from_data_root(paths.data_root)
        project = database.create_project("M4 smoke")
        chat = database.create_chat(project.id)
        vault = AesGcmVault(b"m" * 32)
        runtime = CodexRuntime(paths, executable=sys.executable)
        # This is a controlled protocol fixture, not evidence of the installed
        # Windows sandbox. The real runtime proof is a separate release gate.
        runtime.permission_profile_enforced = lambda: True
        sessions = CodexSessionManager(
            database, paths, runtime=runtime, vault=vault
        )
        try:
            sessions.workspace.ensure_project_roots(project.id, str(project_root))
            sessions.open_chat(chat.id)
            sessions.start_turn(chat.id, "run a background test")
            completed = wait_until(lambda: (
                bool(sessions.list_background_jobs(project.id))
                and sessions.list_background_jobs(project.id)[0]["followup_state"] == "completed"
                and "M4_BACKGROUND_OK" in [
                    message["content"]["text"] for message in sessions.timeline(chat.id)["messages"]
                ]
            ), timeout=8)
            if not completed:
                raise RuntimeError("background job or read-only follow-up did not complete")
            jobs = sessions.list_background_jobs(project.id)
            database.upsert_turn(chat.id, "turn_recovery", "inProgress")
            database.upsert_item(
                "item_recovery", chat.id, "turn_recovery", "commandExecution", "inProgress",
                json.dumps(vault.encrypt(b"{}", context="item:item_recovery").as_dict()),
            )
            BackgroundJobManager(database, vault).command_started(
                project.id, chat.id, "turn_recovery", "item_recovery", "pytest -q"
            )
            recovered = BackgroundJobManager(database, vault).reconciled_on_startup
            result = {
                "status": "pass",
                "mode": "controlled_app_server_protocol",
                "background_job": {key: jobs[0][key] for key in (
                    "status", "command", "output_chars", "followup_state", "notification_pending"
                )},
                "assistant_marker": "M4_BACKGROUND_OK",
                "recovered_interrupted_jobs": recovered,
                "security": {
                    "followup_approval_policy": "never",
                    "followup_permission_profile": "human-codex-project-read-only",
                    "legacy_sandbox_override": False,
                    "command_execution_api_exposed": False,
                },
            }
        finally:
            sessions.close()
    artifact.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
