import json
import sys
import tempfile
import unittest
from pathlib import Path

from human_codex.app_server import wait_until
from human_codex.database import MetadataDatabase
from human_codex.jobs import BackgroundJobManager
from human_codex.paths import PortablePaths
from human_codex.sessions import CodexSessionManager
from human_codex.codex_runtime import CodexRuntime
from human_codex.vault import AesGcmVault


FAKE_SERVER = r'''
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({"id": message["id"], "result": {"userAgent": "fake"}}), flush=True)
    elif method == "initialized":
        continue
    elif method == "windowsSandbox/readiness":
        print(json.dumps({"id": message["id"], "result": {"status": "ready"}}), flush=True)
    elif method == "thread/start":
        if message["params"].get("serviceName") == "human_codex_background_read_only" and message["params"].get("config", {}).get("default_permissions") != "human-codex-project-read-only":
            print(json.dumps({"id": message["id"], "error": {"code": -1, "message": "unsafe background profile"}}), flush=True)
            continue
        print(json.dumps({"id": message["id"], "result": {"thread": {"id": "thr_m4"}}}), flush=True)
    elif method == "thread/resume":
        print(json.dumps({"id": message["id"], "result": {"thread": {"id": message["params"]["threadId"]}}}), flush=True)
    elif method == "turn/start":
        prompt = message["params"]["input"][0]["text"]
        thread_id = message["params"]["threadId"]
        if "background test or build command completed" in prompt:
            if message["params"]["approvalPolicy"] != "never" or "sandboxPolicy" in message["params"]:
                print(json.dumps({"id": message["id"], "error": {"code": -1, "message": "unsafe followup"}}), flush=True)
                continue
            turn = {"id": "turn_followup", "status": "inProgress"}
            print(json.dumps({"id": message["id"], "result": {"turn": turn}}), flush=True)
            print(json.dumps({"method": "turn/started", "params": {"threadId": thread_id, "turn": turn}}), flush=True)
            print(json.dumps({"method": "item/completed", "params": {"threadId": thread_id, "turnId": "turn_followup", "item": {"type": "agentMessage", "id": "item_followup", "text": "background complete"}}}), flush=True)
            print(json.dumps({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": "turn_followup", "status": "completed"}}}), flush=True)
        else:
            turn = {"id": "turn_primary", "status": "inProgress"}
            print(json.dumps({"id": message["id"], "result": {"turn": turn}}), flush=True)
            print(json.dumps({"method": "turn/started", "params": {"threadId": thread_id, "turn": turn}}), flush=True)
            print(json.dumps({"method": "item/started", "params": {"threadId": thread_id, "turnId": "turn_primary", "item": {"type": "commandExecution", "id": "item_test", "command": "py -m unittest"}}}), flush=True)
            print(json.dumps({"method": "item/commandExecution/outputDelta", "params": {"threadId": thread_id, "turnId": "turn_primary", "itemId": "item_test", "delta": "passed"}}), flush=True)
            print(json.dumps({"method": "item/completed", "params": {"threadId": thread_id, "turnId": "turn_primary", "item": {"type": "commandExecution", "id": "item_test", "status": "completed"}}}), flush=True)
            print(json.dumps({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": "turn_primary", "status": "completed"}}}), flush=True)
'''


class BackgroundJobTests(unittest.TestCase):
    def test_completed_test_job_creates_checkpoints_and_safe_followup_turn(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            project_root = root / "project"
            project_root.mkdir()
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("M4")
            chat = database.create_chat(project.id)
            vault = AesGcmVault(b"j" * 32)
            manager = CodexSessionManager(
                database, paths, runtime=CodexRuntime(paths, executable=sys.executable), vault=vault
            )
            manager.runtime.permission_profile_enforced = lambda: True
            manager.runtime.sandbox_setup_marker_present = lambda: True
            try:
                manager.workspace.ensure_project_roots(project.id, str(project_root))
                manager.open_chat(chat.id)
                manager.start_turn(chat.id, "run a background test")
                self.assertTrue(wait_until(lambda: (
                    bool(manager.list_background_jobs(project.id))
                    and manager.list_background_jobs(project.id)[0]["followup_state"] == "completed"
                    and "background complete" in [
                        entry["content"]["text"] for entry in manager.timeline(chat.id)["messages"]
                    ]
                ), timeout=5), manager.list_background_jobs(project.id))
                jobs = manager.list_background_jobs(project.id)
                self.assertEqual(jobs[0]["status"], "completed")
                self.assertEqual(jobs[0]["command"], "py -m unittest")
                self.assertEqual(jobs[0]["output_chars"], len("passed"))
                timeline = manager.timeline(chat.id)
                self.assertIn("background complete", [entry["content"]["text"] for entry in timeline["messages"]])
                with database.connection() as connection:
                    stored = connection.execute(
                        "SELECT command_ciphertext, output_ciphertext FROM background_jobs"
                    ).fetchone()
                    checkpoints = connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
                self.assertNotIn("py -m unittest", stored[0])
                self.assertNotIn("passed", stored[1])
                self.assertGreaterEqual(checkpoints, 4)
            finally:
                manager.close()

    def test_startup_reconciliation_marks_unfinished_job_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("Recovery")
            chat = database.create_chat(project.id)
            vault = AesGcmVault(b"r" * 32)
            database.upsert_turn(chat.id, "turn_recovery", "inProgress")
            database.upsert_item(
                "item_recovery", chat.id, "turn_recovery", "commandExecution", "inProgress",
                json.dumps(vault.encrypt(b"{}", context="item:item_recovery").as_dict()),
            )
            tracker = BackgroundJobManager(database, vault)
            tracker.command_started(project.id, chat.id, "turn_recovery", "item_recovery", "pytest")
            restarted = BackgroundJobManager(database, vault)
            jobs = restarted.list(project.id)
            self.assertEqual(restarted.reconciled_on_startup, 1)
            self.assertEqual(jobs[0]["status"], "interrupted")


if __name__ == "__main__":
    unittest.main()
