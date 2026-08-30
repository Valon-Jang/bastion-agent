import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from human_codex.app_server import wait_until
from human_codex.codex_runtime import CodexRuntime
from human_codex.database import MetadataDatabase
from human_codex.paths import PortablePaths
from human_codex.sessions import CodexSessionManager, SecretPreflightError, SecureSandboxError
from human_codex.vault import AesGcmVault


FAKE_SERVER = r'''
import json
import sys

sandbox_ready = True

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({"id": message["id"], "result": {"userAgent": "fake"}}), flush=True)
    elif method == "initialized":
        continue
    elif method == "windowsSandbox/readiness":
        if message.get("params") is not None:
            print(json.dumps({"id": message["id"], "error": {"code": -1, "message": "readiness params must be null"}}), flush=True)
            continue
        print(json.dumps({"id": message["id"], "result": {"status": "ready" if sandbox_ready else "notConfigured"}}), flush=True)
    elif method == "windowsSandbox/setupStart":
        params = message.get("params", {})
        if params.get("mode") != "elevated" or not isinstance(params.get("cwd"), str):
            print(json.dumps({"id": message["id"], "error": {"code": -1, "message": "invalid setup"}}), flush=True)
            continue
        print(json.dumps({"id": message["id"], "result": {"started": True}}), flush=True)
        sandbox_ready = True
        print(json.dumps({"method": "windowsSandbox/setupCompleted", "params": {"mode": "elevated", "success": True, "error": None}}), flush=True)
    elif method == "thread/start":
        config = message["params"].get("config")
        if config is not None and (message["params"].get("sandbox") is not None or config.get("default_permissions") != "human-codex-project"):
            print(json.dumps({"id": message["id"], "error": {"code": -1, "message": "unsafe thread profile"}}), flush=True)
            continue
        print(json.dumps({"id": message["id"], "result": {"thread": {"id": "thr_m2"}}}), flush=True)
    elif method == "thread/resume":
        print(json.dumps({"id": message["id"], "result": {"thread": {"id": message["params"]["threadId"]}}}), flush=True)
    elif method == "turn/start":
        sandbox = message["params"].get("sandboxPolicy")
        if message["params"].get("approvalPolicy") != "untrusted" or sandbox is not None or message["params"].get("sandbox") is not None:
            print(json.dumps({"id": message["id"], "error": {"code": -1, "message": "unsafe turn policy"}}), flush=True)
            continue
        thread_id = message["params"]["threadId"]
        turn = {"id": "turn_m2", "status": "inProgress"}
        print(json.dumps({"id": message["id"], "result": {"turn": turn}}), flush=True)
        print(json.dumps({"method": "turn/started", "params": {"threadId": thread_id, "turn": turn}}), flush=True)
        print(json.dumps({"method": "item/agentMessage/delta", "params": {"threadId": thread_id, "turnId": "turn_m2", "itemId": "item_agent", "delta": "hello "}}), flush=True)
        print(json.dumps({"method": "item/agentMessage/delta", "params": {"threadId": thread_id, "turnId": "turn_m2", "itemId": "item_agent", "delta": "world"}}), flush=True)
        print(json.dumps({"method": "item/completed", "params": {"threadId": thread_id, "turnId": "turn_m2", "completedAtMs": 1, "item": {"type": "agentMessage", "id": "item_agent", "text": "hello world", "phase": None, "memoryCitation": None}}}), flush=True)
        print(json.dumps({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": "turn_m2", "status": "completed"}}}), flush=True)
    elif method == "turn/interrupt":
        print(json.dumps({"id": message["id"], "result": {}}), flush=True)
'''


class SessionManagerTests(unittest.TestCase):
    def test_company_direct_mode_opens_chat_without_any_sandbox_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project_root = root / "project"
            project_root.mkdir()
            (project_root / ".env").write_text(
                "LOCAL_ONLY=value\n", encoding="utf-8"
            )
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            project = database.create_project("Direct")
            chat = database.create_chat(project.id)
            runtime = CodexRuntime(paths, executable=sys.executable)
            manager = CodexSessionManager(
                database,
                paths,
                runtime=runtime,
                vault=AesGcmVault(b"x" * 32),
                direct_mode=True,
            )
            manager.workspace.ensure_project_roots(project.id, str(project_root))
            requests = []
            clients = []

            class FakeClient:
                def __init__(self, _runtime, **kwargs):
                    self.windows_sandbox_override = kwargs.get(
                        "windows_sandbox_override"
                    )
                    self.default_permissions_override = kwargs.get(
                        "default_permissions_override"
                    )
                    self.process_cwd_override = kwargs.get("process_cwd_override")
                    clients.append(self)

                def __enter__(self):
                    return self

                def initialize(self):
                    return {}

                def close(self):
                    return None

                def request(self, method, params, **_kwargs):
                    requests.append((method, params))
                    if method == "thread/start":
                        return {"thread": {"id": "thr_direct"}}
                    if method == "turn/start":
                        return {
                            "turn": {"id": "turn_direct", "status": "inProgress"}
                        }
                    raise AssertionError(f"unexpected method: {method}")

            try:
                status = manager.sandbox_status()
                self.assertTrue(status["can_start"])
                self.assertEqual(status["active_mode"], "company-direct")
                self.assertFalse(status["direct"]["native_isolation"])
                with patch("human_codex.sessions.AppServerClient", FakeClient):
                    opened = manager.open_chat(chat.id)
                    self.assertEqual(opened["thread"]["id"], "thr_direct")
                    started = manager.start_turn(chat.id, "프로젝트를 확인해줘")
                    self.assertEqual(started["turn"]["id"], "turn_direct")
                self.assertTrue(clients)
                self.assertIsNone(clients[0].windows_sandbox_override)
                self.assertEqual(clients[0].default_permissions_override, ":workspace")
                self.assertEqual(
                    clients[0].process_cwd_override,
                    paths.app_server_working_root,
                )
                self.assertFalse(
                    any(method == "command/exec" for method, _params in requests)
                )
                thread_params = next(
                    params for method, params in requests if method == "thread/start"
                )
                self.assertEqual(thread_params["sandbox"], "danger-full-access")
                self.assertEqual(
                    thread_params["config"]["default_permissions"], ":workspace"
                )
                self.assertNotIn("permissions", thread_params["config"])
                self.assertIn(
                    str(paths.repository_root), thread_params["config"]["projects"]
                )
                self.assertIn(
                    str(paths.repository_root), thread_params["developerInstructions"]
                )
                self.assertIn(
                    str(paths.skills_root), thread_params["developerInstructions"]
                )
                self.assertIn(
                    "must never terminate, restart, reload, or replace",
                    thread_params["developerInstructions"],
                )
                self.assertIn(
                    "take effect the next time Human Codex is started normally",
                    thread_params["developerInstructions"],
                )
                self.assertIn(
                    "Never hot-replace a locked running executable",
                    thread_params["developerInstructions"],
                )
                turn_params = next(
                    params for method, params in requests if method == "turn/start"
                )
                self.assertNotIn("sandboxPolicy", turn_params)
            finally:
                manager.close()

    def test_running_chat_accepts_and_starts_fifo_message_after_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project_root = root / "project"
            project_root.mkdir()
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("Queued")
            chat = database.create_chat(project.id)
            manager = CodexSessionManager(
                database,
                paths,
                runtime=CodexRuntime(paths, executable=sys.executable),
                vault=AesGcmVault(b"q" * 32),
                direct_mode=True,
            )
            manager.workspace.ensure_project_roots(project.id, str(project_root))
            requests = []

            class FakeClient:
                def close(self):
                    return None

                def request(self, method, params, **_kwargs):
                    requests.append((method, params))
                    if method == "thread/start":
                        return {"thread": {"id": "thr_queue"}}
                    if method == "turn/start":
                        turn_number = len(
                            [entry for entry in requests if entry[0] == "turn/start"]
                        )
                        return {
                            "turn": {
                                "id": f"turn_queue_{turn_number}",
                                "status": "inProgress",
                            }
                        }
                    raise AssertionError(method)

            manager._client = FakeClient()
            try:
                first = manager.start_turn(chat.id, "첫 번째")
                queued = manager.start_turn(chat.id, "두 번째")
                self.assertEqual(first["turn"]["id"], "turn_queue_1")
                self.assertTrue(queued["queued"])
                self.assertEqual(
                    manager.timeline(chat.id)["queued_messages"][0]["content"]["text"],
                    "두 번째",
                )
                database.upsert_turn(chat.id, "turn_queue_1", "completed")
                manager._schedule_queued_turn(chat.id)
                self.assertTrue(wait_until(
                    lambda: database.open_chat(chat.id).last_turn_id == "turn_queue_2"
                    and not database.queued_message_rows(chat.id)
                ))
                timeline = manager.timeline(chat.id)
                self.assertEqual(timeline["queued_messages"], [])
                self.assertEqual(timeline["messages"][-1]["content"]["text"], "두 번째")
            finally:
                manager.close()

    def test_corporate_policy_preserves_install_and_project_roots_on_different_drives(self) -> None:
        roots = [
            r"C:\Users\employee\Downloads\HumanCodex\Workspace\.human-codex-temp\p1",
            r"E:\Company\Division\Projects\Nested\Project-A",
        ]
        policy = CodexSessionManager._corporate_sandbox_policy(
            {"writableRoots": roots}
        )
        self.assertEqual(policy["writableRoots"], roots)
        self.assertFalse(policy["networkAccess"])

    def test_thread_turn_encrypted_persistence_and_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            paths = PortablePaths(root, root / "user-data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("M2")
            chat = database.create_chat(project.id)
            vault = AesGcmVault(b"k" * 32)
            runtime = CodexRuntime(paths, executable=sys.executable)
            runtime.permission_profile_enforced = lambda: True
            runtime.sandbox_setup_marker_present = lambda: True
            manager = CodexSessionManager(database, paths, runtime=runtime, vault=vault)
            try:
                opened = manager.open_chat(chat.id)
                self.assertEqual(opened["thread"]["id"], "thr_m2")
                started = manager.start_turn(chat.id, "hello")
                self.assertEqual(started["turn"]["id"], "turn_m2")
                self.assertTrue(wait_until(lambda: database.open_chat(chat.id).status == "ready"))
                timeline = manager.timeline(chat.id)
                self.assertLess(len(json.dumps(timeline).encode("utf-8")), manager.MAX_TIMELINE_BYTES)
                self.assertEqual([entry["content"]["text"] for entry in timeline["messages"]], ["hello", "hello world"])
                self.assertEqual(timeline["turns"][0]["status"], "completed")
                with database.connection() as connection:
                    stored = connection.execute("SELECT content_ciphertext FROM messages").fetchall()
                    snapshots = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
                self.assertTrue(all("hello" not in row[0] for row in stored))
                self.assertGreaterEqual(snapshots, 1)
                self.assertEqual(
                    len(manager._bounded_value({"text": "x" * 200_000})["text"]),
                    manager.MAX_PROVIDER_TEXT_CHARS,
                )
            finally:
                manager.close()

            restarted = CodexSessionManager(database, paths, runtime=runtime, vault=vault)
            try:
                resumed = restarted.open_chat(chat.id)
                self.assertEqual(resumed["thread"]["id"], "thr_m2")
                self.assertEqual(restarted.timeline(chat.id)["messages"][-1]["content"]["text"], "hello world")
            finally:
                restarted.close()

    def test_secure_sandbox_and_secret_preflight_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            project_root = root / "project"
            project_root.mkdir()
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("Secret guard")
            chat = database.create_chat(project.id)
            runtime = CodexRuntime(paths, executable=sys.executable)
            runtime.permission_profile_enforced = lambda: False
            runtime.sandbox_setup_marker_present = lambda: True
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"s" * 32)
            )
            try:
                manager.workspace.ensure_project_roots(project.id, str(project_root))
                (project_root / ".env").write_text("VALUE=local-only\n", encoding="utf-8")
                with self.assertRaises(SecureSandboxError):
                    manager.open_chat(chat.id)
                manager._permission_profile_enforced = True
                (project_root / ".env").unlink()
                manager.open_chat(chat.id)
                pasted = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1L2"
                with self.assertRaises(SecretPreflightError):
                    manager.start_turn(chat.id, pasted)
                (project_root / "settings.py").write_text(
                    'api_key = "N7wQ2pL9sR4mK8xV6cD3"\n', encoding="utf-8"
                )
                with self.assertRaises(SecretPreflightError):
                    manager.start_turn(chat.id, "inspect settings")
                self.assertEqual(manager.timeline(chat.id)["messages"], [])
            finally:
                manager.close()

    def test_enforced_native_profile_routes_dynamic_roots_without_sandbox_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            project_root = root / "project"
            project_root.mkdir()
            (project_root / ".env").write_text("VALUE=os-denied\n", encoding="utf-8")
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("Native profile")
            chat = database.create_chat(project.id)
            runtime = CodexRuntime(paths, executable=sys.executable)
            runtime.permission_profile_enforced = lambda: True
            runtime.sandbox_setup_marker_present = lambda: True
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"n" * 32)
            )
            try:
                manager.workspace.ensure_project_roots(project.id, str(project_root))
                self.assertEqual(manager.open_chat(chat.id)["thread"]["id"], "thr_m2")
                self.assertEqual(manager.start_turn(chat.id, "work safely")["turn"]["id"], "turn_m2")
            finally:
                manager.close()

    def test_explicit_elevated_sandbox_setup_reproves_the_permission_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(
                FAKE_SERVER.replace(
                    "sandbox_ready = True", "sandbox_ready = False", 1
                ),
                encoding="utf-8",
            )
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)
            probe_results = [True]
            runtime.permission_profile_enforced = lambda **_: probe_results.pop(0)
            runtime.reset_permission_profile_probe = lambda: None
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"p" * 32)
            )
            try:
                with self.assertRaisesRegex(Exception, "explicit approval"):
                    manager.setup_sandbox(approved=False)
                initial = manager.sandbox_status()
                self.assertEqual(initial["status"], "notConfigured")
                self.assertFalse(initial["can_start"])
                started = manager.setup_sandbox(approved=True)
                self.assertTrue(started["started"])
                self.assertTrue(wait_until(
                    lambda: bool(
                        manager._sandbox_setup_result
                        and manager._sandbox_setup_result.get("success") is True
                    )
                ))
                self.assertTrue(
                    wait_until(lambda: manager.sandbox_status()["can_start"])
                )
                verified = manager.sandbox_status()
                self.assertEqual(verified["status"], "ready")
                self.assertTrue(verified["profile_enforced"])
                self.assertTrue(verified["can_start"])
                self.assertEqual(probe_results, [])
            finally:
                manager.close()

    def test_live_sandbox_probe_runs_without_blocking_status_polling(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)
            probe_started = threading.Event()
            release_probe = threading.Event()

            def probe(*, progress_callback=None) -> bool:
                probe_started.set()
                if progress_callback is not None:
                    progress_callback(28, 30)
                return release_probe.wait(timeout=2.0)

            runtime.permission_profile_enforced = probe
            runtime.reset_permission_profile_probe = lambda: None
            runtime.sandbox_setup_marker_present = lambda: True
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"a" * 32)
            )
            try:
                started_at = time.monotonic()
                status = manager.sandbox_status()
                elapsed = time.monotonic() - started_at
                self.assertLess(elapsed, 0.5)
                self.assertEqual(status["verification"]["state"], "running")
                self.assertTrue(probe_started.wait(timeout=1.0))
                self.assertEqual(
                    manager.sandbox_status()["verification"]["checks_completed"],
                    28,
                )
                release_probe.set()
                self.assertTrue(
                    wait_until(lambda: manager.sandbox_status()["can_start"])
                )
            finally:
                release_probe.set()
                manager.close()

    def test_live_sandbox_probe_timeout_is_reported_without_restarting(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)
            release_probe = threading.Event()
            runtime.permission_profile_enforced = (
                lambda **_: release_probe.wait(timeout=2.0)
            )
            runtime.reset_permission_profile_probe = lambda: None
            runtime.sandbox_setup_marker_present = lambda: True
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"z" * 32)
            )
            manager.SANDBOX_PROBE_TIMEOUT_SECONDS = 0.0
            try:
                self.assertEqual(
                    manager.sandbox_status()["verification"]["state"], "running"
                )
                timed_out = manager.sandbox_status()
                self.assertEqual(timed_out["verification"]["state"], "failed")
                self.assertEqual(
                    timed_out["verification"]["error"],
                    "sandbox_live_verification_timed_out",
                )
                self.assertFalse(timed_out["can_start"])
            finally:
                release_probe.set()
                manager.close()

    def test_ready_without_app_setup_marker_returns_without_running_live_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)
            probe_called = False

            def probe() -> bool:
                nonlocal probe_called
                probe_called = True
                return True

            runtime.permission_profile_enforced = probe
            runtime.sandbox_setup_marker_present = lambda: False
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"m" * 32)
            )
            try:
                status = manager.sandbox_status()
                self.assertEqual(status["status"], "ready")
                self.assertFalse(status["profile_enforced"])
                self.assertFalse(status["can_start"])
                self.assertFalse(probe_called)
            finally:
                manager.close()

    def test_sandbox_setup_times_out_instead_of_waiting_forever(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            silent_server = FAKE_SERVER.replace(
                "sandbox_ready = True", "sandbox_ready = False", 1
            ).replace(
                'print(json.dumps({"method": "windowsSandbox/setupCompleted", "params": {"mode": "elevated", "success": True, "error": None}}), flush=True)',
                "pass",
            )
            (root / "app-server").write_text(silent_server, encoding="utf-8")
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)
            runtime.permission_profile_enforced = lambda: False
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"t" * 32)
            )
            manager.SANDBOX_SETUP_TIMEOUT_SECONDS = 0.0
            try:
                self.assertTrue(manager.setup_sandbox(approved=True)["started"])
                status = manager.sandbox_status()
                self.assertFalse(status["setup"]["success"])
                self.assertEqual(
                    status["setup"]["error"], "Windows sandbox setup timed out"
                )
            finally:
                manager.close()

    def test_unelevated_ab_diagnostic_does_not_unlock_secure_chat(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)
            runtime.unelevated_sandbox_diagnostic = lambda: {
                "mode": "unelevated",
                "diagnostic_only": True,
                "configuration_changed": False,
                "command_launch": True,
                "workspace_read": True,
                "workspace_write": True,
                "outside_write_denied": True,
                "evidence": [],
                "error": None,
            }
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"d" * 32)
            )
            manager._sandbox_readiness = "ready"
            manager._sandbox_probe_completed = True
            manager._sandbox_probe_checks_completed = 0
            manager._sandbox_probe_error = "sandbox_live_verification_could_not_start"
            try:
                with self.assertRaisesRegex(Exception, "explicit approval"):
                    manager.diagnose_unelevated_sandbox(approved=False)
                result = manager.diagnose_unelevated_sandbox(approved=True)
                self.assertEqual(
                    result["classification"],
                    "elevated_verification_failed_unelevated_available",
                )
                self.assertEqual(result["secure_mode"], "elevated")
                self.assertFalse(result["secure_mode_changed"])
                self.assertFalse(result["chat_unlocked"])
                self.assertEqual(result["elevated_checks_completed"], 0)
                self.assertEqual(
                    result["elevated_error"],
                    "sandbox_live_verification_could_not_start",
                )
                self.assertFalse(manager._permission_profile_enforced)
            finally:
                manager.close()

    def test_unelevated_diagnostic_only_reports_logon_policy_with_1385(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)
            runtime.unelevated_sandbox_diagnostic = lambda: {
                "mode": "unelevated",
                "diagnostic_only": True,
                "configuration_changed": False,
                "command_launch": True,
                "workspace_read": True,
                "workspace_write": True,
                "outside_write_denied": True,
                "evidence": ["windows_error_1385"],
                "error": None,
            }
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"e" * 32)
            )
            manager._sandbox_probe_completed = True
            manager._sandbox_probe_error = "sandbox_live_verification_could_not_start"
            try:
                result = manager.diagnose_unelevated_sandbox(approved=True)
                self.assertEqual(
                    result["classification"],
                    "sandbox_user_logon_policy_confirmed",
                )
            finally:
                manager.close()

    def test_corporate_sandbox_test_reports_progress_without_unlocking_chat(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            runtime = CodexRuntime(paths, executable=sys.executable)

            def fake_test(*, progress_callback, test_parent=None):
                self.assertEqual(test_parent, root.resolve())
                progress_callback(5, 47, "preflight")
                progress_callback(31, 47, "read_only")
                progress_callback(47, 47, "cleanup")
                return {
                    "mode": "corporate-restricted-test",
                    "test_only": True,
                    "checks_completed": 47,
                    "checks_total": 47,
                    "checks_passed": 40,
                    "verdict": "blocked",
                    "chat_unlocked": False,
                    "error": None,
                    "checks": [],
                }

            runtime.corporate_sandbox_test = fake_test
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"c" * 32)
            )
            try:
                with self.assertRaisesRegex(Exception, "explicit approval"):
                    manager.start_corporate_sandbox_test(approved=False)
                started = manager.start_corporate_sandbox_test(approved=True)
                self.assertIn(started["state"], {"running", "completed"})
                wait_until(
                    lambda: manager.corporate_sandbox_test_status()["state"]
                    == "completed"
                )
                status = manager.corporate_sandbox_test_status()
                self.assertEqual(status["checks_completed"], 47)
                self.assertEqual(status["result"]["verdict"], "blocked")
                self.assertTrue(status["test_only"])
                self.assertFalse(status["production_approved"])
                self.assertFalse(status["chat_unlocked"])
                self.assertFalse(manager._permission_profile_enforced)
            finally:
                manager.close()

    def test_eligible_corporate_mode_persists_and_routes_builtin_workspace_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project_root = root / "Workspace" / "사용자-프로젝트"
            project_root.mkdir(parents=True)
            paths = PortablePaths(root, root / "HumanCodexData")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("회사 모드")
            chat = database.create_chat(project.id)
            runtime = CodexRuntime(paths, executable=sys.executable)
            manager = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"u" * 32)
            )
            manager.workspace.ensure_project_roots(project.id, str(project_root))
            required = set(runtime.CORPORATE_ACTIVATION_REQUIRED_CHECKS)
            checks = [
                {
                    "id": check_id,
                    "stage": stage,
                    "critical": check_id in required,
                    "status": "passed" if check_id in required else "failed",
                }
                for check_id, stage in runtime.CORPORATE_TEST_CHECKS
            ]
            eligible = {
                "mode": "corporate-restricted-test",
                "backend": "codex-unelevated-restricted-token",
                "test_only": True,
                "activation_eligible": True,
                "production_approved": False,
                "chat_unlocked": False,
                "checks_total": runtime.CORPORATE_TEST_TOTAL,
                "checks_completed": runtime.CORPORATE_TEST_TOTAL,
                "checks_passed": len(required),
                "required_checks_total": len(required),
                "required_checks_passed": len(required),
                "warning_checks": [
                    item["id"] for item in checks if item["status"] != "passed"
                ],
                "verdict": "eligible_with_warnings",
                "checks": checks,
                "error": None,
            }
            manager._corporate_test_state = "completed"
            manager._corporate_test_result = eligible
            with patch.object(
                manager,
                "sandbox_status",
                return_value={
                    "can_start": True,
                    "active_mode": "corporate-restricted",
                },
            ):
                activated = manager.activate_corporate_sandbox(approved=True)
            self.assertTrue(activated["can_start"])
            self.assertTrue(manager._corporate_mode_active())
            self.assertTrue(manager._corporate_activation_path.is_file())

            requests = []

            class FakeClient:
                def __init__(self, _runtime, **kwargs):
                    self.windows_sandbox_override = kwargs.get(
                        "windows_sandbox_override"
                    )
                    self.default_permissions_override = kwargs.get(
                        "default_permissions_override"
                    )

                def __enter__(self):
                    return self

                def initialize(self):
                    return {}

                def close(self):
                    return None

                def request(self, method, params, **_kwargs):
                    requests.append((method, params))
                    if method == "command/exec":
                        if "HC_WRITE_PROBE" in params.get("env", {}):
                            Path(params["env"]["HC_WRITE_PROBE"]).write_text(
                                "HC_WORKSPACE_WRITE", encoding="utf-8"
                            )
                            return {
                                "exitCode": 0,
                                "stdout": "HC_WORKSPACE_ACCESS_READY\n",
                                "stderr": "",
                            }
                        return {
                            "exitCode": 0,
                            "stdout": "HC_WORKSPACE_READY\n",
                            "stderr": "",
                        }
                    if method == "thread/start":
                        return {"thread": {"id": "thr_corporate"}}
                    if method == "turn/start":
                        return {"turn": {"id": "turn_corporate", "status": "inProgress"}}
                    raise AssertionError(f"unexpected method: {method}")

            try:
                with patch.object(
                    runtime, "prepare_corporate_workspace_roots"
                ) as prepare_roots, patch(
                    "human_codex.sessions.AppServerClient", FakeClient
                ):
                    opened = manager.open_chat(chat.id)
                    self.assertEqual(opened["thread"]["id"], "thr_corporate")
                    manager.start_turn(chat.id, "공개 자료를 웹에서 찾아 정리해줘")
                prepare_roots.assert_called_once()
                thread_params = next(
                    params for method, params in requests if method == "thread/start"
                )
                self.assertEqual(thread_params["sandbox"], "workspace-write")
                self.assertEqual(thread_params["config"]["default_permissions"], ":workspace")
                self.assertEqual(thread_params["config"]["web_search"], "live")
                self.assertNotIn("permissions", thread_params["config"])
                turn_params = next(
                    params for method, params in requests if method == "turn/start"
                )
                self.assertEqual(turn_params["sandboxPolicy"]["type"], "workspaceWrite")
                self.assertFalse(turn_params["sandboxPolicy"]["networkAccess"])
                self.assertIn(
                    str(project_root.resolve()),
                    turn_params["sandboxPolicy"]["writableRoots"],
                )
            finally:
                manager.close()

            restored = CodexSessionManager(
                database, paths, runtime=runtime, vault=AesGcmVault(b"u" * 32)
            )
            try:
                self.assertTrue(restored._corporate_mode_active())
                self.assertTrue(
                    restored.corporate_sandbox_test_status()["chat_unlocked"]
                )
            finally:
                restored.close()

    def test_streamed_provider_text_is_withheld_until_complete_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            database.migrate()
            project = database.create_project("Stream redaction")
            chat = database.create_chat(project.id)
            manager = CodexSessionManager(
                database,
                paths,
                runtime=CodexRuntime(paths, executable=sys.executable),
                vault=AesGcmVault(b"r" * 32),
            )
            secret = "sk-proj-" + "Q7wE9rT2yU4iO6pA8sD1fG3hJ5kL"
            try:
                manager._thread_to_chat["thr_stream"] = chat.id
                manager._on_notification(
                    "item/agentMessage/delta",
                    {
                        "threadId": "thr_stream",
                        "turnId": "turn_stream",
                        "itemId": "item_stream",
                        "delta": secret[:18],
                    },
                )
                manager._on_notification(
                    "item/agentMessage/delta",
                    {
                        "threadId": "thr_stream",
                        "turnId": "turn_stream",
                        "itemId": "item_stream",
                        "delta": secret[18:],
                    },
                )
                streamed = json.dumps(manager.timeline(chat.id), ensure_ascii=False)
                self.assertNotIn(secret[:18], streamed)
                self.assertNotIn(secret[18:], streamed)
                manager._on_notification(
                    "item/completed",
                    {
                        "threadId": "thr_stream",
                        "turnId": "turn_stream",
                        "item": {
                            "type": "agentMessage",
                            "id": "item_stream",
                            "text": secret,
                        },
                    },
                )
                completed = json.dumps(manager.timeline(chat.id), ensure_ascii=False)
                self.assertNotIn(secret, completed)
                self.assertIn("REDACTED_SECRET", completed)
            finally:
                manager.close()


if __name__ == "__main__":
    unittest.main()
