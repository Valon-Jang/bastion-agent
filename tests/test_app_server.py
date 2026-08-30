import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from human_codex.app_server import (
    AppServerClient,
    AppServerError,
    _product_version,
    run_initialize_thread_smoke,
)
from human_codex.codex_runtime import CodexRuntime
from human_codex.paths import PortablePaths


FAKE_SERVER = r'''
import json
import sys
import threading
import time

write_lock = threading.Lock()
approval_parent = None
def emit(payload):
    with write_lock:
        print(json.dumps(payload), flush=True)

def delayed(message):
    time.sleep(0.15)
    emit({"id": message["id"], "result": {"name": "slow"}})

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if message.get("id") == "approval_1" and "result" in message:
        emit({"id": approval_parent, "result": {"decision": message["result"]["decision"]}})
        continue
    if method == "initialize":
        emit({"id": message["id"], "result": {
            "userAgent": "fake", "platformFamily": "windows", "platformOs": "windows"
        }})
    elif method == "initialized":
        continue
    elif method == "thread/start":
        params = message["params"]
        config = params.get("config", {})
        projects = config.get("projects", {})
        if (
            "sandbox" in params
            or config.get("default_permissions") != "human-codex-project-read-only"
            or config.get("web_search") != "live"
            or not projects
            or any(value.get("trust_level") != "untrusted" for value in projects.values())
        ):
            emit({"id": message["id"], "error": {"code": -1, "message": "unsafe smoke profile"}})
            continue
        emit({"method": "thread/started", "params": {
            "thread": {"id": "thr_fake"}
        }})
        emit({"id": message["id"], "result": {"thread": {
            "id": "thr_fake", "sessionId": "thr_fake", "ephemeral": True,
            "modelProvider": "fake"
        }}})
    elif method == "test/slow":
        threading.Thread(target=delayed, args=(message,), daemon=False).start()
    elif method == "test/fast":
        emit({"id": message["id"], "result": {"name": "fast"}})
    elif method == "test/approval":
        approval_parent = message["id"]
        emit({"id": "approval_1", "method": "item/commandExecution/requestApproval", "params": {"threadId": "thr_fake", "turnId": "turn_fake", "itemId": "item_fake", "startedAtMs": 1, "command": "pytest", "cwd": ".", "environmentId": None}})
'''


class AppServerProtocolTests(unittest.TestCase):
    def test_initialize_uses_release_metadata_version(self) -> None:
        expected = json.loads((Path(__file__).resolve().parents[1] / "VERSION.json").read_text(encoding="utf-8"))["version"]
        self.assertEqual(_product_version(), expected)
        self.assertNotIn("dev", _product_version())

    def test_unelevated_override_is_a_scoped_cli_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = CodexRuntime(PortablePaths(root, root / "data"), executable="codex.exe")
            client = AppServerClient(
                runtime,
                windows_sandbox_override="unelevated",
                default_permissions_override=":workspace",
            )
            self.assertEqual(
                client._startup_command("codex.exe"),
                [
                    "codex.exe",
                    "-c",
                    'windows.sandbox="unelevated"',
                    "-c",
                    'default_permissions=":workspace"',
                    "app-server",
                    "--strict-config",
                    "--listen",
                    "stdio://",
                ],
            )
            with self.assertRaisesRegex(ValueError, "unsupported"):
                AppServerClient(runtime, windows_sandbox_override="dangerous")
            with self.assertRaisesRegex(ValueError, "unsupported"):
                AppServerClient(runtime, default_permissions_override="unsafe")

    def test_oversized_method_name_is_rejected_before_notification_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            client = AppServerClient(
                CodexRuntime(PortablePaths(root, root / "data"), executable=sys.executable)
            )
            with self.assertRaises(AppServerError):
                client._dispatch(
                    {"method": "x" * (client.MAX_METHOD_CHARS + 1), "params": {}}
                )
            self.assertEqual(client.notifications, [])

    def test_initialize_then_thread_start(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            paths = PortablePaths(root, root / "data")
            runtime = CodexRuntime(paths, executable=sys.executable)
            result = run_initialize_thread_smoke(runtime, cwd=root, timeout=5)
            self.assertEqual(result.status, "pass")
            self.assertEqual(result.thread["id"], "thr_fake")
            self.assertIn("thread/started", result.notifications)

    def test_concurrent_requests_are_routed_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            runtime = CodexRuntime(PortablePaths(root, root / "data"), executable=sys.executable)
            with AppServerClient(runtime, timeout=5) as client:
                client.initialize()
                result = {}
                slow = threading.Thread(target=lambda: result.update(slow=client.request("test/slow", {})))
                slow.start()
                time.sleep(0.02)
                result["fast"] = client.request("test/fast", {})
                slow.join(timeout=2)
                self.assertFalse(slow.is_alive())
                self.assertEqual(result["fast"]["name"], "fast")
                self.assertEqual(result["slow"]["name"], "slow")

    def test_server_approval_request_is_answered_without_blocking_response_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app-server").write_text(FAKE_SERVER, encoding="utf-8")
            runtime = CodexRuntime(PortablePaths(root, root / "data"), executable=sys.executable)
            handled = []
            def approve(method, request_id, params):
                handled.append((method, request_id, params["itemId"]))
                return {"decision": "accept"}
            with AppServerClient(runtime, timeout=5, server_request_handler=approve) as client:
                client.initialize()
                result = client.request("test/approval", {})
                self.assertEqual(result["decision"], "accept")
                self.assertEqual(handled, [("item/commandExecution/requestApproval", "approval_1", "item_fake")])


if __name__ == "__main__":
    unittest.main()
