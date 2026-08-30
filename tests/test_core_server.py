import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from human_codex.core_ipc import MAX_FRAME_BYTES, IpcValidationError, decode, encode, request
from human_codex.core_server import CoreService, serve
from human_codex.database import MetadataDatabase
from human_codex.paths import PortablePaths


class CoreServerTests(unittest.TestCase):
    def _run(self, data_root: Path, *messages: str) -> list[dict]:
        output = io.StringIO()
        previous = os.environ.get("HUMAN_CODEX_DATA_ROOT")
        os.environ["HUMAN_CODEX_DATA_ROOT"] = str(data_root)
        try:
            paths = PortablePaths.discover(Path.cwd())
            serve(io.StringIO("\n".join(messages) + "\n"), output, paths)
        finally:
            if previous is None:
                os.environ.pop("HUMAN_CODEX_DATA_ROOT", None)
            else:
                os.environ["HUMAN_CODEX_DATA_ROOT"] = previous
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_health_project_chat_and_restart_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            health = request("system.health", {})
            create_project = request("project.create", {"name": "Alpha"})
            responses = self._run(Path(temp), encode(health), encode(create_project))
            self.assertEqual(decode(json.dumps(responses[0])).params["status"], "pass")
            project_id = responses[1]["params"]["project"]["id"]
            create_chat = request("chat.create", {"project_id": project_id, "title": "Plan"})
            list_chats = request("chat.list", {"project_id": project_id})
            restarted = self._run(Path(temp), encode(create_chat), encode(list_chats))
            self.assertEqual(restarted[1]["params"]["chats"][0]["title"], "Plan")

    def test_packaged_core_starts_in_company_direct_chat_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            status = request("system.sandbox.status", {})
            responses = self._run(Path(temp), encode(status))
            payload = decode(json.dumps(responses[0])).params
            self.assertTrue(payload["can_start"])
            self.assertEqual(payload["active_mode"], "company-direct")
            self.assertEqual(payload["verification"]["state"], "skipped")
            self.assertFalse(payload["direct"]["native_isolation"])

    def test_malformed_and_unknown_method_return_safe_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            unknown = request("shell.execute", {"command": "whoami"})
            responses = self._run(Path(temp), "{", "[]", '"scalar"', encode(unknown))
            self.assertEqual(responses[0]["error"]["code"], "invalid_request")
            self.assertEqual(responses[1]["error"]["code"], "invalid_request")
            self.assertEqual(responses[2]["error"]["code"], "invalid_request")
            self.assertEqual(responses[3]["error"]["code"], "invalid_request")

    def test_unelevated_diagnostic_requires_consent_and_stays_diagnostic(self) -> None:
        class FakeSessions:
            def close(self):
                return None

            def diagnose_unelevated_sandbox(self, *, approved):
                return {
                    "diagnostic_only": True,
                    "secure_mode": "elevated",
                    "secure_mode_changed": False,
                    "chat_unlocked": False,
                    "approved": approved,
                }

        with tempfile.TemporaryDirectory() as temp:
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            service = CoreService(database, paths, sessions=FakeSessions())
            with self.assertRaises(IpcValidationError):
                service.handle(
                    request(
                        "system.sandbox.diagnose-unelevated",
                        {"approved": False},
                    )
                )
            result, should_stop = service.handle(
                request(
                    "system.sandbox.diagnose-unelevated",
                    {"approved": True},
                )
            )
            self.assertTrue(result["diagnostic_only"])
            self.assertEqual(result["secure_mode"], "elevated")
            self.assertFalse(result["secure_mode_changed"])
            self.assertFalse(result["chat_unlocked"])
            self.assertFalse(should_stop)

    def test_corporate_test_and_activation_endpoints_require_consent(self) -> None:
        class FakeSessions:
            def close(self):
                return None

            def corporate_sandbox_test_status(self):
                return {
                    "state": "running",
                    "test_only": True,
                    "checks_completed": 4,
                    "checks_total": 47,
                    "chat_unlocked": False,
                }

            def start_corporate_sandbox_test(self, *, approved, project_id=None):
                return {
                    **self.corporate_sandbox_test_status(),
                    "approved": approved,
                    "project_id": project_id,
                }

            def activate_corporate_sandbox(self, *, approved):
                return {"can_start": approved, "active_mode": "corporate-restricted"}

        with tempfile.TemporaryDirectory() as temp:
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            service = CoreService(database, paths, sessions=FakeSessions())
            with self.assertRaises(IpcValidationError):
                service.handle(
                    request(
                        "system.sandbox.corporate-test.start",
                        {"approved": False},
                    )
                )
            status, should_stop = service.handle(
                request("system.sandbox.corporate-test.status", {})
            )
            self.assertEqual(status["checks_total"], 47)
            self.assertFalse(status["chat_unlocked"])
            started, should_stop = service.handle(
                request(
                    "system.sandbox.corporate-test.start",
                    {"approved": True},
                )
            )
            self.assertTrue(started["approved"])
            self.assertTrue(started["test_only"])
            self.assertFalse(started["chat_unlocked"])
            self.assertFalse(should_stop)
            with self.assertRaises(IpcValidationError):
                service.handle(
                    request(
                        "system.sandbox.corporate.activate",
                        {"approved": False},
                    )
                )
            activated, should_stop = service.handle(
                request(
                    "system.sandbox.corporate.activate",
                    {"approved": True},
                )
            )
            self.assertTrue(activated["can_start"])
            self.assertEqual(activated["active_mode"], "corporate-restricted")
            self.assertFalse(should_stop)

    def test_oversized_unterminated_frame_is_discarded_before_the_next_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = io.StringIO()
            previous = os.environ.get("HUMAN_CODEX_DATA_ROOT")
            os.environ["HUMAN_CODEX_DATA_ROOT"] = temp
            try:
                paths = PortablePaths.discover(Path.cwd())
                oversized = "{" + "x" * (MAX_FRAME_BYTES + 32)
                serve(io.StringIO(oversized + "\n" + encode(request("system.health", {})) + "\n"), output, paths)
            finally:
                if previous is None:
                    os.environ.pop("HUMAN_CODEX_DATA_ROOT", None)
                else:
                    os.environ["HUMAN_CODEX_DATA_ROOT"] = previous
            responses = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(responses[0]["error"]["code"], "invalid_request")
            self.assertEqual(responses[1]["params"]["status"], "pass")

    def test_oversized_internal_response_fails_closed_without_stopping_core(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            health = encode(request("system.health", {}))
            original_handle = None

            from human_codex.core_server import CoreService

            original_handle = CoreService.handle
            calls = 0

            def oversized_once(service, message):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return {"value": "x" * MAX_FRAME_BYTES}, False
                return original_handle(service, message)

            with patch.object(CoreService, "handle", oversized_once):
                responses = self._run(Path(temp), health, health)
            self.assertEqual(responses[0]["error"]["code"], "response_too_large")
            self.assertEqual(responses[1]["params"]["status"], "pass")

    def test_project_roots_workspace_and_snapshot_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data_root = Path(temp) / "data"
            main_root = Path(temp) / "project"
            main_root.mkdir()
            (main_root / "file.txt").write_text("baseline", encoding="utf-8")
            created = self._run(
                data_root,
                encode(request("project.create", {"name": "Workspace", "main_root": str(main_root)})),
            )
            project_id = created[0]["params"]["project"]["id"]
            responses = self._run(
                data_root,
                encode(request("project.roots", {"project_id": project_id})),
                encode(request("workspace.status", {"project_id": project_id})),
                encode(request("snapshot.create", {"project_id": project_id, "reason": "checkpoint"})),
                encode(request("snapshot.list", {"project_id": project_id})),
                encode(request("workspace.git.init", {"project_id": project_id, "approved": False})),
                encode(request("workspace.git.init", {"project_id": project_id, "approved": True})),
            )
            self.assertEqual(responses[0]["params"]["roots"][0]["kind"], "main")
            self.assertTrue(responses[1]["params"]["git"]["available"])
            self.assertEqual(responses[2]["params"]["snapshot"]["file_count"], 1)
            self.assertEqual(responses[3]["params"]["snapshots"][0]["reason"], "checkpoint")
            self.assertEqual(responses[4]["error"]["code"], "invalid_request")
            self.assertTrue(responses[5]["params"]["git"]["repository"])


if __name__ == "__main__":
    unittest.main()
