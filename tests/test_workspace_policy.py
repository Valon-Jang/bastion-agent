import json
import hashlib
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from human_codex.app_server import wait_until
from human_codex.approvals import ApprovalBroker, ApprovalError
from human_codex.database import MetadataDatabase
from human_codex.paths import PortablePaths
from human_codex.risk import RiskEngine
from human_codex.vault import AesGcmVault
from human_codex.workspace import GitWorkspaceManager, SnapshotManager, WorkspaceError, WorkspacePolicy


class WorkspacePolicyTests(unittest.TestCase):
    def make_services(self, root: Path):
        paths = PortablePaths(root, root / "data")
        database = MetadataDatabase.from_data_root(paths.data_root)
        vault = AesGcmVault(b"m" * 32)
        workspace = WorkspacePolicy(database, paths, vault)
        snapshots = SnapshotManager(database, paths, vault, workspace)
        risk = RiskEngine(workspace)
        return paths, database, vault, workspace, snapshots, risk

    def test_roots_are_encrypted_and_canonical_boundaries_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            _, database, _, workspace, _, _ = self.make_services(root)
            project = database.create_project("Bounded")
            roots = workspace.ensure_project_roots(project.id, str(main))
            self.assertEqual(roots[0].path, str(main.resolve()))
            self.assertEqual(workspace.classify_path(project.id, str(main / "file.py"), write=True), "allowed")
            self.assertEqual(workspace.classify_path(project.id, str(main / ".." / "outside.txt"), write=True), "external")
            with database.connection() as connection:
                stored = connection.execute("SELECT path_ciphertext, path_hmac FROM project_roots WHERE kind = 'main'").fetchone()
            self.assertNotIn(str(main), stored[0])
            self.assertRegex(stored[1], r"^[0-9a-f]{64}$")

    def test_broad_sensitive_roots_are_rejected_but_managed_roots_remain_usable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths, database, _, workspace, _, _ = self.make_services(root)
            project = database.create_project("Safe roots")

            managed = workspace.ensure_project_roots(project.id)
            managed_main = next(item for item in managed if item.kind == "main")
            managed_temp = next(item for item in managed if item.kind == "temp")
            self.assertEqual(
                workspace.classify_path(
                    project.id, str(Path(managed_main.path) / "source.py"), write=True
                ),
                "allowed",
            )
            self.assertEqual(
                workspace.classify_path(
                    project.id, str(Path(managed_temp.path) / "scratch.txt"), write=True
                ),
                "allowed",
            )

            drive_root = Path(root.anchor)
            with self.assertRaises(WorkspaceError):
                workspace.validate_main_root(str(drive_root))
            with self.assertRaises(WorkspaceError):
                workspace.validate_main_root(str(Path.home()))
            with self.assertRaises(WorkspaceError):
                workspace.validate_main_root(str(paths.data_root))
            with self.assertRaises(WorkspaceError):
                workspace.validate_main_root(str(paths.repository_root))

            user_workspace = paths.workspace_root / "사용자-파일"
            user_workspace.mkdir(parents=True)
            self.assertEqual(
                workspace.validate_main_root(str(user_workspace)),
                str(user_workspace.resolve()),
            )

            secret_root = root / ".ssh"
            secret_root.mkdir()
            with self.assertRaises(WorkspaceError):
                workspace.add_root(project.id, "reference", str(secret_root))

            self.assertEqual(
                workspace.classify_path(
                    project.id, str(paths.data_root / "vault" / "master-key.dpapi"), write=False
                ),
                "system",
            )

            for number in range(workspace.MAX_ROOTS - len(managed)):
                additional = root / f"additional-{number}"
                additional.mkdir()
                workspace.add_root(project.id, "reference", str(additional))
            overflow = root / "additional-overflow"
            overflow.mkdir()
            with self.assertRaises(WorkspaceError):
                workspace.add_root(project.id, "reference", str(overflow))

    @unittest.skipUnless(os.name == "nt", "Windows filesystem policy")
    def test_windows_rejects_project_roots_without_acl_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            _, _, _, workspace, _, _ = self.make_services(root)
            with patch(
                "human_codex.workspace._windows_filesystem_name", return_value="EXFAT"
            ):
                with self.assertRaisesRegex(WorkspaceError, "NTFS or ReFS"):
                    workspace.validate_main_root(str(main))

    @unittest.skipUnless(os.name == "nt", "Windows Downloads folder policy")
    def test_windows_downloads_and_nested_folders_are_selectable(self) -> None:
        downloads = Path.home() / "Downloads"
        if not downloads.is_dir():
            self.skipTest("Downloads folder is unavailable")
        with tempfile.TemporaryDirectory() as temp:
            _, _, _, workspace, _, _ = self.make_services(Path(temp))
            self.assertEqual(
                workspace.validate_main_root(str(downloads)),
                str(downloads.resolve()),
            )
            nested = downloads / f"human-codex-path-test-{os.getpid()}"
            nested.mkdir()
            try:
                self.assertEqual(
                    workspace.validate_main_root(str(nested)),
                    str(nested.resolve()),
                )
            finally:
                nested.rmdir()

    def test_codex_config_enables_hosted_search_but_disables_external_apps(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            _, database, _, workspace, _, _ = self.make_services(root)
            project = database.create_project("Restricted config")
            workspace.ensure_project_roots(project.id, str(main))
            profile = workspace.permission_profile(project.id)
            self.assertNotIn("sandbox", profile)
            self.assertNotIn("sandboxPolicy", profile)
            for key in ("codexConfig", "codexReadOnlyConfig"):
                config = profile[key]
                self.assertEqual(config["web_search"], "live")
                self.assertFalse(config["apps"]["_default"]["enabled"])
                self.assertFalse(config["agents"]["enabled"])
                self.assertFalse(config["features"]["hooks"])
                self.assertEqual(
                    config["projects"][str(main.resolve())]["trust_level"],
                    "untrusted",
                )

    def test_snapshot_restores_verified_blobs_but_never_backs_up_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            normal = main / "app.py"
            secret = main / ".env"
            inline_secret = main / "settings.py"
            normal.write_text("before", encoding="utf-8")
            secret.write_text("TOKEN=private", encoding="utf-8")
            inline_secret.write_text(
                'api_key = "N7wQ2pL9sR4mK8xV6cD3"\n', encoding="utf-8"
            )
            paths, database, _, workspace, snapshots, _ = self.make_services(root)
            project = database.create_project("Snapshot")
            workspace.ensure_project_roots(project.id, str(main))
            snapshot = snapshots.create(project.id, "before edit")
            self.assertEqual(snapshot["file_count"], 1)
            self.assertEqual(snapshot["excluded_count"], 2)
            blobs = [
                path
                for path in (paths.data_root / "snapshots" / "blobs-v2").rglob("*")
                if path.is_file()
            ]
            self.assertEqual(len(blobs), 1)
            encrypted = blobs[0].read_bytes()
            self.assertNotIn(b"before", encrypted)
            blobs[0].write_bytes(encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
            with self.assertRaises(WorkspaceError):
                snapshots.restore(project.id, snapshot["id"], approved=True)
            blobs[0].write_bytes(encrypted)
            normal.write_text("after", encoding="utf-8")
            secret.write_text("TOKEN=changed", encoding="utf-8")
            with self.assertRaises(WorkspaceError):
                snapshots.restore(project.id, snapshot["id"], approved=False)
            restored = snapshots.restore(project.id, snapshot["id"], approved=True)
            self.assertEqual(restored["restored_files"], 1)
            self.assertEqual(normal.read_text(encoding="utf-8"), "before")
            self.assertEqual(secret.read_text(encoding="utf-8"), "TOKEN=changed")

    def test_legacy_plaintext_snapshot_blobs_are_authenticated_encrypted_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root, root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            vault = AesGcmVault(b"m" * 32)
            workspace = WorkspacePolicy(database, paths, vault)
            plaintext = b"legacy snapshot content"
            digest = hashlib.sha256(plaintext).hexdigest()
            legacy = paths.data_root / "snapshots" / "blobs" / digest[:2] / digest
            legacy.parent.mkdir(parents=True)
            legacy.write_bytes(plaintext)
            snapshots = SnapshotManager(database, paths, vault, workspace)
            self.assertFalse(legacy.exists())
            encrypted = snapshots._blob_path(digest)
            self.assertTrue(encrypted.is_file())
            self.assertNotIn(plaintext, encrypted.read_bytes())
            self.assertEqual(snapshots._load_blob(digest), plaintext)

    def test_risk_engine_blocks_remote_push_and_requires_correct_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            _, database, _, workspace, _, risk = self.make_services(root)
            project = database.create_project("Risk")
            workspace.ensure_project_roots(project.id, str(main))
            self.assertEqual(risk.assess(project.id, action="execute", command="git push origin main").decision, "block")
            self.assertEqual(risk.assess(project.id, action="execute", command="git -C . push origin main").decision, "block")
            self.assertEqual(risk.assess(project.id, action="execute", command="g^it p^ush origin main").decision, "block")
            self.assertEqual(risk.assess(project.id, action="execute", command="git remote add origin https://example.invalid/x").decision, "block")
            self.assertEqual(risk.assess(project.id, action="execute", command="git remote set-url origin https://example.invalid/x").decision, "block")
            self.assertEqual(risk.assess(project.id, action="execute", command="git config remote.origin.url https://example.invalid/x").decision, "block")
            test = risk.assess(project.id, action="execute", targets=[str(main)], command="py -m unittest")
            self.assertEqual((test.level, test.decision, test.requires_snapshot), ("R1", "snapshot", True))
            delete = risk.assess(project.id, action="execute", targets=[str(main)], command="Remove-Item a.txt")
            self.assertEqual((delete.level, delete.decision), ("R3", "approval"))
            outside = risk.assess(project.id, action="edit", targets=[str(root / "outside.txt")])
            self.assertEqual((outside.level, outside.decision), ("R2", "approval"))
            secret = risk.assess(project.id, action="read", targets=[".env"])
            self.assertEqual((secret.level, secret.decision), ("R4", "block"))
            auth_archive = risk.assess(
                project.id,
                action="execute",
                targets=[str(main)],
                command="7z a backup.7z .ssh",
            )
            self.assertEqual((auth_archive.level, auth_archive.decision), ("R4", "block"))
            escalation = risk.assess(
                project.id,
                action="permission_escalation",
                targets=[str(main)],
            )
            self.assertEqual((escalation.level, escalation.decision), ("R4", "block"))

    def test_approval_waits_for_user_and_records_only_encrypted_details(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            _, database, vault, workspace, snapshots, risk = self.make_services(root)
            project = database.create_project("Approval")
            workspace.ensure_project_roots(project.id, str(main))
            chat = database.create_chat(project.id)
            broker = ApprovalBroker(database, vault, workspace, risk, snapshots)
            broker.WAIT_SECONDS = 3
            result = {}
            params = {"threadId": "thr", "turnId": "turn", "itemId": "item", "startedAtMs": 1, "command": "npm run build", "cwd": str(main), "environmentId": None}
            worker = threading.Thread(target=lambda: result.update(value=broker.handle_server_request(chat.id, "item/commandExecution/requestApproval", "req1", params)))
            worker.start()
            self.assertTrue(wait_until(lambda: len(broker.list_pending(project.id)) == 1))
            pending = broker.list_pending(project.id)[0]
            self.assertEqual(pending["risk_level"], "R2")
            broker.decide(pending["id"], "approve", "once")
            worker.join(timeout=3)
            self.assertEqual(result["value"], {"decision": "accept"})
            with database.connection() as connection:
                encrypted = connection.execute("SELECT details_ciphertext FROM approvals WHERE id = ?", (pending["id"],)).fetchone()[0]
            self.assertNotIn("npm run build", encrypted)
            blocked = broker.handle_server_request(chat.id, "item/commandExecution/requestApproval", "req2", {**params, "command": "git push origin main"})
            self.assertEqual(blocked, {"decision": "decline"})
            permission = broker.handle_server_request(
                chat.id,
                "item/permissions/requestApproval",
                "permission-request",
                {
                    "threadId": "thr",
                    "turnId": "turn",
                    "itemId": "permission-item",
                    "startedAtMs": 2,
                    "cwd": str(main),
                    "environmentId": None,
                    "permissions": {
                        "network": {"enabled": True},
                        "fileSystem": {
                            "read": [str(root)],
                            "write": [str(root)],
                            "entries": [
                                {
                                    "path": {"type": "special", "value": {"kind": "root"}},
                                    "access": "write",
                                }
                            ],
                        },
                    },
                },
            )
            self.assertEqual(
                permission,
                {
                    "permissions": {
                        "network": {"enabled": False},
                        "fileSystem": {"read": [], "write": [], "entries": []},
                    },
                    "scope": "turn",
                },
            )
            external = root / "external"
            external.mkdir()
            changed = {}
            patch_params = {"threadId": "thr", "turnId": "turn", "itemId": "patch", "startedAtMs": 2, "grantRoot": str(external)}
            patch_worker = threading.Thread(target=lambda: changed.update(value=broker.handle_server_request(chat.id, "item/fileChange/requestApproval", "req3", patch_params)))
            patch_worker.start()
            self.assertTrue(wait_until(lambda: len(broker.list_pending(project.id)) == 1))
            patch_approval = broker.list_pending(project.id)[0]
            workspace.add_root(project.id, "write", str(external))
            broker.decide(patch_approval["id"], "approve", "once")
            patch_worker.join(timeout=3)
            self.assertEqual(changed["value"], {"decision": "decline"})
            broker.close()

    def test_turn_scope_cannot_be_reused_for_a_changed_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            _, database, vault, workspace, snapshots, risk = self.make_services(root)
            project = database.create_project("Scoped approval")
            workspace.ensure_project_roots(project.id, str(main))
            chat = database.create_chat(project.id)
            broker = ApprovalBroker(database, vault, workspace, risk, snapshots)
            broker.WAIT_SECONDS = 3
            base = {
                "threadId": "thr",
                "turnId": "turn",
                "itemId": "same-item",
                "startedAtMs": 1,
                "cwd": str(main),
                "environmentId": None,
            }
            first: dict[str, object] = {}
            second: dict[str, object] = {}
            first_worker = threading.Thread(
                target=lambda: first.update(
                    value=broker.handle_server_request(
                        chat.id,
                        "item/commandExecution/requestApproval",
                        "first",
                        {**base, "command": "npm run build"},
                    )
                )
            )
            first_worker.start()
            try:
                self.assertTrue(wait_until(lambda: len(broker.list_pending(project.id)) == 1))
                pending = broker.list_pending(project.id)[0]
                broker.decide(pending["id"], "approve", "task")
                first_worker.join(timeout=3)
                self.assertEqual(first["value"], {"decision": "accept"})

                second_worker = threading.Thread(
                    target=lambda: second.update(
                        value=broker.handle_server_request(
                            chat.id,
                            "item/commandExecution/requestApproval",
                            "second",
                            {**base, "command": "python -c print(1)"},
                        )
                    )
                )
                second_worker.start()
                self.assertTrue(wait_until(lambda: len(broker.list_pending(project.id)) == 1))
                changed = broker.list_pending(project.id)[0]
                broker.decide(changed["id"], "deny", "once")
                second_worker.join(timeout=3)
                self.assertEqual(second["value"], {"decision": "decline"})
            finally:
                broker.close()
                first_worker.join(timeout=3)
                if "second_worker" in locals():
                    second_worker.join(timeout=3)

    def test_local_git_operations_disable_ambient_config_hooks_and_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            paths, database, vault, workspace, _, _ = self.make_services(root)
            project = database.create_project("Sanitized Git")
            workspace.ensure_project_roots(project.id, str(main))
            manager = GitWorkspaceManager(database, paths, vault, workspace)
            completed = subprocess.CompletedProcess(["git"], 0, "", "")
            with patch.dict(os.environ, {"OPENAI_API_KEY": "must-not-pass"}), patch(
                "human_codex.workspace.subprocess.run", return_value=completed
            ) as run:
                manager._git(main, "status")
            command = run.call_args.args[0]
            environment = run.call_args.kwargs["env"]
            self.assertIn("core.fsmonitor=false", command)
            self.assertIn("credential.helper=", command)
            self.assertIn("init.templateDir=", command)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
            self.assertNotIn("OPENAI_API_KEY", environment)

    def test_pending_list_exposes_only_decidable_requests_and_rejects_duplicate_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            _, database, vault, workspace, snapshots, risk = self.make_services(root)
            project = database.create_project("Approval race")
            workspace.ensure_project_roots(project.id, str(main))
            chat = database.create_chat(project.id)
            broker = ApprovalBroker(database, vault, workspace, risk, snapshots)
            broker.WAIT_SECONDS = 3
            snapshot_started = threading.Event()
            allow_snapshot = threading.Event()
            original_create = snapshots.create

            def delayed_snapshot(project_id: str, label: str):
                snapshot_started.set()
                self.assertTrue(allow_snapshot.wait(3))
                return original_create(project_id, label)

            snapshots.create = delayed_snapshot
            result = {}
            params = {
                "threadId": "thr",
                "turnId": "turn",
                "itemId": "item",
                "startedAtMs": 1,
                "command": "py -m unittest",
                "cwd": str(main),
                "environmentId": None,
            }
            worker = threading.Thread(
                target=lambda: result.update(
                    value=broker.handle_server_request(
                        chat.id, "item/commandExecution/requestApproval", "race", params
                    )
                )
            )
            worker.start()
            try:
                self.assertTrue(snapshot_started.wait(3))
                with database.connection() as connection:
                    stored_pending = connection.execute(
                        "SELECT COUNT(*) FROM approvals WHERE decision = 'pending'"
                    ).fetchone()[0]
                self.assertEqual(stored_pending, 1)
                self.assertEqual(broker.list_pending(project.id), [])

                allow_snapshot.set()
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(result["value"], {"decision": "accept"})
                self.assertEqual(broker.list_pending(project.id), [])

                approval_result = {}
                approval_params = {**params, "command": "npm run build"}
                approval_worker = threading.Thread(
                    target=lambda: approval_result.update(
                        value=broker.handle_server_request(
                            chat.id,
                            "item/commandExecution/requestApproval",
                            "duplicate",
                            approval_params,
                        )
                    )
                )
                approval_worker.start()
                self.assertTrue(wait_until(lambda: len(broker.list_pending(project.id)) == 1))
                pending = broker.list_pending(project.id)[0]
                broker.decide(pending["id"], "approve", "once")
                with self.assertRaisesRegex(ApprovalError, "no longer pending"):
                    broker.decide(pending["id"], "approve", "once")
                approval_worker.join(timeout=3)
                self.assertFalse(approval_worker.is_alive())
                self.assertEqual(approval_result["value"], {"decision": "accept"})
            finally:
                allow_snapshot.set()
                broker.close()
                worker.join(timeout=3)

    def test_git_worktree_preserves_dirty_source_and_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "project"
            main.mkdir()
            subprocess.run(["git", "init"], cwd=main, check=True, capture_output=True)
            (main / "file.txt").write_text("base", encoding="utf-8")
            subprocess.run(["git", "add", "file.txt"], cwd=main, check=True, capture_output=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-m", "base"], cwd=main, check=True, capture_output=True)
            (main / "file.txt").write_text("user dirty", encoding="utf-8")
            paths, database, vault, workspace, _, _ = self.make_services(root)
            project = database.create_project("Git")
            workspace.ensure_project_roots(project.id, str(main))
            manager = GitWorkspaceManager(database, paths, vault, workspace)
            self.assertTrue(manager.inspect(project.id)["dirty"])
            with self.assertRaises(WorkspaceError):
                manager.prepare_worktree(project.id, approved=False)
            prepared = manager.prepare_worktree(project.id, approved=True)
            self.assertTrue(prepared["source_dirty"])
            self.assertEqual((main / "file.txt").read_text(encoding="utf-8"), "user dirty")
            self.assertEqual((Path(prepared["path"]) / "file.txt").read_text(encoding="utf-8"), "base")


if __name__ == "__main__":
    unittest.main()
