from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import Any, TextIO

from human_codex.core_ipc import (
    ID_PATTERN,
    MAX_FRAME_BYTES,
    MAX_METHOD_CHARS,
    Envelope,
    IpcValidationError,
    decode,
    encode,
    response_for,
)
from human_codex.database import DatabaseError, MetadataDatabase
from human_codex.paths import PortablePaths
from human_codex.sessions import (
    CodexSessionManager,
    SecretPreflightError,
    SecureSandboxError,
    SessionError,
)
from human_codex.secret_guard import redact_text
from human_codex.skills import SkillError, SkillManager
from human_codex.approvals import ApprovalError
from human_codex.vault import VaultError
from human_codex.workspace import WorkspaceError


class CoreService:
    """Allowlisted Main-process-facing Core command surface."""

    ALLOWED_METHODS = frozenset(
        {
            "system.health",
            "system.shutdown",
            "system.sandbox.status",
            "system.sandbox.setup",
            "system.sandbox.diagnose-unelevated",
            "system.sandbox.corporate-test.status",
            "system.sandbox.corporate-test.start",
            "system.sandbox.corporate.activate",
            "project.list",
            "project.create",
            "project.open",
            "project.roots",
            "project.root.add",
            "project.permission",
            "chat.list",
            "chat.create",
            "chat.open",
            "chat.timeline",
            "chat.send",
            "chat.interrupt",
            "chat.delete",
            "skill.list",
            "skill.catalog",
            "skill.install",
            "approval.list",
            "approval.decide",
            "workspace.status",
            "workspace.git.init",
            "workspace.worktree.prepare",
            "snapshot.list",
            "snapshot.create",
            "job.list",
            "job.acknowledge",
            "recovery.resume",
        }
    )

    def __init__(
        self,
        database: MetadataDatabase,
        paths: PortablePaths,
        sessions: CodexSessionManager | None = None,
    ) -> None:
        self.database = database
        self.database.migrate()
        self.skills = SkillManager(paths)
        # Company build: chat starts without Windows native sandbox probes.
        # The UI states that this is current-user execution, not OS isolation.
        self.sessions = sessions or CodexSessionManager(
            database, paths, direct_mode=True
        )

    def close(self) -> None:
        self.sessions.close()

    def handle(self, message: Envelope) -> tuple[dict[str, Any], bool]:
        if message.kind != "request":
            raise IpcValidationError("Core accepts request envelopes only")
        if message.method not in self.ALLOWED_METHODS:
            raise IpcValidationError("method is not allowed")
        params = message.params
        if message.method == "system.health":
            self._require_exact_keys(params, set())
            return {"status": "pass", "service": "human-codex-core", "protocol": "hc-ipc/1"}, False
        if message.method == "system.shutdown":
            self._require_exact_keys(params, set())
            self.close()
            return {"status": "stopping"}, True
        if message.method == "system.sandbox.status":
            self._require_exact_keys(params, set())
            return self.sessions.sandbox_status(), False
        if message.method == "system.sandbox.setup":
            self._require_exact_keys(params, {"approved"})
            if params.get("approved") is not True:
                raise IpcValidationError("Windows sandbox setup requires explicit approval")
            return self.sessions.setup_sandbox(approved=True), False
        if message.method == "system.sandbox.diagnose-unelevated":
            self._require_exact_keys(params, {"approved"})
            if params.get("approved") is not True:
                raise IpcValidationError(
                    "Unelevated sandbox diagnostic requires explicit approval"
                )
            return self.sessions.diagnose_unelevated_sandbox(approved=True), False
        if message.method == "system.sandbox.corporate-test.status":
            self._require_exact_keys(params, set())
            return self.sessions.corporate_sandbox_test_status(), False
        if message.method == "system.sandbox.corporate-test.start":
            if set(params) - {"approved", "project_id"}:
                raise IpcValidationError(
                    "Corporate sandbox test payload is invalid"
                )
            if params.get("approved") is not True:
                raise IpcValidationError(
                    "Corporate sandbox test requires explicit approval"
                )
            project_id = params.get("project_id")
            if project_id is not None and not isinstance(project_id, str):
                raise IpcValidationError("project_id must be a string")
            return self.sessions.start_corporate_sandbox_test(
                approved=True, project_id=project_id
            ), False
        if message.method == "system.sandbox.corporate.activate":
            self._require_exact_keys(params, {"approved"})
            if params.get("approved") is not True:
                raise IpcValidationError(
                    "Corporate sandbox activation requires explicit approval"
                )
            return self.sessions.activate_corporate_sandbox(approved=True), False
        if message.method == "project.list":
            self._require_exact_keys(params, set())
            return {"projects": [asdict(project) for project in self.database.list_projects()]}, False
        if message.method == "project.create":
            if set(params) - {"name", "main_root"} or "name" not in params:
                raise IpcValidationError("project.create payload is invalid")
            main_root = params.get("main_root")
            if main_root is not None and not isinstance(main_root, str):
                raise IpcValidationError("main_root must be a string")
            if main_root is not None:
                main_root = self.sessions.workspace.validate_main_root(main_root)
            project = self.database.create_project(self._string(params, "name"))
            roots = self.sessions.workspace.ensure_project_roots(project.id, main_root)
            return {"project": asdict(project), "roots": [asdict(root) for root in roots]}, False
        if message.method == "project.open":
            self._require_exact_keys(params, {"id"})
            return {"project": asdict(self.database.open_project(self._string(params, "id")))}, False
        if message.method == "project.roots":
            self._require_exact_keys(params, {"project_id"})
            project_id = self._string(params, "project_id")
            roots = self.sessions.workspace.ensure_project_roots(project_id)
            return {"roots": [asdict(root) for root in roots]}, False
        if message.method == "project.root.add":
            self._require_exact_keys(params, {"project_id", "kind", "path"})
            root = self.sessions.workspace.add_root(
                self._string(params, "project_id"),
                self._string(params, "kind"),
                self._string(params, "path"),
            )
            return {"root": asdict(root)}, False
        if message.method == "project.permission":
            self._require_exact_keys(params, {"project_id"})
            return {"profile": self.sessions.workspace.permission_profile(self._string(params, "project_id"))}, False
        if message.method == "chat.list":
            self._require_exact_keys(params, {"project_id"})
            return {"chats": [asdict(chat) for chat in self.database.list_chats(self._string(params, "project_id"))]}, False
        if message.method == "chat.create":
            if set(params) - {"project_id", "title"} or "project_id" not in params:
                raise IpcValidationError("chat.create payload is invalid")
            title = params.get("title")
            if title is not None and not isinstance(title, str):
                raise IpcValidationError("title must be a string")
            return {"chat": asdict(self.database.create_chat(self._string(params, "project_id"), title))}, False
        if message.method == "chat.open":
            self._require_exact_keys(params, {"chat_id"})
            return self.sessions.open_chat(self._string(params, "chat_id")), False
        if message.method == "chat.timeline":
            self._require_exact_keys(params, {"chat_id"})
            return self.sessions.timeline(self._string(params, "chat_id")), False
        if message.method == "chat.send":
            self._require_exact_keys(params, {"chat_id", "text"})
            return self.sessions.start_turn(
                self._string(params, "chat_id"), self._string(params, "text")
            ), False
        if message.method == "chat.interrupt":
            self._require_exact_keys(params, {"chat_id"})
            return self.sessions.interrupt_turn(self._string(params, "chat_id")), False
        if message.method == "chat.delete":
            self._require_exact_keys(params, {"chat_id"})
            return self.sessions.delete_chat(self._string(params, "chat_id")), False
        if message.method == "skill.list":
            self._require_exact_keys(params, set())
            return {
                "skills": self.skills.list_installed(),
                "install_root": str(self.skills.paths.skills_root),
            }, False
        if message.method == "skill.catalog":
            self._require_exact_keys(params, {"query"})
            return {"skills": self.skills.catalog(self._string(params, "query"))}, False
        if message.method == "skill.install":
            self._require_exact_keys(params, {"source", "approved"})
            if params.get("approved") is not True:
                raise IpcValidationError("skill installation requires explicit approval")
            return {
                "skill": self.skills.install(
                    self._string(params, "source"), approved=True
                )
            }, False
        if message.method == "approval.list":
            if set(params) - {"project_id"}:
                raise IpcValidationError("approval.list payload is invalid")
            project_id = params.get("project_id")
            if project_id is not None and not isinstance(project_id, str):
                raise IpcValidationError("project_id must be a string")
            return {"approvals": self.sessions.approvals.list_pending(project_id)}, False
        if message.method == "approval.decide":
            self._require_exact_keys(params, {"id", "decision", "scope"})
            return {"approval": self.sessions.approvals.decide(
                self._string(params, "id"), self._string(params, "decision"),
                self._string(params, "scope"),
            )}, False
        if message.method == "workspace.status":
            self._require_exact_keys(params, {"project_id"})
            project_id = self._string(params, "project_id")
            from human_codex.workspace import GitWorkspaceManager
            manager = GitWorkspaceManager(
                self.database, self.sessions.paths, self.sessions.vault, self.sessions.workspace
            )
            return {"git": manager.inspect(project_id)}, False
        if message.method in {"workspace.git.init", "workspace.worktree.prepare"}:
            self._require_exact_keys(params, {"project_id", "approved"})
            project_id = self._string(params, "project_id")
            if params.get("approved") is not True:
                raise IpcValidationError("workspace mutation requires explicit approval")
            from human_codex.workspace import GitWorkspaceManager
            manager = GitWorkspaceManager(
                self.database, self.sessions.paths, self.sessions.vault, self.sessions.workspace
            )
            roots = self.sessions.workspace.ensure_project_roots(project_id)
            main_root = next(root.path for root in roots if root.kind == "main")
            action = "git_init" if message.method == "workspace.git.init" else "worktree_create"
            approval = self.sessions.approvals.record_manual_approval(
                project_id, action,
                "User explicitly confirmed a local Git workspace operation",
                {
                    "targets": [main_root],
                    "side_effect": "Creates local Git metadata/branch/worktree; no remote operation",
                },
            )
            if message.method == "workspace.git.init":
                return {"approval": approval, "git": manager.initialize(project_id, approved=True)}, False
            return {"approval": approval, "worktree": manager.prepare_worktree(project_id, approved=True)}, False
        if message.method == "snapshot.list":
            self._require_exact_keys(params, {"project_id"})
            return {"snapshots": self.sessions.snapshots.list(self._string(params, "project_id"))}, False
        if message.method == "snapshot.create":
            self._require_exact_keys(params, {"project_id", "reason"})
            return {"snapshot": self.sessions.snapshots.create(
                self._string(params, "project_id"), self._string(params, "reason")
            )}, False
        if message.method == "job.list":
            self._require_exact_keys(params, {"project_id"})
            return {"jobs": self.sessions.list_background_jobs(self._string(params, "project_id"))}, False
        if message.method == "job.acknowledge":
            self._require_exact_keys(params, {"id"})
            self.sessions.acknowledge_job_notification(self._string(params, "id"))
            return {"status": "acknowledged"}, False
        if message.method == "recovery.resume":
            self._require_exact_keys(params, {"chat_id"})
            return self.sessions.resume_recovery_chat(self._string(params, "chat_id")), False
        raise IpcValidationError("method is not implemented")

    @staticmethod
    def _require_exact_keys(params: dict[str, Any], required: set[str]) -> None:
        if set(params) != required:
            raise IpcValidationError("payload keys are invalid")

    @staticmethod
    def _string(params: dict[str, Any], key: str) -> str:
        value = params.get(key)
        if not isinstance(value, str):
            raise IpcValidationError(f"{key} must be a string")
        return value


def serve(input_stream: TextIO, output_stream: TextIO, paths: PortablePaths) -> int:
    """Serve NDJSON strictly on stdout; all diagnostics remain on stderr."""

    paths.ensure_data_layout()
    service = CoreService(MetadataDatabase.from_data_root(paths.data_root), paths)
    try:
        while raw_line := _read_bounded_line(input_stream):
            try:
                message = decode(raw_line.rstrip("\r\n"))
                result, should_stop = service.handle(message)
                response = response_for(message, params=result)
            except SecretPreflightError:
                request_stub = _request_stub(raw_line)
                response = response_for(
                    request_stub,
                    error={
                        "code": "secret_preflight_blocked",
                        "message": "Local secret preflight blocked provider access",
                    },
                )
                should_stop = False
                print("core request rejected: secret preflight blocked", file=sys.stderr)
            except SecureSandboxError:
                request_stub = _request_stub(raw_line)
                response = response_for(
                    request_stub,
                    error={
                        "code": "secure_sandbox_required",
                        "message": "Native project read isolation must be configured",
                    },
                )
                should_stop = False
                print("core request rejected: secure sandbox required", file=sys.stderr)
            except (
                IpcValidationError, DatabaseError, SessionError, ApprovalError,
                WorkspaceError, VaultError, SkillError, ValueError,
            ) as exc:
                request_stub = _request_stub(raw_line)
                response = response_for(
                    request_stub,
                    error={"code": "invalid_request", "message": redact_text(str(exc))},
                )
                should_stop = False
                print(f"core request rejected: {redact_text(str(exc))}", file=sys.stderr)
            try:
                rendered = encode(response)
            except (IpcValidationError, TypeError, ValueError):
                request_stub = _request_stub(raw_line)
                rendered = encode(
                    response_for(
                        request_stub,
                        error={
                            "code": "response_too_large",
                            "message": "Core response exceeded its safety limit",
                        },
                    )
                )
                should_stop = False
                print("core request rejected: response exceeded safety limit", file=sys.stderr)
            output_stream.write(rendered + "\n")
            output_stream.flush()
            if should_stop:
                return 0
        return 0
    finally:
        service.close()


def _read_bounded_line(input_stream: TextIO) -> str:
    """Read at most one IPC frame without allowing an unterminated line to grow unbounded."""
    raw_line = input_stream.readline(MAX_FRAME_BYTES + 1)
    if not raw_line:
        return ""
    if not raw_line.endswith(("\n", "\r")) and len(raw_line.encode("utf-8")) > MAX_FRAME_BYTES:
        _discard_oversized_remainder(input_stream)
    return raw_line


def _discard_oversized_remainder(input_stream: TextIO) -> None:
    """Consume the rest of one rejected oversized frame in bounded chunks."""
    while chunk := input_stream.readline(MAX_FRAME_BYTES + 1):
        if chunk.endswith(("\n", "\r")):
            return


def _request_stub(raw_line: str) -> Envelope:
    """Create a correlation-safe error response without trusting invalid input."""

    try:
        raw = json.loads(raw_line)
    except json.JSONDecodeError:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    message_id = raw.get("id") if isinstance(raw.get("id"), str) and ID_PATTERN.fullmatch(raw["id"]) else "msg_invalid"
    correlation = raw.get("correlation_id") if isinstance(raw.get("correlation_id"), str) and ID_PATTERN.fullmatch(raw["correlation_id"]) else message_id
    method = raw.get("method") if isinstance(raw.get("method"), str) and 1 <= len(raw["method"]) <= MAX_METHOD_CHARS else "invalid"
    from human_codex.core_ipc import PROTOCOL, utc_timestamp

    return Envelope(PROTOCOL, "request", message_id, correlation, method, {}, utc_timestamp())
