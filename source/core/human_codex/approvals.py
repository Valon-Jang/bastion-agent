from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from human_codex.database import MetadataDatabase, utc_now
from human_codex.risk import RiskAssessment, RiskEngine
from human_codex.secret_guard import redact_text, redact_value
from human_codex.vault import AesGcmVault, VaultError
from human_codex.workspace import SnapshotManager, WorkspaceError, WorkspacePolicy


class ApprovalError(RuntimeError):
    pass


@dataclass
class PendingDecision:
    approval_id: str
    allowed_scopes: tuple[str, ...]
    event: threading.Event
    decision: str | None = None
    scope: str = "once"


class ApprovalBroker:
    APPROVAL_METHODS = frozenset(
        {
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
            "item/permissions/requestApproval",
            "execCommandApproval",
            "applyPatchApproval",
        }
    )
    WAIT_SECONDS = 600.0
    MAX_PENDING_RESULTS = 20
    MAX_DISPLAY_COMMAND_CHARS = 2_000
    MAX_DISPLAY_TARGETS = 20
    MAX_DISPLAY_TARGET_CHARS = 500
    def __init__(
        self,
        database: MetadataDatabase,
        vault: AesGcmVault,
        workspace: WorkspacePolicy,
        risk: RiskEngine,
        snapshots: SnapshotManager,
    ) -> None:
        self.database = database
        self.vault = vault
        self.workspace = workspace
        self.risk = risk
        self.snapshots = snapshots
        self._lock = threading.RLock()
        self._pending: dict[str, PendingDecision] = {}
        self._task_grants: set[tuple[str, str]] = set()
        self._closing = threading.Event()

    def close(self) -> None:
        self._closing.set()
        with self._lock:
            pending = list(self._pending.values())
        for item in pending:
            item.decision = "deny"
            item.event.set()

    def handle_server_request(
        self,
        chat_id: str,
        method: str,
        request_id: str | int,
        params: dict[str, Any],
        *,
        item_targets: list[str] | None = None,
    ) -> dict[str, Any]:
        if method not in self.APPROVAL_METHODS:
            raise ApprovalError("unsupported App Server request")
        project_id = self.workspace.project_for_chat(chat_id)
        action, command, targets = self._proposal(method, params, item_targets or [])
        project = self.database.open_project(project_id)
        write_action = action not in {"read", "search", "metadata"}
        path_preconditions = [
            self.workspace.classify_path(project_id, target, write=write_action)
            for target in targets
        ]
        assessment = self.risk.assess(
            project_id,
            action=action,
            targets=targets,
            command=command,
            strict=project.risk_profile == "strict",
        )
        fingerprint = self._fingerprint(method, params, targets)
        turn_id = self._turn_id(params)
        if turn_id and (turn_id, fingerprint) in self._task_grants and assessment.level in {"R1", "R2"}:
            assessment = RiskAssessment(
                assessment.level, "auto", assessment.action,
                "Previously approved for this Turn", assessment.side_effect,
                assessment.requires_snapshot, assessment.allowed_scopes,
            )
        approval_id, action_id = self._record_request(
            chat_id, method, request_id, params, assessment, targets, command, fingerprint
        )
        snapshot_id = None
        if assessment.requires_snapshot:
            try:
                snapshot_id = self.snapshots.create(project_id, f"Before {assessment.action}")['id']
                with self.database.connection() as connection:
                    connection.execute("UPDATE actions SET rollback_ref = ? WHERE id = ?", (snapshot_id, action_id))
                    connection.commit()
            except WorkspaceError:
                assessment = RiskAssessment(
                    "R2", "approval", assessment.action,
                    "Automatic snapshot was unavailable; explicit approval is required",
                    assessment.side_effect, False, ("once",),
                )
        if assessment.decision == "block":
            self._finish(approval_id, action_id, "blocked", "policy", "once")
            return self._provider_response(method, False, "once", params)
        if assessment.decision in {"auto", "snapshot"}:
            self._finish(approval_id, action_id, "auto_approved", "risk_engine", "once")
            return self._provider_response(method, True, "once", params)

        pending = PendingDecision(approval_id, assessment.allowed_scopes, threading.Event())
        with self._lock:
            self._pending[approval_id] = pending
        if not pending.event.wait(self.WAIT_SECONDS) or self._closing.is_set():
            self._finish(approval_id, action_id, "timed_out", "system", "once")
            with self._lock:
                self._pending.pop(approval_id, None)
            return self._provider_response(method, False, "once", params, timed_out=True)
        approved = pending.decision == "approve"
        scope = pending.scope if approved else "once"
        precondition_failed = False
        if approved:
            current_classes = [
                self.workspace.classify_path(project_id, target, write=write_action)
                for target in targets
            ]
            if current_classes != path_preconditions:
                approved = False
                scope = "once"
                precondition_failed = True
        if approved and scope == "task" and turn_id:
            self._task_grants.add((turn_id, fingerprint))
        self._finish(
            approval_id, action_id, "approved" if approved else "denied",
            "policy_recheck" if precondition_failed else "user", scope,
        )
        with self._lock:
            self._pending.pop(approval_id, None)
        return self._provider_response(method, approved, scope, params)

    def list_pending(self, project_id: str | None = None) -> list[dict[str, Any]]:
        query = """SELECT approvals.id, approvals.provider_method, approvals.requested_scope,
                          approvals.reason_ciphertext, approvals.details_ciphertext,
                          approvals.requested_at, actions.risk_level, actions.type,
                          actions.chat_id, actions.rollback_ref
                   FROM approvals JOIN actions ON actions.id = approvals.action_id
                   WHERE approvals.decision = 'pending'"""
        values: tuple[Any, ...] = ()
        if project_id:
            query += " AND actions.project_id = ?"
            values = (project_id,)
        query += f" ORDER BY approvals.requested_at, approvals.id LIMIT {self.MAX_PENDING_RESULTS}"
        with self.database.connection() as connection:
            rows = connection.execute(query, values).fetchall()
        with self._lock:
            decidable_ids = {
                approval_id
                for approval_id, pending in self._pending.items()
                if pending.decision is None and not pending.event.is_set()
            }
        result = []
        for row in rows:
            approval_id = str(row["id"])
            if approval_id not in decidable_ids:
                continue
            reason = self._decrypt(str(row["reason_ciphertext"]), f"approval:{approval_id}:reason")
            details = self._decrypt(str(row["details_ciphertext"]), f"approval:{approval_id}:details")
            details["snapshot_id"] = row["rollback_ref"]
            result.append({
                "id": approval_id,
                "method": row["provider_method"],
                "risk_level": row["risk_level"],
                "action": row["type"],
                "chat_id": row["chat_id"],
                "reason": reason,
                "details": details,
                "requested_at": row["requested_at"],
            })
        return result

    def decide(self, approval_id: str, decision: str, scope: str) -> dict[str, Any]:
        if decision not in {"approve", "deny"}:
            raise ApprovalError("approval decision is invalid")
        if scope not in {"once", "task", "session"}:
            raise ApprovalError("approval scope is invalid")
        with self._lock:
            pending = self._pending.get(approval_id)
            if pending is None or pending.decision is not None or pending.event.is_set():
                raise ApprovalError("approval is no longer pending")
            if decision == "approve" and scope not in pending.allowed_scopes:
                raise ApprovalError("approval scope is not allowed for this risk level")
            pending.decision = decision
            pending.scope = scope
            pending.event.set()
        return {"id": approval_id, "decision": decision, "scope": scope}

    def record_manual_approval(
        self, project_id: str, action: str, reason: str, details: dict[str, Any]
    ) -> dict[str, str]:
        self.database.open_project(project_id)
        action_id = str(uuid.uuid4())
        approval_id = str(uuid.uuid4())
        now = utc_now()
        fingerprint = hashlib.sha256(
            json.dumps({"project": project_id, "action": action, "time": now}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        safe_details = {
            "action": action,
            "side_effect": str(details.get("side_effect", "Local workspace change"))[:500],
            "targets": [self._redact(str(value))[:1_000] for value in details.get("targets", [])[:20]],
            "allowed_scopes": ["once"],
            "snapshot_required": bool(details.get("snapshot_required", False)),
        }
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO actions(
                       id, project_id, chat_id, type, status, risk_level,
                       idempotency_key, started_at, completed_at
                   ) VALUES (?, ?, NULL, ?, 'approved', 'R3', ?, ?, ?)""",
                (action_id, project_id, action, fingerprint, now, now),
            )
            connection.execute(
                """INSERT INTO approvals(
                       id, action_id, request_key, provider_method, requested_scope,
                       decision, decided_by, reason_ciphertext, details_ciphertext,
                       requested_at, decided_at
                   ) VALUES (?, ?, ?, 'human-codex/manual', 'once', 'approved', 'user', ?, ?, ?, ?)""",
                (
                    approval_id, action_id, fingerprint,
                    self._encrypt(reason[:1_000], f"approval:{approval_id}:reason"),
                    self._encrypt(safe_details, f"approval:{approval_id}:details"), now, now,
                ),
            )
            connection.commit()
        return {"approval_id": approval_id, "action_id": action_id}

    def _record_request(
        self,
        chat_id: str,
        method: str,
        request_id: str | int,
        params: dict[str, Any],
        assessment: RiskAssessment,
        targets: list[str],
        command: str | None,
        fingerprint: str,
    ) -> tuple[str, str]:
        action_id = str(uuid.uuid4())
        approval_id = str(uuid.uuid4())
        request_key = hashlib.sha256(
            f"{method}:{request_id}:{params.get('threadId') or params.get('conversationId')}".encode("utf-8")
        ).hexdigest()
        safe_command = self._redact(command or "")[: self.MAX_DISPLAY_COMMAND_CHARS]
        details = {
            "action": assessment.action,
            "targets": [
                self._redact(target)[: self.MAX_DISPLAY_TARGET_CHARS]
                for target in targets[: self.MAX_DISPLAY_TARGETS]
            ],
            "command": safe_command or None,
            "side_effect": assessment.side_effect,
            "risk_level": assessment.level,
            "allowed_scopes": list(assessment.allowed_scopes),
            "snapshot_required": assessment.requires_snapshot,
        }
        now = utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO actions(
                       id, project_id, chat_id, provider_item_id, type, target_hmac, status,
                       risk_level, idempotency_key, started_at
                   ) VALUES (?, ?, ?, ?, ?, ?, 'approval_pending', ?, ?, ?)""",
                (
                    action_id, self.workspace.project_for_chat(chat_id), chat_id,
                    params.get("itemId") or params.get("callId"),
                    assessment.action,
                    self.vault.blind_index("\n".join(targets), context="approval-targets") if targets else None,
                    assessment.level, fingerprint + request_key, now,
                ),
            )
            connection.execute(
                """INSERT INTO approvals(
                       id, action_id, request_key, provider_method, requested_scope,
                       decision, reason_ciphertext, details_ciphertext, requested_at
                   ) VALUES (?, ?, ?, ?, 'once', 'pending', ?, ?, ?)""",
                (
                    approval_id, action_id, request_key, method,
                    self._encrypt(assessment.reason, f"approval:{approval_id}:reason"),
                    self._encrypt(details, f"approval:{approval_id}:details"), now,
                ),
            )
            connection.commit()
        return approval_id, action_id

    def _finish(self, approval_id: str, action_id: str, decision: str, decided_by: str, scope: str) -> None:
        now = utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE approvals SET requested_scope = ?, decision = ?, decided_by = ?, decided_at = ?
                   WHERE id = ? AND decision = 'pending'""",
                (scope, decision, decided_by, now, approval_id),
            )
            connection.execute(
                "UPDATE actions SET status = ?, completed_at = ? WHERE id = ?",
                (decision, now, action_id),
            )
            connection.commit()

    def _proposal(
        self, method: str, params: dict[str, Any], item_targets: list[str]
    ) -> tuple[str, str | None, list[str]]:
        if method == "item/commandExecution/requestApproval":
            command = params.get("command")
            if command is not None and not isinstance(command, str):
                raise ApprovalError("command approval payload is invalid")
            cwd = params.get("cwd")
            return "execute", command, [cwd] if isinstance(cwd, str) else []
        if method == "execCommandApproval":
            command_parts = params.get("command")
            if not isinstance(command_parts, list) or not all(isinstance(item, str) for item in command_parts):
                raise ApprovalError("legacy command approval payload is invalid")
            cwd = params.get("cwd")
            return "execute", " ".join(command_parts), [cwd] if isinstance(cwd, str) else []
        if method == "item/fileChange/requestApproval":
            grant_root = params.get("grantRoot")
            targets = list(item_targets)
            if isinstance(grant_root, str):
                targets.append(grant_root)
            return "edit", None, targets
        if method == "applyPatchApproval":
            changes = params.get("fileChanges")
            if not isinstance(changes, dict):
                raise ApprovalError("legacy patch approval payload is invalid")
            return "edit", None, [str(path) for path in changes.keys()]
        permissions = params.get("permissions")
        if not isinstance(permissions, dict):
            raise ApprovalError("permission approval payload is invalid")
        targets = self._permission_paths(permissions)
        return "permission_escalation", None, targets

    @staticmethod
    def _permission_paths(permissions: dict[str, Any]) -> list[str]:
        filesystem = permissions.get("fileSystem")
        if not isinstance(filesystem, dict):
            return []
        paths: list[str] = []
        for key in ("read", "write"):
            values = filesystem.get(key)
            if isinstance(values, list):
                paths.extend(str(value) for value in values if isinstance(value, str))
        entries = filesystem.get("entries")
        if isinstance(entries, list):
            for entry in entries:
                path = entry.get("path") if isinstance(entry, dict) else None
                if isinstance(path, dict) and path.get("type") == "path" and isinstance(path.get("path"), str):
                    paths.append(path["path"])
        return paths

    def _provider_response(
        self,
        method: str,
        approved: bool,
        scope: str,
        params: dict[str, Any],
        *,
        timed_out: bool = False,
    ) -> dict[str, Any]:
        if method in {"item/commandExecution/requestApproval", "item/fileChange/requestApproval"}:
            if timed_out:
                decision = "cancel"
            elif approved and scope == "session":
                decision = "acceptForSession"
            else:
                decision = "accept" if approved else "decline"
            return {"decision": decision}
        if method == "item/permissions/requestApproval":
            permissions = self._granted_permissions(params.get("permissions"), approved)
            return {"permissions": permissions, "scope": "session" if approved and scope == "session" else "turn"}
        if timed_out:
            decision: Any = "timed_out"
        elif approved and scope == "session":
            decision = "approved_for_session"
        elif approved:
            decision = "approved"
        else:
            decision = {"denied": {"rejection": "Denied by Human Codex policy or user"}}
        return {"decision": decision}

    def _granted_permissions(self, requested: Any, approved: bool) -> dict[str, Any]:
        # Provider requests never expand the live native profile. Canonical roots
        # are added only through Human Codex's separate validated UI workflow.
        return {
            "network": {"enabled": False},
            "fileSystem": {"read": [], "write": [], "entries": []},
        }

    @staticmethod
    def _turn_id(params: dict[str, Any]) -> str | None:
        value = params.get("turnId")
        return value if isinstance(value, str) else None

    @staticmethod
    def _fingerprint(method: str, params: dict[str, Any], targets: list[str]) -> str:
        proposal = {
            "command": params.get("command"),
            "grantRoot": params.get("grantRoot"),
            "permissions": params.get("permissions"),
            "fileChanges": sorted(params.get("fileChanges", {}))
            if isinstance(params.get("fileChanges"), dict)
            else None,
        }
        value = json.dumps(
            {
                "method": method,
                "item": params.get("itemId") or params.get("callId"),
                "targets": targets,
                "proposal": redact_value(proposal),
            },
            sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _redact(self, value: str) -> str:
        return redact_text(value)

    def _encrypt(self, value: Any, context: str) -> str:
        value = redact_value(value)
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return json.dumps(self.vault.encrypt(payload, context=context).as_dict(), separators=(",", ":"))

    def _decrypt(self, value: str, context: str) -> Any:
        try:
            return json.loads(self.vault.decrypt(json.loads(value), context=context))
        except Exception as exc:
            raise ApprovalError("stored approval failed authentication") from exc
