from __future__ import annotations

import json
import re
from typing import Any

from human_codex.database import MetadataDatabase
from human_codex.secret_guard import redact_text, redact_value
from human_codex.vault import AesGcmVault, VaultError


class BackgroundJobManager:
    """Persist and recover long-running Codex command activity without exposing shell execution."""

    CANDIDATE_COMMAND = re.compile(
        r"(?:pytest|unittest|npm\s+(?:run\s+)?test|node\s+--test|\b(?:build|compile|test)\b)",
        re.IGNORECASE,
    )
    def __init__(self, database: MetadataDatabase, vault: AesGcmVault) -> None:
        self.database = database
        self.vault = vault
        self.reconciled_on_startup = self.database.reconcile_background_jobs()

    def command_started(
        self, project_id: str, chat_id: str, turn_id: str, item_id: str, command: str,
    ) -> str | None:
        if not self.CANDIDATE_COMMAND.search(command):
            return None
        job_id = self.database.create_background_job(
            project_id, chat_id, turn_id, item_id, "command",
            self._encrypt(command[:8_000], f"job:{item_id}:command"),
        )
        self.checkpoint(
            project_id, chat_id, turn_id, job_id, "background_started",
            {"item_id": item_id, "kind": "command"},
        )
        return job_id

    def command_output(
        self, project_id: str, chat_id: str, turn_id: str, item_id: str, output: str,
    ) -> None:
        job_id = self.database.background_job_id(item_id)
        if job_id is None:
            return
        changed = self.database.update_background_job(
            item_id, output_ciphertext=self._encrypt(output[-131_072:], f"job:{item_id}:output")
        )
        if not changed:
            return
        self.checkpoint(
            project_id, chat_id, turn_id, job_id, "background_output",
            {"item_id": item_id, "output_chars": len(output)},
        )

    def command_completed(
        self, project_id: str, chat_id: str, turn_id: str, item_id: str,
        status: str, output: str,
    ) -> None:
        job_id = self.database.background_job_id(item_id)
        if job_id is None:
            return
        completed = status == "completed"
        changed = self.database.update_background_job(
            item_id,
            status="completed" if completed else "failed",
            output_ciphertext=self._encrypt(output[-131_072:], f"job:{item_id}:output"),
            completed=True,
            followup_state="pending" if completed else "not_needed",
        )
        if not changed:
            return
        self.checkpoint(
            project_id, chat_id, turn_id, job_id, "background_completed",
            {"item_id": item_id, "status": "completed" if completed else "failed"},
        )

    def checkpoint(
        self, project_id: str, chat_id: str | None, turn_id: str | None,
        job_id: str | None, event_type: str, state: dict[str, Any],
    ) -> None:
        bounded = self._bounded(state)
        self.database.create_checkpoint(
            project_id, chat_id, turn_id, job_id, event_type,
            self._encrypt(bounded, f"checkpoint:{project_id}:{event_type}:{job_id or 'event'}"),
        )

    def list(self, project_id: str) -> list[dict[str, Any]]:
        result = []
        for row in self.database.list_background_jobs(project_id):
            item_id = str(row["provider_item_id"])
            command = self._decrypt_optional(row.get("command_ciphertext"), f"job:{item_id}:command")
            output = self._decrypt_optional(row.get("output_ciphertext"), f"job:{item_id}:output")
            result.append(
                {
                    "id": row["id"],
                    "chat_id": row["chat_id"],
                    "turn_id": row["turn_id"],
                    "item_id": item_id,
                    "kind": row["kind"],
                    "status": row["status"],
                    "command": self._redact(str(command or ""))[:500] or None,
                    "output_chars": len(str(output or "")),
                    "followup_state": row["followup_state"],
                    "notification_pending": row["notification_state"] == "pending",
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                }
            )
        return result

    def claim_followups(
        self, chat_id: str, turn_id: str | None = None
    ) -> list[dict[str, Any]]:
        return self.database.claim_followups(chat_id, turn_id)

    def bind_followup_turn(self, job_id: str, turn_id: str) -> None:
        self.database.bind_followup_turn(job_id, turn_id)

    def fail_followup_start(self, job_id: str) -> None:
        self.database.fail_followup_start(job_id)

    def finish_followups_for_turn(self, turn_id: str, status: str) -> None:
        self.database.finish_followups_for_turn(turn_id, status)

    def acknowledge_notification(self, job_id: str) -> None:
        self.database.acknowledge_job_notification(job_id)

    def _encrypt(self, value: Any, context: str) -> str:
        value = redact_value(value)
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return json.dumps(self.vault.encrypt(payload, context=context).as_dict(), separators=(",", ":"))

    def _decrypt_optional(self, ciphertext: object, context: str) -> Any | None:
        if not isinstance(ciphertext, str) or not ciphertext:
            return None
        try:
            return json.loads(self.vault.decrypt(json.loads(ciphertext), context=context))
        except (TypeError, ValueError, json.JSONDecodeError, VaultError):
            return None

    def _redact(self, value: str) -> str:
        return redact_text(value)

    def _bounded(self, value: Any, depth: int = 0) -> Any:
        if depth >= 6:
            return "[depth limit]"
        if isinstance(value, str):
            return self._redact(value)[:2_000]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, list):
            return [self._bounded(item, depth + 1) for item in value[:40]]
        if isinstance(value, dict):
            return {str(key)[:100]: self._bounded(item, depth + 1) for key, item in list(value.items())[:40]}
        return str(value)[:2_000]
