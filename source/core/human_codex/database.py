from __future__ import annotations

import shutil
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator


class DatabaseError(RuntimeError):
    """Raised when the metadata database cannot satisfy its contract."""


@dataclass(frozen=True)
class Project:
    id: str
    name: str
    status: str
    risk_profile: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class Chat:
    id: str
    project_id: str
    title: str
    provider: str
    status: str
    provider_thread_id: str | None
    last_turn_id: str | None
    created_at: str
    updated_at: str


MIGRATIONS: tuple[tuple[int, str, str], ...] = (
    (
        1,
        "metadata_base",
        """
        CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );
        """,
    ),
    (
        2,
        "projects_and_chats",
        """
        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE chats (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            title TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX chats_by_project_created ON chats(project_id, created_at);
        """,
    ),
    (
        3,
        "app_server_threads_and_turns",
        """
        ALTER TABLE chats ADD COLUMN provider_thread_id TEXT;
        ALTER TABLE chats ADD COLUMN last_turn_id TEXT;
        CREATE UNIQUE INDEX chats_by_provider_thread ON chats(provider_thread_id)
            WHERE provider_thread_id IS NOT NULL;
        CREATE TABLE turns (
            id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE RESTRICT,
            status TEXT NOT NULL,
            error_ciphertext TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX turns_by_chat_created ON turns(chat_id, created_at);
        CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE RESTRICT,
            turn_id TEXT REFERENCES turns(id) ON DELETE RESTRICT,
            role TEXT NOT NULL,
            content_ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX messages_by_chat_created ON messages(chat_id, created_at);
        CREATE TABLE items (
            id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE RESTRICT,
            turn_id TEXT NOT NULL REFERENCES turns(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX items_by_turn ON items(turn_id, created_at);
        CREATE TABLE provider_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE RESTRICT,
            turn_id TEXT,
            method TEXT NOT NULL,
            payload_ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX provider_events_by_chat_sequence ON provider_events(chat_id, sequence);
        """,
    ),
    (
        4,
        "workspace_policy_git_snapshot",
        """
        ALTER TABLE projects ADD COLUMN risk_profile TEXT NOT NULL DEFAULT 'balanced';
        CREATE TABLE project_roots (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL,
            path_ciphertext TEXT NOT NULL,
            path_hmac TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(project_id, kind, path_hmac)
        );
        CREATE INDEX project_roots_by_project_kind ON project_roots(project_id, kind);
        CREATE TABLE project_settings (
            project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE RESTRICT,
            permission_profile_ciphertext TEXT NOT NULL,
            risk_overrides_ciphertext TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE actions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            chat_id TEXT REFERENCES chats(id) ON DELETE RESTRICT,
            provider_item_id TEXT,
            type TEXT NOT NULL,
            target_hmac TEXT,
            status TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            rollback_ref TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE TABLE approvals (
            id TEXT PRIMARY KEY,
            action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
            request_key TEXT NOT NULL UNIQUE,
            provider_method TEXT NOT NULL,
            requested_scope TEXT NOT NULL,
            decision TEXT NOT NULL,
            decided_by TEXT,
            reason_ciphertext TEXT NOT NULL,
            details_ciphertext TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            decided_at TEXT
        );
        CREATE INDEX approvals_by_decision_requested ON approvals(decision, requested_at);
        CREATE TABLE snapshots (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            root_hmac TEXT NOT NULL,
            reason_ciphertext TEXT NOT NULL,
            status TEXT NOT NULL,
            manifest_ciphertext TEXT NOT NULL,
            file_count INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX snapshots_by_project_created ON snapshots(project_id, created_at);
        CREATE TABLE git_workspaces (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL,
            path_ciphertext TEXT NOT NULL,
            path_hmac TEXT NOT NULL,
            branch TEXT,
            baseline_commit TEXT,
            dirty INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX git_workspaces_by_project_created ON git_workspaces(project_id, created_at);
        """,
    ),
    (
        5,
        "background_jobs_and_checkpoints",
        """
        CREATE TABLE background_jobs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE RESTRICT,
            turn_id TEXT NOT NULL REFERENCES turns(id) ON DELETE RESTRICT,
            provider_item_id TEXT NOT NULL UNIQUE REFERENCES items(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            command_ciphertext TEXT,
            output_ciphertext TEXT,
            followup_state TEXT NOT NULL,
            followup_turn_id TEXT REFERENCES turns(id) ON DELETE RESTRICT,
            notification_state TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX background_jobs_by_project_updated ON background_jobs(project_id, updated_at);
        CREATE INDEX background_jobs_by_turn_followup ON background_jobs(chat_id, turn_id, followup_state);
        CREATE TABLE checkpoints (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            chat_id TEXT REFERENCES chats(id) ON DELETE RESTRICT,
            turn_id TEXT REFERENCES turns(id) ON DELETE RESTRICT,
            job_id TEXT REFERENCES background_jobs(id) ON DELETE RESTRICT,
            event_type TEXT NOT NULL,
            state_ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX checkpoints_by_project_created ON checkpoints(project_id, created_at);
        """,
    ),
    (
        6,
        "queued_chat_messages",
        """
        CREATE TABLE queued_messages (
            id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE RESTRICT,
            content_ciphertext TEXT NOT NULL,
            status TEXT NOT NULL,
            error_ciphertext TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX queued_messages_by_chat_created
            ON queued_messages(chat_id, status, created_at);
        """,
    ),
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class MetadataDatabase:
    """SQLite metadata store; user data never belongs in the source/runtime tree."""

    def __init__(self, database_path: Path, backup_root: Path) -> None:
        self.database_path = database_path
        self.backup_root = backup_root

    MAX_LIST_RESULTS = 100

    @classmethod
    def from_data_root(cls, data_root: Path) -> "MetadataDatabase":
        return cls(data_root / "data" / "human_codex.db", data_root / "backups")

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    def migrate(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            has_migration_table = bool(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
                ).fetchone()
            )
            current = (
                int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0])
                if has_migration_table
                else 0
            )
            pending = [migration for migration in MIGRATIONS if migration[0] > current]
            if not pending:
                return
            self._backup_before_migration()
            try:
                connection.execute("BEGIN IMMEDIATE")
                for version, name, script in pending:
                    for statement in script.split(";"):
                        if statement.strip():
                            connection.execute(statement)
                    connection.execute(
                        "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                        (version, name, utc_now()),
                    )
                connection.commit()
            except sqlite3.Error as exc:
                connection.rollback()
                raise DatabaseError("metadata migration failed; transaction was rolled back") from exc

    def _backup_before_migration(self) -> None:
        if not self.database_path.exists() or self.database_path.stat().st_size == 0:
            return
        self.backup_root.mkdir(parents=True, exist_ok=True)
        suffix = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(self.database_path, self.backup_root / f"human_codex-pre-migration-{suffix}.db")

    def create_project(self, name: str) -> Project:
        normalized = name.strip()
        if not 1 <= len(normalized) <= 120:
            raise DatabaseError("project name must contain 1-120 characters")
        self.migrate()
        project = Project(str(uuid.uuid4()), normalized, "active", "balanced", utc_now(), utc_now())
        try:
            with self.connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO projects(id, name, status, risk_profile, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        project.id, project.name, project.status, project.risk_profile,
                        project.created_at, project.updated_at,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise DatabaseError("project name already exists") from exc
        return project

    def list_projects(self) -> list[Project]:
        self.migrate()
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT id, name, status, risk_profile, created_at, updated_at
                   FROM projects ORDER BY created_at, id LIMIT ?""",
                (self.MAX_LIST_RESULTS,),
            ).fetchall()
        return [Project(**dict(row)) for row in rows]

    def open_project(self, project_id: str) -> Project:
        self.migrate()
        with self.connection() as connection:
            row = connection.execute(
                """SELECT id, name, status, risk_profile, created_at, updated_at
                   FROM projects WHERE id = ?""", (project_id,)
            ).fetchone()
        if row is None:
            raise DatabaseError("project not found")
        return Project(**dict(row))

    def create_chat(self, project_id: str, title: str | None = None) -> Chat:
        self.open_project(project_id)
        normalized = (title or "새 채팅").strip()
        if not 1 <= len(normalized) <= 160:
            raise DatabaseError("chat title must contain 1-160 characters")
        now = utc_now()
        chat = Chat(
            str(uuid.uuid4()), project_id, normalized, "codex_app_server", "ready",
            None, None, now, now,
        )
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO chats(
                       id, project_id, title, provider, status, provider_thread_id,
                       last_turn_id, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    chat.id, chat.project_id, chat.title, chat.provider, chat.status,
                    chat.provider_thread_id, chat.last_turn_id, chat.created_at, chat.updated_at,
                ),
            )
            connection.commit()
        return chat

    def list_chats(self, project_id: str) -> list[Chat]:
        self.open_project(project_id)
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT id, project_id, title, provider, status, provider_thread_id,
                          last_turn_id, created_at, updated_at
                   FROM chats WHERE project_id = ? ORDER BY created_at, id LIMIT ?""",
                (project_id, self.MAX_LIST_RESULTS),
            ).fetchall()
        return [Chat(**dict(row)) for row in rows]

    def open_chat(self, chat_id: str) -> Chat:
        self.migrate()
        with self.connection() as connection:
            row = connection.execute(
                """SELECT id, project_id, title, provider, status, provider_thread_id,
                          last_turn_id, created_at, updated_at
                   FROM chats WHERE id = ?""",
                (chat_id,),
            ).fetchone()
        if row is None:
            raise DatabaseError("chat not found")
        return Chat(**dict(row))

    def delete_chat(self, chat_id: str) -> None:
        """Delete one local chat and its dependent metadata atomically."""

        chat = self.open_chat(chat_id)
        if chat.status == "running":
            raise DatabaseError("running chat cannot be deleted")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT 1 FROM turns WHERE chat_id = ? AND status = 'inProgress' LIMIT 1",
                (chat_id,),
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise DatabaseError("running chat cannot be deleted")
            connection.execute("DELETE FROM checkpoints WHERE chat_id = ?", (chat_id,))
            connection.execute(
                "DELETE FROM approvals WHERE action_id IN (SELECT id FROM actions WHERE chat_id = ?)",
                (chat_id,),
            )
            connection.execute("DELETE FROM actions WHERE chat_id = ?", (chat_id,))
            connection.execute("DELETE FROM background_jobs WHERE chat_id = ?", (chat_id,))
            connection.execute("DELETE FROM provider_events WHERE chat_id = ?", (chat_id,))
            connection.execute("DELETE FROM items WHERE chat_id = ?", (chat_id,))
            connection.execute("DELETE FROM messages WHERE chat_id = ?", (chat_id,))
            connection.execute("DELETE FROM queued_messages WHERE chat_id = ?", (chat_id,))
            connection.execute("DELETE FROM turns WHERE chat_id = ?", (chat_id,))
            deleted = connection.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
            if deleted.rowcount != 1:
                connection.rollback()
                raise DatabaseError("chat not found")
            connection.commit()

    def enqueue_message(self, chat_id: str, content_ciphertext: str) -> dict[str, str]:
        self.open_chat(chat_id)
        now = utc_now()
        queued_id = str(uuid.uuid4())
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(connection.execute(
                "SELECT COUNT(*) FROM queued_messages WHERE chat_id = ? AND status IN ('pending', 'starting')",
                (chat_id,),
            ).fetchone()[0])
            if count >= 50:
                connection.rollback()
                raise DatabaseError("chat message queue is full")
            connection.execute(
                """INSERT INTO queued_messages(
                       id, chat_id, content_ciphertext, status, error_ciphertext,
                       created_at, updated_at
                   ) VALUES (?, ?, ?, 'pending', NULL, ?, ?)""",
                (queued_id, chat_id, content_ciphertext, now, now),
            )
            connection.commit()
        return {"id": queued_id, "status": "pending", "created_at": now}

    def claim_next_queued_message(self, chat_id: str) -> dict[str, object] | None:
        """Claim one FIFO message only while the chat has no active Turn."""

        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            chat = connection.execute(
                "SELECT status FROM chats WHERE id = ?", (chat_id,)
            ).fetchone()
            if chat is None:
                connection.rollback()
                return None
            active = connection.execute(
                "SELECT 1 FROM turns WHERE chat_id = ? AND status = 'inProgress' LIMIT 1",
                (chat_id,),
            ).fetchone()
            if str(chat["status"]) == "running" or active is not None:
                connection.rollback()
                return None
            row = connection.execute(
                """SELECT id, chat_id, content_ciphertext, status, created_at, updated_at
                   FROM queued_messages
                   WHERE chat_id = ? AND status = 'pending'
                   ORDER BY created_at, id LIMIT 1""",
                (chat_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                return None
            updated = connection.execute(
                """UPDATE queued_messages SET status = 'starting', updated_at = ?
                   WHERE id = ? AND status = 'pending'""",
                (utc_now(), row["id"]),
            )
            if updated.rowcount != 1:
                connection.rollback()
                return None
            connection.commit()
        result = dict(row)
        result["status"] = "starting"
        return result

    def complete_queued_message(self, queued_id: str) -> None:
        with self.connection() as connection:
            connection.execute("DELETE FROM queued_messages WHERE id = ?", (queued_id,))
            connection.commit()

    def fail_queued_message(self, queued_id: str, error_ciphertext: str) -> None:
        with self.connection() as connection:
            connection.execute(
                """UPDATE queued_messages SET status = 'failed', error_ciphertext = ?,
                       updated_at = ? WHERE id = ? AND status = 'starting'""",
                (error_ciphertext, utc_now(), queued_id),
            )
            connection.commit()

    def queued_message_rows(self, chat_id: str) -> list[dict[str, object]]:
        self.open_chat(chat_id)
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT id, content_ciphertext, status, error_ciphertext, created_at, updated_at
                   FROM queued_messages WHERE chat_id = ?
                   ORDER BY created_at, id LIMIT ?""",
                (chat_id, self.MAX_LIST_RESULTS),
            ).fetchall()
        return [dict(row) for row in rows]

    def bind_provider_thread(self, chat_id: str, provider_thread_id: str) -> Chat:
        if not provider_thread_id or len(provider_thread_id) > 160:
            raise DatabaseError("provider thread id is invalid")
        self.open_chat(chat_id)
        now = utc_now()
        try:
            with self.connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """UPDATE chats SET provider_thread_id = ?, status = 'ready', updated_at = ?
                       WHERE id = ?""",
                    (provider_thread_id, now, chat_id),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise DatabaseError("provider thread is already bound to another chat") from exc
        return self.open_chat(chat_id)

    def upsert_turn(self, chat_id: str, turn_id: str, status: str, error_ciphertext: str | None = None) -> None:
        self.open_chat(chat_id)
        now = utc_now()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO turns(id, chat_id, status, error_ciphertext, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET status = CASE
                       WHEN turns.status IN ('completed', 'interrupted', 'failed')
                            AND excluded.status = 'inProgress' THEN turns.status
                       ELSE excluded.status END,
                       error_ciphertext = excluded.error_ciphertext, updated_at = excluded.updated_at""",
                (turn_id, chat_id, status, error_ciphertext, now, now),
            )
            effective_status = connection.execute(
                "SELECT status FROM turns WHERE id = ?", (turn_id,)
            ).fetchone()[0]
            connection.execute(
                "UPDATE chats SET last_turn_id = ?, status = ?, updated_at = ? WHERE id = ?",
                (turn_id, "running" if effective_status == "inProgress" else "ready", now, chat_id),
            )
            connection.commit()

    def save_message(
        self, message_id: str, chat_id: str, turn_id: str | None, role: str,
        content_ciphertext: str, *, created_at: str | None = None,
    ) -> bool:
        if role not in {"user", "assistant"}:
            raise DatabaseError("message role is invalid")
        with self.connection() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO messages(
                       id, chat_id, turn_id, role, content_ciphertext, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?)""",
                (message_id, chat_id, turn_id, role, content_ciphertext, created_at or utc_now()),
            )
            connection.commit()

    def upsert_item(
        self, item_id: str, chat_id: str, turn_id: str, kind: str, status: str,
        payload_ciphertext: str,
    ) -> None:
        now = utc_now()
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO items(
                       id, chat_id, turn_id, kind, status, payload_ciphertext, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, status = excluded.status,
                       payload_ciphertext = excluded.payload_ciphertext, updated_at = excluded.updated_at""",
                (item_id, chat_id, turn_id, kind, status, payload_ciphertext, now, now),
            )
            connection.commit()

    def save_provider_event(
        self, chat_id: str, turn_id: str | None, method: str, payload_ciphertext: str,
    ) -> None:
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO provider_events(chat_id, turn_id, method, payload_ciphertext, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (chat_id, turn_id, method, payload_ciphertext, utc_now()),
            )
            connection.commit()

    def create_background_job(
        self, project_id: str, chat_id: str, turn_id: str, provider_item_id: str,
        kind: str, command_ciphertext: str | None,
    ) -> str:
        if kind not in {"command", "file_change"}:
            raise DatabaseError("background job kind is invalid")
        job_id = str(uuid.uuid4())
        now = utc_now()
        with self.connection() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO background_jobs(
                       id, project_id, chat_id, turn_id, provider_item_id, kind, status,
                       command_ciphertext, output_ciphertext, followup_state, followup_turn_id,
                       notification_state, started_at, completed_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, NULL, 'not_needed', NULL, 'none', ?, NULL, ?)""",
                (
                    job_id, project_id, chat_id, turn_id, provider_item_id, kind,
                    command_ciphertext, now, now,
                ),
            )
            row = connection.execute(
                "SELECT id FROM background_jobs WHERE provider_item_id = ?", (provider_item_id,)
            ).fetchone()
            connection.commit()
        assert row is not None
        return str(row["id"])

    def update_background_job(
        self, provider_item_id: str, *, status: str | None = None,
        output_ciphertext: str | None = None, completed: bool = False,
        followup_state: str | None = None,
    ) -> None:
        if status is not None and status not in {"running", "completed", "failed", "interrupted"}:
            raise DatabaseError("background job status is invalid")
        if followup_state is not None and followup_state not in {
            "not_needed", "pending", "starting", "completed", "failed",
        }:
            raise DatabaseError("background job followup state is invalid")
        updates = ["updated_at = ?"]
        values: list[object] = [utc_now()]
        if status is not None:
            updates.append("status = ?")
            values.append(status)
            if status == "completed":
                updates.append("notification_state = 'pending'")
        if output_ciphertext is not None:
            updates.append("output_ciphertext = ?")
            values.append(output_ciphertext)
        if followup_state is not None:
            updates.append("followup_state = ?")
            values.append(followup_state)
        if completed:
            updates.append("completed_at = ?")
            values.append(utc_now())
        values.append(provider_item_id)
        with self.connection() as connection:
            cursor = connection.execute(
                f"UPDATE background_jobs SET {', '.join(updates)} WHERE provider_item_id = ?", values
            )
            connection.commit()
        return cursor.rowcount == 1

    def background_job_id(self, provider_item_id: str) -> str | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT id FROM background_jobs WHERE provider_item_id = ?", (provider_item_id,)
            ).fetchone()
        return str(row["id"]) if row is not None else None

    def create_checkpoint(
        self, project_id: str, chat_id: str | None, turn_id: str | None,
        job_id: str | None, event_type: str, state_ciphertext: str,
    ) -> str:
        if not 1 <= len(event_type) <= 80:
            raise DatabaseError("checkpoint event type is invalid")
        checkpoint_id = str(uuid.uuid4())
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO checkpoints(id, project_id, chat_id, turn_id, job_id, event_type,
                                             state_ciphertext, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (checkpoint_id, project_id, chat_id, turn_id, job_id, event_type,
                 state_ciphertext, utc_now()),
            )
            connection.commit()
        return checkpoint_id

    def list_background_jobs(self, project_id: str) -> list[dict[str, object]]:
        self.open_project(project_id)
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT id, chat_id, turn_id, provider_item_id, kind, status,
                          command_ciphertext, output_ciphertext, followup_state, followup_turn_id,
                          notification_state, started_at, completed_at, updated_at
                   FROM background_jobs WHERE project_id = ?
                   ORDER BY updated_at DESC, id DESC LIMIT ?""",
                (project_id, self.MAX_LIST_RESULTS),
            ).fetchall()
        return [dict(row) for row in rows]

    def claim_followups(
        self, chat_id: str, completed_turn_id: str | None = None
    ) -> list[dict[str, object]]:
        now = utc_now()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if completed_turn_id is None:
                rows = connection.execute(
                    """SELECT id, project_id, provider_item_id FROM background_jobs
                       WHERE chat_id = ? AND status = 'completed'
                         AND followup_state = 'pending'""",
                    (chat_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT id, project_id, provider_item_id FROM background_jobs
                       WHERE chat_id = ? AND turn_id = ? AND status = 'completed'
                         AND followup_state = 'pending'""",
                    (chat_id, completed_turn_id),
                ).fetchall()
            for row in rows:
                connection.execute(
                    """UPDATE background_jobs SET followup_state = 'starting', updated_at = ?
                       WHERE id = ? AND followup_state = 'pending'""",
                    (now, row["id"]),
                )
            connection.commit()
        return [dict(row) for row in rows]

    def bind_followup_turn(self, job_id: str, followup_turn_id: str) -> None:
        with self.connection() as connection:
            turn = connection.execute(
                "SELECT status FROM turns WHERE id = ?", (followup_turn_id,)
            ).fetchone()
            status = str(turn["status"]) if turn is not None else "inProgress"
            followup_state = "completed" if status == "completed" else (
                "failed" if status in {"failed", "interrupted"} else "starting"
            )
            connection.execute(
                """UPDATE background_jobs SET followup_turn_id = ?, followup_state = ?,
                       updated_at = ? WHERE id = ?""",
                (followup_turn_id, followup_state, utc_now(), job_id),
            )
            connection.commit()

    def fail_followup_start(self, job_id: str) -> None:
        with self.connection() as connection:
            connection.execute(
                """UPDATE background_jobs SET followup_state = 'failed', updated_at = ?
                   WHERE id = ? AND followup_state = 'starting'""",
                (utc_now(), job_id),
            )
            connection.commit()

    def finish_followups_for_turn(self, turn_id: str, status: str) -> None:
        if status not in {"completed", "failed", "interrupted"}:
            return
        state = "completed" if status == "completed" else "failed"
        with self.connection() as connection:
            connection.execute(
                """UPDATE background_jobs SET followup_state = ?, updated_at = ?
                   WHERE followup_turn_id = ? AND followup_state = 'starting'""",
                (state, utc_now(), turn_id),
            )
            connection.commit()

    def reconcile_background_jobs(self) -> int:
        with self.connection() as connection:
            cursor = connection.execute(
                """UPDATE background_jobs SET status = 'interrupted', followup_state = 'not_needed',
                       notification_state = 'none', completed_at = ?, updated_at = ?
                   WHERE status = 'running'""",
                (utc_now(), utc_now()),
            )
            connection.commit()
        return int(cursor.rowcount)

    def acknowledge_job_notification(self, job_id: str) -> None:
        with self.connection() as connection:
            connection.execute(
                """UPDATE background_jobs SET notification_state = 'notified', updated_at = ?
                   WHERE id = ? AND notification_state = 'pending'""",
                (utc_now(), job_id),
            )
            connection.commit()

    def timeline_rows(self, chat_id: str) -> dict[str, list[dict[str, object]]]:
        self.open_chat(chat_id)
        with self.connection() as connection:
            messages = [dict(row) for row in connection.execute(
                """SELECT id, turn_id, role, content_ciphertext, created_at
                   FROM messages WHERE chat_id = ? ORDER BY created_at DESC, id DESC LIMIT ?""",
                (chat_id, self.MAX_LIST_RESULTS),
            ).fetchall()]
            items = [dict(row) for row in connection.execute(
                """SELECT id, turn_id, kind, status, payload_ciphertext, created_at, updated_at
                   FROM items WHERE chat_id = ? ORDER BY created_at DESC, id DESC LIMIT ?""",
                (chat_id, self.MAX_LIST_RESULTS),
            ).fetchall()]
            turns = [dict(row) for row in connection.execute(
                """SELECT id, status, error_ciphertext, created_at, updated_at
                   FROM turns WHERE chat_id = ? ORDER BY created_at DESC, id DESC LIMIT ?""",
                (chat_id, self.MAX_LIST_RESULTS),
            ).fetchall()]
            queued_messages = [dict(row) for row in connection.execute(
                """SELECT id, content_ciphertext, status, error_ciphertext, created_at, updated_at
                   FROM queued_messages WHERE chat_id = ?
                   ORDER BY created_at, id LIMIT ?""",
                (chat_id, self.MAX_LIST_RESULTS),
            ).fetchall()]
        return {
            "messages": list(reversed(messages)),
            "items": list(reversed(items)),
            "turns": list(reversed(turns)),
            "queued_messages": queued_messages,
        }
