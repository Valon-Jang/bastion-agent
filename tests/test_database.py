import tempfile
import unittest
from pathlib import Path

import human_codex.database as database_module
from human_codex.database import DatabaseError, MetadataDatabase


class MetadataDatabaseTests(unittest.TestCase):
    def test_migrations_are_sequential_and_persist_projects_and_chats(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data_root = Path(temp) / "user-data"
            database = MetadataDatabase.from_data_root(data_root)
            database.migrate()
            project = database.create_project("Alpha")
            chat = database.create_chat(project.id, "Planning")

            restarted = MetadataDatabase.from_data_root(data_root)
            self.assertEqual([item.name for item in restarted.list_projects()], ["Alpha"])
            self.assertEqual([item.title for item in restarted.list_chats(project.id)], ["Planning"])
            with restarted.connection() as connection:
                versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
            self.assertEqual(versions, [1, 2, 3, 4, 5, 6])

    def test_project_names_are_unique_and_chat_requires_existing_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = MetadataDatabase.from_data_root(Path(temp))
            database.create_project("Alpha")
            with self.assertRaises(DatabaseError):
                database.create_project("alpha")
            with self.assertRaises(DatabaseError):
                database.create_chat("missing")

    def test_project_list_is_bounded_for_ipc_responses(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = MetadataDatabase.from_data_root(Path(temp))
            for index in range(database.MAX_LIST_RESULTS + 1):
                database.create_project(f"Project {index}")
            self.assertEqual(len(database.list_projects()), database.MAX_LIST_RESULTS)

    def test_failed_pending_migration_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = MetadataDatabase.from_data_root(Path(temp))
            database.migrate()
            original = database_module.MIGRATIONS
            database_module.MIGRATIONS = original + ((7, "invalid", "CREATE TABLE broken ("),)
            try:
                with self.assertRaises(DatabaseError):
                    database.migrate()
            finally:
                database_module.MIGRATIONS = original
            with database.connection() as connection:
                versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
            self.assertEqual(versions, [1, 2, 3, 4, 5, 6])

    def test_multiple_projects_queue_and_completed_chat_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = MetadataDatabase.from_data_root(Path(temp))
            first = database.create_project("First")
            second = database.create_project("Second")
            self.assertEqual(
                [project.name for project in database.list_projects()],
                ["First", "Second"],
            )
            chat = database.create_chat(first.id, "Disposable")
            queued = database.enqueue_message(chat.id, "encrypted")
            claimed = database.claim_next_queued_message(chat.id)
            self.assertEqual(claimed["id"], queued["id"])
            database.complete_queued_message(queued["id"])
            database.upsert_turn(chat.id, "turn-running", "inProgress")
            with self.assertRaisesRegex(DatabaseError, "running chat"):
                database.delete_chat(chat.id)
            database.upsert_turn(chat.id, "turn-running", "completed")
            database.delete_chat(chat.id)
            self.assertEqual(database.list_chats(first.id), [])
            self.assertEqual(database.list_chats(second.id), [])


if __name__ == "__main__":
    unittest.main()
