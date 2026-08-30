import os
import tempfile
import unittest
from pathlib import Path

from human_codex.paths import (
    PathBoundaryError,
    PortablePaths,
    canonical_key,
    require_within,
)


class PortablePathTests(unittest.TestCase):
    def test_default_state_and_workspace_are_inside_installation_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            previous = os.environ.pop("HUMAN_CODEX_DATA_ROOT", None)
            try:
                repository = Path(temp) / "HumanCodex"
                paths = PortablePaths.discover(repository)
            finally:
                if previous is not None:
                    os.environ["HUMAN_CODEX_DATA_ROOT"] = previous
            self.assertEqual(paths.data_root, (repository / "HumanCodexData").resolve())
            self.assertEqual(paths.workspace_root, (repository / "Workspace").resolve())
            self.assertEqual(
                paths.app_server_working_root,
                (repository / "Workspace" / ".human-codex-app-server").resolve(),
            )
            paths.ensure_data_layout()
            self.assertTrue(paths.app_server_working_root.is_dir())

    def test_data_root_can_be_overridden_without_changing_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            previous = os.environ.get("HUMAN_CODEX_DATA_ROOT")
            os.environ["HUMAN_CODEX_DATA_ROOT"] = str(Path(temp) / "data")
            try:
                paths = PortablePaths.discover(Path(temp) / "repo")
            finally:
                if previous is None:
                    os.environ.pop("HUMAN_CODEX_DATA_ROOT", None)
                else:
                    os.environ["HUMAN_CODEX_DATA_ROOT"] = previous
            self.assertNotEqual(paths.repository_root, paths.data_root)
            self.assertEqual(paths.codex_home, paths.data_root / "codex-home")

    def test_require_within_accepts_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "folder" / "file.txt"
            self.assertEqual(require_within(child, root), child.resolve())

    def test_require_within_rejects_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            with self.assertRaises(PathBoundaryError):
                require_within(root / ".." / "outside.txt", root)

    def test_canonical_key_is_case_insensitive_on_windows(self) -> None:
        if os.name == "nt":
            self.assertEqual(canonical_key("C:/Temp/Case"), canonical_key("c:/temp/case"))


if __name__ == "__main__":
    unittest.main()
