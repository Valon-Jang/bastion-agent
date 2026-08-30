import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from human_codex.paths import PortablePaths
from human_codex.skills import SkillError, SkillManager


class SkillManagerTests(unittest.TestCase):
    def test_installs_official_skill_inside_portable_codex_home_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root, root / "HumanCodexData")
            manager = SkillManager(paths)

            def download(_owner, _repository, _ref, _path, destination, state, *, depth):
                self.assertEqual(depth, 0)
                (destination / "SKILL.md").write_text(
                    "---\nname: demo-skill\ndescription: Test skill\n---\n",
                    encoding="utf-8",
                )
                (destination / "helper.py").write_text(
                    "raise RuntimeError('must not execute')\n", encoding="utf-8"
                )
                state.update(files=2, bytes=100)

            with patch.object(manager, "catalog", return_value=[{"name": "demo-skill"}]), patch.object(
                manager, "_download_directory", side_effect=download
            ):
                result = manager.install("demo-skill", approved=True)

            self.assertEqual(result["path"], str(paths.skills_root / "demo-skill"))
            self.assertFalse(result["scripts_executed"])
            self.assertEqual(manager.list_installed()[0]["name"], "demo-skill")

    def test_rejects_unapproved_non_github_and_traversal_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manager = SkillManager(PortablePaths(Path(temp), Path(temp) / "data"))
            with self.assertRaises(SkillError):
                manager.install("demo", approved=False)
            with self.assertRaises(SkillError):
                manager._parse_source("http://github.com/openai/skills/tree/main/demo")
            with self.assertRaises(SkillError):
                manager._safe_relative("../escape")

    def test_discovers_skill_directories_in_public_github_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manager = SkillManager(PortablePaths(Path(temp), Path(temp) / "data"))
            responses = [
                {"items": [{"full_name": "example/codex-tools", "default_branch": "main"}]},
                {
                    "tree": [
                        {"type": "blob", "path": "skills/blender/SKILL.md"},
                        {"type": "blob", "path": "skills/blender/scripts/run.py"},
                    ]
                },
            ]
            with patch.object(manager, "_json", side_effect=responses):
                result = manager._github_catalog("blender", set())
            self.assertEqual(result[0]["name"], "blender")
            self.assertEqual(result[0]["repository"], "example/codex-tools")
            self.assertEqual(
                result[0]["source"],
                "https://github.com/example/codex-tools/tree/main/skills/blender",
            )


if __name__ == "__main__":
    unittest.main()
