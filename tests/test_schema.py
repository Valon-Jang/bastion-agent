import json
import tempfile
import unittest
from pathlib import Path

from human_codex.codex_runtime import CodexRuntimeInfo
from human_codex.paths import PortablePaths
from human_codex.process import CommandResult
from human_codex.schema import generate_version_matched_schema, verify_pinned_schema


class FakeRuntime:
    def __init__(self, paths: PortablePaths) -> None:
        self.paths = paths

    def inspect(self) -> CodexRuntimeInfo:
        return CodexRuntimeInfo("codex", "1.2.3", True, True, True, "logged_in")

    def version(self) -> str:
        return "1.2.3"

    def run(self, *args: str, **_: object) -> CommandResult:
        output = Path(args[args.index("--out") + 1])
        output.mkdir(parents=True, exist_ok=True)
        (output / "generated.txt").write_text("generated\n", encoding="utf-8")
        return CommandResult(args=args, returncode=0, stdout="", stderr="")


class SchemaTests(unittest.TestCase):
    def test_generate_and_verify_version_matched_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = FakeRuntime(PortablePaths(root, root / "data"))
            destination = generate_version_matched_schema(runtime)  # type: ignore[arg-type]
            metadata = json.loads(
                (destination / "schema-metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["codex_cli_version"], "1.2.3")
            self.assertFalse(metadata["experimental"])
            self.assertEqual(verify_pinned_schema(runtime)["status"], "pass")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
