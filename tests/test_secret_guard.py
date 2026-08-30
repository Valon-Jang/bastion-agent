import tempfile
import unittest
from pathlib import Path

from human_codex.secret_guard import (
    REDACTED_SECRET,
    WorkspaceSecretScanner,
    detect_secret_types,
    redact_text,
    redact_value,
)


class SecretGuardTests(unittest.TestCase):
    def test_detector_redactor_and_placeholders(self) -> None:
        credential = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1L2"
        assignment = "client_secret=J8vVZ3rN5qP2mS7xC4kL"
        self.assertIn("openai_key", detect_secret_types(credential))
        self.assertIn("credential_assignment", detect_secret_types(assignment))
        self.assertFalse(detect_secret_types("client_secret=YOUR_CLIENT_SECRET"))
        redacted = redact_text(f"{credential} {assignment}")
        self.assertIn(REDACTED_SECRET, redacted)
        self.assertNotIn(credential, redacted)
        self.assertNotIn("J8vVZ3rN5qP2mS7xC4kL", redacted)
        keyed = redact_value({credential: "safe"})
        self.assertNotIn(credential, keyed)
        self.assertIn(REDACTED_SECRET, next(iter(keyed)))
        entropy_value = "Ab3dEf7hIj9kLm2nOp4qRs6tUv8wXy0z+/CDeFgHiJkLmNoPqRsTuVwXyZ1"
        self.assertIn(
            "high_entropy_candidate",
            detect_secret_types(f"opaque_token={entropy_value}"),
        )
        self.assertNotIn(
            "high_entropy_candidate",
            detect_secret_types(f"integrity=sha512-{entropy_value}"),
        )

    def test_scanner_distinguishes_os_denied_paths_from_content_candidates(self) -> None:
        scanner = WorkspaceSecretScanner()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.py").write_text("print('clean')\n", encoding="utf-8")
            (root / ".env").write_text("VALUE=local-only\n", encoding="utf-8")
            path_result = scanner.scan([root])
            self.assertIn("secret_path", {finding.kind for finding in path_result.findings})
            self.assertTrue(path_result.blocks_turn(secret_paths_are_denied=False))
            self.assertFalse(path_result.blocks_turn(secret_paths_are_denied=True))

            (root / ".env").unlink()
            secret_value = "N7wQ2pL9sR4mK8xV6cD3"
            (root / "settings.py").write_text(
                f'api_key = "{secret_value}"\n', encoding="utf-8"
            )
            content_result = scanner.scan([root])
            self.assertIn("content_candidate", {finding.kind for finding in content_result.findings})
            self.assertTrue(content_result.blocks_turn(secret_paths_are_denied=True))
            self.assertNotIn(secret_value, repr(content_result))


if __name__ == "__main__":
    unittest.main()
