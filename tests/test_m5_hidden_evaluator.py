import shutil
import tempfile
import unittest
from pathlib import Path

from workers.m5_hidden_evaluator import evaluate


ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "smoke" / "tolerance_app_seed"


class M5HiddenEvaluatorTests(unittest.TestCase):
    def test_seed_project_fails_without_revealing_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            shutil.copytree(SEED, project)
            result = evaluate(project)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(result["symptoms"])
        self.assertIn("worst-case clearance bounds are inconsistent with opposing tolerance extremes", result["symptoms"])
        self.assertIn("save/load does not preserve the complete analysis state", result["symptoms"])
        self.assertNotIn("expected", " ".join(result["symptoms"]).lower())


if __name__ == "__main__":
    unittest.main()
