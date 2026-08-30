from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_portable = _load_script("human_codex_build_portable", "build_portable.py")
verify_portable = _load_script("human_codex_verify_portable", "verify_portable.py")
m6_portable = _load_script("human_codex_m6_portable", "m6_portable_smoke.py")


class PortablePackagingTests(unittest.TestCase):
    def test_login_helper_uses_only_bundled_runtime_and_app_cli(self) -> None:
        helper = (ROOT / "bootstrapper" / "Login-HumanCodex.bat").read_text(
            encoding="utf-8"
        )
        self.assertIn("runtime\\python\\python.exe", helper)
        self.assertIn("runtime\\codex\\codex.exe", helper)
        self.assertIn("-B -s -m human_codex codex login", helper)
        self.assertIn('set "PYTHONHOME="', helper)
        self.assertIn('set "NODE_OPTIONS="', helper)
        self.assertNotIn("OPENAI_API_KEY", helper)
        self.assertTrue(helper.isascii())
        launcher = (ROOT / "bootstrapper" / "Launch-HumanCodex.bat").read_text(
            encoding="utf-8"
        )
        self.assertTrue(launcher.isascii())
        skill_manager = (
            ROOT / "bootstrapper" / "Manage-HumanCodex-Skills.bat"
        ).read_text(encoding="utf-8")
        self.assertIn("HumanCodexData", skill_manager)
        self.assertIn("-m human_codex skills", skill_manager)
        self.assertTrue(skill_manager.isascii())

    def test_release_candidate_metadata_and_lock_are_aligned(self) -> None:
        version = build_portable._load_version()
        package_json = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        package_lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(version["version"], "0.1.0-rc.6")
        self.assertEqual(version["milestone"], 6)
        self.assertEqual(package_json["version"], package_lock["version"])
        self.assertEqual(package_json["version"], package_lock["packages"][""]["version"])
        self.assertEqual(
            build_portable._package_name(version["version"]),
            "HumanCodex-0.1.0-rc.6-windows-x64",
        )
        self.assertEqual(
            {name: value[0] for name, value in build_portable._read_lock().items()},
            {"cryptography": "50.0.1", "cffi": "2.1.0", "pycparser": "3.0"},
        )
        self.assertTrue(
            all(
                len(value[1]) == 64
                for value in build_portable._read_lock().values()
            )
        )
        self.assertEqual(
            {
                item["name"]: item["version"]
                for item in build_portable._read_node_runtime_dependencies()
            },
            {"react": "19.1.1", "react-dom": "19.1.1", "scheduler": "0.26.0"},
        )

    def test_sbom_covers_python_and_bundled_node_dependencies(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-sbom-") as temp:
            bundle = Path(temp)
            runtimes = {
                "python": "Python 3.12.10",
                "codex": "codex-cli 0.147.0",
                "electron": "v44.0.0",
            }
            python_dependencies = [
                {
                    "name": name,
                    "version": locked[0],
                    "tree_sha256": locked[1],
                    "license": "MIT",
                    "files": 1,
                }
                for name, locked in build_portable._read_lock().items()
            ]
            node_dependencies = build_portable._read_node_runtime_dependencies()
            build_portable._write_sbom(
                bundle,
                "0.1.0-rc.6",
                runtimes,
                python_dependencies,
                node_dependencies,
            )
            manifest = {
                "product": {"version": "0.1.0-rc.6"},
                "runtimes": runtimes,
                "locked_python_distributions": python_dependencies,
                "bundled_node_distributions": node_dependencies,
            }
            inventory = verify_portable._sbom_inventory(bundle, manifest)
            self.assertEqual(inventory["status"], "pass")
            self.assertEqual(inventory["component_count"], 9)

    def test_verifier_preserves_windows_runtime_context_but_removes_tool_injection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-verify-env-") as temp:
            state = Path(temp)
            with patch.dict(
                os.environ,
                {
                    "PYTHONHOME": "C:\\untrusted-python",
                    "NODE_OPTIONS": "--require C:\\untrusted.js",
                    "CODEX_HOME": "C:\\untrusted-codex",
                    "OPENAI_API_KEY": "must-not-pass",
                    "HTTPS_PROXY": "http://user:password@proxy.invalid:8080",
                    "USERPROFILE": "C:\\WindowsUser",
                },
            ):
                environment = verify_portable._verification_environment(
                    state, state / "smoke.json"
                )
            self.assertNotIn("PYTHONHOME", environment)
            self.assertNotIn("NODE_OPTIONS", environment)
            self.assertNotIn("CODEX_HOME", environment)
            self.assertNotIn("OPENAI_API_KEY", environment)
            self.assertNotIn("HTTPS_PROXY", environment)
            self.assertEqual(environment["USERPROFILE"], "C:\\WindowsUser")
            self.assertEqual(environment["HOME"], str(state / "user"))
            self.assertEqual(environment["HUMAN_CODEX_DATA_ROOT"], str(state / "data"))
            self.assertEqual(
                environment["HUMAN_CODEX_ELECTRON_USER_DATA"],
                str(state / "electron"),
            )
            self.assertIn("SystemRoot", environment)

    def test_only_locked_distribution_files_are_staged(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-dist-stage-") as temp:
            site_packages = Path(temp) / "site-packages"
            locked = build_portable._read_lock()
            staged = [
                build_portable._copy_locked_distribution(
                    name, values[0], values[1], site_packages
                )
                for name, values in locked.items()
            ]
            discovered = {
                str(dist.metadata["Name"]).lower().replace("_", "-"): dist.version
                for dist in importlib.metadata.distributions(path=[str(site_packages)])
            }
            self.assertEqual(
                discovered, {name: value[0] for name, value in locked.items()}
            )
            self.assertEqual({item["name"].lower() for item in staged}, set(locked))
            self.assertEqual(
                {item["name"].lower(): item["tree_sha256"] for item in staged},
                {name: value[1] for name, value in locked.items()},
            )
            self.assertFalse(any(site_packages.rglob("*.pth")))
            self.assertFalse(any(site_packages.rglob("*.pyc")))

    def test_portable_copy_rejects_reparse_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-reparse-stage-") as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "payload.txt").write_text("payload", encoding="utf-8")
            with patch.object(
                build_portable,
                "_is_reparse",
                side_effect=lambda path: Path(path).name == "payload.txt",
            ):
                with self.assertRaises(ValueError):
                    build_portable._copytree(source, root / "destination")

    def test_codex_runtime_copy_includes_native_sandbox_helpers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-codex-runtime-") as temp:
            root = Path(temp)
            bin_dir = root / "vendor" / "bin"
            resources = root / "vendor" / "codex-resources"
            bin_dir.mkdir(parents=True)
            resources.mkdir()
            codex_exe = bin_dir / "codex.exe"
            codex_exe.write_bytes(b"codex")
            for name in build_portable.CODEX_RESOURCE_RUNTIME_FILES:
                (resources / name).write_bytes(name.encode("ascii"))
            for name in build_portable.CODEX_ADJACENT_RUNTIME_FILES:
                (bin_dir / name).write_bytes(name.encode("ascii"))
            destination = root / "bundle" / "runtime" / "codex"

            build_portable._copy_codex_runtime(codex_exe, destination)

            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {
                    "codex.exe",
                    *build_portable.CODEX_RESOURCE_RUNTIME_FILES,
                    *build_portable.CODEX_ADJACENT_RUNTIME_FILES,
                },
            )

    def test_codex_runtime_copy_requires_code_mode_host(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-code-mode-host-missing-") as temp:
            root = Path(temp)
            bin_dir = root / "vendor" / "bin"
            resources = root / "vendor" / "codex-resources"
            bin_dir.mkdir(parents=True)
            resources.mkdir()
            codex_exe = bin_dir / "codex.exe"
            codex_exe.write_bytes(b"codex")
            for name in build_portable.CODEX_RESOURCE_RUNTIME_FILES:
                (resources / name).write_bytes(name.encode("ascii"))

            with self.assertRaisesRegex(FileNotFoundError, "code-mode-host"):
                build_portable._copy_codex_runtime(
                    codex_exe, root / "bundle" / "runtime" / "codex"
                )

    def test_codex_runtime_copy_fails_closed_when_helpers_are_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-codex-runtime-missing-") as temp:
            root = Path(temp)
            codex_exe = root / "bin" / "codex.exe"
            codex_exe.parent.mkdir()
            codex_exe.write_bytes(b"codex")
            with self.assertRaisesRegex(FileNotFoundError, "sandbox helpers"):
                build_portable._copy_codex_runtime(codex_exe, root / "destination")

    def test_minimal_python_runtime_loads_core_crypto_and_locked_metadata(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-python-runtime-") as temp:
            runtime = Path(temp) / "runtime" / "python"
            build_portable._copy_standard_runtime(Path(sys.executable).parent, runtime)
            site_packages = runtime / "Lib" / "site-packages"
            locked = build_portable._read_lock()
            for name, values in locked.items():
                build_portable._copy_locked_distribution(
                    name, values[0], values[1], site_packages
                )
            build_portable._runtime_probe(
                runtime / "python.exe", ROOT / "source" / "core", locked
            )
            discovered = {
                str(dist.metadata["Name"]).lower().replace("_", "-"): dist.version
                for dist in importlib.metadata.distributions(path=[str(site_packages)])
            }
            self.assertEqual(
                discovered, {name: value[0] for name, value in locked.items()}
            )
            self.assertFalse((runtime / "Scripts").exists())
            self.assertFalse((runtime / "Lib" / "ensurepip").exists())

    def test_manifest_detects_extras_and_zip_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-manifest-") as temp:
            root = Path(temp)
            bundle = root / "HumanCodex-0.1.0-rc.6-windows-x64"
            bundle.mkdir()
            (bundle / "payload.txt").write_text("portable\n", encoding="utf-8")
            manifest = {
                "schema": "human-codex-portable/2",
                "files": build_portable._manifest_files(bundle),
            }
            (bundle / "portable-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            self.assertEqual(verify_portable._manifest_integrity(bundle)["status"], "pass")

            first = root / "first.zip"
            second = root / "second.zip"
            build_portable._write_deterministic_zip(bundle, first)
            build_portable._write_deterministic_zip(bundle, second)
            self.assertEqual(build_portable._sha256(first), build_portable._sha256(second))
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        f"{bundle.name}/payload.txt",
                        f"{bundle.name}/portable-manifest.json",
                    ],
                )

            (bundle / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
            integrity = verify_portable._manifest_integrity(bundle)
            self.assertEqual(integrity["status"], "fail")
            self.assertEqual(integrity["extra"], ["unexpected.txt"])

    def test_portable_verifier_launches_a_disposable_install_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-runtime-copy-") as temp:
            root = Path(temp)
            bundle = root / "HumanCodex-test"
            bundle.mkdir()
            original = bundle / "payload.txt"
            original.write_text("clean\n", encoding="utf-8")
            runtime_bundle = verify_portable._copy_runtime_bundle(
                bundle, root / "runtime"
            )
            (runtime_bundle / "HumanCodexData").mkdir()
            (runtime_bundle / "HumanCodexData" / "state.txt").write_text(
                "runtime\n", encoding="utf-8"
            )
            self.assertEqual(original.read_text(encoding="utf-8"), "clean\n")
            self.assertFalse((bundle / "HumanCodexData").exists())

    def test_cleanliness_rejects_user_state_and_python_startup_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-cleanliness-") as temp:
            bundle = Path(temp)
            (bundle / "source").mkdir()
            self.assertEqual(verify_portable._cleanliness(bundle)["status"], "pass")
            (bundle / "source" / "injected.pth").write_text("C:\\builder\n", encoding="utf-8")
            (bundle / "artifacts").mkdir()
            cleanliness = verify_portable._cleanliness(bundle)
            self.assertEqual(cleanliness["status"], "fail")
            self.assertEqual(cleanliness["violation_count"], 2)

    def test_release_extraction_rejects_unsafe_windows_entries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-extract-") as temp:
            root = Path(temp)
            parent_archive = root / "parent.zip"
            with zipfile.ZipFile(parent_archive, "w") as archive:
                archive.writestr("../outside.txt", "blocked")
            destination = root / "parent-output"
            destination.mkdir()
            with self.assertRaises(RuntimeError):
                m6_portable._extract_release(parent_archive, destination)

            symlink_archive = root / "symlink.zip"
            with zipfile.ZipFile(symlink_archive, "w") as archive:
                entry = zipfile.ZipInfo("bundle/link")
                entry.external_attr = (0o120777 << 16)
                archive.writestr(entry, "target")
            destination = root / "symlink-output"
            destination.mkdir()
            with self.assertRaises(RuntimeError):
                m6_portable._extract_release(symlink_archive, destination)

            collision_archive = root / "collision.zip"
            with zipfile.ZipFile(collision_archive, "w") as archive:
                archive.writestr("bundle/Readme.txt", "one")
                archive.writestr("bundle/README.TXT", "two")
            destination = root / "collision-output"
            destination.mkdir()
            with self.assertRaises(RuntimeError):
                m6_portable._extract_release(collision_archive, destination)

            for unsafe_name in ("bundle/data:stream", "bundle/CON.txt", "bundle/trailing. "):
                archive_path = root / f"unsafe-{len(unsafe_name)}-{unsafe_name[-1:].encode().hex()}.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(unsafe_name, "blocked")
                destination = root / f"unsafe-output-{len(unsafe_name)}-{unsafe_name[-1:].encode().hex()}"
                destination.mkdir()
                with self.assertRaises(RuntimeError):
                    m6_portable._extract_release(archive_path, destination)

    def test_release_extraction_accepts_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hc-extract-ok-") as temp:
            root = Path(temp)
            archive_path = root / "release.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("bundle/readme.txt", "portable\n")
                archive.writestr("bundle/", b"")
            destination = root / "output"
            destination.mkdir()
            m6_portable._extract_release(archive_path, destination)
            self.assertEqual(
                (destination / "bundle" / "readme.txt").read_text(encoding="utf-8"),
                "portable\n",
            )


if __name__ == "__main__":
    unittest.main()
