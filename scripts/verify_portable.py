"""Verify a clean Human Codex package using a disposable runtime copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "source" / "core"))
from human_codex.secret_guard import redact_text


FORBIDDEN_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "auth.json",
    "config.toml",
    "direct_url.json",
    "human_codex.db",
    "master-key.dpapi",
    "sitecustomize.py",
    "usercustomize.py",
}
FORBIDDEN_TOP_LEVEL = {"artifacts", "tests", "user-data"}


def _safe_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return redact_text(value or "")[-2000:]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(
    command: list[str], environment: dict[str, str], timeout: int = 90
) -> dict[str, object]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "command": [Path(command[0]).name, *command[1:]],
            "returncode": None,
            "stdout": _safe_output(exc.stdout),
            "stderr": f"timeout after {timeout} seconds",
        }
    return {
        "command": [Path(command[0]).name, *command[1:]],
        "returncode": result.returncode,
        "stdout": _safe_output(result.stdout),
        "stderr": _safe_output(result.stderr),
    }


def _passed(result: dict[str, object]) -> bool:
    return result["returncode"] == 0


def _cleanliness(root: Path) -> dict[str, Any]:
    violations: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0].lower() in FORBIDDEN_TOP_LEVEL:
            violations.append(relative.as_posix())
            continue
        if path.name.lower() in FORBIDDEN_NAMES:
            violations.append(relative.as_posix())
            continue
        if path.is_file() and path.suffix.lower() in {
            ".egg-link",
            ".pyc",
            ".pyo",
            ".pth",
        }:
            violations.append(relative.as_posix())
    return {
        "status": "pass" if not violations else "fail",
        "violations": violations[:50],
        "violation_count": len(violations),
    }


def _sbom_inventory(bundle: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    try:
        sbom = json.loads((bundle / "sbom.cdx.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "fail", "error": "SBOM is missing or invalid JSON"}
    components = sbom.get("components")
    if not isinstance(components, list):
        return {"status": "fail", "error": "SBOM components are missing"}

    actual: list[tuple[str, str]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        name = component.get("name")
        version = component.get("version")
        if isinstance(name, str) and isinstance(version, str):
            actual.append((name, version))

    runtimes = manifest.get("runtimes", {})
    expected: set[tuple[str, str]] = {
        ("Python", str(runtimes.get("python", "")).removeprefix("Python ")),
        (
            "OpenAI Codex CLI",
            str(runtimes.get("codex", "")).removeprefix("codex-cli "),
        ),
        ("Electron", str(runtimes.get("electron", "")).removeprefix("v")),
    }
    for key in ("locked_python_distributions", "bundled_node_distributions"):
        values = manifest.get(key)
        if not isinstance(values, list) or not values:
            return {"status": "fail", "error": f"manifest has no {key}"}
        for value in values:
            if not isinstance(value, dict):
                return {"status": "fail", "error": f"manifest has invalid {key}"}
            name = value.get("name")
            version = value.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                return {"status": "fail", "error": f"manifest has invalid {key}"}
            expected.add((name, version))

    actual_set = set(actual)
    missing = sorted(f"{name}@{version}" for name, version in expected - actual_set)
    duplicate = sorted(
        f"{name}@{version}"
        for name, version in actual_set
        if actual.count((name, version)) > 1
    )
    metadata = sbom.get("metadata", {})
    application = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    expected_version = str(manifest.get("product", {}).get("version", ""))
    application_version = (
        application.get("version") if isinstance(application, dict) else None
    )
    status = (
        "pass"
        if not missing
        and not duplicate
        and expected_version
        and application_version == expected_version
        else "fail"
    )
    return {
        "status": status,
        "component_count": len(actual),
        "missing": missing,
        "duplicates": duplicate,
        "application_version": application_version,
        "expected_application_version": expected_version,
    }


def _manifest_integrity(bundle: Path) -> dict[str, Any]:
    manifest_path = bundle / "portable-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return {"status": "fail", "error": str(exc), "manifest": None}
    if manifest.get("schema") != "human-codex-portable/2":
        return {
            "status": "fail",
            "error": "unsupported portable manifest schema",
            "manifest": manifest,
        }
    entries = manifest.get("files")
    if not isinstance(entries, list):
        return {"status": "fail", "error": "manifest files must be a list", "manifest": manifest}

    expected: dict[str, dict[str, Any]] = {}
    duplicate_paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            return {"status": "fail", "error": "invalid manifest file entry", "manifest": manifest}
        path = entry["path"]
        if path in expected:
            duplicate_paths.append(path)
        expected[path] = entry

    actual = {
        path.relative_to(bundle).as_posix(): path
        for path in bundle.rglob("*")
        if path.is_file() and path.name != "portable-manifest.json"
    }
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    mismatched: list[str] = []
    for relative in sorted(set(expected) & set(actual)):
        entry = expected[relative]
        path = actual[relative]
        if entry.get("size") != path.stat().st_size or entry.get("sha256") != _sha256(path):
            mismatched.append(relative)
    status = "pass" if not (duplicate_paths or missing or extra or mismatched) else "fail"
    return {
        "status": status,
        "file_count": len(expected),
        "duplicates": duplicate_paths[:20],
        "missing": missing[:20],
        "extra": extra[:20],
        "mismatched": mismatched[:20],
        "manifest": manifest,
    }


def _write_report(artifact: Path, report: dict[str, Any]) -> None:
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _copy_runtime_bundle(bundle: Path, destination: Path) -> Path:
    """Copy a clean bundle before launch because portable state is install-local."""

    runtime_bundle = destination / bundle.name
    shutil.copytree(bundle, runtime_bundle)
    return runtime_bundle


def _verification_environment(state_root: Path, smoke_path: Path) -> dict[str, str]:
    # The verifier must not turn the developer's ambient shell into part of the
    # release candidate. In particular, never forward provider credentials,
    # Python/Node injection variables, or a developer CODEX_HOME to the smoke
    # process. Start from a tiny OS allowlist. The launcher deliberately replaces
    # Human Codex state paths with install-local HumanCodexData and Workspace.
    source = {name.upper(): value for name, value in os.environ.items()}
    safe_names = (
        "ALLUSERSPROFILE",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432",
        "DRIVERDATA",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "NO_COLOR",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PUBLIC",
        "SESSIONNAME",
        "SYSTEMDRIVE",
        "TERM",
        "USERDOMAIN",
        "USERNAME",
    )
    environment = {
        name: source[name] for name in safe_names if source.get(name)
    }
    system_root = Path(
        source.get("SYSTEMROOT") or source.get("WINDIR") or r"C:\Windows"
    )
    user_root = state_root / "user"
    # Chromium verifies USERPROFILE against the signed-in Windows profile and
    # deliberately breakpoints if it is forged. Keep that OS identity path,
    # while redirecting APPDATA/LOCALAPPDATA/HOME/TEMP and all Human Codex state.
    windows_user_profile = source.get("USERPROFILE") or str(user_root)
    home_drive, home_path = os.path.splitdrive(str(user_root))
    environment.update(
        {
            "SystemRoot": str(system_root),
            "WINDIR": str(system_root),
            "ComSpec": str(system_root / "System32" / "cmd.exe"),
            "TEMP": str(state_root / "temp"),
            "TMP": str(state_root / "temp"),
            "LOCALAPPDATA": str(state_root / "local"),
            "APPDATA": str(state_root / "roaming"),
            "USERPROFILE": windows_user_profile,
            "HOME": str(user_root),
            "PATH": str(system_root / "System32") + ";" + str(system_root),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONIOENCODING": "utf-8",
            "HUMAN_CODEX_PORTABLE_SMOKE": "1",
            "HUMAN_CODEX_SMOKE_ARTIFACT": str(smoke_path),
            "HUMAN_CODEX_DATA_ROOT": str(state_root / "data"),
            "HUMAN_CODEX_ELECTRON_USER_DATA": str(state_root / "electron"),
        }
    )
    if home_drive:
        environment["HOMEDRIVE"] = home_drive
        environment["HOMEPATH"] = home_path
    return environment


def verify(bundle: Path, artifact: Path) -> int:
    bundle = bundle.expanduser().resolve()
    artifact = artifact.expanduser().resolve()
    try:
        artifact.relative_to(bundle)
    except ValueError:
        pass
    else:
        raise ValueError("verification artifact must be outside the release bundle")

    required = {
        "python": bundle / "runtime" / "python" / "python.exe",
        "codex": bundle / "runtime" / "codex" / "codex.exe",
        "code_mode_host": bundle
        / "runtime"
        / "codex"
        / "codex-code-mode-host.exe",
        "electron": bundle / "node_modules" / "electron" / "dist" / "electron.exe",
        "launcher": bundle / "Launch-HumanCodex.bat",
        "login_helper": bundle / "Login-HumanCodex.bat",
        "skill_manager": bundle / "Manage-HumanCodex-Skills.bat",
        "main": bundle / "app" / "electron" / "main.cjs",
        "readme": bundle / "README_PORTABLE.md",
        "sbom": bundle / "sbom.cdx.json",
        "lock": bundle / "requirements-portable.lock",
        "version": bundle / "VERSION.json",
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    integrity_before = _manifest_integrity(bundle)
    cleanliness_before = _cleanliness(bundle)
    report: dict[str, Any] = {
        "schema": "human-codex-portable-smoke/2",
        "bundle": str(bundle),
        "missing": missing,
        "manifest_before": {key: value for key, value in integrity_before.items() if key != "manifest"},
        "cleanliness_before": cleanliness_before,
    }
    if missing or integrity_before["status"] != "pass" or cleanliness_before["status"] != "pass":
        report["status"] = "fail"
        _write_report(artifact, report)
        return 2

    manifest = integrity_before["manifest"]
    sbom_inventory = _sbom_inventory(bundle, manifest)
    report["sbom_inventory"] = sbom_inventory
    if sbom_inventory["status"] != "pass":
        report["status"] = "fail"
        _write_report(artifact, report)
        return 2
    locked = {
        str(item["name"]).lower().replace("_", "-"): str(item["version"])
        for item in manifest.get("locked_python_distributions", [])
    }
    if not locked:
        report["status"] = "fail"
        report["error"] = "portable manifest has no locked Python distributions"
        _write_report(artifact, report)
        return 2

    artifact.parent.mkdir(parents=True, exist_ok=True)
    smoke_path = artifact.with_name("m6-electron-launcher-smoke.json")
    smoke_path.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="m6-runtime-state-", dir=artifact.parent) as temp:
        state_root = Path(temp).resolve()
        for child in ("temp", "local", "roaming", "user", "data"):
            (state_root / child).mkdir()
        runtime_bundle = _copy_runtime_bundle(bundle, state_root / "install")
        runtime_launcher = runtime_bundle / required["launcher"].relative_to(bundle)
        runtime_skill_manager = runtime_bundle / required["skill_manager"].relative_to(bundle)
        environment = _verification_environment(state_root, smoke_path)
        probe = (
            "import importlib.metadata as m, json; "
            f"expected=json.loads({json.dumps(json.dumps(locked))}); "
            "actual={k:m.version(k) for k in expected}; "
            "assert actual == expected, (actual, expected); "
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; "
            "from human_codex.paths import PortablePaths; "
            "print(json.dumps(actual, sort_keys=True))"
        )
        commands = {
            "bundled_python": _run(
                [str(required["python"]), "-B", "-s", "-c", probe],
                {
                    **environment,
                    "PYTHONPATH": str(bundle / "source" / "core"),
                },
            ),
            "bundled_codex": _run(
                [str(required["codex"]), "--version"], environment
            ),
            "bundled_app_server": _run(
                [str(required["codex"]), "app-server", "--help"], environment
            ),
            "bundled_code_mode_host": _run(
                [str(required["code_mode_host"]), "--help"], environment
            ),
            "portable_skill_manager": _run(
                [
                    str(environment["ComSpec"]),
                    "/d",
                    "/c",
                    "call",
                    str(runtime_skill_manager),
                    "list",
                ],
                environment,
            ),
            "launcher_electron_core": _run(
                [
                    str(environment["ComSpec"]),
                    "/d",
                    "/c",
                    "call",
                    str(runtime_launcher),
                    "--portable-smoke",
                ],
                environment,
            ),
        }
        portable_state = {
            "runtime_copy_used": runtime_bundle != bundle,
            "human_codex_data_created": (
                runtime_bundle / "HumanCodexData" / "data" / "human_codex.db"
            ).is_file(),
            "workspace_available": (runtime_bundle / "Workspace").is_dir(),
            "source_bundle_unchanged_during_launch": False,
        }

    smoke = None
    if smoke_path.is_file():
        try:
            smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            smoke = {"status": "invalid_json"}
    integrity_after = _manifest_integrity(bundle)
    cleanliness_after = _cleanliness(bundle)
    portable_state["source_bundle_unchanged_during_launch"] = (
        integrity_after["status"] == "pass"
        and cleanliness_after["status"] == "pass"
    )
    report.update(
        {
            "commands": commands,
            "electron_smoke": smoke,
            "portable_state": portable_state,
            "manifest_after": {key: value for key, value in integrity_after.items() if key != "manifest"},
            "cleanliness_after": cleanliness_after,
        }
    )
    report["status"] = (
        "pass"
        if all(_passed(item) for item in commands.values())
        and smoke
        and smoke.get("status") == "pass"
        and all(portable_state.values())
        and integrity_after["status"] == "pass"
        and cleanliness_after["status"] == "pass"
        else "fail"
    )
    _write_report(artifact, report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "pass" else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()
    try:
        return verify(args.bundle, args.artifact)
    except ValueError as exc:
        print(f"Portable verification failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
