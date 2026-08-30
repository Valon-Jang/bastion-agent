"""Build a clean, self-contained Human Codex Windows release candidate."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = ROOT / "requirements-portable.lock"
LOCK_PATTERN = re.compile(
    r"^([A-Za-z0-9_.-]+)==([^\s]+) tree-sha256=([0-9a-f]{64})$"
)
STDLIB_EXCLUDES = {
    "ensurepip",
    "idlelib",
    "lib2to3",
    "site-packages",
    "test",
    "turtledemo",
    "venv",
}
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
ZIP_TIMESTAMP = (2026, 8, 28, 0, 0, 0)
CODEX_RESOURCE_RUNTIME_FILES = (
    "codex-command-runner.exe",
    "codex-windows-sandbox-setup.exe",
)
CODEX_ADJACENT_RUNTIME_FILES = (
    "codex-code-mode-host.exe",
)


def _load_version() -> dict[str, Any]:
    data = json.loads((ROOT / "VERSION.json").read_text(encoding="utf-8"))
    if data.get("product") != "Human Codex" or not isinstance(data.get("version"), str):
        raise ValueError("VERSION.json does not contain a valid Human Codex version")
    if data.get("milestone") != 6:
        raise ValueError("VERSION.json must identify milestone 6 before packaging")
    return data


def _package_name(version: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", version).strip("-.")
    if not safe:
        raise ValueError("release version cannot be converted to a package name")
    return f"HumanCodex-{safe}-windows-x64"


def _default_codex_exe() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        root = Path(appdata) / "npm" / "node_modules" / "@openai" / "codex"
        matches = sorted(
            root.glob(
                "node_modules/@openai/codex-win32-x64/vendor/**/bin/codex.exe"
            )
        )
        if matches:
            return matches[0]
    raise FileNotFoundError(
        "Unable to locate the installed Windows Codex executable; pass --codex-exe."
    )


def _require_file(path: Path, description: str) -> Path:
    candidate = path.expanduser()
    if _is_reparse(candidate):
        raise ValueError(f"{description} is an unsafe reparse point")
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"{description} was not found: {resolved}")
    return resolved


def _require_directory(path: Path, description: str) -> Path:
    candidate = path.expanduser()
    if _is_reparse(candidate):
        raise ValueError(f"{description} is an unsafe reparse point")
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"{description} was not found: {resolved}")
    return resolved


def _is_reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or (
            hasattr(os.path, "isjunction") and os.path.isjunction(path)
        )
    except OSError:
        return True


def _assert_no_reparse(source: Path) -> None:
    if _is_reparse(source):
        raise ValueError(f"portable input is an unsafe reparse point: {source.name}")
    for current, directory_names, file_names in os.walk(source, followlinks=False):
        directory = Path(current)
        for name in (*directory_names, *file_names):
            if _is_reparse(directory / name):
                raise ValueError(
                    f"portable input contains an unsafe reparse point: {name}"
                )


def _copytree(source: Path, destination: Path) -> None:
    _assert_no_reparse(source)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )


def _copy_codex_runtime(codex_exe: Path, destination: Path) -> None:
    """Stage Codex and every native helper required on a clean Windows PC."""

    codex_exe = _require_file(codex_exe, "Codex executable")
    resource_candidates = (
        codex_exe.parent,
        codex_exe.parent / "codex-resources",
        codex_exe.parent.parent / "codex-resources",
    )
    resources = next(
        (
            candidate
            for candidate in resource_candidates
            if all(
                (candidate / name).is_file()
                for name in CODEX_RESOURCE_RUNTIME_FILES
            )
        ),
        None,
    )
    if resources is None:
        raise FileNotFoundError(
            "Codex native sandbox helpers were not found beside the executable"
        )
    _assert_no_reparse(resources)
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copy2(codex_exe, destination / "codex.exe")
    for name in CODEX_RESOURCE_RUNTIME_FILES:
        shutil.copy2(
            _require_file(resources / name, f"Codex runtime helper {name}"),
            destination / name,
        )
    for name in CODEX_ADJACENT_RUNTIME_FILES:
        source = next(
            (
                candidate / name
                for candidate in (codex_exe.parent, resources)
                if (candidate / name).is_file()
            ),
            None,
        )
        if source is None:
            raise FileNotFoundError(
                f"Codex capability helper {name} was not found beside the executable"
            )
        shutil.copy2(
            _require_file(source, f"Codex capability helper {name}"),
            destination / name,
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_lock(path: Path = LOCK_FILE) -> dict[str, tuple[str, str]]:
    locked: dict[str, tuple[str, str]] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_PATTERN.fullmatch(line)
        if not match:
            raise ValueError(f"invalid portable lock entry at line {number}: {line}")
        name, version, tree_sha256 = match.groups()
        canonical = name.lower().replace("_", "-")
        if canonical in locked:
            raise ValueError(f"duplicate portable lock entry: {name}")
        locked[canonical] = (version, tree_sha256)
    if not locked:
        raise ValueError("portable dependency lock is empty")
    return locked


def _read_node_runtime_dependencies(
    package_path: Path = ROOT / "package.json",
    lock_path: Path = ROOT / "package-lock.json",
) -> list[dict[str, Any]]:
    package = json.loads(package_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    direct = package.get("dependencies")
    packages = lock.get("packages")
    if not isinstance(direct, dict) or not isinstance(packages, dict):
        raise ValueError("package metadata does not contain locked runtime dependencies")

    pending = sorted(str(name) for name in direct)
    discovered: dict[str, dict[str, Any]] = {}
    while pending:
        name = pending.pop(0)
        if name in discovered:
            continue
        entry = packages.get(f"node_modules/{name}")
        if not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
            raise ValueError(f"package-lock.json has no locked runtime entry for {name}")
        requires = entry.get("dependencies", {})
        if not isinstance(requires, dict):
            raise ValueError(f"package-lock.json has invalid dependencies for {name}")
        dependency_names = sorted(str(value) for value in requires)
        discovered[name] = {
            "name": name,
            "version": entry["version"],
            "license": entry.get("license") or "UNKNOWN",
            "dependencies": dependency_names,
        }
        pending.extend(
            dependency for dependency in dependency_names if dependency not in discovered
        )
    return [discovered[name] for name in sorted(discovered)]


def _copy_standard_runtime(python_root: Path, destination: Path) -> None:
    required_files = (
        "LICENSE.txt",
        "python.exe",
        "pythonw.exe",
        "python3.dll",
        "python312.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
    )
    destination.mkdir(parents=True)
    for filename in required_files:
        shutil.copy2(
            _require_file(python_root / filename, f"Python runtime file {filename}"),
            destination / filename,
        )
    _copytree(
        _require_directory(python_root / "DLLs", "Python DLL directory"),
        destination / "DLLs",
    )
    _copytree(
        _require_directory(python_root / "tcl", "Python Tcl/Tk directory"),
        destination / "tcl",
    )

    lib_source = _require_directory(python_root / "Lib", "Python standard library")

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = {
            name
            for name in names
            if name == "__pycache__" or fnmatch.fnmatch(name, "*.pyc")
        }
        if Path(directory).resolve() == lib_source:
            ignored.update(name for name in names if name in STDLIB_EXCLUDES)
        return ignored

    shutil.copytree(lib_source, destination / "Lib", ignore=ignore)


def _copy_locked_distribution(
    name: str,
    expected_version: str,
    expected_tree_sha256: str,
    destination_site_packages: Path,
) -> dict[str, Any]:
    distribution = importlib.metadata.distribution(name)
    actual_version = distribution.version
    if actual_version != expected_version:
        raise ValueError(
            f"portable dependency version mismatch for {name}: "
            f"expected {expected_version}, installed {actual_version}"
        )
    files = distribution.files
    if not files:
        raise ValueError(f"portable dependency has no RECORD file list: {name}")

    copied = 0
    tree_digest = hashlib.sha256()
    for entry in sorted(files, key=lambda value: str(value).replace("\\", "/")):
        relative = PurePosixPath(str(entry).replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            continue
        located = Path(distribution.locate_file(entry))
        if _is_reparse(located):
            raise ValueError(
                f"portable dependency contains an unsafe reparse point: {name}"
            )
        source = located.resolve()
        if not source.is_file() or source.suffix in {".pyc", ".pyo"}:
            continue
        file_digest = bytes.fromhex(_sha256(source))
        tree_digest.update(relative.as_posix().encode("utf-8"))
        tree_digest.update(b"\0")
        tree_digest.update(file_digest)
        tree_digest.update(b"\n")
        target = destination_site_packages.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied += 1

    if copied == 0:
        raise ValueError(f"portable dependency copied no files: {name}")
    actual_tree_sha256 = tree_digest.hexdigest()
    if actual_tree_sha256 != expected_tree_sha256:
        raise ValueError(
            f"portable dependency file-tree hash mismatch for {name}"
        )
    metadata = distribution.metadata
    return {
        "name": metadata.get("Name", name),
        "version": actual_version,
        "license": metadata.get("License-Expression")
        or metadata.get("License")
        or "UNKNOWN",
        "files": copied,
        "tree_sha256": actual_tree_sha256,
    }


def _copy_electron_runtime(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True)
    _copytree(
        _require_directory(source / "dist", "Electron distribution"),
        destination / "dist",
    )
    for filename in (
        "LICENSE",
        "README.md",
        "package.json",
        "index.js",
        "path.txt",
        "abi_version",
    ):
        shutil.copy2(
            _require_file(source / filename, f"Electron {filename}"),
            destination / filename,
        )


def _version(command: list[str]) -> str:
    result = subprocess.run(
        command, capture_output=True, text=True, check=True, timeout=30
    )
    return (result.stdout or result.stderr).strip()


def _runtime_probe(
    python_exe: Path, source_root: Path, locked: dict[str, tuple[str, str]]
) -> None:
    versions = {name: value[0] for name, value in locked.items()}
    script = (
        "import importlib.metadata as m, json; "
        f"expected=json.loads({json.dumps(json.dumps(versions))}); "
        "actual={k:m.version(k) for k in expected}; "
        "assert actual == expected, (actual, expected); "
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; "
        "from human_codex.paths import PortablePaths; "
        "print(json.dumps(actual, sort_keys=True))"
    )
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    environment = {
        "SystemRoot": str(system_root),
        "PATH": str(system_root / "System32"),
        "PYTHONPATH": str(source_root),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
    }
    subprocess.run(
        [str(python_exe), "-B", "-s", "-c", script],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
        timeout=30,
    )


def _assert_clean_bundle(root: Path) -> None:
    violations: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if _is_reparse(path):
            violations.append(relative.as_posix())
            continue
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
    if violations:
        sample = ", ".join(violations[:10])
        raise ValueError(f"bundle cleanliness check failed: {sample}")


def _write_sbom(
    root: Path,
    version: str,
    runtimes: dict[str, str],
    python_dependencies: list[dict[str, Any]],
    node_dependencies: list[dict[str, Any]],
) -> None:
    application_ref = f"pkg:generic/human-codex@{version}"
    components: list[dict[str, Any]] = [
        {
            "type": "framework",
            "name": "Python",
            "version": runtimes["python"].removeprefix("Python "),
            "bom-ref": f"pkg:generic/python@{runtimes['python'].removeprefix('Python ')}",
            "licenses": [{"license": {"id": "PSF-2.0"}}],
        },
        {
            "type": "application",
            "name": "OpenAI Codex CLI",
            "version": runtimes["codex"].removeprefix("codex-cli "),
            "bom-ref": f"pkg:github/openai/codex@{runtimes['codex'].removeprefix('codex-cli ')}",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {
            "type": "framework",
            "name": "Electron",
            "version": runtimes["electron"].removeprefix("v"),
            "purl": f"pkg:npm/electron@{runtimes['electron'].removeprefix('v')}",
            "bom-ref": f"pkg:npm/electron@{runtimes['electron'].removeprefix('v')}",
            "licenses": [{"license": {"id": "MIT"}}],
        },
    ]
    for dependency in python_dependencies:
        purl = f"pkg:pypi/{dependency['name'].lower()}@{dependency['version']}"
        component: dict[str, Any] = {
            "type": "library",
            "name": dependency["name"],
            "version": dependency["version"],
            "purl": purl,
            "bom-ref": purl,
        }
        license_value = dependency["license"]
        if " OR " in license_value or " AND " in license_value:
            component["licenses"] = [{"expression": license_value}]
        elif license_value != "UNKNOWN":
            component["licenses"] = [{"license": {"id": license_value}}]
        components.append(component)
    for dependency in node_dependencies:
        encoded_name = quote(dependency["name"], safe="/")
        purl = f"pkg:npm/{encoded_name}@{dependency['version']}"
        component = {
            "type": "library",
            "name": dependency["name"],
            "version": dependency["version"],
            "purl": purl,
            "bom-ref": purl,
        }
        if dependency["license"] != "UNKNOWN":
            component["licenses"] = [
                {"license": {"id": dependency["license"]}}
            ]
        components.append(component)
    component_refs = sorted(str(component["bom-ref"]) for component in components)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "Human Codex",
                "version": version,
                "bom-ref": application_ref,
            }
        },
        "components": components,
        "dependencies": [{"ref": application_ref, "dependsOn": component_refs}],
    }
    (root / "sbom.cdx.json").write_text(
        json.dumps(sbom, indent=2) + "\n", encoding="utf-8"
    )


def _manifest_files(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix().lower(),
    ):
        relative = path.relative_to(root).as_posix()
        if relative == "portable-manifest.json":
            continue
        entries.append(
            {"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)}
        )
    return entries


def _write_deterministic_zip(source: Path, archive: Path) -> None:
    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as output:
        for path in sorted(
            (item for item in source.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(source).as_posix().lower(),
        ):
            relative = PurePosixPath(source.name) / PurePosixPath(
                path.relative_to(source).as_posix()
            )
            info = zipfile.ZipInfo(relative.as_posix(), date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            with path.open("rb") as source_handle, output.open(
                info, "w", force_zip64=True
            ) as archive_handle:
                shutil.copyfileobj(source_handle, archive_handle, 1024 * 1024)


def build_package(
    output: Path,
    python_root: Path,
    codex_exe: Path,
    electron_module: Path,
    archive: Path | None,
) -> dict[str, Any]:
    version_data = _load_version()
    expected_name = _package_name(version_data["version"])
    output = output.expanduser().resolve()
    if output.name != expected_name:
        raise ValueError(
            f"output folder must be named {expected_name}; received {output.name}"
        )
    archive = archive.expanduser().resolve() if archive else None
    checksum_path = (
        archive.parent / f"{archive.name}.sha256" if archive is not None else None
    )
    for candidate in (output, archive, checksum_path):
        if candidate is not None and candidate.exists():
            raise FileExistsError(f"Refusing to overwrite an existing release: {candidate}")

    renderer = _require_directory(
        ROOT / "app" / "renderer" / "dist", "renderer production build"
    )
    python_root = _require_directory(python_root, "Python runtime")
    codex_exe = _require_file(codex_exe, "Codex executable")
    electron_module = _require_directory(electron_module, "Electron module")
    _require_file(electron_module / "dist" / "electron.exe", "Electron executable")
    locked = _read_lock()
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=f".{expected_name}-staging-", dir=output.parent
    ) as temporary:
        package = Path(temporary) / expected_name
        runtime_python = package / "runtime" / "python"
        _copy_standard_runtime(python_root, runtime_python)
        site_packages = runtime_python / "Lib" / "site-packages"
        dependencies = [
            _copy_locked_distribution(name, expected[0], expected[1], site_packages)
            for name, expected in sorted(locked.items())
        ]
        node_dependencies = _read_node_runtime_dependencies()
        _copy_electron_runtime(
            electron_module, package / "node_modules" / "electron"
        )
        _copytree(ROOT / "app" / "electron", package / "app" / "electron")
        _copytree(renderer, package / "app" / "renderer" / "dist")
        _copytree(ROOT / "source" / "core", package / "source" / "core")
        _copytree(ROOT / "schemas", package / "schemas")
        _copy_codex_runtime(codex_exe, package / "runtime" / "codex")
        shutil.copy2(
            ROOT / "bootstrapper" / "Launch-HumanCodex.bat",
            package / "Launch-HumanCodex.bat",
        )
        shutil.copy2(
            ROOT / "bootstrapper" / "Login-HumanCodex.bat",
            package / "Login-HumanCodex.bat",
        )
        shutil.copy2(
            ROOT / "bootstrapper" / "Manage-HumanCodex-Skills.bat",
            package / "Manage-HumanCodex-Skills.bat",
        )
        for filename in (
            "VERSION.json",
            "requirements-portable.lock",
            "README_PORTABLE.md",
        ):
            shutil.copy2(ROOT / filename, package / filename)
        workspace = package / "Workspace"
        workspace.mkdir()
        shutil.copy2(
            ROOT / "bootstrapper" / "WORKSPACE_README.txt",
            workspace / "README.txt",
        )

        runtimes = {
            "python": _version([str(runtime_python / "python.exe"), "--version"]),
            "codex": _version([str(codex_exe), "--version"]),
            "electron": _version(
                [str(electron_module / "dist" / "electron.exe"), "--version"]
            ),
        }
        _runtime_probe(
            runtime_python / "python.exe", package / "source" / "core", locked
        )
        _write_sbom(
            package,
            version_data["version"],
            runtimes,
            dependencies,
            node_dependencies,
        )
        _assert_clean_bundle(package)
        manifest = {
            "schema": "human-codex-portable/2",
            "product": version_data,
            "package": expected_name,
            "runtimes": runtimes,
            "locked_python_distributions": dependencies,
            "bundled_node_distributions": node_dependencies,
            "files": _manifest_files(package),
        }
        (package / "portable-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        _assert_clean_bundle(package)
        shutil.move(str(package), str(output))

    archive_hash = None
    if archive is not None and checksum_path is not None:
        archive.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f".{expected_name}-archive-", dir=archive.parent
        ) as temporary:
            staged_archive = Path(temporary) / archive.name
            _write_deterministic_zip(output, staged_archive)
            archive_hash = _sha256(staged_archive)
            shutil.move(str(staged_archive), str(archive))
        checksum_path.write_text(
            f"{archive_hash}  {archive.name}\n", encoding="ascii"
        )

    return {
        "package": str(output),
        "archive": str(archive) if archive else None,
        "archive_sha256": archive_hash,
        **runtimes,
    }


def main() -> int:
    version = _load_version()["version"]
    package_name = _package_name(version)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "release" / package_name
    )
    parser.add_argument("--python-root", type=Path, default=Path(sys.executable).parent)
    parser.add_argument("--codex-exe", type=Path, default=None)
    parser.add_argument(
        "--electron-module", type=Path, default=ROOT / "node_modules" / "electron"
    )
    parser.add_argument(
        "--archive",
        type=Path,
        default=ROOT / "release" / f"{package_name}.zip",
    )
    parser.add_argument(
        "--no-archive", action="store_true", help="Build only the release folder."
    )
    args = parser.parse_args()
    try:
        result = build_package(
            args.output,
            args.python_root,
            args.codex_exe or _default_codex_exe(),
            args.electron_module,
            None if args.no_archive else args.archive,
        )
    except (
        FileNotFoundError,
        FileExistsError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            f"Portable build failed ({type(exc).__name__}): {exc!r}",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
