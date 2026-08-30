"""Build a fresh portable package and prove it launches with only bundled runtimes."""

from __future__ import annotations

import json
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "source" / "core"))
from human_codex.secret_guard import redact_text

ARTIFACT = ROOT / "artifacts" / "test" / "m6-portable-smoke.json"
MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def _windows_safe_parts(entry_name: str) -> tuple[str, ...]:
    if not entry_name or "\\" in entry_name or "\x00" in entry_name:
        raise RuntimeError("release ZIP contains an unsafe path")
    name = PurePosixPath(entry_name)
    if name.is_absolute() or ".." in name.parts:
        raise RuntimeError("release ZIP contains an unsafe path")
    parts = tuple(part for part in name.parts if part != ".")
    if not parts:
        raise RuntimeError("release ZIP contains an unsafe path")
    for part in parts:
        if (
            ":" in part
            or part.endswith((" ", "."))
            or any(ord(character) < 32 for character in part)
            or part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
        ):
            raise RuntimeError("release ZIP contains an unsafe Windows path")
    return parts


def _extract_release(archive: Path, destination: Path) -> None:
    destination = destination.resolve()
    if not destination.is_dir() or any(destination.iterdir()):
        raise RuntimeError("release ZIP destination must be an empty directory")
    with zipfile.ZipFile(archive) as release_zip:
        entries = release_zip.infolist()
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise RuntimeError("release ZIP contains too many entries")
        if sum(entry.file_size for entry in entries) > MAX_ARCHIVE_TOTAL_BYTES:
            raise RuntimeError("release ZIP is too large to extract safely")

        validated: list[tuple[zipfile.ZipInfo, tuple[str, ...], bool]] = []
        paths: dict[tuple[str, ...], bool] = {}
        for entry in entries:
            if entry.file_size > MAX_ARCHIVE_FILE_BYTES:
                raise RuntimeError("release ZIP entry is too large to extract safely")
            parts = _windows_safe_parts(entry.filename)
            mode = stat.S_IFMT(entry.external_attr >> 16)
            is_directory = entry.is_dir()
            if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise RuntimeError("release ZIP contains a non-regular entry")
            if mode == stat.S_IFDIR and not is_directory:
                raise RuntimeError("release ZIP has inconsistent entry metadata")

            key = tuple(part.casefold() for part in parts)
            if key in paths:
                raise RuntimeError("release ZIP contains duplicate Windows paths")
            paths[key] = is_directory
            validated.append((entry, parts, is_directory))

        for key, is_directory in paths.items():
            for size in range(1, len(key)):
                if paths.get(key[:size]) is False:
                    raise RuntimeError("release ZIP contains a file/directory collision")
            if not is_directory and any(
                other[: len(key)] == key and len(other) > len(key) for other in paths
            ):
                raise RuntimeError("release ZIP contains a file/directory collision")

        for entry, parts, is_directory in validated:
            target = (destination / Path(*parts)).resolve()
            try:
                target.relative_to(destination)
            except ValueError as exc:
                raise RuntimeError("release ZIP path escapes extraction root") from exc
            if is_directory:
                target.mkdir(parents=True, exist_ok=True)
                if not target.is_dir() or target.is_symlink() or (
                    hasattr(target, "is_junction") and target.is_junction()
                ):
                    raise RuntimeError("release ZIP directory target is unsafe")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            resolved_parent = target.parent.resolve()
            try:
                resolved_parent.relative_to(destination)
            except ValueError as exc:
                raise RuntimeError("release ZIP parent escapes extraction root") from exc
            with release_zip.open(entry, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="m6-portable-", dir=ROOT / "artifacts" / "test") as temp:
        version = json.loads((ROOT / "VERSION.json").read_text(encoding="utf-8"))["version"]
        package_name = f"HumanCodex-{version}-windows-x64"
        bundle = Path(temp) / package_name
        archive = Path(temp) / f"{package_name}.zip"
        build = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "build_portable.py"),
                "--output",
                str(bundle),
                "--archive",
                str(archive),
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if build.returncode == 0:
            extracted = Path(temp) / "extracted"
            extracted.mkdir()
            _extract_release(archive, extracted)
            extracted_bundle = extracted / package_name
            verify = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "verify_portable.py"),
                    "--bundle",
                    str(extracted_bundle),
                    "--artifact",
                    str(ARTIFACT.resolve()),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
        else:
            verify = None
        if verify is None:
            result = {
                "schema": "human-codex-portable-smoke/1",
                "status": "fail",
                "build_stdout": redact_text(build.stdout)[-2000:],
                "build_stderr": redact_text(build.stderr)[-2000:],
            }
            ARTIFACT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result, indent=2))
            return 2
        print(verify.stdout)
        if verify.returncode:
            print(verify.stderr, file=sys.stderr)
        return verify.returncode


if __name__ == "__main__":
    raise SystemExit(main())
