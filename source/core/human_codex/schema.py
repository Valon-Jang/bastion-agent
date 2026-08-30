from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from human_codex.codex_runtime import CodexRuntime, CodexRuntimeError


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_version_matched_schema(runtime: CodexRuntime) -> Path:
    info = runtime.inspect()
    if not info.schema_generation or not info.typescript_generation:
        raise CodexRuntimeError(
            "installed Codex does not advertise both schema generators"
        )
    assert info.version
    schema_root = runtime.paths.schema_root
    schema_root.mkdir(parents=True, exist_ok=True)
    destination = schema_root / info.version
    if destination.exists():
        metadata = destination / "schema-metadata.json"
        if metadata.exists():
            return destination
        raise CodexRuntimeError(
            f"schema destination exists without metadata: {destination}"
        )

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{info.version}-", dir=str(schema_root))
    )
    try:
        json_dir = temporary / "json"
        ts_dir = temporary / "ts"
        json_dir.mkdir()
        ts_dir.mkdir()
        json_result = runtime.run(
            "app-server",
            "generate-json-schema",
            "--out",
            str(json_dir),
            timeout=60.0,
            use_app_home=False,
        )
        if not json_result.ok:
            raise CodexRuntimeError(
                json_result.stderr or "generate-json-schema failed"
            )
        ts_result = runtime.run(
            "app-server",
            "generate-ts",
            "--out",
            str(ts_dir),
            timeout=60.0,
            use_app_home=False,
        )
        if not ts_result.ok:
            raise CodexRuntimeError(ts_result.stderr or "generate-ts failed")
        files = []
        for path in sorted(temporary.rglob("*")):
            if path.is_file():
                files.append(
                    {
                        "path": path.relative_to(temporary).as_posix(),
                        "sha256": _sha256(path),
                        "size": path.stat().st_size,
                    }
                )
        metadata = {
            "codex_cli_version": info.version,
            "generated_at": datetime.now(UTC).isoformat(),
            "experimental": False,
            "commands": [
                "codex app-server generate-json-schema --out <json-dir>",
                "codex app-server generate-ts --out <ts-dir>",
            ],
            "files": files,
        }
        (temporary / "schema-metadata.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        return destination
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def verify_pinned_schema(runtime: CodexRuntime) -> dict[str, object]:
    version = runtime.version()
    root = runtime.paths.schema_root / version
    metadata_path = root / "schema-metadata.json"
    if not metadata_path.exists():
        return {"status": "missing", "codex_cli_version": version}
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    mismatches: list[str] = []
    for record in metadata.get("files", []):
        path = root / record["path"]
        if not path.is_file() or _sha256(path) != record["sha256"]:
            mismatches.append(record["path"])
    return {
        "status": "pass" if not mismatches else "fail",
        "codex_cli_version": version,
        "file_count": len(metadata.get("files", [])),
        "mismatches": mismatches,
    }
