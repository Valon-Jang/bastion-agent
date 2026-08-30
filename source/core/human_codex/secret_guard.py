from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from human_codex.paths import canonical_path, require_within


REDACTED_SECRET = "[REDACTED_SECRET]"

_KNOWN_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.IGNORECASE)),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", re.IGNORECASE)),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b", re.IGNORECASE)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "authorization",
        re.compile(r"(?i)\bAuthorization\s*[:=]\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]{12,}={0,2}"),
    ),
    (
        "credential_url",
        re.compile(r"(?i)\bhttps?://[^\s/:@]{1,128}:[^\s/@]{8,128}@[^\s/]+"),
    ),
)

_ASSIGNMENT_PATTERN = re.compile(
    r"(?ix)"
    r"(?P<prefix>\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|secret[_-]?key|authorization|bearer|token|secret)\b"
    r"[\"']?\s*[:=]\s*[\"']?)"
    r"(?P<value>[A-Za-z0-9_./+\-=:${}@]{12,512})"
)

_BEARER_PATTERN = re.compile(
    r"(?i)(?P<prefix>\b(?:Authorization\s*[:=]\s*)?(?:Bearer|Basic)\s+)"
    r"(?P<value>[A-Za-z0-9._~+/-]{12,}={0,2})"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_HIGH_ENTROPY_BLOB = re.compile(
    r"(?=[A-Za-z0-9+/=_-]{48,256}\b)(?=[A-Za-z0-9+/=_-]*[+/=])"
    r"[A-Za-z0-9+/=_-]{48,256}"
)

_PLACEHOLDER_MARKERS = frozenset(
    {
        "changeme",
        "dummy",
        "example",
        "fake",
        "none",
        "null",
        "placeholder",
        "redacted",
        "replace",
        "sample",
        "test",
        "todo",
        "your",
        "xxxx",
    }
)
_REFERENCE_PREFIXES = ("os.environ", "process.env", "env.", "settings.", "config.", "${")

_TEXT_SUFFIXES = frozenset(
    {
        ".bat",
        ".cfg",
        ".cjs",
        ".cmd",
        ".conf",
        ".css",
        ".csv",
        ".env",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".md",
        ".mjs",
        ".properties",
        ".ps1",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
_TEXT_FILENAMES = frozenset({"dockerfile", "gemfile", "makefile", "procfile"})
_SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nox",
        ".nuxt",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
)
_VCS_CONFIGS = (Path(".git/config"), Path(".hg/hgrc"), Path(".svn/servers"))


def _is_placeholder(value: str) -> bool:
    lowered = value.casefold()
    if lowered.startswith(_REFERENCE_PREFIXES):
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def detect_secret_types(text: str) -> tuple[str, ...]:
    """Return secret categories without ever retaining or returning matched values."""

    categories = {name for name, pattern in _KNOWN_SECRET_PATTERNS if pattern.search(text)}
    for match in _ASSIGNMENT_PATTERN.finditer(text):
        value = match.group("value")
        if _is_placeholder(value):
            continue
        if value.casefold().endswith((".pem", ".key", ".p12", ".pfx")):
            continue
        if len(value) >= 20 or _entropy(value) >= 3.2:
            categories.add("credential_assignment")
    for line in text.splitlines():
        lowered = line.casefold()
        if not re.search(r"(?:token|secret|key|credential|auth|password)", lowered):
            continue
        if re.search(r"(?:integrity|sha(?:256|384|512)|checksum|digest|hash)", lowered):
            continue
        if any(_entropy(match.group(0)) >= 4.2 for match in _HIGH_ENTROPY_BLOB.finditer(line)):
            categories.add("high_entropy_candidate")
    return tuple(sorted(categories))


def is_text_candidate(path: str | os.PathLike[str]) -> bool:
    candidate = Path(path)
    return (
        candidate.suffix.casefold() in _TEXT_SUFFIXES
        or candidate.name.casefold() in _TEXT_FILENAMES
    )


def decode_candidate_text(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or raw.count(b"\x00") > len(raw) // 8:
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="ignore")


def redact_text(text: str) -> str:
    """Remove likely credential material from diagnostics and provider text."""

    redacted = _PRIVATE_KEY_BLOCK.sub(f"{REDACTED_SECRET}:private_key", text)
    for category, pattern in _KNOWN_SECRET_PATTERNS:
        redacted = pattern.sub(f"{REDACTED_SECRET}:{category}", redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        if _is_placeholder(value):
            return match.group(0)
        return f"{match.group('prefix')}{REDACTED_SECRET}:assignment"

    redacted = _ASSIGNMENT_PATTERN.sub(redact_assignment, redacted)
    redacted = _BEARER_PATTERN.sub(
        lambda match: f"{match.group('prefix')}{REDACTED_SECRET}:authorization", redacted
    )
    return _HIGH_ENTROPY_BLOB.sub(f"{REDACTED_SECRET}:encoded", redacted)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            redact_text(key) if isinstance(key, str) else key: redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value


def is_secret_path(path: str | os.PathLike[str]) -> bool:
    parts = [part.casefold() for part in Path(path).parts]
    for part in parts:
        if part == ".env" or part.startswith(".env."):
            return True
        if part in {
            ".codex",
            ".git-credentials",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "auth.json",
            "credentials",
            "credentials.json",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "id_rsa",
            "secrets.json",
            "service-account.json",
            "token.json",
        }:
            return True
        if part.endswith((".jks", ".key", ".p12", ".pem", ".pfx")):
            return True
        if "credential" in part or "secret" in part:
            return True
    if any(part in {".aws", ".gnupg", ".ssh"} for part in parts):
        return True
    joined = "/".join(parts)
    return joined.endswith("/.docker/config.json") or joined.endswith("/.kube/config")


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    path: str


@dataclass(frozen=True)
class SecretScanResult:
    findings: tuple[SecretFinding, ...]
    files_checked: int
    bytes_checked: int

    def blocks_turn(self, *, secret_paths_are_denied: bool) -> bool:
        for finding in self.findings:
            if finding.kind == "secret_path" and secret_paths_are_denied:
                continue
            return True
        return False

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.kind] = counts.get(finding.kind, 0) + 1
        return {
            "status": "blocked" if self.findings else "pass",
            "finding_counts": counts,
            "files_checked": self.files_checked,
            "bytes_checked": self.bytes_checked,
        }


class WorkspaceSecretScanner:
    MAX_DEPTH = 32
    MAX_FILES = 50_000
    MAX_FILE_BYTES = 4_194_304
    MAX_TOTAL_BYTES = 268_435_456

    def scan(self, roots: Iterable[str | os.PathLike[str]]) -> SecretScanResult:
        findings: list[SecretFinding] = []
        files_checked = 0
        bytes_checked = 0
        seen_roots: set[str] = set()

        for root_index, raw_root in enumerate(roots):
            root = canonical_path(raw_root)
            root_key = os.path.normcase(str(root))
            if root_key in seen_roots:
                continue
            seen_roots.add(root_key)
            if not root.is_dir():
                findings.append(SecretFinding("scan_incomplete", f"root-{root_index}"))
                continue

            for relative in _VCS_CONFIGS:
                candidate = root / relative
                if candidate.is_file():
                    checked, size, new_findings = self._scan_file(
                        candidate, root, root_index, allow_secret_path=False
                    )
                    files_checked += checked
                    bytes_checked += size
                    findings.extend(new_findings)

            for current_text, directory_names, file_names in os.walk(
                root, topdown=True, followlinks=False
            ):
                current = Path(current_text)
                try:
                    relative_current = current.relative_to(root)
                except ValueError:
                    findings.append(SecretFinding("reparse_point", f"root-{root_index}"))
                    directory_names[:] = []
                    continue
                depth = len(relative_current.parts)
                if depth > self.MAX_DEPTH:
                    findings.append(
                        SecretFinding("scan_incomplete", self._label(root_index, relative_current))
                    )
                    directory_names[:] = []
                    continue

                kept_directories: list[str] = []
                for name in directory_names:
                    candidate = current / name
                    relative = candidate.relative_to(root)
                    if self._is_reparse(candidate):
                        findings.append(
                            SecretFinding("reparse_point", self._label(root_index, relative))
                        )
                        continue
                    if is_secret_path(relative):
                        findings.append(
                            SecretFinding("secret_path", self._label(root_index, relative))
                        )
                    if name.casefold() in _SKIP_DIRECTORIES:
                        continue
                    kept_directories.append(name)
                directory_names[:] = kept_directories

                for name in file_names:
                    if files_checked >= self.MAX_FILES:
                        findings.append(
                            SecretFinding("scan_incomplete", self._label(root_index, relative_current))
                        )
                        return SecretScanResult(tuple(findings), files_checked, bytes_checked)
                    candidate = current / name
                    relative = candidate.relative_to(root)
                    if self._is_reparse(candidate):
                        findings.append(
                            SecretFinding("reparse_point", self._label(root_index, relative))
                        )
                        continue
                    checked, size, new_findings = self._scan_file(
                        candidate, root, root_index, allow_secret_path=True
                    )
                    files_checked += checked
                    bytes_checked += size
                    findings.extend(new_findings)
                    if bytes_checked > self.MAX_TOTAL_BYTES:
                        findings.append(
                            SecretFinding("scan_incomplete", self._label(root_index, relative))
                        )
                        return SecretScanResult(tuple(findings), files_checked, bytes_checked)

        unique = tuple(dict.fromkeys(findings))
        return SecretScanResult(unique, files_checked, bytes_checked)

    def _scan_file(
        self,
        candidate: Path,
        root: Path,
        root_index: int,
        *,
        allow_secret_path: bool,
    ) -> tuple[int, int, list[SecretFinding]]:
        relative = candidate.relative_to(root)
        label = self._label(root_index, relative)
        if allow_secret_path and is_secret_path(relative):
            return 1, 0, [SecretFinding("secret_path", label)]
        if not self._is_text_candidate(candidate):
            return 1, 0, []
        try:
            resolved = require_within(candidate, root)
            before = resolved.stat()
            if before.st_size > self.MAX_FILE_BYTES:
                return 1, 0, [SecretFinding("scan_incomplete", label)]
            raw = resolved.read_bytes()
            after = resolved.stat()
        except (OSError, ValueError):
            return 1, 0, [SecretFinding("scan_incomplete", label)]
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return 1, 0, [SecretFinding("scan_incomplete", label)]
        text = self._decode(raw)
        return (
            1,
            len(raw),
            [SecretFinding("content_candidate", label) for _ in detect_secret_types(text)][:1],
        )

    @staticmethod
    def _is_text_candidate(path: Path) -> bool:
        return is_text_candidate(path)

    @staticmethod
    def _decode(raw: bytes) -> str:
        return decode_candidate_text(raw)

    @staticmethod
    def _is_reparse(path: Path) -> bool:
        try:
            return path.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(path))
        except OSError:
            return True

    @staticmethod
    def _label(root_index: int, relative: Path) -> str:
        value = relative.as_posix() or "."
        return f"root-{root_index}/{value}"
