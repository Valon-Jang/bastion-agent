from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class PathBoundaryError(ValueError):
    """Raised when a path escapes an allowed root."""


def canonical_path(path: str | os.PathLike[str]) -> Path:
    """Return an absolute path with existing links/junctions resolved."""

    return Path(path).expanduser().resolve(strict=False)


def canonical_key(path: str | os.PathLike[str]) -> str:
    """Return the case-insensitive comparison key used on Windows."""

    return os.path.normcase(str(canonical_path(path)))


def require_within(
    candidate: str | os.PathLike[str], root: str | os.PathLike[str]
) -> Path:
    resolved_candidate = canonical_path(candidate)
    resolved_root = canonical_path(root)
    candidate_key = canonical_key(resolved_candidate)
    root_key = canonical_key(resolved_root)
    try:
        common = os.path.commonpath([candidate_key, root_key])
    except ValueError as exc:
        raise PathBoundaryError(f"path is on a different volume: {candidate}") from exc
    if common != root_key:
        raise PathBoundaryError(f"path escapes root: {candidate}")
    return resolved_candidate


@dataclass(frozen=True)
class PortablePaths:
    repository_root: Path
    data_root: Path

    @classmethod
    def discover(cls, repository_root: Path | None = None) -> "PortablePaths":
        repo = canonical_path(
            repository_root
            if repository_root is not None
            else Path(__file__).resolve().parents[3]
        )
        configured_data = os.environ.get("HUMAN_CODEX_DATA_ROOT")
        if configured_data:
            data = canonical_path(configured_data)
        else:
            data = canonical_path(repo / "HumanCodexData")
        return cls(repository_root=repo, data_root=data)

    @property
    def source_root(self) -> Path:
        return self.repository_root / "source"

    @property
    def runtime_root(self) -> Path:
        return self.repository_root / "runtime"

    @property
    def codex_home(self) -> Path:
        return self.data_root / "codex-home"

    @property
    def skills_root(self) -> Path:
        """Portable Codex skill directory kept inside the installation tree."""

        return self.codex_home / "skills"

    @property
    def workspace_root(self) -> Path:
        return self.repository_root / "Workspace"

    @property
    def app_server_working_root(self) -> Path:
        return self.workspace_root / ".human-codex-app-server"

    @property
    def schema_root(self) -> Path:
        return self.repository_root / "schemas" / "codex-app-server"

    def ensure_data_layout(self) -> None:
        for child in (
            "data",
            "vault",
            "cache",
            "logs",
            "codex-home",
            "sessions",
            "snapshots",
            "tools",
            "knowledge",
            "temp",
            "backups",
        ):
            (self.data_root / child).mkdir(parents=True, exist_ok=True)
        (self.workspace_root / "Projects").mkdir(parents=True, exist_ok=True)
        (self.workspace_root / ".human-codex-temp").mkdir(
            parents=True, exist_ok=True
        )
        self.app_server_working_root.mkdir(parents=True, exist_ok=True)
        self.skills_root.mkdir(parents=True, exist_ok=True)

    def codex_environment(self) -> dict[str, str]:
        """Build a minimal provider environment without inheriting ambient credentials."""

        allowed_names = {
            "ALLUSERSPROFILE",
            "APPDATA",
            "COMMONPROGRAMFILES",
            "COMMONPROGRAMFILES(X86)",
            "COMMONPROGRAMW6432",
            "COMSPEC",
            "DRIVERDATA",
            "HOMEDRIVE",
            "HOMEPATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LOCALAPPDATA",
            "NO_COLOR",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "PATH",
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
            "SHELL",
            "SYSTEMDRIVE",
            "SYSTEMROOT",
            "TEMP",
            "TERM",
            "TMP",
            "USERDOMAIN",
            "USERNAME",
            "USERPROFILE",
            "WINDIR",
        }
        environment = {
            key: value for key, value in os.environ.items() if key.upper() in allowed_names
        }
        for key in (
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
        ):
            value = next(
                (item for name, item in os.environ.items() if name.upper() == key), None
            )
            if value and self._safe_network_setting(key, value):
                environment[key] = value
        codex_home = str(self.codex_home)
        environment["CODEX_HOME"] = codex_home
        environment["CODEX_SQLITE_HOME"] = codex_home
        return environment

    @staticmethod
    def _safe_network_setting(name: str, value: str) -> bool:
        if name not in {"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"}:
            return True
        try:
            parsed = urlsplit(value)
        except ValueError:
            return False
        return (
            parsed.scheme.casefold() in {"http", "https", "socks5", "socks5h"}
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
        )
