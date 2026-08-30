from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from human_codex.paths import PortablePaths
from human_codex.process import CommandResult, run_command


class CodexRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class CodexRuntimeInfo:
    executable: str | None
    version: str | None
    app_server: bool
    schema_generation: bool
    typescript_generation: bool
    login_status: str


class CodexRuntime:
    SECURITY_PROFILE = "human-codex-project"
    READ_ONLY_PROFILE = "human-codex-project-read-only"
    CORPORATE_TEST_CHECKS = (
        ("windows_host", "preflight"),
        ("codex_executable", "preflight"),
        ("acl_filesystem", "preflight"),
        ("provider_environment_scrubbed", "preflight"),
        ("test_root_created", "preflight"),
        ("direct_command_launch", "filesystem"),
        ("direct_command_finished", "filesystem"),
        ("workspace_read", "filesystem"),
        ("workspace_write", "filesystem"),
        ("outside_read_denied", "filesystem"),
        ("outside_write_denied", "filesystem"),
        ("codex_home_read_denied", "filesystem"),
        ("codex_home_write_denied", "filesystem"),
        ("secret_env_read_denied", "filesystem"),
        ("secret_key_read_denied", "filesystem"),
        ("metadata_read", "filesystem"),
        ("metadata_write_denied", "filesystem"),
        ("junction_read_denied", "filesystem"),
        ("junction_write_denied", "filesystem"),
        ("hardlink_read_denied", "filesystem"),
        ("hardlink_write_denied", "filesystem"),
        ("child_command_launch", "child_process"),
        ("child_workspace_write", "child_process"),
        ("child_outside_read_denied", "child_process"),
        ("child_outside_write_denied", "child_process"),
        ("child_secret_read_denied", "child_process"),
        ("readonly_command_launch", "read_only"),
        ("readonly_workspace_read", "read_only"),
        ("readonly_workspace_write_denied", "read_only"),
        ("readonly_outside_read_denied", "read_only"),
        ("readonly_child_write_denied", "read_only"),
        ("powershell_probe_launch", "network_privilege"),
        ("outbound_ipv4_denied", "network_privilege"),
        ("dns_denied", "network_privilege"),
        ("loopback_denied", "network_privilege"),
        ("administrator_token_denied", "network_privilege"),
        ("registry_write_denied", "network_privilege"),
        ("profile_command_launch", "permission_profile"),
        ("profile_workspace_read", "permission_profile"),
        ("profile_workspace_write", "permission_profile"),
        ("profile_secret_env_denied", "permission_profile"),
        ("profile_secret_key_denied", "permission_profile"),
        ("profile_metadata_write_denied", "permission_profile"),
        ("profile_outside_read_denied", "permission_profile"),
        ("configuration_unchanged", "cleanup"),
        ("registry_cleanup", "cleanup"),
        ("filesystem_cleanup", "cleanup"),
    )
    CORPORATE_TEST_TOTAL = len(CORPORATE_TEST_CHECKS)
    # The restricted-token backend is an explicitly selected fallback for managed
    # company PCs.  These checks prove that the backend launches and that the
    # containment controls needed for useful project work stay intact. Strong
    # split-read rules, fine-grained secret reads, read-only/custom profiles, and
    # DNS hardening are warnings because Codex's unelevated backend cannot enforce
    # them with the same guarantees as the elevated backend.
    CORPORATE_ACTIVATION_REQUIRED_CHECKS = (
        "windows_host",
        "codex_executable",
        "acl_filesystem",
        "provider_environment_scrubbed",
        "test_root_created",
        "direct_command_launch",
        "direct_command_finished",
        "workspace_read",
        "workspace_write",
        "outside_write_denied",
        "codex_home_write_denied",
        "metadata_read",
        "metadata_write_denied",
        "junction_write_denied",
        "hardlink_write_denied",
        "child_command_launch",
        "child_workspace_write",
        "child_outside_write_denied",
        "powershell_probe_launch",
        "outbound_ipv4_denied",
        "loopback_denied",
        "administrator_token_denied",
        "registry_write_denied",
        "configuration_unchanged",
        "registry_cleanup",
        "filesystem_cleanup",
    )
    CORPORATE_ACTIVATION_REQUIRED_TOTAL = len(CORPORATE_ACTIVATION_REQUIRED_CHECKS)
    _PROFILE_CONFIG = """default_permissions = "human-codex-project"
permissions.human-codex-project.description = "Human Codex project boundary"
permissions.human-codex-project.filesystem.glob_scan_max_depth = 32
permissions.human-codex-project.filesystem.":root" = "deny"
permissions.human-codex-project.filesystem.":minimal" = "read"
permissions.human-codex-project.filesystem.":workspace_roots"."." = "write"
permissions.human-codex-project.filesystem.":workspace_roots".".git" = "read"
permissions.human-codex-project.filesystem.":workspace_roots".".hg" = "read"
permissions.human-codex-project.filesystem.":workspace_roots".".svn" = "read"
permissions.human-codex-project.filesystem.":workspace_roots".".codex" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.env" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.env.*" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/*.pem" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/*.key" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/*.p12" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/*.pfx" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/*.jks" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.npmrc" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.pypirc" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.netrc" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.git-credentials" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/token.json" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.docker/config.json" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.kube/config" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.ssh/**" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.aws/**" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/.gnupg/**" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/auth.json" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/id_dsa" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/id_ecdsa" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/id_ed25519" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/id_rsa" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/service-account.json" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/*credential*" = "deny"
permissions.human-codex-project.filesystem.":workspace_roots"."**/*secret*" = "deny"
permissions.human-codex-project.network.enabled = false
permissions.human-codex-project-read-only.description = "Human Codex read-only project boundary"
permissions.human-codex-project-read-only.filesystem.glob_scan_max_depth = 32
permissions.human-codex-project-read-only.filesystem.":root" = "deny"
permissions.human-codex-project-read-only.filesystem.":minimal" = "read"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."." = "read"
permissions.human-codex-project-read-only.filesystem.":workspace_roots".".git" = "read"
permissions.human-codex-project-read-only.filesystem.":workspace_roots".".hg" = "read"
permissions.human-codex-project-read-only.filesystem.":workspace_roots".".svn" = "read"
permissions.human-codex-project-read-only.filesystem.":workspace_roots".".codex" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.env" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.env.*" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/*.pem" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/*.key" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/*.p12" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/*.pfx" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/*.jks" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.npmrc" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.pypirc" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.netrc" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.git-credentials" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/token.json" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.docker/config.json" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.kube/config" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.ssh/**" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.aws/**" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/.gnupg/**" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/auth.json" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/id_dsa" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/id_ecdsa" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/id_ed25519" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/id_rsa" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/service-account.json" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/*credential*" = "deny"
permissions.human-codex-project-read-only.filesystem.":workspace_roots"."**/*secret*" = "deny"
permissions.human-codex-project-read-only.network.enabled = false
"""
    _MANAGED_BEGIN = "# human-codex-managed-security-v3-begin"
    _MANAGED_END = "# human-codex-managed-security-end"
    _SECURITY_CONFIG = (
        _MANAGED_BEGIN
        + "\n"
        + 'forced_login_method = "chatgpt"\n'
        + 'web_search = "live"\n'
        + "allow_login_shell = false\n"
        + "check_for_update_on_startup = false\n"
        + "agents.enabled = false\n"
        + "analytics.enabled = false\n"
        + 'history.persistence = "none"\n'
        + "feedback.enabled = false\n"
        + "apps._default.enabled = false\n"
        + "features.hooks = false\n"
        + "features.memories = false\n"
        + "features.multi_agent = false\n"
        + "features.remote_plugin = false\n"
        + "features.skill_mcp_dependency_install = false\n"
        + 'windows.sandbox = "elevated"\n'
        + 'shell_environment_policy.inherit = "core"\n'
        + "shell_environment_policy.ignore_default_excludes = false\n"
        + _PROFILE_CONFIG
        + _MANAGED_END
        + "\n"
    )
    _SAFE_OPTIONAL_KEYS = frozenset(
        {
            "model",
            "model_reasoning_effort",
            "model_reasoning_summary",
            "model_verbosity",
            "service_tier",
            "personality",
            "hide_agent_reasoning",
            "windows",
            "windows_wsl_setup_acknowledged",
        }
    )

    def __init__(self, paths: PortablePaths, executable: str | None = None) -> None:
        self.paths = paths
        self.executable = executable or shutil.which("codex")
        self._permission_profile_enforced: bool | None = None
        self._permission_profile_diagnostics: dict[str, bool] = {}

    def require_executable(self) -> str:
        if not self.executable:
            raise CodexRuntimeError("codex executable was not found on PATH")
        return self.executable

    def ensure_home(self) -> Path:
        self.paths.ensure_data_layout()
        security_config = self._security_config()
        config_path = self.paths.codex_home / "config.toml"
        current = ""
        if config_path.exists():
            try:
                current = config_path.read_text(encoding="utf-8")
                parsed = tomllib.loads(current)
            except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
                raise CodexRuntimeError("app Codex config is invalid; refusing unsafe startup") from exc
        else:
            parsed = {}
        auth_store = parsed.get("cli_auth_credentials_store")
        if auth_store not in {None, "keyring"}:
            raise CodexRuntimeError("app Codex credentials must use the OS keyring")
        updated = current
        if self._has_security_policy(parsed):
            pass
        elif "default_permissions" in parsed or "permissions" in parsed:
            remainder = self._legacy_policy_remainder(current)
            if remainder is None:
                raise CodexRuntimeError(
                    "app Codex permission profile conflicts with the required policy"
                )
            updated = security_config + remainder
        else:
            legacy_projects = self._legacy_projects_remainder(current, parsed)
            if legacy_projects is not None:
                updated = security_config + legacy_projects
            else:
                if not self._safe_optional_config(parsed):
                    raise CodexRuntimeError(
                        "app Codex configuration contains unsupported security-sensitive settings"
                    )
                updated = security_config + current
        if auth_store != "keyring":
            updated = self._insert_after_managed_block(
                updated, 'cli_auth_credentials_store = "keyring"\n'
            )
        if updated != current:
            self._atomic_write(config_path, updated)
        return self.paths.codex_home

    def _security_config(self) -> str:
        path = json.dumps(str(self.paths.codex_home.resolve()), ensure_ascii=True)
        deny = (
            f"permissions.{self.SECURITY_PROFILE}.filesystem.{path} = \"deny\"\n"
            f"permissions.{self.READ_ONLY_PROFILE}.filesystem.{path} = \"deny\"\n"
        )
        return self._SECURITY_CONFIG.replace(
            self._MANAGED_END + "\n", deny + self._MANAGED_END + "\n"
        )

    def _has_security_policy(self, config: dict[str, object]) -> bool:
        if not self._has_managed_controls(config):
            return False
        return self._has_profile_policy(config, require_root_deny=True)

    def _has_profile_policy(
        self, config: dict[str, object], *, require_root_deny: bool
    ) -> bool:
        if config.get("default_permissions") != self.SECURITY_PROFILE:
            return False
        permissions = config.get("permissions")
        if not isinstance(permissions, dict) or set(permissions) != {
            self.SECURITY_PROFILE,
            self.READ_ONLY_PROFILE,
        }:
            return False
        protected = {
            ".git": "read",
            ".hg": "read",
            ".svn": "read",
            ".codex": "deny",
            "**/.env": "deny",
            "**/.env.*": "deny",
            "**/*.pem": "deny",
            "**/*.key": "deny",
            "**/*.p12": "deny",
            "**/*.pfx": "deny",
            "**/*.jks": "deny",
            "**/.npmrc": "deny",
            "**/.pypirc": "deny",
            "**/.netrc": "deny",
            "**/.git-credentials": "deny",
            "**/token.json": "deny",
            "**/.docker/config.json": "deny",
            "**/.kube/config": "deny",
            "**/.ssh/**": "deny",
            "**/.aws/**": "deny",
            "**/.gnupg/**": "deny",
            "**/auth.json": "deny",
            "**/id_dsa": "deny",
            "**/id_ecdsa": "deny",
            "**/id_ed25519": "deny",
            "**/id_rsa": "deny",
            "**/service-account.json": "deny",
            "**/*credential*": "deny",
            "**/*secret*": "deny",
        }

        def valid_profile(name: str, root_access: str) -> bool:
            profile = permissions.get(name)
            if not isinstance(profile, dict) or set(profile) != {
                "description",
                "filesystem",
                "network",
            }:
                return False
            network = profile.get("network")
            filesystem = profile.get("filesystem")
            if network != {"enabled": False}:
                return False
            if not isinstance(filesystem, dict):
                return False
            depth = filesystem.get("glob_scan_max_depth")
            roots = filesystem.get(":workspace_roots")
            expected_filesystem_keys = {
                "glob_scan_max_depth",
                ":minimal",
                ":workspace_roots",
                str(self.paths.codex_home.resolve()),
            }
            if require_root_deny:
                expected_filesystem_keys.add(":root")
            return (
                set(filesystem) == expected_filesystem_keys
                and depth == 32
                and (
                    filesystem.get(":root") == "deny"
                    if require_root_deny
                    else ":root" not in filesystem
                )
                and filesystem.get(":minimal") == "read"
                and filesystem.get(str(self.paths.codex_home.resolve())) == "deny"
                and isinstance(roots, dict)
                and set(roots) == {".", *protected}
                and roots.get(".") == root_access
                and all(roots.get(pattern) == access for pattern, access in protected.items())
            )

        return valid_profile(self.SECURITY_PROFILE, "write") and valid_profile(
            self.READ_ONLY_PROFILE, "read"
        )

    @classmethod
    def _has_managed_controls(cls, config: dict[str, object]) -> bool:
        allowed = {
            "default_permissions",
            "permissions",
            "cli_auth_credentials_store",
            "forced_login_method",
            "web_search",
            "allow_login_shell",
            "check_for_update_on_startup",
            "agents",
            "analytics",
            "history",
            "feedback",
            "apps",
            "features",
            "shell_environment_policy",
            *cls._SAFE_OPTIONAL_KEYS,
        }
        if not set(config).issubset(allowed) or not cls._valid_optional_values(config):
            return False
        return (
            config.get("forced_login_method") == "chatgpt"
            and config.get("web_search") == "live"
            and config.get("allow_login_shell") is False
            and config.get("check_for_update_on_startup") is False
            and config.get("agents") == {"enabled": False}
            and config.get("analytics") == {"enabled": False}
            and config.get("history") == {"persistence": "none"}
            and config.get("feedback") == {"enabled": False}
            and config.get("apps") == {"_default": {"enabled": False}}
            and config.get("features")
            == {
                "hooks": False,
                "memories": False,
                "multi_agent": False,
                "remote_plugin": False,
                "skill_mcp_dependency_install": False,
            }
            and config.get("windows") == {"sandbox": "elevated"}
            and config.get("shell_environment_policy")
            == {"inherit": "core", "ignore_default_excludes": False}
        )

    @classmethod
    def _safe_optional_config(cls, config: dict[str, object]) -> bool:
        return set(config).issubset(
            {"cli_auth_credentials_store", *cls._SAFE_OPTIONAL_KEYS}
        ) and cls._valid_optional_values(config)

    @classmethod
    def _valid_optional_values(cls, config: dict[str, object]) -> bool:
        windows = config.get("windows")
        if windows is not None:
            if not isinstance(windows, dict) or set(windows) - {
                "sandbox",
                "sandbox_private_desktop",
            }:
                return False
            if windows.get("sandbox") not in {None, "elevated"}:
                return False
            if windows.get("sandbox_private_desktop") is False:
                return False
        acknowledged = config.get("windows_wsl_setup_acknowledged")
        return acknowledged is None or isinstance(acknowledged, bool)

    @classmethod
    def _legacy_policy_remainder(cls, current: str) -> str | None:
        managed_marker = cls._MANAGED_END + "\n"
        if current.startswith(cls._MANAGED_BEGIN + "\n"):
            marker_index = current.find(managed_marker)
            if marker_index >= 0:
                remainder = current[marker_index + len(managed_marker) :]
                try:
                    parsed_remainder = tomllib.loads(remainder)
                except tomllib.TOMLDecodeError:
                    return None
                if cls._safe_optional_config(parsed_remainder):
                    return remainder

        metadata_lines = "".join(
            f'permissions.{{profile}}.filesystem.":workspace_roots"."{name}" = "{access}"\n'
            for name, access in (
                (".git", "read"),
                (".hg", "read"),
                (".svn", "read"),
                (".codex", "deny"),
            )
        )
        without_metadata = cls._PROFILE_CONFIG
        for profile in (cls.SECURITY_PROFILE, cls.READ_ONLY_PROFILE):
            without_metadata = without_metadata.replace(
                metadata_lines.format(profile=profile), ""
            )

        prefixes: list[str] = []
        for profile_config in (cls._PROFILE_CONFIG, without_metadata):
            without_root = profile_config.replace(
                f'permissions.{cls.SECURITY_PROFILE}.filesystem.":root" = "deny"\n', ""
            ).replace(
                f'permissions.{cls.READ_ONLY_PROFILE}.filesystem.":root" = "deny"\n', ""
            )
            normal_only = profile_config.split(
                f"permissions.{cls.READ_ONLY_PROFILE}.description", 1
            )[0]
            normal_without_root = normal_only.replace(
                f'permissions.{cls.SECURITY_PROFILE}.filesystem.":root" = "deny"\n', ""
            )
            prefixes.extend(
                (profile_config, without_root, normal_only, normal_without_root)
            )
        for prefix in prefixes:
            if not current.startswith(prefix):
                continue
            remainder = current[len(prefix) :]
            try:
                parsed_remainder = tomllib.loads(remainder)
            except tomllib.TOMLDecodeError:
                return None
            if cls._safe_optional_config(parsed_remainder):
                return remainder
        return None

    @classmethod
    def _legacy_projects_remainder(
        cls, current: str, parsed: dict[str, object]
    ) -> str | None:
        """Drop only old app-owned trust entries; never preserve trusted roots."""

        projects = parsed.get("projects")
        if not isinstance(projects, dict) or not projects:
            return None
        if not all(
            isinstance(path, str)
            and isinstance(settings, dict)
            and set(settings) == {"trust_level"}
            and settings.get("trust_level") in {"trusted", "untrusted"}
            for path, settings in projects.items()
        ):
            return None
        without_projects = dict(parsed)
        without_projects.pop("projects", None)
        if not cls._safe_optional_config(without_projects):
            return None

        output: list[str] = []
        in_projects_table = False
        for line in current.splitlines(keepends=True):
            stripped = line.strip()
            if stripped.startswith("["):
                header = stripped.lstrip("[").lstrip("[").strip()
                in_projects_table = header == "projects]" or header.startswith(
                    ("projects.", 'projects"', "projects'")
                )
                if in_projects_table:
                    continue
            if in_projects_table:
                continue
            if re.match(r"^projects(?:\.|\s*=)", stripped):
                # Only a self-contained single-line dotted/inline form is safe
                # to remove without a general TOML rewriter.
                if "\n" in line[:-1] or ("{" in line and "}" not in line):
                    return None
                continue
            output.append(line)
        remainder = "".join(output)
        try:
            if not cls._safe_optional_config(tomllib.loads(remainder)):
                return None
        except tomllib.TOMLDecodeError:
            return None
        return remainder

    @classmethod
    def _insert_after_managed_block(cls, current: str, value: str) -> str:
        marker = cls._MANAGED_END + "\n"
        index = current.find(marker)
        if index < 0:
            return value + current
        index += len(marker)
        return current[:index] + value + current[index:]

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
                delete=False,
            ) as handle:
                handle.write(content)
                temporary = Path(handle.name)
            temporary.replace(path)
        except OSError as exc:
            try:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise CodexRuntimeError("app Codex security configuration could not be written") from exc

    def permission_profile_enforced(
        self,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> bool:
        """Prove both normal reads and secret-path denial with the installed sandbox."""

        if self._permission_profile_enforced is not None:
            return self._permission_profile_enforced
        if not self.executable or os.name != "nt":
            self._permission_profile_enforced = False
            return False
        self.ensure_home()
        from human_codex.app_server import AppServerClient, AppServerError, _product_version

        temp_parent = self.paths.data_root / "temp" / "sandbox-probe"
        temp_parent.mkdir(parents=True, exist_ok=True)
        codex_home_probe: Path | None = None
        try:
            with (
                tempfile.TemporaryDirectory(
                    prefix="permission-probe-",
                    dir=temp_parent,
                    ignore_cleanup_errors=True,
                ) as temp,
                tempfile.TemporaryDirectory(
                    prefix="permission-outside-",
                    dir=temp_parent,
                    ignore_cleanup_errors=True,
                ) as outside,
            ):
                root = Path(temp)
                outside_root = Path(outside)
                (root / "normal.txt").write_text("HC_NORMAL_PROBE\n", encoding="utf-8")
                secret_probes = {
                    ".env": "HC_DENY_ENV_ROOT",
                    ".codex/config.toml": "HC_DENY_PROJECT_CODEX_CONFIG",
                    "nested/.env.local": "HC_DENY_ENV_NESTED",
                    "nested/private.pem": "HC_DENY_PEM",
                    "nested/private.key": "HC_DENY_KEY",
                    "nested/archive.p12": "HC_DENY_P12",
                    "nested/archive.pfx": "HC_DENY_PFX",
                    "nested/store.jks": "HC_DENY_JKS",
                    "nested/.npmrc": "HC_DENY_NPMRC",
                    "nested/.pypirc": "HC_DENY_PYPIRC",
                    "nested/.netrc": "HC_DENY_NETRC",
                    "nested/.ssh/id_rsa": "HC_DENY_SSH",
                    "nested/.aws/credentials": "HC_DENY_AWS",
                    "nested/.gnupg/private-keys-v1.d/value": "HC_DENY_GNUPG",
                    "nested/auth.json": "HC_DENY_AUTH",
                    "nested/id_ed25519": "HC_DENY_IDENTITY",
                    "nested/service-account.json": "HC_DENY_SERVICE_ACCOUNT",
                    "nested/database-credentials.json": "HC_DENY_CREDENTIAL",
                    "nested/app-secret.txt": "HC_DENY_SECRET",
                }
                for relative, sentinel in secret_probes.items():
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(sentinel + "\n", encoding="utf-8")
                outside_file = outside_root / "outside.txt"
                outside_file.write_text("HC_OUTSIDE_PROBE\n", encoding="utf-8")
                git_metadata = root / ".git"
                git_metadata.mkdir(exist_ok=True)
                (git_metadata / "visible.txt").write_text(
                    "HC_GIT_READ_PROBE\n", encoding="utf-8"
                )
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    prefix=".permission-outside-",
                    suffix=".txt",
                    dir=self.paths.codex_home,
                    delete=False,
                ) as handle:
                    handle.write("HC_CODEX_HOME_OUTSIDE_PROBE\n")
                    codex_home_probe = Path(handle.name)

                def batch_path(path: str | Path) -> str:
                    return str(path).replace("%", "%%").replace("/", "\\")

                main_script = root / "main-profile-probe.bat"
                main_lines = [
                    "@echo off",
                    "@setlocal",
                    "@echo HC_MAIN_PROBE_STARTED",
                    '@findstr /x /c:"HC_NORMAL_PROBE" "normal.txt" >nul 2>&1 && '
                    "echo HC_WORKSPACE_READ_PASS || echo HC_WORKSPACE_READ_FAIL",
                    "@(echo HC_WRITE_PROBE>created.txt) >nul 2>&1 && "
                    "echo HC_WORKSPACE_WRITE_PASS || echo HC_WORKSPACE_WRITE_FAIL",
                    '@findstr /x /c:"HC_GIT_READ_PROBE" ".git\\visible.txt" >nul 2>&1 && '
                    "echo HC_METADATA_READ_PASS || echo HC_METADATA_READ_FAIL",
                    "@(echo HC_GIT_WRITE_PROBE>.git\\blocked.txt) >nul 2>&1 && "
                    "echo HC_METADATA_WRITE_LEAKED || echo HC_METADATA_WRITE_DENIED",
                ]
                for index, relative in enumerate(secret_probes):
                    probe_path = batch_path(relative)
                    main_lines.append(
                        f'@type "{probe_path}" >nul 2>&1 && '
                        f"echo HC_SECRET_{index:02d}_LEAKED || "
                        f"echo HC_SECRET_{index:02d}_DENIED"
                    )
                main_lines.extend(
                    [
                        f'@type "{batch_path(outside_file)}" >nul 2>&1 && '
                        "echo HC_OUTSIDE_LEAKED || echo HC_OUTSIDE_DENIED",
                        f'@type "{batch_path(codex_home_probe)}" >nul 2>&1 && '
                        "echo HC_CODEX_HOME_LEAKED || echo HC_CODEX_HOME_DENIED",
                        "@echo HC_MAIN_PROBE_FINISHED",
                        "@exit /b 0",
                    ]
                )
                main_script.write_text("\n".join(main_lines) + "\n", encoding="utf-8")

                read_only_script = root / "read-only-profile-probe.bat"
                read_only_script.write_text(
                    "@echo off\n@setlocal\n@echo HC_READ_ONLY_PROBE_STARTED\n"
                    '@findstr /x /c:"HC_NORMAL_PROBE" "normal.txt" >nul 2>&1 && '
                    "echo HC_READ_ONLY_READ_PASS || echo HC_READ_ONLY_READ_FAIL\n"
                    "@(echo HC_READ_ONLY_PROBE>blocked.txt) >nul 2>&1 && "
                    "echo HC_READ_ONLY_WRITE_LEAKED || echo HC_READ_ONLY_WRITE_DENIED\n"
                    "@echo HC_READ_ONLY_PROBE_FINISHED\n@exit /b 0\n",
                    encoding="utf-8",
                )

                with AppServerClient(self, timeout=30.0) as client:
                    client.request(
                        "initialize",
                        {
                            "clientInfo": {
                                "name": "human-codex-sandbox-probe",
                                "title": "Human Codex Sandbox Probe",
                                "version": _product_version(),
                            },
                            "capabilities": {"experimentalApi": True},
                        },
                    )
                    client.notify("initialized", {})

                    def sandbox(profile: str, *command: str) -> CommandResult:
                        argv = ("cmd.exe", "/d", "/c", *command)
                        result = client.request(
                            "command/exec",
                            {
                                "command": list(argv),
                                "cwd": str(root),
                                "permissionProfile": profile,
                                "timeoutMs": 20_000,
                            },
                            timeout=30.0,
                        )
                        return CommandResult(
                            args=argv,
                            returncode=int(result.get("exitCode", -1)),
                            stdout=str(result.get("stdout", "")),
                            stderr=str(result.get("stderr", "")),
                        )

                    main = sandbox(self.SECURITY_PROFILE, "call", main_script.name)
                    if progress_callback is not None:
                        try:
                            progress_callback(28, 30)
                        except Exception:
                            pass
                    read_only = sandbox(
                        self.READ_ONLY_PROFILE, "call", read_only_script.name
                    )
                    if progress_callback is not None:
                        try:
                            progress_callback(30, 30)
                        except Exception:
                            pass
                self._permission_profile_diagnostics = {
                    "workspace_read": main.ok
                    and "HC_WORKSPACE_READ_PASS" in main.stdout,
                    "workspace_write": main.ok
                    and "HC_WORKSPACE_WRITE_PASS" in main.stdout
                    and (root / "created.txt").exists(),
                    "metadata_read": main.ok
                    and "HC_METADATA_READ_PASS" in main.stdout,
                    "metadata_write_denied": main.ok
                    and "HC_METADATA_WRITE_DENIED" in main.stdout
                    and "HC_METADATA_WRITE_LEAKED" not in main.stdout
                    and not (git_metadata / "blocked.txt").exists(),
                    "secret_probe_started": "HC_MAIN_PROBE_STARTED" in main.stdout,
                    "secret_probe_finished": "HC_MAIN_PROBE_FINISHED" in main.stdout,
                    "outside_workspace_denied": main.ok
                    and "HC_OUTSIDE_DENIED" in main.stdout
                    and "HC_OUTSIDE_LEAKED" not in main.stdout,
                    "codex_home_command_failed": main.ok
                    and "HC_CODEX_HOME_DENIED" in main.stdout,
                    "codex_home_content_hidden": "HC_CODEX_HOME_LEAKED"
                    not in main.stdout,
                    "read_only_workspace_read": read_only.ok
                    and "HC_READ_ONLY_READ_PASS" in read_only.stdout,
                    "read_only_workspace_write_denied": read_only.ok
                    and "HC_READ_ONLY_WRITE_DENIED" in read_only.stdout
                    and "HC_READ_ONLY_WRITE_LEAKED" not in read_only.stdout
                    and not (root / "blocked.txt").exists(),
                }
                for index, relative in enumerate(secret_probes):
                    check_name = "secret_" + re.sub(r"[^a-z0-9]+", "_", relative.lower()).strip("_")
                    self._permission_profile_diagnostics[check_name] = (
                        main.ok
                        and f"HC_SECRET_{index:02d}_DENIED" in main.stdout
                        and f"HC_SECRET_{index:02d}_LEAKED" not in main.stdout
                    )
                self._permission_profile_enforced = all(
                    self._permission_profile_diagnostics.values()
                )
        except (OSError, subprocess.SubprocessError, UnicodeError, AppServerError) as exc:
            self._permission_profile_diagnostics = {
                "probe_completed": False,
                f"error_{type(exc).__name__}": False,
            }
            self._permission_profile_enforced = False
        finally:
            if codex_home_probe is not None:
                try:
                    codex_home_probe.unlink(missing_ok=True)
                except OSError:
                    self._permission_profile_enforced = False
        return self._permission_profile_enforced

    def unelevated_sandbox_diagnostic(self) -> dict[str, object]:
        """A/B-test restricted-token command launch without changing the secure mode."""

        evidence = self.sandbox_log_evidence()
        base: dict[str, object] = {
            "mode": "unelevated",
            "diagnostic_only": True,
            "configuration_changed": False,
            "command_launch": False,
            "workspace_read": False,
            "workspace_write": False,
            "outside_write_denied": False,
            "exit_code": None,
            "evidence": evidence,
            "error": None,
        }
        if not self.executable or os.name != "nt":
            base["error"] = "unelevated_diagnostic_unavailable"
            return base

        from human_codex.app_server import AppServerClient, AppServerError, _product_version

        temp_parent = self.paths.data_root / "temp" / "sandbox-diagnostic"
        try:
            self.ensure_home()
            temp_parent.mkdir(parents=True, exist_ok=True)
            with (
                tempfile.TemporaryDirectory(
                    prefix="unelevated-workspace-",
                    dir=temp_parent,
                    ignore_cleanup_errors=True,
                ) as temp,
                tempfile.TemporaryDirectory(
                    prefix="unelevated-outside-",
                    dir=temp_parent,
                    ignore_cleanup_errors=True,
                ) as outside,
            ):
                root = Path(temp).resolve()
                outside_root = Path(outside).resolve()
                (root / "normal.txt").write_text(
                    "HC_UNELEVATED_NORMAL\n", encoding="utf-8"
                )
                normal_target = root / "normal.txt"
                created_target = root / "created.txt"
                outside_target = outside_root / "blocked.txt"
                command_line = (
                    "echo HC_UNELEVATED_STARTED & "
                    '(findstr /x /c:"HC_UNELEVATED_NORMAL" "%HC_DIAG_NORMAL%" '
                    ">nul 2>&1 && echo HC_UNELEVATED_READ_PASS || "
                    "echo HC_UNELEVATED_READ_FAIL) & "
                    '(echo HC_UNELEVATED_WRITE>"%HC_DIAG_CREATED%" 2>nul && '
                    "echo HC_UNELEVATED_WRITE_PASS || echo HC_UNELEVATED_WRITE_FAIL) & "
                    '(echo HC_OUTSIDE_WRITE>"%HC_DIAG_OUTSIDE%" 2>nul && '
                    "echo HC_UNELEVATED_OUTSIDE_LEAKED || "
                    "echo HC_UNELEVATED_OUTSIDE_DENIED) & "
                    "echo HC_UNELEVATED_FINISHED"
                )
                with AppServerClient(
                    self,
                    timeout=25.0,
                    windows_sandbox_override="unelevated",
                ) as client:
                    client.request(
                        "initialize",
                        {
                            "clientInfo": {
                                "name": "human-codex-unelevated-diagnostic",
                                "title": "Human Codex Unelevated Diagnostic",
                                "version": _product_version(),
                            },
                            "capabilities": {"experimentalApi": True},
                        },
                    )
                    client.notify("initialized", {})
                    result = client.request(
                        "command/exec",
                        {
                            "command": [
                                "cmd.exe",
                                "/d",
                                "/s",
                                "/c",
                                command_line,
                            ],
                            "cwd": str(root),
                            "env": {
                                "HC_DIAG_NORMAL": str(normal_target),
                                "HC_DIAG_CREATED": str(created_target),
                                "HC_DIAG_OUTSIDE": str(outside_target),
                            },
                            "sandboxPolicy": {
                                "type": "workspaceWrite",
                                "writableRoots": [str(root)],
                                "networkAccess": False,
                                "excludeSlashTmp": True,
                                "excludeTmpdirEnvVar": True,
                            },
                            "timeoutMs": 15_000,
                        },
                        timeout=25.0,
                    )
                stdout = str(result.get("stdout", ""))
                exit_code = result.get("exitCode")
                command_launch = (
                    exit_code == 0
                    and "HC_UNELEVATED_STARTED" in stdout
                    and "HC_UNELEVATED_FINISHED" in stdout
                )
                base.update(
                    {
                        "command_launch": command_launch,
                        "workspace_read": command_launch
                        and "HC_UNELEVATED_READ_PASS" in stdout,
                        "workspace_write": command_launch
                        and "HC_UNELEVATED_WRITE_PASS" in stdout
                        and created_target.is_file(),
                        "outside_write_denied": command_launch
                        and "HC_UNELEVATED_OUTSIDE_DENIED" in stdout
                        and "HC_UNELEVATED_OUTSIDE_LEAKED" not in stdout
                        and not outside_target.exists(),
                        "exit_code": exit_code
                        if isinstance(exit_code, int)
                        else None,
                        "error": None
                        if command_launch
                        else "unelevated_command_could_not_start",
                    }
                )
        except AppServerError:
            base["error"] = "unelevated_app_server_failed"
        except (CodexRuntimeError, OSError, subprocess.SubprocessError, UnicodeError):
            base["error"] = "unelevated_diagnostic_failed"
        return base

    def corporate_sandbox_test(
        self,
        progress_callback: Callable[[int, int, str], None] | None = None,
        *,
        test_parent: Path | None = None,
    ) -> dict[str, object]:
        """Run a fail-closed restricted-token feasibility suite without enabling chat."""

        total = self.CORPORATE_TEST_TOTAL
        statuses = {check_id: "pending" for check_id, _stage in self.CORPORATE_TEST_CHECKS}
        stages = {check_id: stage for check_id, stage in self.CORPORATE_TEST_CHECKS}
        completed = 0
        error_code: str | None = None
        evidence = self.sandbox_log_evidence()
        diagnostic_markers: dict[str, list[str]] = {}

        def set_status(check_id: str, status: str) -> None:
            nonlocal completed
            if statuses[check_id] != "pending":
                return
            if status not in {"passed", "failed", "unavailable", "dependency_failed"}:
                raise ValueError("invalid corporate sandbox check status")
            statuses[check_id] = status
            completed += 1
            if progress_callback is not None:
                try:
                    progress_callback(completed, total, stages[check_id])
                except Exception:
                    pass

        def set_check(check_id: str, passed: bool, *, available: bool = True) -> None:
            set_status(
                check_id,
                "unavailable" if not available else "passed" if passed else "failed",
            )

        def set_dependency_failed(*check_ids: str) -> None:
            for check_id in check_ids:
                set_status(check_id, "dependency_failed")

        def finish_remaining(*, available: bool = False) -> None:
            for check_id, _stage in self.CORPORATE_TEST_CHECKS:
                if statuses[check_id] == "pending":
                    set_check(check_id, False, available=available)

        def result_payload() -> dict[str, object]:
            required = set(self.CORPORATE_ACTIVATION_REQUIRED_CHECKS)
            checks = [
                {
                    "id": check_id,
                    "stage": stage,
                    "critical": check_id in required,
                    "status": statuses[check_id],
                }
                for check_id, stage in self.CORPORATE_TEST_CHECKS
            ]
            passed = sum(1 for item in checks if item["status"] == "passed")
            required_passed = sum(
                1
                for item in checks
                if item["critical"] and item["status"] == "passed"
            )
            critical_failed = [
                str(item["id"])
                for item in checks
                if item["critical"] and item["status"] != "passed"
            ]
            warning_checks = [
                str(item["id"])
                for item in checks
                if not item["critical"] and item["status"] != "passed"
            ]
            all_passed = passed == total and completed == total
            activation_eligible = not critical_failed and completed == total
            verdict = (
                "candidate"
                if all_passed
                else "eligible_with_warnings"
                if activation_eligible
                else "blocked"
            )
            return {
                "mode": "corporate-restricted-test",
                "backend": "codex-unelevated-restricted-token",
                "test_only": True,
                "configuration_changed": statuses["configuration_unchanged"] != "passed",
                "activation_eligible": activation_eligible,
                "production_approved": False,
                "chat_unlocked": False,
                "checks_total": total,
                "checks_completed": completed,
                "checks_passed": passed,
                "required_checks_total": self.CORPORATE_ACTIVATION_REQUIRED_TOTAL,
                "required_checks_passed": required_passed,
                "critical_failed": critical_failed,
                "warning_checks": warning_checks,
                "verdict": verdict,
                "checks": checks,
                "evidence": evidence,
                "diagnostic_markers": diagnostic_markers,
                "error": error_code,
            }

        set_check("windows_host", os.name == "nt")
        set_check("codex_executable", bool(self.executable))
        if os.name != "nt" or not self.executable:
            error_code = "corporate_sandbox_test_unavailable"
            finish_remaining()
            return result_payload()

        from human_codex.app_server import AppServerClient, AppServerError, _product_version

        root: Path | None = None
        outside_root: Path | None = None
        test_container: Path | None = None
        codex_home_probe: Path | None = None
        codex_home_write: Path | None = None
        junction: Path | None = None
        registry_key = f"Software\\HumanCodex\\SandboxProbe_{uuid.uuid4().hex}"
        listener: socket.socket | None = None
        config_path = self.paths.codex_home / "config.toml"
        config_before: bytes | None = None

        try:
            self.ensure_home()
            config_before = config_path.read_bytes()
            provider_environment = self.paths.codex_environment()
            blocked_environment_names = {
                "OPENAI_API_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "AZURE_CLIENT_SECRET",
                "GITHUB_TOKEN",
            }
            set_check(
                "provider_environment_scrubbed",
                not any(name in provider_environment for name in blocked_environment_names),
            )

            # Test the same path family the user selected for real project work.
            # Keeping the synthetic workspace out of LOCALAPPDATA also avoids
            # conflating project ACLs with protected application-state ACLs.
            test_base = (test_parent or self.paths.repository_root).resolve()
            if not test_base.is_dir():
                raise OSError("corporate sandbox test parent is unavailable")
            test_container = Path(
                tempfile.mkdtemp(prefix=".human-codex-sandbox-", dir=test_base)
            ).resolve()
            root = test_container / "workspace"
            outside_root = test_container / "outside"
            root.mkdir()
            outside_root.mkdir()
            set_check(
                "acl_filesystem",
                self._windows_filesystem_name(root).casefold() in {"ntfs", "refs"},
            )
            set_check("test_root_created", root.is_dir() and outside_root.is_dir())

            normal = root / "normal.txt"
            normal.write_text("HC_CORPORATE_NORMAL\n", encoding="utf-8")
            workspace_created = root / "created.txt"
            outside_file = outside_root / "outside.txt"
            outside_file.write_text("HC_CORPORATE_OUTSIDE\n", encoding="utf-8")
            outside_write = outside_root / "outside-write.txt"
            secret_env = root / ".env"
            secret_env.write_text("HC_CORPORATE_SECRET_ENV\n", encoding="utf-8")
            secret_key = root / "nested" / "private.key"
            secret_key.parent.mkdir(parents=True, exist_ok=True)
            secret_key.write_text("HC_CORPORATE_SECRET_KEY\n", encoding="utf-8")
            metadata = root / ".git"
            metadata.mkdir(exist_ok=True)
            metadata_visible = metadata / "visible.txt"
            metadata_visible.write_text("HC_CORPORATE_GIT\n", encoding="utf-8")
            metadata_write = metadata / "blocked.txt"
            codex_home_probe = self.paths.codex_home / f".corporate-read-{uuid.uuid4().hex}.txt"
            codex_home_probe.write_text("HC_CORPORATE_CODEX_HOME\n", encoding="utf-8")
            codex_home_write = self.paths.codex_home / f".corporate-write-{uuid.uuid4().hex}.txt"

            junction = root / "junction-outside"
            junction_write = outside_root / "junction-write.txt"
            hardlink = root / "hardlink-outside.txt"
            junction_available = False
            hardlink_available = False

            child_created = root / "child-created.txt"
            child_outside_write = outside_root / "child-outside-write.txt"
            readonly_created = root / "readonly-created.txt"
            readonly_child_created = root / "readonly-child-created.txt"
            profile_created = root / "profile-created.txt"

            environment = {
                "HC_WS_NORMAL": str(normal),
                "HC_WS_CREATED": str(workspace_created),
                "HC_OUTSIDE_FILE": str(outside_file),
                "HC_OUTSIDE_WRITE": str(outside_write),
                "HC_CODEX_HOME_FILE": str(codex_home_probe),
                "HC_CODEX_HOME_WRITE": str(codex_home_write),
                "HC_SECRET_ENV": str(secret_env),
                "HC_SECRET_KEY": str(secret_key),
                "HC_METADATA_VISIBLE": str(metadata_visible),
                "HC_METADATA_WRITE": str(metadata_write),
                "HC_JUNCTION_FILE": str(junction / "outside.txt"),
                "HC_JUNCTION_WRITE": str(junction / "junction-write.txt"),
                "HC_HARDLINK_FILE": str(hardlink),
                "HC_CHILD_CREATED": str(child_created),
                "HC_CHILD_OUTSIDE_WRITE": str(child_outside_write),
                "HC_RO_CREATED": str(readonly_created),
                "HC_RO_CHILD_CREATED": str(readonly_child_created),
                "HC_PROFILE_CREATED": str(profile_created),
                "HC_REGISTRY_KEY": registry_key,
            }
            windows_root = Path(
                os.environ.get("SystemRoot")
                or os.environ.get("WINDIR")
                or r"C:\Windows"
            )
            powershell_executable = str(
                windows_root
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "powershell.exe"
            )

            readonly_child_script = root / "readonly-child-probe.bat"
            readonly_child_script.write_text(
                "@echo off\n@(echo HC_RO_CHILD>\"%HC_RO_CHILD_CREATED%\") >nul 2>&1 && "
                "echo HC_RO_CHILD_WRITE_LEAKED || echo HC_RO_CHILD_WRITE_DENIED\n@exit /b 0\n",
                encoding="utf-8",
            )
            readonly_script = root / "readonly-probe.bat"
            readonly_script.write_text(
                "@echo off\n@echo HC_RO_STARTED\n"
                "@type \"%HC_WS_NORMAL%\" >nul 2>&1 && "
                "echo HC_RO_READ_PASS || echo HC_RO_READ_FAIL\n"
                "@(echo HC_RO_WRITE>\"%HC_RO_CREATED%\") >nul 2>&1 && "
                "echo HC_RO_WRITE_LEAKED || echo HC_RO_WRITE_DENIED\n"
                "@type \"%HC_OUTSIDE_FILE%\" >nul 2>&1 && echo HC_RO_OUTSIDE_LEAKED || echo HC_RO_OUTSIDE_DENIED\n"
                "@cmd.exe /d /c readonly-child-probe.bat\n"
                "@echo HC_RO_FINISHED\n@exit /b 0\n",
                encoding="utf-8",
            )
            profile_script = root / "profile-probe.bat"
            profile_script.write_text(
                "@echo off\n@echo HC_PROFILE_STARTED\n"
                "@type \"%HC_WS_NORMAL%\" >nul 2>&1 && "
                "echo HC_PROFILE_READ_PASS || echo HC_PROFILE_READ_FAIL\n"
                "@(echo HC_PROFILE_WRITE>\"%HC_PROFILE_CREATED%\") >nul 2>&1 && "
                "echo HC_PROFILE_WRITE_PASS || echo HC_PROFILE_WRITE_FAIL\n"
                "@type \"%HC_SECRET_ENV%\" >nul 2>&1 && echo HC_PROFILE_ENV_LEAKED || echo HC_PROFILE_ENV_DENIED\n"
                "@type \"%HC_SECRET_KEY%\" >nul 2>&1 && echo HC_PROFILE_KEY_LEAKED || echo HC_PROFILE_KEY_DENIED\n"
                "@(echo HC_PROFILE_GIT>\"%HC_METADATA_WRITE%\") >nul 2>&1 && "
                "echo HC_PROFILE_METADATA_LEAKED || echo HC_PROFILE_METADATA_DENIED\n"
                "@type \"%HC_OUTSIDE_FILE%\" >nul 2>&1 && echo HC_PROFILE_OUTSIDE_LEAKED || echo HC_PROFILE_OUTSIDE_DENIED\n"
                "@echo HC_PROFILE_FINISHED\n@exit /b 0\n",
                encoding="utf-8",
            )
            direct_script = root / "direct-probe.bat"
            direct_script.write_text(
                "@echo off\n@echo HC_DIRECT_STARTED\n"
                "@type \"%HC_WS_NORMAL%\" >nul 2>&1 && echo HC_WS_READ_PASS || echo HC_WS_READ_FAIL\n"
                "@(echo HC_WS_WRITE>\"%HC_WS_CREATED%\") >nul 2>&1 && echo HC_WS_WRITE_PASS || echo HC_WS_WRITE_FAIL\n"
                "@type \"%HC_OUTSIDE_FILE%\" >nul 2>&1 && echo HC_OUTSIDE_READ_LEAKED || echo HC_OUTSIDE_READ_DENIED\n"
                "@(echo HC_OUTSIDE_WRITE>\"%HC_OUTSIDE_WRITE%\") >nul 2>&1 && echo HC_OUTSIDE_WRITE_LEAKED || echo HC_OUTSIDE_WRITE_DENIED\n"
                "@type \"%HC_CODEX_HOME_FILE%\" >nul 2>&1 && echo HC_CODEX_HOME_READ_LEAKED || echo HC_CODEX_HOME_READ_DENIED\n"
                "@(echo HC_CODEX_HOME_WRITE>\"%HC_CODEX_HOME_WRITE%\") >nul 2>&1 && echo HC_CODEX_HOME_WRITE_LEAKED || echo HC_CODEX_HOME_WRITE_DENIED\n"
                "@type \"%HC_SECRET_ENV%\" >nul 2>&1 && echo HC_SECRET_ENV_LEAKED || echo HC_SECRET_ENV_DENIED\n"
                "@type \"%HC_SECRET_KEY%\" >nul 2>&1 && echo HC_SECRET_KEY_LEAKED || echo HC_SECRET_KEY_DENIED\n"
                "@type \"%HC_METADATA_VISIBLE%\" >nul 2>&1 && echo HC_METADATA_READ_PASS || echo HC_METADATA_READ_FAIL\n"
                "@(echo HC_METADATA_WRITE>\"%HC_METADATA_WRITE%\") >nul 2>&1 && echo HC_METADATA_WRITE_LEAKED || echo HC_METADATA_WRITE_DENIED\n"
                "@echo HC_DIRECT_FINISHED\n@exit /b 0\n",
                encoding="utf-8",
            )
            link_script = root / "link-probe.bat"
            link_script.write_text(
                "@echo off\n"
                "@type \"%HC_JUNCTION_FILE%\" >nul 2>&1 && echo HC_JUNCTION_READ_LEAKED || echo HC_JUNCTION_READ_DENIED\n"
                "@(echo HC_JUNCTION_WRITE>\"%HC_JUNCTION_WRITE%\") >nul 2>&1 && echo HC_JUNCTION_WRITE_LEAKED || echo HC_JUNCTION_WRITE_DENIED\n"
                "@type \"%HC_HARDLINK_FILE%\" >nul 2>&1 && echo HC_HARDLINK_READ_LEAKED || echo HC_HARDLINK_READ_DENIED\n"
                "@(echo HC_HARDLINK_WRITE>\"%HC_HARDLINK_FILE%\") >nul 2>&1 && echo HC_HARDLINK_WRITE_LEAKED || echo HC_HARDLINK_WRITE_DENIED\n"
                "@echo HC_LINK_FINISHED\n@exit /b 0\n",
                encoding="utf-8",
            )
            child_script = root / "child-probe.bat"
            child_script.write_text(
                "@echo off\n@echo HC_CHILD_STARTED\n"
                "@(echo HC_CHILD_WRITE>\"%HC_CHILD_CREATED%\") >nul 2>&1 && echo HC_CHILD_WORKSPACE_WRITE_PASS || echo HC_CHILD_WORKSPACE_WRITE_FAIL\n"
                "@type \"%HC_OUTSIDE_FILE%\" >nul 2>&1 && echo HC_CHILD_OUTSIDE_READ_LEAKED || echo HC_CHILD_OUTSIDE_READ_DENIED\n"
                "@(echo HC_CHILD_OUTSIDE>\"%HC_CHILD_OUTSIDE_WRITE%\") >nul 2>&1 && echo HC_CHILD_OUTSIDE_WRITE_LEAKED || echo HC_CHILD_OUTSIDE_WRITE_DENIED\n"
                "@type \"%HC_SECRET_ENV%\" >nul 2>&1 && echo HC_CHILD_SECRET_LEAKED || echo HC_CHILD_SECRET_DENIED\n"
                "@echo HC_CHILD_FINISHED\n@exit /b 0\n",
                encoding="utf-8",
            )

            def output(result: dict[str, object] | None) -> str:
                return str(result.get("stdout", "")) if result is not None else ""

            def successful(result: dict[str, object] | None, marker: str) -> bool:
                return (
                    result is not None
                    and result.get("exitCode") == 0
                    and marker in output(result)
                )

            def denied(result: dict[str, object] | None, denied_marker: str, leaked_marker: str) -> bool:
                captured = output(result)
                return successful(result, denied_marker) and leaked_marker not in captured

            def execute(
                client: AppServerClient,
                command: list[str],
                *,
                policy: dict[str, object] | None = None,
                permission_profile: str | None = None,
                timeout_ms: int = 12_000,
            ) -> dict[str, object] | None:
                nonlocal error_code
                params: dict[str, object] = {
                    "command": command,
                    "cwd": str(root),
                    "env": environment,
                    "timeoutMs": timeout_ms,
                }
                if policy is not None:
                    params["sandboxPolicy"] = policy
                if permission_profile is not None:
                    params["permissionProfile"] = permission_profile
                try:
                    result = client.request(
                        "command/exec",
                        params,
                        timeout=max(20.0, timeout_ms / 1_000 + 8.0),
                    )
                except (AppServerError, OSError, subprocess.SubprocessError, UnicodeError):
                    return None
                return result if isinstance(result, dict) else None

            write_policy: dict[str, object] = {
                "type": "workspaceWrite",
                "writableRoots": [str(root)],
                "networkAccess": False,
                "excludeSlashTmp": True,
                "excludeTmpdirEnvVar": True,
            }
            with AppServerClient(
                self,
                timeout=30.0,
                windows_sandbox_override="unelevated",
                default_permissions_override=":workspace",
                process_cwd_override=self.paths.app_server_working_root,
            ) as client:
                client.request(
                    "initialize",
                    {
                        "clientInfo": {
                            "name": "human-codex-corporate-sandbox-test",
                            "title": "Human Codex Corporate Sandbox Test",
                            "version": _product_version(),
                        },
                        "capabilities": {"experimentalApi": True},
                    },
                )
                client.notify("initialized", {})

                acl_warmup = execute(
                    client,
                    ["cmd.exe", "/d", "/c", "echo", "HC_ACL_READY"],
                    policy=write_policy,
                )
                diagnostic_markers["acl_warmup"] = sorted(
                    set(re.findall(r"HC_[A-Z0-9_]+", output(acl_warmup)))
                )[:8]
                if not successful(acl_warmup, "HC_ACL_READY"):
                    raise CodexRuntimeError("corporate_workspace_acl_warmup_failed")
                self.prepare_corporate_workspace_roots(
                    [
                        root,
                        self.paths.repository_root.resolve(),
                        self.paths.workspace_root.resolve(),
                        self.paths.app_server_working_root,
                    ]
                )

                direct = execute(
                    client,
                    ["cmd.exe", "/d", "/c", "call", direct_script.name],
                    policy=write_policy,
                )
                diagnostic_markers["direct"] = sorted(
                    set(re.findall(r"HC_[A-Z0-9_]+", output(direct)))
                )[:64]
                set_check("direct_command_launch", successful(direct, "HC_DIRECT_STARTED"))
                set_check("direct_command_finished", successful(direct, "HC_DIRECT_FINISHED"))
                set_check("workspace_read", successful(direct, "HC_WS_READ_PASS"))
                set_check(
                    "workspace_write",
                    successful(direct, "HC_WS_WRITE_PASS") and workspace_created.is_file(),
                )
                set_check(
                    "outside_read_denied",
                    denied(direct, "HC_OUTSIDE_READ_DENIED", "HC_OUTSIDE_READ_LEAKED"),
                )
                set_check(
                    "outside_write_denied",
                    denied(direct, "HC_OUTSIDE_WRITE_DENIED", "HC_OUTSIDE_WRITE_LEAKED")
                    and not outside_write.exists(),
                )
                set_check(
                    "codex_home_read_denied",
                    denied(direct, "HC_CODEX_HOME_READ_DENIED", "HC_CODEX_HOME_READ_LEAKED"),
                )
                set_check(
                    "codex_home_write_denied",
                    denied(direct, "HC_CODEX_HOME_WRITE_DENIED", "HC_CODEX_HOME_WRITE_LEAKED")
                    and not codex_home_write.exists(),
                )
                set_check(
                    "secret_env_read_denied",
                    denied(direct, "HC_SECRET_ENV_DENIED", "HC_SECRET_ENV_LEAKED"),
                )
                set_check(
                    "secret_key_read_denied",
                    denied(direct, "HC_SECRET_KEY_DENIED", "HC_SECRET_KEY_LEAKED"),
                )
                set_check("metadata_read", successful(direct, "HC_METADATA_READ_PASS"))
                set_check(
                    "metadata_write_denied",
                    denied(direct, "HC_METADATA_WRITE_DENIED", "HC_METADATA_WRITE_LEAKED")
                    and not metadata_write.exists(),
                )
                # Create escape artifacts only after the baseline workspace probe.
                # Otherwise the sandbox's own preflight can reject the whole root
                # before ordinary project read/write is measured.
                junction_available = self._create_directory_junction(
                    junction, outside_root
                )
                try:
                    os.link(outside_file, hardlink)
                    hardlink_available = hardlink.is_file()
                except OSError:
                    hardlink_available = False
                links = execute(
                    client,
                    ["cmd.exe", "/d", "/c", "call", link_script.name],
                    policy=write_policy,
                )
                diagnostic_markers["links"] = sorted(
                    set(re.findall(r"HC_[A-Z0-9_]+", output(links)))
                )[:24]
                set_check(
                    "junction_read_denied",
                    denied(links, "HC_JUNCTION_READ_DENIED", "HC_JUNCTION_READ_LEAKED"),
                    available=junction_available,
                )
                set_check(
                    "junction_write_denied",
                    denied(links, "HC_JUNCTION_WRITE_DENIED", "HC_JUNCTION_WRITE_LEAKED")
                    and not junction_write.exists(),
                    available=junction_available,
                )
                set_check(
                    "hardlink_read_denied",
                    denied(links, "HC_HARDLINK_READ_DENIED", "HC_HARDLINK_READ_LEAKED"),
                    available=hardlink_available,
                )
                set_check(
                    "hardlink_write_denied",
                    denied(links, "HC_HARDLINK_WRITE_DENIED", "HC_HARDLINK_WRITE_LEAKED")
                    and outside_file.read_text(encoding="utf-8") == "HC_CORPORATE_OUTSIDE\n",
                    available=hardlink_available,
                )
                if junction.exists():
                    try:
                        os.rmdir(junction)
                    except OSError:
                        pass
                try:
                    hardlink.unlink(missing_ok=True)
                except OSError:
                    pass

                child_line = (
                    "& $env:ComSpec /d /c call child-probe.bat;"
                    "exit $LASTEXITCODE"
                )
                child = execute(
                    client,
                    [
                        powershell_executable,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        child_line,
                    ],
                    policy=write_policy,
                )
                diagnostic_markers["child"] = sorted(
                    set(re.findall(r"HC_[A-Z0-9_]+", output(child)))
                )[:32]
                set_check(
                    "child_command_launch",
                    successful(child, "HC_CHILD_STARTED")
                    and successful(child, "HC_CHILD_FINISHED"),
                )
                set_check(
                    "child_workspace_write",
                    successful(child, "HC_CHILD_WORKSPACE_WRITE_PASS")
                    and child_created.is_file(),
                )
                set_check(
                    "child_outside_read_denied",
                    denied(child, "HC_CHILD_OUTSIDE_READ_DENIED", "HC_CHILD_OUTSIDE_READ_LEAKED"),
                )
                set_check(
                    "child_outside_write_denied",
                    denied(child, "HC_CHILD_OUTSIDE_WRITE_DENIED", "HC_CHILD_OUTSIDE_WRITE_LEAKED")
                    and not child_outside_write.exists(),
                )
                set_check(
                    "child_secret_read_denied",
                    denied(child, "HC_CHILD_SECRET_DENIED", "HC_CHILD_SECRET_LEAKED"),
                )

                readonly = execute(
                    client,
                    ["cmd.exe", "/d", "/c", "call", readonly_script.name],
                    permission_profile=":read-only",
                )
                diagnostic_markers["read_only"] = sorted(
                    set(re.findall(r"HC_[A-Z0-9_]+", output(readonly)))
                )[:24]
                readonly_launched = (
                    successful(readonly, "HC_RO_STARTED")
                    and successful(readonly, "HC_RO_FINISHED")
                )
                set_check(
                    "readonly_command_launch",
                    readonly_launched,
                )
                if readonly_launched:
                    set_check("readonly_workspace_read", successful(readonly, "HC_RO_READ_PASS"))
                    set_check(
                        "readonly_workspace_write_denied",
                        denied(readonly, "HC_RO_WRITE_DENIED", "HC_RO_WRITE_LEAKED")
                        and not readonly_created.exists(),
                    )
                    set_check(
                        "readonly_outside_read_denied",
                        denied(readonly, "HC_RO_OUTSIDE_DENIED", "HC_RO_OUTSIDE_LEAKED"),
                    )
                    set_check(
                        "readonly_child_write_denied",
                        denied(readonly, "HC_RO_CHILD_WRITE_DENIED", "HC_RO_CHILD_WRITE_LEAKED")
                        and not readonly_child_created.exists(),
                    )
                else:
                    set_dependency_failed(
                        "readonly_workspace_read",
                        "readonly_workspace_write_denied",
                        "readonly_outside_read_denied",
                        "readonly_child_write_denied",
                    )

                loopback_available = False
                loopback_port = 0
                try:
                    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    listener.settimeout(8.0)
                    loopback_port = int(listener.getsockname()[1])
                    loopback_available = loopback_port > 0
                    def answer_loopback(server: socket.socket = listener) -> None:
                        try:
                            connection, _address = server.accept()
                            with connection:
                                connection.sendall(
                                    b"HTTP/1.1 204 No Content\r\n"
                                    b"Connection: close\r\n\r\n"
                                )
                        except OSError:
                            pass

                    threading.Thread(target=answer_loopback, daemon=True).start()
                except OSError:
                    if listener is not None:
                        listener.close()
                        listener = None
                environment["HC_LOOPBACK_PORT"] = str(loopback_port)
                powershell_line = (
                    "Write-Output 'HC_PS_STARTED';"
                    "Write-Output 'HC_PS_FINISHED';exit 0"
                )
                powershell = execute(
                    client,
                    [
                        powershell_executable,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        powershell_line,
                    ],
                    policy=write_policy,
                    timeout_ms=15_000,
                )
                set_check(
                    "powershell_probe_launch",
                    successful(powershell, "HC_PS_STARTED")
                    and successful(powershell, "HC_PS_FINISHED"),
                )
                network_line = (
                    "$ErrorActionPreference='Stop';"
                    "function Test-HcTcp([string]$Address,[int]$Port){"
                    "$client=$null;try{$client=[Net.Sockets.TcpClient]::new();"
                    "$task=$client.ConnectAsync($Address,$Port);"
                    "$connected=$task.Wait(3000)-and $client.Connected;return $connected}"
                    "catch{return $false}finally{if($null-ne $client){$client.Dispose()}}};"
                    "if(Test-HcTcp '1.1.1.1' 443){'HC_IPV4_LEAKED'}else{'HC_IPV4_DENIED'};"
                    "try{$addresses=[Net.Dns]::GetHostAddresses('example.com');"
                    "if($addresses.Count-gt 0){'HC_DNS_LEAKED'}else{'HC_DNS_DENIED'}}"
                    "catch{'HC_DNS_DENIED'};"
                    "if(Test-HcTcp '127.0.0.1' ([int]$env:HC_LOOPBACK_PORT))"
                    "{'HC_LOOPBACK_LEAKED'}else{'HC_LOOPBACK_DENIED'};"
                    "try{$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
                    "$principal=[Security.Principal.WindowsPrincipal]::new($identity);"
                    "if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
                    "{'HC_ADMIN_LEAKED'}else{'HC_ADMIN_DENIED'}}catch{'HC_ADMIN_DENIED'};"
                    "try{New-Item -Path ('Registry::HKEY_CURRENT_USER\\'+$env:HC_REGISTRY_KEY) "
                    "-Force|Out-Null;'HC_REGISTRY_LEAKED'}catch{'HC_REGISTRY_DENIED'};"
                    "'HC_NETWORK_FINISHED';exit 0"
                )
                network = execute(
                    client,
                    [
                        powershell_executable,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        network_line,
                    ],
                    policy=write_policy,
                    timeout_ms=18_000,
                )
                diagnostic_markers["network"] = sorted(
                    set(re.findall(r"HC_[A-Z0-9_]+", output(network)))
                )[:24]
                set_check(
                    "outbound_ipv4_denied",
                    denied(network, "HC_IPV4_DENIED", "HC_IPV4_LEAKED"),
                )
                set_check(
                    "dns_denied",
                    denied(network, "HC_DNS_DENIED", "HC_DNS_LEAKED"),
                )
                set_check(
                    "loopback_denied",
                    denied(network, "HC_LOOPBACK_DENIED", "HC_LOOPBACK_LEAKED"),
                    available=loopback_available,
                )
                set_check(
                    "administrator_token_denied",
                    denied(network, "HC_ADMIN_DENIED", "HC_ADMIN_LEAKED"),
                )
                set_check(
                    "registry_write_denied",
                    denied(network, "HC_REGISTRY_DENIED", "HC_REGISTRY_LEAKED")
                    and not self._registry_probe_present(registry_key),
                )
                if listener is not None:
                    listener.close()
                    listener = None

                profile = execute(
                    client,
                    ["cmd.exe", "/d", "/c", "call", profile_script.name],
                    permission_profile=self.SECURITY_PROFILE,
                    timeout_ms=15_000,
                )
                diagnostic_markers["profile"] = sorted(
                    set(re.findall(r"HC_[A-Z0-9_]+", output(profile)))
                )[:24]
                profile_launched = (
                    successful(profile, "HC_PROFILE_STARTED")
                    and successful(profile, "HC_PROFILE_FINISHED")
                )
                set_check(
                    "profile_command_launch",
                    profile_launched,
                )
                if profile_launched:
                    set_check("profile_workspace_read", successful(profile, "HC_PROFILE_READ_PASS"))
                    set_check(
                        "profile_workspace_write",
                        successful(profile, "HC_PROFILE_WRITE_PASS") and profile_created.is_file(),
                    )
                    set_check(
                        "profile_secret_env_denied",
                        denied(profile, "HC_PROFILE_ENV_DENIED", "HC_PROFILE_ENV_LEAKED"),
                    )
                    set_check(
                        "profile_secret_key_denied",
                        denied(profile, "HC_PROFILE_KEY_DENIED", "HC_PROFILE_KEY_LEAKED"),
                    )
                    set_check(
                        "profile_metadata_write_denied",
                        denied(profile, "HC_PROFILE_METADATA_DENIED", "HC_PROFILE_METADATA_LEAKED")
                        and not metadata_write.exists(),
                    )
                    set_check(
                        "profile_outside_read_denied",
                        denied(profile, "HC_PROFILE_OUTSIDE_DENIED", "HC_PROFILE_OUTSIDE_LEAKED"),
                    )
                else:
                    set_dependency_failed(
                        "profile_workspace_read",
                        "profile_workspace_write",
                        "profile_secret_env_denied",
                        "profile_secret_key_denied",
                        "profile_metadata_write_denied",
                        "profile_outside_read_denied",
                    )
        except (AppServerError, CodexRuntimeError, OSError, subprocess.SubprocessError, UnicodeError):
            if error_code is None:
                error_code = "corporate_sandbox_test_failed"
        finally:
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            config_unchanged = False
            try:
                config_unchanged = config_before is not None and config_path.read_bytes() == config_before
            except OSError:
                config_unchanged = False
            set_check("configuration_unchanged", config_unchanged)

            self._remove_registry_probe(registry_key)
            set_check("registry_cleanup", not self._registry_probe_present(registry_key))

            if junction is not None:
                try:
                    if junction.exists():
                        os.rmdir(junction)
                except OSError:
                    pass
            for path in (codex_home_probe, codex_home_write):
                if path is not None:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
            if test_container is not None:
                try:
                    shutil.rmtree(test_container)
                except OSError:
                    pass
            filesystem_cleanup = all(
                path is None or not path.exists()
                for path in (
                    test_container,
                    root,
                    outside_root,
                    codex_home_probe,
                    codex_home_write,
                )
            )
            set_check("filesystem_cleanup", filesystem_cleanup)

        finish_remaining()
        return result_payload()

    def prepare_corporate_workspace_roots(self, roots: list[Path]) -> None:
        """Restore the current-user side of the unelevated token access check.

        Codex adds a restricted SID ACE to each writable root. Some managed-PC
        ACL layouts lose the current user's explicit ACE during that operation,
        so Windows' normal-token half of the access check denies the same root.
        Adding one inheritable current-user Modify ACE keeps the restricted SID
        boundary intact while making the selected root usable.
        """

        if os.name != "nt":
            raise CodexRuntimeError("corporate_workspace_acl_requires_windows")
        if not roots:
            raise CodexRuntimeError("corporate_workspace_root_required")

        windows_root = Path(
            os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        )
        system32 = windows_root / "System32"
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            identity = subprocess.run(
                [str(system32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                capture_output=True,
                check=False,
                timeout=15.0,
                creationflags=creation_flags,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CodexRuntimeError("corporate_workspace_user_sid_unavailable") from exc
        sid_match = re.search(rb"S-1-(?:\d+-)+\d+", identity.stdout or b"")
        if identity.returncode != 0 or sid_match is None:
            raise CodexRuntimeError("corporate_workspace_user_sid_unavailable")
        sid = sid_match.group(0).decode("ascii")

        for root in roots:
            resolved = root.resolve()
            if not resolved.is_dir():
                raise CodexRuntimeError("corporate_workspace_root_unavailable")
            if self._windows_filesystem_name(resolved).casefold() not in {"ntfs", "refs"}:
                raise CodexRuntimeError("corporate_workspace_acl_filesystem_required")
            try:
                grant = subprocess.run(
                    [
                        str(system32 / "icacls.exe"),
                        str(resolved),
                        "/grant",
                        f"*{sid}:(OI)(CI)(M)",
                        "/Q",
                    ],
                    capture_output=True,
                    check=False,
                    timeout=120.0,
                    creationflags=creation_flags,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise CodexRuntimeError("corporate_workspace_acl_grant_failed") from exc
            if grant.returncode != 0:
                raise CodexRuntimeError("corporate_workspace_acl_grant_failed")

    @staticmethod
    def _windows_filesystem_name(path: Path) -> str:
        if os.name != "nt":
            return ""
        try:
            import ctypes

            volume_path = ctypes.create_unicode_buffer(261)
            filesystem = ctypes.create_unicode_buffer(261)
            if not ctypes.windll.kernel32.GetVolumePathNameW(
                str(path), volume_path, len(volume_path)
            ):
                return ""
            if not ctypes.windll.kernel32.GetVolumeInformationW(
                volume_path.value,
                None,
                0,
                None,
                None,
                None,
                filesystem,
                len(filesystem),
            ):
                return ""
            return filesystem.value
        except (AttributeError, OSError, ValueError):
            return ""

    @staticmethod
    def _create_directory_junction(link: Path, target: Path) -> bool:
        if os.name != "nt":
            return False
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        try:
            completed = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5.0,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0 and link.exists()

    @staticmethod
    def _registry_probe_present(relative_key: str) -> bool:
        if os.name != "nt":
            return False
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, relative_key):
                return True
        except FileNotFoundError:
            return False
        except OSError:
            return True

    @staticmethod
    def _remove_registry_probe(relative_key: str) -> None:
        if os.name != "nt":
            return
        try:
            import winreg

            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, relative_key)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def sandbox_log_evidence(self) -> list[str]:
        """Return only allowlisted policy indicators, never raw sandbox log text."""

        sandbox_root = self.paths.codex_home / ".sandbox"
        try:
            candidates = sorted(
                (path for path in sandbox_root.glob("*.log*") if path.is_file()),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )[:8]
        except OSError:
            return []
        chunks: list[str] = []
        for path in candidates:
            try:
                with path.open("rb") as handle:
                    handle.seek(0, os.SEEK_END)
                    length = handle.tell()
                    handle.seek(max(0, length - 524_288), os.SEEK_SET)
                    chunks.append(handle.read(524_288).decode("utf-8", errors="ignore"))
            except OSError:
                continue
        content = "\n".join(chunks).casefold()
        evidence: list[str] = []
        if (
            re.search(r"(?<!\d)1385(?!\d)", content)
            or "error_logon_type_not_granted" in content
            or "0x80070569" in content
        ):
            evidence.append("windows_error_1385")
        if any(
            marker in content
            for marker in ("applocker", "windows defender application control", "wdac")
        ):
            evidence.append("application_control")
        if any(
            marker in content
            for marker in (
                "access is denied",
                "access denied",
                "0xc0000022",
                "액세스가 거부",
            )
        ):
            evidence.append("access_denied")
        return evidence

    def reset_permission_profile_probe(self) -> None:
        """Require the native sandbox proof to run again after setup changes."""

        self._permission_profile_enforced = None
        self._permission_profile_diagnostics = {}

    def sandbox_setup_marker_present(self) -> bool:
        """Return whether elevated setup completed for this app-local Codex home."""

        return (self.paths.codex_home / ".sandbox" / "setup_marker.json").is_file()

    @property
    def permission_profile_diagnostics(self) -> dict[str, bool]:
        """Return safe pass/fail details from the most recent native proof."""

        return dict(self._permission_profile_diagnostics)

    def run(
        self, *args: str, timeout: float = 20.0, use_app_home: bool = True
    ) -> CommandResult:
        executable = self.require_executable()
        environment = None
        if use_app_home:
            self.ensure_home()
            environment = self.paths.codex_environment()
        return run_command(
            [executable, *args],
            cwd=self.paths.repository_root,
            env=environment,
            timeout=timeout,
        )

    def version(self) -> str:
        result = self.run("--version", use_app_home=False)
        if not result.ok:
            raise CodexRuntimeError(result.stderr or "codex --version failed")
        match = re.search(r"(\d+\.\d+\.\d+(?:[-+][^\s]+)?)", result.stdout)
        if not match:
            raise CodexRuntimeError(f"unrecognized Codex version: {result.stdout}")
        return match.group(1)

    def inspect(self) -> CodexRuntimeInfo:
        if not self.executable:
            return CodexRuntimeInfo(None, None, False, False, False, "unavailable")
        version = self.version()
        root_help = self.run("--help", use_app_home=False)
        app_help = self.run("app-server", "--help", use_app_home=False)
        login = self.run("login", "status")
        login_text = "\n".join(part for part in (login.stdout, login.stderr) if part)
        if login.ok and "Logged in" in login_text:
            login_status = "logged_in"
        elif "not logged in" in login_text.lower():
            login_status = "required"
        else:
            login_status = "unknown"
        return CodexRuntimeInfo(
            executable=self.executable,
            version=version,
            app_server=root_help.ok and "app-server" in root_help.stdout,
            schema_generation=app_help.ok and "generate-json-schema" in app_help.stdout,
            typescript_generation=app_help.ok and "generate-ts" in app_help.stdout,
            login_status=login_status,
        )

    def doctor(self) -> CommandResult:
        return self.run("doctor", "--json", timeout=60.0)

    def login(self, *, device_auth: bool = False) -> int:
        executable = self.require_executable()
        self.ensure_home()
        args = [executable, "login"]
        if device_auth:
            args.append("--device-auth")
        completed = subprocess.run(
            args,
            cwd=str(self.paths.repository_root),
            env=self.paths.codex_environment(),
            check=False,
        )
        return completed.returncode
