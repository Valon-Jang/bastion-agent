from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from human_codex.workspace import WorkspacePolicy


@dataclass(frozen=True)
class RiskAssessment:
    level: str
    decision: str
    action: str
    reason: str
    side_effect: str
    requires_snapshot: bool
    allowed_scopes: tuple[str, ...]


class RiskEngine:
    """Deterministic product policy; model-provided safety claims are never inputs."""

    LEVELS = ("R0", "R1", "R2", "R3", "R4")
    BLOCKED_COMMANDS = (
        re.compile(r"\bgit(?:\.exe)?\b[^\r\n;&|]{0,200}\bpush\b", re.IGNORECASE),
        re.compile(r"\bgit(?:\.exe)?\b[^\r\n;&|]{0,200}\bremote\s+(?:add|set-url|rename)\b", re.IGNORECASE),
        re.compile(r"\bgit(?:\.exe)?\b[^\r\n;&|]{0,200}\bconfig\b[^\r\n;&|]{0,200}\bremote\.", re.IGNORECASE),
        re.compile(r"\bgh(?:\.exe)?\s+repo\s+create\b", re.IGNORECASE),
        re.compile(r"\bforce[- ]?push\b", re.IGNORECASE),
        re.compile(r"chatgpt.*(?:scrape|output)", re.IGNORECASE),
    )
    SECRET_READ = re.compile(
        r"(?:type|get-content|cat|more|copy|tar|zip|7z).*"
        r"(?:\.env(?:\s|$)|\.(?:pem|key|p12|pfx|jks)\b|\.npmrc\b|\.pypirc\b|"
        r"\.netrc\b|\.git-credentials\b|auth\.json\b|token\.json\b|service-account\.json\b|"
        r"id_(?:dsa|ecdsa|ed25519|rsa)\b|\.ssh(?:[\\/]|$)|\.aws(?:[\\/]|$)|"
        r"\.gnupg(?:[\\/]|$)|credential|secret)",
        re.IGNORECASE,
    )
    SECRET_TARGET = re.compile(r"(^|[\\/])(?:\.env(?:\.|$)|\.ssh(?:[\\/]|$)|[^\\/]*\.(?:pem|key)$|[^\\/]*(?:credential|secret|auth(?:entication)?)[^\\/]*)", re.IGNORECASE)

    def __init__(self, workspace: WorkspacePolicy) -> None:
        self.workspace = workspace

    def assess(
        self,
        project_id: str,
        *,
        action: str,
        targets: Iterable[str] = (),
        command: str | None = None,
        strict: bool = False,
    ) -> RiskAssessment:
        normalized_command = re.sub(r"['\"]", "", (command or "").strip())
        normalized_command = re.sub(r"[`^](?=[A-Za-z])", "", normalized_command)
        if "[REDACTED_SECRET]" in normalized_command:
            return self._result(
                "R4",
                "block",
                action,
                "Credential material was redacted before approval",
                "Credential disclosure",
            )
        if any(pattern.search(normalized_command) for pattern in self.BLOCKED_COMMANDS):
            return self._result("R4", "block", action, "Remote push and prohibited automation are globally blocked", "Prohibited external or irreversible side effect")
        if self.SECRET_READ.search(normalized_command):
            return self._result("R4", "block", action, "Secret or authentication material must not be printed or archived", "Credential disclosure")
        target_values = [target for target in targets if target]
        if any(self.SECRET_TARGET.search(target) for target in target_values):
            return self._result("R4", "block", action, "Secret and authentication paths are denied", "Credential disclosure or modification")
        if action == "permission_escalation":
            return self._result(
                "R4",
                "block",
                action,
                "Runtime permission expansion is disabled; add an approved root in Human Codex instead",
                "Native filesystem or network boundary expansion",
            )
        path_classes = [
            self.workspace.classify_path(project_id, target, write=action not in {"read", "search", "metadata"})
            for target in target_values
        ]
        if "system" in path_classes:
            return self._result("R4", "approval", action, "Target is inside a protected system directory", "System configuration or integrity change", scopes=("once",))
        if "read_only_root" in path_classes or "external" in path_classes:
            return self._result("R2", "approval", action, "Target is outside an approved writable root", "External-root write", scopes=("once", "task"))

        command_action = self._classify_command(normalized_command) if normalized_command else action
        if command_action in {"remote_push", "secret_access"}:
            return self._result("R4", "block", command_action, "Action is globally blocked", "Credential or remote side effect")
        if command_action in {"admin", "registry", "firewall", "service"}:
            return self._result("R4", "approval", command_action, "Administrative system action requires detailed approval", "System-wide change", scopes=("once",))
        if command_action in {"delete", "install", "settings", "git_init", "restore"}:
            return self._result("R3", "approval", command_action, "Destructive or configuration action requires approval", "Deletion, installation, or configuration change", scopes=("once",))
        if command_action in {"build", "execute", "download", "commit", "merge", "external_write", "unknown_command"}:
            return self._result("R2", "approval", command_action, "Executable or repository side effect requires project approval", "Process, build, or repository mutation", scopes=("once", "task", "session"))
        if command_action in {"edit", "test", "temp"}:
            if strict:
                return self._result("R1", "approval", command_action, "Strict project profile requires approval for edits/tests", "Reversible project-local change", snapshot=True, scopes=("once", "task"))
            return self._result("R1", "snapshot", command_action, "Project-local reversible action", "Project files or test artifacts may change", snapshot=True)
        return self._result("R0", "auto", command_action, "Read-only analysis inside approved roots", "No intended side effect")

    @staticmethod
    def _classify_command(command: str) -> str:
        lowered = command.casefold()
        if not lowered:
            return "read"
        if re.search(r"\bgit(?:\.exe)?\b[^\r\n;&|]{0,200}\bpush\b", lowered):
            return "remote_push"
        if re.search(r"\bgit\s+init\b", lowered):
            return "git_init"
        if re.search(r"\bgit\s+commit\b", lowered):
            return "commit"
        if re.search(r"\bgit\s+(merge|rebase)\b", lowered):
            return "merge"
        if re.search(r"(?:remove-item|\brm\b|\bdel\b|\brmdir\b|\bgit\s+clean\b)", lowered):
            return "delete"
        if re.search(r"(?:reg(?:\.exe)?\s+(?:add|delete)|set-itemproperty.*registry)", lowered):
            return "registry"
        if re.search(r"(?:netsh.*firewall|new-netfirewallrule|set-netfirewallprofile)", lowered):
            return "firewall"
        if re.search(r"(?:sc(?:\.exe)?\s+(?:create|delete|config)|new-service|set-service)", lowered):
            return "service"
        if re.search(r"(?:runas|start-process.*-verb\s+runas|sudo\b)", lowered):
            return "admin"
        if re.search(r"(?:pip|npm|winget|choco|scoop)\s+(?:install|add)\b|\.msi\b|\.exe\b", lowered):
            return "install"
        if re.search(r"(?:pytest|unittest|npm\s+(?:run\s+)?test|node\s+--test|dotnet\s+test)", lowered):
            return "test"
        if re.search(r"(?:npm\s+run\s+build|vite\s+build|dotnet\s+build|cargo\s+build|cmake\s+--build)", lowered):
            return "build"
        if re.search(r"(?:rg\b|git\s+(?:status|diff|log|show)\b|get-childitem|\bdir\b|\bls\b|type\b|get-content|\bcat\b)", lowered):
            return "read"
        return "unknown_command"

    @staticmethod
    def _result(
        level: str,
        decision: str,
        action: str,
        reason: str,
        side_effect: str,
        *,
        snapshot: bool = False,
        scopes: tuple[str, ...] = ("once",),
    ) -> RiskAssessment:
        return RiskAssessment(level, decision, action, reason, side_effect, snapshot, scopes)
