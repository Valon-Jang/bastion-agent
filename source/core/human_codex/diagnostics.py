from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from human_codex.codex_runtime import CodexRuntime
from human_codex.paths import PortablePaths
from human_codex.process import run_command
from human_codex.schema import verify_pinned_schema
from human_codex.secret_guard import redact_value


def _memory_bytes() -> int | None:
    if os.name != "nt":
        return None

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(MemoryStatus)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return int(status.ullTotalPhys)
    return None


def _is_admin() -> bool | None:
    if os.name != "nt":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return None


def _write_probe(root: Path) -> bool:
    try:
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="hc-write-", dir=root, delete=True):
            pass
        return True
    except OSError:
        return False


def _tcp_probe(host: str, port: int = 443) -> str:
    try:
        with socket.create_connection((host, port), timeout=4):
            return "reachable"
    except OSError as exc:
        return f"unreachable:{type(exc).__name__}"


def _named_pipe_probe() -> bool | None:
    if os.name != "nt":
        return None
    try:
        from multiprocessing.connection import Client, Listener

        address = rf"\\.\pipe\HumanCodexDiag-{uuid.uuid4().hex}"
        listener = Listener(address, family="AF_PIPE")
        result: list[bool] = []

        def connect() -> None:
            connection = Client(address, family="AF_PIPE")
            connection.send("ping")
            result.append(connection.recv() == "pong")
            connection.close()

        thread = threading.Thread(target=connect, daemon=True)
        thread.start()
        connection = listener.accept()
        if connection.recv() == "ping":
            connection.send("pong")
        connection.close()
        listener.close()
        thread.join(timeout=3)
        return result == [True]
    except (OSError, EOFError):
        return False


def _registry_value(root: Any, path: str, name: str) -> Any:
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(root, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except (OSError, ImportError):
        return None


def _office_status() -> dict[str, bool]:
    if os.name != "nt":
        return {"excel": False, "powerpoint": False, "word": False}
    import winreg

    return {
        "excel": _registry_value(
            winreg.HKEY_CLASSES_ROOT, r"Excel.Application\CurVer", ""
        )
        is not None,
        "powerpoint": _registry_value(
            winreg.HKEY_CLASSES_ROOT, r"PowerPoint.Application\CurVer", ""
        )
        is not None,
        "word": _registry_value(
            winreg.HKEY_CLASSES_ROOT, r"Word.Application\CurVer", ""
        )
        is not None,
    }


def _chrome_status() -> dict[str, Any]:
    candidates = []
    for variable, suffix in (
        ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
        ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
        ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
    ):
        base = os.environ.get(variable)
        if base:
            candidates.append(Path(base) / suffix)
    executable = next((path for path in candidates if path.is_file()), None)
    if not executable:
        return {"available": False, "path": None, "version": None}
    result = run_command([str(executable), "--version"], timeout=10)
    return {
        "available": True,
        "path": str(executable),
        "version": result.stdout or None,
    }


def _gpu_status() -> dict[str, Any]:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        return {"status": "unknown", "adapters": []}
    script = (
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name,AdapterRAM,DriverVersion | ConvertTo-Json -Compress"
    )
    result = run_command(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=15,
    )
    if not result.ok or not result.stdout:
        return {"status": "unknown", "adapters": []}
    try:
        adapters = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "unknown", "adapters": []}
    if isinstance(adapters, dict):
        adapters = [adapters]
    return {"status": "detected", "adapters": adapters}


def _windows_sandbox_status() -> str:
    dism = shutil.which("dism.exe")
    if not dism:
        return "unknown"
    result = run_command(
        [
            dism,
            "/Online",
            "/Get-FeatureInfo",
            "/FeatureName:Containers-DisposableClientVM",
            "/English",
        ],
        timeout=30,
    )
    combined = f"{result.stdout}\n{result.stderr}"
    if "State : Enabled" in combined:
        return "enabled"
    if "State : Disabled" in combined:
        return "disabled"
    return "unknown"


def _git_status(project_root: Path) -> dict[str, Any]:
    executable = shutil.which("git")
    if not executable:
        return {"available": False, "version": None, "commit_test": False}
    version = run_command([executable, "--version"]).stdout
    with tempfile.TemporaryDirectory(prefix="human-codex-git-") as temp:
        root = Path(temp)
        init = run_command([executable, "init", "--quiet"], cwd=root)
        if not init.ok:
            return {"available": True, "version": version, "commit_test": False}
        (root / "probe.txt").write_text("probe\n", encoding="utf-8")
        run_command([executable, "add", "probe.txt"], cwd=root)
        commit = run_command(
            [
                executable,
                "-c",
                "user.name=Human Codex Diagnostic",
                "-c",
                "user.email=diagnostic@localhost",
                "commit",
                "--quiet",
                "-m",
                "diagnostic",
            ],
            cwd=root,
        )
    return {"available": True, "version": version, "commit_test": commit.ok}


def collect_diagnostics(paths: PortablePaths) -> dict[str, Any]:
    runtime = CodexRuntime(paths)
    codex_info = runtime.inspect()
    codex = asdict(codex_info)
    doctor = runtime.doctor() if codex_info.executable else None
    if doctor and doctor.stdout:
        try:
            codex["doctor"] = redact_value(json.loads(doctor.stdout))
        except json.JSONDecodeError:
            codex["doctor"] = {"status": "unparseable", "returncode": doctor.returncode}
    else:
        codex["doctor"] = {
            "status": "unavailable",
            "returncode": doctor.returncode if doctor else None,
        }
    native_sandbox = "unavailable"
    if codex_info.executable:
        sandbox = runtime.run(
            "sandbox",
            "cmd.exe",
            "/d",
            "/c",
            "echo",
            "HUMAN_CODEX_SANDBOX_OK",
            timeout=30,
        )
        if sandbox.ok and "HUMAN_CODEX_SANDBOX_OK" in sandbox.stdout:
            native_sandbox = "available"
        else:
            native_sandbox = "blocked_or_unavailable"

    disk = shutil.disk_usage(paths.repository_root)
    child = run_command(
        [sys.executable, "-c", "print('HUMAN_CODEX_CHILD_OK')"], timeout=10
    )
    local_write = _write_probe(paths.data_root / "temp")
    # The installed package can live in a read-only extracted directory.  Runtime
    # state belongs under LocalAppData, so package writability is informational.
    package_write = _write_probe(paths.repository_root / "artifacts" / "diagnostics")
    portable_python = paths.runtime_root.joinpath("python", "python.exe").is_file()
    bundled_electron = paths.repository_root / "node_modules" / "electron" / "dist" / "electron.exe"
    electron = str(bundled_electron) if bundled_electron.is_file() else shutil.which("electron")
    git = _git_status(paths.repository_root)

    blocking: list[str] = []
    limits: list[str] = []
    if sys.version_info < (3, 12):
        blocking.append("python_3_12_required")
    if not codex_info.executable or not codex_info.app_server:
        blocking.append("codex_app_server_unavailable")
    if not local_write:
        blocking.append("local_app_data_not_writable")
    if not child.ok:
        blocking.append("child_process_blocked")
    if codex_info.login_status != "logged_in":
        limits.append("app_codex_login_required")
    if not portable_python:
        limits.append("portable_python_not_bundled")
    if not electron:
        limits.append("electron_runtime_not_bundled")
    if native_sandbox != "available":
        limits.append("codex_native_sandbox_unavailable")
    if not git["available"]:
        limits.append("git_unavailable_snapshot_required")

    status = "blocked" if blocking else ("ready_with_limits" if limits else "ready")
    return {
        "schema": "human-codex-diagnostics/1",
        "status": status,
        "system": {
            "platform": platform.platform(),
            "windows_version": platform.win32_ver(),
            "architecture": platform.machine(),
            "admin": _is_admin(),
            "cpu_count": os.cpu_count(),
            "ram_bytes": _memory_bytes(),
            "disk_total_bytes": disk.total,
            "disk_free_bytes": disk.free,
            "gpu": _gpu_status(),
        },
        "runtime": {
            "python": {
                "version": platform.python_version(),
                "executable": sys.executable,
                "portable_bundled": portable_python,
            },
            "node": shutil.which("node"),
            "npm": shutil.which("npm"),
            "electron": electron,
            "child_process": child.ok,
            "named_pipe": _named_pipe_probe(),
        },
        "codex": codex,
        "git": git,
        "sandbox": {
            "codex_native": native_sandbox,
            "windows_sandbox": _windows_sandbox_status(),
        },
        "apps": {"chrome": _chrome_status(), "office": _office_status()},
        "policy": {
            "defender_realtime_disabled": _defender_disabled_value(),
            "smartscreen": _smartscreen_value(),
            "applocker_service": _applocker_status(),
        },
        "filesystem": {
            "local_app_data": str(paths.data_root),
            "local_app_data_writable": local_write,
            "project_root": str(paths.repository_root),
            "package_root_writable": package_write,
        },
        "network": {
            "chatgpt_443": _tcp_probe("chatgpt.com"),
            "api_openai_443": _tcp_probe("api.openai.com"),
            "proxy_configured": any(
                os.environ.get(name)
                for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
            ),
        },
        "schema_pin": verify_pinned_schema(runtime)
        if codex_info.executable
        else {"status": "unavailable"},
        "blocking_issues": blocking,
        "limits": limits,
    }


def _defender_disabled_value() -> Any:
    if os.name != "nt":
        return None
    import winreg

    return _registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
    )


def _smartscreen_value() -> Any:
    if os.name != "nt":
        return None
    import winreg

    return _registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SmartScreenEnabled",
    )


def _applocker_status() -> str:
    service = shutil.which("sc.exe")
    if not service:
        return "unknown"
    result = run_command([service, "query", "AppIDSvc"], timeout=10)
    combined = f"{result.stdout}\n{result.stderr}"
    if "RUNNING" in combined:
        return "running"
    if result.ok:
        return "stopped"
    return "unknown"
