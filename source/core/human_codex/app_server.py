from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from human_codex.codex_runtime import CodexRuntime
from human_codex.secret_guard import redact_text


class AppServerError(RuntimeError):
    pass


def _product_version() -> str:
    version_path = Path(__file__).resolve().parents[3] / "VERSION.json"
    try:
        value = json.loads(version_path.read_text(encoding="utf-8")).get("version")
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError("Human Codex VERSION.json is unavailable") from exc
    if not isinstance(value, str) or not value:
        raise AppServerError("Human Codex VERSION.json has no valid version")
    return value


@dataclass
class AppServerSmokeResult:
    status: str
    codex_version: str
    initialize: dict[str, Any]
    thread: dict[str, Any]
    notifications: list[str] = field(default_factory=list)
    duration_ms: int = 0


@dataclass
class AppServerTurnSmokeResult:
    status: str
    codex_version: str
    thread_id: str
    turn_id: str
    completed_status: str
    assistant_text: str
    notifications: list[str] = field(default_factory=list)
    duration_ms: int = 0


NotificationHandler = Callable[[str, dict[str, Any]], None]
ServerRequestHandler = Callable[[str, str | int, dict[str, Any]], dict[str, Any]]


def _locked_thread_config(cwd: Path, profile_name: str) -> dict[str, Any]:
    root = str(cwd.resolve())
    return {
        "default_permissions": profile_name,
        "web_search": "live",
        "allow_login_shell": False,
        "agents": {"enabled": False},
        "apps": {"_default": {"enabled": False}},
        "features": {
            "hooks": False,
            "memories": False,
            "multi_agent": False,
            "remote_plugin": False,
            "skill_mcp_dependency_install": False,
        },
        "projects": {root: {"trust_level": "untrusted"}},
        "permissions": {profile_name: {"workspace_roots": {root: True}}},
    }


class AppServerClient:
    """Thread-safe JSONL client for ``codex app-server --listen stdio://``."""

    MAX_LINE_BYTES = 4_194_304
    MAX_NOTIFICATION_HISTORY = 1_000
    MAX_NOTIFICATION_BACKLOG = 2_048
    MAX_STDERR_LINE_CHARS = 16_384
    MAX_METHOD_CHARS = 256

    def __init__(
        self,
        runtime: CodexRuntime,
        *,
        timeout: float = 15.0,
        notification_handler: NotificationHandler | None = None,
        server_request_handler: ServerRequestHandler | None = None,
        windows_sandbox_override: str | None = None,
        default_permissions_override: str | None = None,
        process_cwd_override: Path | None = None,
    ) -> None:
        if windows_sandbox_override not in {None, "unelevated"}:
            raise ValueError("unsupported Windows sandbox override")
        if default_permissions_override not in {None, ":workspace"}:
            raise ValueError("unsupported default permissions override")
        self.runtime = runtime
        self.timeout = timeout
        self.notification_handler = notification_handler
        self.server_request_handler = server_request_handler
        self.windows_sandbox_override = windows_sandbox_override
        self.default_permissions_override = default_permissions_override
        if process_cwd_override is not None:
            resolved_cwd = process_cwd_override.resolve()
            try:
                resolved_cwd.relative_to(self.runtime.paths.workspace_root.resolve())
            except ValueError as exc:
                raise ValueError(
                    "App Server working directory must stay inside Workspace"
                ) from exc
            self.process_cwd_override: Path | None = resolved_cwd
        else:
            self.process_cwd_override = None
        self.process: subprocess.Popen[str] | None = None
        self.stderr_lines: list[str] = []
        self.notifications: list[str] = []
        self._next_id = 1
        self._id_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[int, queue.Queue[dict[str, Any] | BaseException]] = {}
        self._closing = threading.Event()
        self._notification_queue: queue.Queue[tuple[str, dict[str, Any]] | None] = queue.Queue(
            maxsize=self.MAX_NOTIFICATION_BACKLOG
        )
        self._notification_thread: threading.Thread | None = None
        self._server_request_queue: queue.Queue[tuple[str, str | int, dict[str, Any]] | None] = queue.Queue(maxsize=128)
        self._server_request_thread: threading.Thread | None = None
        self._initialized = False
        self._initialize_result: dict[str, Any] | None = None
        self._stderr_private_key = False

    def __enter__(self) -> "AppServerClient":
        executable = self.runtime.require_executable()
        self.runtime.ensure_home()
        startupinfo = None
        creationflags = 0
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW
        self.process = subprocess.Popen(
            self._startup_command(executable),
            cwd=str(self.process_cwd_override or self.runtime.paths.repository_root),
            env=self.runtime.paths.codex_environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        self._notification_thread = threading.Thread(target=self._handle_notifications, daemon=True)
        self._notification_thread.start()
        self._server_request_thread = threading.Thread(target=self._handle_server_requests, daemon=True)
        self._server_request_thread.start()
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        return self

    def _startup_command(self, executable: str) -> list[str]:
        command = [executable]
        if self.windows_sandbox_override is not None:
            command.extend(
                ["-c", f'windows.sandbox="{self.windows_sandbox_override}"']
            )
        if self.default_permissions_override is not None:
            command.extend(
                ["-c", f'default_permissions="{self.default_permissions_override}"']
            )
        command.extend(["app-server", "--strict-config", "--listen", "stdio://"])
        return command

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def initialize(self) -> dict[str, Any]:
        if self._initialized and self._initialize_result is not None:
            return self._initialize_result
        result = self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "human-codex",
                    "title": "Human Codex",
                    "version": _product_version(),
                },
                "capabilities": {"experimentalApi": False},
            },
        )
        self.notify("initialized", {})
        self._initialized = True
        self._initialize_result = result
        return result

    def request(
        self,
        method: str,
        params: dict[str, Any] | None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if self.process is None:
            raise AppServerError("app-server is not running")
        with self._id_lock:
            request_id = self._next_id
            self._next_id += 1
        response_queue: queue.Queue[dict[str, Any] | BaseException] = queue.Queue(maxsize=1)
        with self._pending_lock:
            self._pending[request_id] = response_queue
        try:
            self._send({"id": request_id, "method": method, "params": params})
            try:
                response = response_queue.get(timeout=timeout or self.timeout)
            except queue.Empty as exc:
                raise AppServerError(f"timed out waiting for {method}") from exc
            if isinstance(response, BaseException):
                raise AppServerError(redact_text(str(response))) from response
            if "error" in response:
                raise AppServerError(
                    f"{method} failed: {redact_text(str(response['error']))}"
                )
            result = response.get("result")
            if not isinstance(result, dict):
                raise AppServerError(f"{method} returned a non-object result")
            return result
        finally:
            with self._pending_lock:
                self._pending.pop(request_id, None)

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"method": method, "params": params})

    def close(self) -> None:
        self._closing.set()
        process = self.process
        self.process = None
        if process is None:
            return
        if process.stdin:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()
        try:
            self._notification_queue.put(None, timeout=2)
        except queue.Full:
            pass
        if self._notification_thread:
            self._notification_thread.join(timeout=3)
        try:
            self._server_request_queue.put(None, timeout=2)
        except queue.Full:
            pass
        if self._server_request_thread:
            self._server_request_thread.join(timeout=3)
        self._fail_pending(AppServerError("app-server closed"))

    def _send(self, payload: dict[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None:
            raise AppServerError("app-server stdin is unavailable")
        serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(serialized.encode("utf-8")) > self.MAX_LINE_BYTES:
            raise AppServerError("outbound app-server frame exceeds size limit")
        with self._write_lock:
            try:
                process.stdin.write(serialized + "\n")
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise AppServerError("failed to write to app-server") from exc

    def _read_stdout(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        try:
            while not self._closing.is_set():
                line = process.stdout.readline(self.MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line.encode("utf-8")) > self.MAX_LINE_BYTES:
                    raise AppServerError("inbound app-server frame exceeds size limit")
                try:
                    message = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AppServerError("app-server emitted invalid JSON") from exc
                if not isinstance(message, dict):
                    raise AppServerError("app-server emitted a non-object frame")
                self._dispatch(message)
        except BaseException as exc:
            if not self._closing.is_set():
                self._fail_pending(exc)
                if process.poll() is None:
                    process.terminate()
        finally:
            if not self._closing.is_set():
                return_code = process.poll()
                details = "\n".join(self.stderr_lines[-10:])
                self._fail_pending(
                    AppServerError(
                        f"app-server exited unexpectedly ({return_code})"
                        + (f": {details}" if details else "")
                    )
                )

    def _dispatch(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        if isinstance(method, str):
            if not 1 <= len(method) <= self.MAX_METHOD_CHARS:
                raise AppServerError("app-server method name exceeds its safety limit")
            params = message.get("params", {})
            if not isinstance(params, dict):
                raise AppServerError(f"notification {method} has invalid params")
            if "id" in message:
                request_id = message["id"]
                if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
                    raise AppServerError("server request has invalid id")
                try:
                    self._server_request_queue.put_nowait((method, request_id, params))
                except queue.Full as exc:
                    raise AppServerError("server request backlog exceeds safety limit") from exc
                return
            self.notifications.append(method)
            if len(self.notifications) > self.MAX_NOTIFICATION_HISTORY:
                del self.notifications[: len(self.notifications) - self.MAX_NOTIFICATION_HISTORY]
            if self.notification_handler:
                try:
                    self._notification_queue.put_nowait((method, params))
                except queue.Full as exc:
                    raise AppServerError("notification backlog exceeds safety limit") from exc
            return
        response_id = message.get("id")
        if not isinstance(response_id, int):
            raise AppServerError("app-server frame has neither method nor integer id")
        with self._pending_lock:
            response_queue = self._pending.get(response_id)
        if response_queue is not None:
            try:
                response_queue.put_nowait(message)
            except queue.Full as exc:
                raise AppServerError("app-server emitted a duplicate response") from exc

    def _read_stderr(self) -> None:
        process = self.process
        if process is None or process.stderr is None:
            return
        while True:
            line = process.stderr.readline(self.MAX_STDERR_LINE_CHARS + 1)
            if not line:
                return
            if len(line) > self.MAX_STDERR_LINE_CHARS:
                if not line.endswith(("\n", "\r")):
                    while remainder := process.stderr.readline(
                        self.MAX_STDERR_LINE_CHARS + 1
                    ):
                        if remainder.endswith(("\n", "\r")):
                            break
                self._append_stderr("[REDACTED_SECRET]:oversized_diagnostic")
                continue
            value = line.rstrip()
            if "-----BEGIN" in value.upper() and "PRIVATE KEY-----" in value.upper():
                self._stderr_private_key = True
                self._append_stderr("[REDACTED_SECRET]:private_key")
                if "-----END" in value.upper():
                    self._stderr_private_key = False
                continue
            if self._stderr_private_key:
                if "-----END" in value.upper() and "PRIVATE KEY-----" in value.upper():
                    self._stderr_private_key = False
                continue
            self._append_stderr(value)

    def _append_stderr(self, value: str) -> None:
        self.stderr_lines.append(redact_text(value)[:4_096])
        if len(self.stderr_lines) > 200:
            del self.stderr_lines[: len(self.stderr_lines) - 200]

    def _handle_notifications(self) -> None:
        while True:
            notification = self._notification_queue.get()
            try:
                if notification is None:
                    return
                method, params = notification
                if self.notification_handler:
                    self.notification_handler(method, params)
            except Exception as exc:
                self._append_stderr(f"notification handler failed: {exc}")
            finally:
                self._notification_queue.task_done()

    def _handle_server_requests(self) -> None:
        while True:
            request = self._server_request_queue.get()
            try:
                if request is None:
                    return
                method, request_id, params = request
                if self.server_request_handler is None:
                    self._send({
                        "id": request_id,
                        "error": {"code": -32601, "message": "server request is unsupported"},
                    })
                    continue
                result = self.server_request_handler(method, request_id, params)
                if not isinstance(result, dict):
                    raise AppServerError("server request handler returned a non-object result")
                self._send({"id": request_id, "result": result})
            except Exception as exc:
                self._append_stderr(f"server request handler failed: {exc}")
                if request is not None:
                    try:
                        self._send({
                            "id": request[1],
                            "error": {"code": -32603, "message": "approval handling failed closed"},
                        })
                    except Exception:
                        pass
            finally:
                self._server_request_queue.task_done()

    def _fail_pending(self, exc: BaseException) -> None:
        with self._pending_lock:
            pending = list(self._pending.values())
        for response_queue in pending:
            try:
                response_queue.put_nowait(exc)
            except queue.Full:
                pass


def run_initialize_thread_smoke(
    runtime: CodexRuntime,
    *,
    cwd: Path,
    timeout: float = 15.0,
) -> AppServerSmokeResult:
    started = time.monotonic()
    with AppServerClient(runtime, timeout=timeout) as client:
        initialized = client.initialize()
        thread_result = client.request(
            "thread/start",
            {
                "cwd": str(cwd.resolve()),
                "approvalPolicy": "on-request",
                "approvalsReviewer": "user",
                "config": _locked_thread_config(cwd, runtime.READ_ONLY_PROFILE),
                "ephemeral": True,
                "serviceName": "human_codex",
            },
        )
        thread = thread_result.get("thread")
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            raise AppServerError("thread/start response is missing thread.id")
        safe_initialize = {
            key: initialized.get(key)
            for key in ("userAgent", "platformFamily", "platformOs")
            if key in initialized
        }
        safe_thread = {
            key: thread.get(key)
            for key in ("id", "sessionId", "ephemeral", "modelProvider")
            if key in thread
        }
        return AppServerSmokeResult(
            status="pass",
            codex_version=runtime.version(),
            initialize=safe_initialize,
            thread=safe_thread,
            notifications=list(client.notifications),
            duration_ms=round((time.monotonic() - started) * 1000),
        )


def wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def run_turn_smoke(
    runtime: CodexRuntime,
    *,
    cwd: Path,
    timeout: float = 120.0,
) -> AppServerTurnSmokeResult:
    if not runtime.permission_profile_enforced():
        raise AppServerError("secure native permission profile is not enforced")
    started_at = time.monotonic()
    completed = threading.Event()
    completed_status = "timeout"
    assistant_text = ""

    def handle(method: str, params: dict[str, Any]) -> None:
        nonlocal completed_status, assistant_text
        if method == "item/completed":
            item = params.get("item")
            if isinstance(item, dict) and item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
                assistant_text = item["text"]
        if method == "turn/completed":
            turn = params.get("turn")
            if isinstance(turn, dict) and isinstance(turn.get("status"), str):
                completed_status = turn["status"]
            else:
                completed_status = "invalid"
            completed.set()

    with AppServerClient(runtime, timeout=min(timeout, 45.0), notification_handler=handle) as client:
        client.initialize()
        thread_result = client.request(
            "thread/start",
            {
                "cwd": str(cwd.resolve()),
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "config": _locked_thread_config(cwd, runtime.READ_ONLY_PROFILE),
                "ephemeral": True,
                "serviceName": "human_codex_m2_verify",
            },
        )
        thread = thread_result.get("thread")
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            raise AppServerError("thread/start response is missing thread.id")
        turn_result = client.request(
            "turn/start",
            {
                "threadId": thread["id"],
                "cwd": str(cwd.resolve()),
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "input": [
                    {
                        "type": "text",
                        "text": "Reply with exactly M2_OK. Do not use tools.",
                        "text_elements": [],
                    }
                ],
            },
        )
        turn = turn_result.get("turn")
        if not isinstance(turn, dict) or not isinstance(turn.get("id"), str):
            raise AppServerError("turn/start response is missing turn.id")
        completed.wait(timeout=max(0.1, timeout))
        status = "pass" if completed_status == "completed" and assistant_text.strip() == "M2_OK" else "fail"
        return AppServerTurnSmokeResult(
            status=status,
            codex_version=runtime.version(),
            thread_id=thread["id"],
            turn_id=turn["id"],
            completed_status=completed_status,
            assistant_text=assistant_text,
            notifications=list(client.notifications),
            duration_ms=round((time.monotonic() - started_at) * 1000),
        )
