"""Authenticated M5 repair loop using a disposable Tkinter project and hidden MCP evaluator."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "source" / "core"))
sys.path.insert(0, str(ROOT))

from human_codex.codex_runtime import CodexRuntime
from human_codex.database import MetadataDatabase
from human_codex.paths import PortablePaths
from human_codex.sessions import CodexSessionManager


SEED = ROOT / "smoke" / "tolerance_app_seed"
EVALUATOR = ROOT / "workers" / "m5_hidden_evaluator.py"
MCP_NAME = "human-codex-m5-evaluator"


def run_mcp(runtime: CodexRuntime, *arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [runtime.require_executable(), "mcp", *arguments], cwd=ROOT, env=environment,
        text=True, capture_output=True, timeout=30, check=False,
    )


def wait_for_turn(manager: CodexSessionManager, chat_id: str, turn_id: str, timeout: float = 180.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        turns = manager.timeline(chat_id)["turns"]
        terminal = [turn for turn in turns if turn["id"] == turn_id and turn["status"] in {"completed", "failed", "interrupted"}]
        if terminal:
            return str(terminal[0]["status"])
        time.sleep(0.2)
    return "timeout"


def settle_background_followups(manager: CodexSessionManager, project_id: str, chat_id: str) -> None:
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        jobs = manager.list_background_jobs(project_id)
        active_turns = [
            turn for turn in manager.timeline(chat_id)["turns"] if turn["status"] == "inProgress"
        ]
        if not any(job["followup_state"] in {"pending", "starting"} for job in jobs) and not active_turns:
            return
        time.sleep(0.2)
    # A summary Turn must never prevent a user-requested repair loop indefinitely.
    try:
        manager.interrupt_turn(chat_id)
    except Exception:
        return
    idle_deadline = time.monotonic() + 15
    while time.monotonic() < idle_deadline:
        if not any(turn["status"] == "inProgress" for turn in manager.timeline(chat_id)["turns"]):
            return
        time.sleep(0.2)


def evaluate_over_mcp(manager: CodexSessionManager, chat_id: str) -> dict[str, object]:
    chat = manager.database.open_chat(chat_id)
    if not chat.provider_thread_id:
        raise RuntimeError("M5 evaluator requires an opened Codex thread")
    response = manager._ensure_client().request(  # App Server schema: mcpServer/tool/call
        "mcpServer/tool/call",
        {
            "server": MCP_NAME,
            "threadId": chat.provider_thread_id,
            "tool": "evaluate_tolerance_app",
            "arguments": {},
        },
    )
    content = response.get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        raise RuntimeError("M5 evaluator returned no content")
    text = content[0].get("text")
    if not isinstance(text, str):
        raise RuntimeError("M5 evaluator returned non-text content")
    result = json.loads(text)
    if not isinstance(result, dict) or result.get("status") not in {"PASS", "FAIL"}:
        raise RuntimeError("M5 evaluator returned an invalid status")
    symptoms = result.get("symptoms")
    if not isinstance(symptoms, list) or not all(isinstance(item, str) for item in symptoms):
        raise RuntimeError("M5 evaluator returned invalid symptoms")
    return {"status": result["status"], "symptoms": symptoms}


def main() -> int:
    artifact = ROOT / "artifacts" / "test" / "m5-e2e-smoke.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    actual_paths = PortablePaths.discover(ROOT)
    runtime = CodexRuntime(actual_paths)
    result: dict[str, object] = {
        "status": "fail", "codex_version": runtime.version(), "initial_evaluator": "not_run",
        "final_evaluator": "not_run", "repair_rounds": 0, "completed_turns": [],
        "approval_count": 0, "snapshot_count": 0, "public_tests": False, "startup_check": False,
    }
    manager: CodexSessionManager | None = None
    mcp_added = False
    try:
        with tempfile.TemporaryDirectory(
            dir=artifact.parent, prefix="m5-smoke-", ignore_cleanup_errors=True
        ) as temporary:
            temp_root = Path(temporary)
            project_root = temp_root / "tolerance-app"
            shutil.copytree(SEED, project_root)
            environment = actual_paths.codex_environment()
            environment["HUMAN_CODEX_M5_PROJECT"] = str(project_root)
            existing = run_mcp(runtime, "list", environment=environment)
            if existing.returncode != 0:
                raise RuntimeError("could not inspect the app-specific Codex MCP configuration")
            if MCP_NAME in existing.stdout:
                raise RuntimeError("M5 evaluator MCP name is already configured; refusing to overwrite it")
            added = run_mcp(
                runtime, "add", MCP_NAME, "--env", f"HUMAN_CODEX_M5_PROJECT={project_root}",
                "--", "py", "-3.12", str(EVALUATOR), environment=environment,
            )
            if added.returncode != 0:
                raise RuntimeError("could not register the temporary M5 evaluator MCP server")
            mcp_added = True
            paths = PortablePaths(ROOT, temp_root / "data")
            database = MetadataDatabase.from_data_root(paths.data_root)
            project = database.create_project("M5 Tkinter smoke")
            chat = database.create_chat(project.id, "Tolerance repair")
            manager = CodexSessionManager(database, paths, runtime=runtime, ephemeral_threads=True)
            manager.workspace.ensure_project_roots(project.id, str(project_root))
            manager.open_chat(chat.id)
            initial = evaluate_over_mcp(manager, chat.id)
            result["initial_evaluator"] = initial["status"]
            if initial["status"] != "FAIL":
                raise RuntimeError("seed project must fail the hidden evaluator")
            evaluation = initial
            for repair_round in range(2):
                if repair_round == 0:
                    prompt = (
                        "이 프로그램 좀 확인해봐. 계산할 때 이상한 것 같고 저장도 가끔 안 돼. 결과 화면도 좀 더 보기 좋게 해줘. "
                        "프로젝트 내부에서만 작업하고 network나 다른 경로는 접근하지 마. 먼저 공개 테스트를 실행하고, 수정 후 공개 테스트를 다시 실행해. "
                        "준비가 되면 Human Codex hidden evaluator MCP tool evaluate_tolerance_app을 호출해 PASS/FAIL 증상만 확인해. 완료 시 정확히 M5_SMOKE_OK라고 답해."
                    )
                else:
                    prompt = (
                        "Human Codex hidden evaluator returned FAIL with these symptoms only: "
                        + "; ".join(str(symptom) for symptom in evaluation["symptoms"])
                        + ". Continue working only inside this project, rerun public tests, then call evaluate_tolerance_app again. "
                        "When all checks pass, reply exactly M5_SMOKE_OK."
                    )
                started = manager.start_turn(chat.id, prompt)
                turn_id = str(started["turn"]["id"])
                deadline = time.monotonic() + 210
                approved: set[str] = set()
                status = "timeout"
                while time.monotonic() < deadline:
                    for approval in manager.approvals.list_pending(project.id):
                        if approval["id"] not in approved:
                            decision = "approve" if approval["risk_level"] in {"R1", "R2"} else "deny"
                            manager.approvals.decide(approval["id"], decision, "once")
                            approved.add(str(approval["id"]))
                    status = wait_for_turn(manager, chat.id, turn_id, timeout=0.25)
                    if status != "timeout":
                        break
                result["approval_count"] = int(result["approval_count"]) + len(approved)
                result["completed_turns"].append(status)
                settle_background_followups(manager, project.id, chat.id)
                evaluation = evaluate_over_mcp(manager, chat.id)
                result["final_evaluator"] = evaluation["status"]
                result["repair_rounds"] = int(result["repair_rounds"]) + 1
                if status == "completed" and evaluation["status"] == "PASS":
                    break
            tests = subprocess.run(
                [sys.executable, "-m", "unittest", "-v"], cwd=project_root,
                capture_output=True, text=True, timeout=30, check=False,
            )
            startup = subprocess.run(
                [sys.executable, "tolerance_app.py", "--headless-check"], cwd=project_root,
                capture_output=True, text=True, timeout=30, check=False,
            )
            result["public_tests"] = tests.returncode == 0
            result["startup_check"] = startup.returncode == 0 and "tolerance-app-ready" in startup.stdout
            result["snapshot_count"] = len(manager.snapshots.list(project.id))
            assistant_messages = [
                message["content"].get("text", "") for message in manager.timeline(chat.id)["messages"]
                if message["role"] == "assistant"
            ]
            result["assistant_marker"] = any(message.strip() == "M5_SMOKE_OK" for message in assistant_messages)
            result["assistant_feedback"] = any(message.strip() for message in assistant_messages)
            result["status"] = "pass" if (
                result["initial_evaluator"] == "FAIL" and result["final_evaluator"] == "PASS"
                and result["public_tests"] is True and result["startup_check"] is True
                and result["assistant_feedback"] is True and "completed" in result["completed_turns"]
            ) else "fail"
            if result["status"] == "pass":
                evidence_root = artifact.parent / f"m5-repaired-tolerance-app-{int(time.time())}"
                shutil.copytree(project_root, evidence_root)
                result["repaired_project_evidence"] = str(evidence_root.relative_to(ROOT)).replace("\\", "/")
    except Exception as exc:
        result["failure_type"] = type(exc).__name__
    finally:
        if manager is not None:
            manager.close()
        if mcp_added:
            try:
                run_mcp(runtime, "remove", MCP_NAME, environment=actual_paths.codex_environment())
            except Exception:
                result["mcp_cleanup"] = "failed"
    artifact.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
