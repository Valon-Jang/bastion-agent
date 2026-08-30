"""M5 evaluator kept outside the agent's test-project workspace.

It returns only PASS/FAIL symptoms. The expected implementation is deliberately not
sent in the result or copied into the project prompt.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def evaluate(project_root: str | Path | None = None) -> dict[str, Any]:
    root = Path(project_root or os.environ.get("HUMAN_CODEX_M5_PROJECT", "")).resolve()
    app_path = root / "tolerance_app.py"
    symptoms: list[str] = []
    if not app_path.is_file():
        return {"status": "FAIL", "symptoms": ["tolerance_app.py is missing"]}
    spec = importlib.util.spec_from_file_location("m5_tolerance_app", app_path)
    if spec is None or spec.loader is None:
        return {"status": "FAIL", "symptoms": ["the application module cannot be loaded"]}
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve postponed annotations through sys.modules during decoration.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        return {"status": "FAIL", "symptoms": ["the application fails during import"]}
    try:
        parts = [module.Dimension("A", 10.0, 0.1), module.Dimension("B", 5.0, 0.05), module.Dimension("C", 16.0, 0.1)]
        result = module.calculate_stack(parts, 0.5, 1.5)
        if not (round(result.minimum, 6) == 0.75 and round(result.nominal, 6) == 1.0 and round(result.maximum, 6) == 1.25):
            symptoms.append("worst-case clearance bounds are inconsistent with opposing tolerance extremes")
        if result.status != "PASS":
            symptoms.append("a clearance range fully inside the target range is not classified PASS")
        interference = module.calculate_stack(parts, 1.3, 1.5)
        if interference.status != "INTERFERENCE":
            symptoms.append("a clearance range completely below the target range is not classified INTERFERENCE")
    except Exception:
        symptoms.append("calculation inputs are not handled reliably")
    try:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            module.save_state(state_path, parts, 0.75, 1.25)
            loaded_parts, target_min, target_max = module.load_state(state_path)
            if loaded_parts != parts or (target_min, target_max) != (0.75, 1.25):
                symptoms.append("save/load does not preserve the complete analysis state")
    except Exception:
        symptoms.append("save/load does not complete reliably")
    started = subprocess.run(
        [sys.executable, str(app_path), "--headless-check"], cwd=root,
        capture_output=True, text=True, timeout=15, check=False,
    )
    if started.returncode != 0 or "tolerance-app-ready" not in started.stdout:
        symptoms.append("the application startup health check fails")
    sys.modules.pop(spec.name, None)
    return {"status": "PASS" if not symptoms else "FAIL", "symptoms": symptoms}


def _reply(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
            "serverInfo": {"name": "human-codex-m5-evaluator", "version": "0.1.0"},
        }}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{
            "name": "evaluate_tolerance_app",
            "description": "Return only PASS/FAIL and symptoms for the current tolerance-app workspace.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        }]}}
    if method == "tools/call":
        result = evaluate()
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
            "isError": False,
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}


def serve() -> int:
    for raw in sys.stdin:
        try:
            response = _reply(json.loads(raw))
            if response is not None:
                print(json.dumps(response, ensure_ascii=False), flush=True)
        except Exception as exc:
            print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": type(exc).__name__}}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
