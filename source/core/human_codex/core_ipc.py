from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Mapping


PROTOCOL = "hc-ipc/1"
MAX_FRAME_BYTES = 1_048_576
MAX_METHOD_CHARS = 120
MAX_TIMESTAMP_CHARS = 64
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,127}$")


class IpcValidationError(ValueError):
    """Raised for malformed or disallowed hc-ipc/1 messages."""


@dataclass(frozen=True)
class Envelope:
    protocol: str
    kind: str
    id: str
    correlation_id: str
    method: str
    params: dict[str, Any]
    timestamp: str
    error: dict[str, str] | None = None

    def payload(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()


def new_id(prefix: str = "msg") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def request(method: str, params: Mapping[str, Any]) -> Envelope:
    message_id = new_id()
    return Envelope(PROTOCOL, "request", message_id, message_id, method, dict(params), utc_timestamp())


def response_for(
    request_envelope: Envelope, *, params: Mapping[str, Any] | None = None, error: Mapping[str, str] | None = None
) -> Envelope:
    return Envelope(
        PROTOCOL,
        "response",
        new_id(),
        request_envelope.id,
        request_envelope.method,
        dict(params or {}),
        utc_timestamp(),
        dict(error) if error else None,
    )


def encode(envelope: Envelope) -> str:
    rendered = json.dumps(envelope.payload(), ensure_ascii=True, separators=(",", ":"))
    if len(rendered.encode("utf-8")) > MAX_FRAME_BYTES:
        raise IpcValidationError("frame exceeds maximum size")
    return rendered


def decode(raw_line: str) -> Envelope:
    if len(raw_line.encode("utf-8")) > MAX_FRAME_BYTES:
        raise IpcValidationError("frame exceeds maximum size")
    try:
        raw = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise IpcValidationError("malformed JSON") from exc
    if not isinstance(raw, dict):
        raise IpcValidationError("envelope must be an object")
    allowed = {"protocol", "kind", "id", "correlation_id", "method", "params", "timestamp", "error"}
    extra = set(raw) - allowed
    missing = {"protocol", "kind", "id", "correlation_id", "method", "params", "timestamp"} - set(raw)
    if extra or missing:
        raise IpcValidationError("envelope keys are invalid")
    if raw["protocol"] != PROTOCOL or raw["kind"] not in {"request", "response", "event"}:
        raise IpcValidationError("protocol or kind is invalid")
    if not all(isinstance(raw[key], str) and ID_PATTERN.match(raw[key]) for key in ("id", "correlation_id")):
        raise IpcValidationError("id or correlation_id is invalid")
    if not isinstance(raw["method"], str) or not 1 <= len(raw["method"]) <= MAX_METHOD_CHARS:
        raise IpcValidationError("method is invalid")
    if not isinstance(raw["params"], dict) or not isinstance(raw["timestamp"], str) or not 1 <= len(raw["timestamp"]) <= MAX_TIMESTAMP_CHARS:
        raise IpcValidationError("params or timestamp is invalid")
    error = raw.get("error")
    if error is not None and (
        not isinstance(error, dict) or set(error) != {"code", "message"} or not all(isinstance(error[key], str) for key in error)
    ):
        raise IpcValidationError("error is invalid")
    return Envelope(
        raw["protocol"], raw["kind"], raw["id"], raw["correlation_id"], raw["method"], raw["params"], raw["timestamp"], error
    )
