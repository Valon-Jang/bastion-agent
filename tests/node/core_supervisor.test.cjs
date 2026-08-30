"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { CoreSupervisor, MAX_FRAME_BYTES, PROTOCOL, validateCoreResponse } = require("../../app/electron/core-supervisor.cjs");
const { DiagnosticRedactor, redactLine } = require("../../app/electron/redaction.cjs");

const root = path.resolve(__dirname, "..", "..");

function core() {
  return new CoreSupervisor({
    command: "py",
    args: ["-3.12", "-m", "human_codex", "core", "serve"],
    cwd: root,
    env: { ...process.env, PYTHONPATH: path.join(root, "source", "core"), HUMAN_CODEX_DATA_ROOT: path.join(root, "artifacts", "test", "node-core-data") },
    timeoutMs: 5_000,
  });
}

test("Node Main-process supervisor completes the Python Core health handshake", async () => {
  const supervisor = core();
  supervisor.start();
  try {
    assert.deepEqual(await supervisor.healthCheck(), { status: "pass", service: "human-codex-core", protocol: "hc-ipc/1" });
  } finally {
    await supervisor.stop();
  }
});

test("Core supervisor rejects requests after child exit", async () => {
  const supervisor = new CoreSupervisor({
    command: "py",
    args: ["-3.12", "-c", "import sys; sys.exit(7)"],
    cwd: root,
    env: process.env,
    timeoutMs: 2_000,
  });
  supervisor.start();
  await new Promise((resolve) => setTimeout(resolve, 200));
  await assert.rejects(() => supervisor.healthCheck(), /not running|exited unexpectedly/);
});

test("Core supervisor rejects oversized child frames and terminates the child", async () => {
  const supervisor = new CoreSupervisor({
    command: process.execPath,
    args: ["-e", `setTimeout(() => process.stdout.write("x".repeat(${MAX_FRAME_BYTES + 1})), 20); setInterval(() => {}, 1_000);`],
    cwd: root,
    env: process.env,
    timeoutMs: 2_000,
  });
  supervisor.start();
  try {
    await assert.rejects(() => supervisor.healthCheck(), /frame exceeding the maximum size/);
  } finally {
    await supervisor.stop();
  }
});

test("Core supervisor accepts only complete validated response envelopes", () => {
  const response = {
    protocol: PROTOCOL,
    kind: "response",
    id: "msg_123",
    correlation_id: "msg_123",
    method: "system.health",
    params: {},
    timestamp: "2026-08-27T00:00:00+00:00",
  };
  assert.deepEqual(validateCoreResponse(response), response);
  assert.throws(() => validateCoreResponse({ ...response, command: "whoami" }), /invalid hc-ipc\/1 response envelope/);
  assert.throws(() => validateCoreResponse({ ...response, error: { code: "failed" } }), /invalid hc-ipc\/1 response error/);
});

test("Core diagnostics redact tokens, assignments, and split private-key blocks", () => {
  const credential = `sk-proj-${"A1b2C3d4E5f6G7h8I9j0K1L2"}`;
  const line = redactLine(`token=${credential}`);
  assert.match(line, /REDACTED_SECRET/);
  assert.doesNotMatch(line, /A1b2C3d4/);
  const redactor = new DiagnosticRedactor();
  assert.equal(redactor.redact(`token=${credential.slice(0, 16)}`), "");
  const split = redactor.redact(`${credential.slice(16)}\n`);
  assert.match(split, /REDACTED_SECRET/);
  assert.doesNotMatch(split, /A1b2C3d4/);
  assert.match(redactor.redact("-----BEGIN PRIVATE KEY-----\n"), /REDACTED_SECRET/);
  assert.equal(redactor.redact("abc+/123=\nstill-private+/456=\n"), "");
  assert.equal(redactor.redact("-----END PRIVATE KEY-----\n"), "");
  assert.equal(redactor.flush(), "");
});
