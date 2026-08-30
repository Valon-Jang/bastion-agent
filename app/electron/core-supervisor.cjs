"use strict";

const { randomUUID } = require("node:crypto");
const { spawn } = require("node:child_process");
const { DiagnosticRedactor } = require("./redaction.cjs");

const PROTOCOL = "hc-ipc/1";
const MAX_FRAME_BYTES = 1_048_576;
const ID_PATTERN = /^[a-z][a-z0-9_-]{2,127}$/;

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validateCoreResponse(message) {
  const required = ["protocol", "kind", "id", "correlation_id", "method", "params", "timestamp"];
  const allowed = new Set([...required, "error"]);
  if (!isPlainObject(message) || Object.keys(message).some((key) => !allowed.has(key)) || required.some((key) => !Object.hasOwn(message, key))) {
    throw new Error("Python Core emitted an invalid hc-ipc/1 response envelope");
  }
  if (message.protocol !== PROTOCOL || message.kind !== "response") {
    throw new Error("Python Core emitted an invalid hc-ipc/1 response envelope");
  }
  if (!ID_PATTERN.test(message.id) || !ID_PATTERN.test(message.correlation_id)) {
    throw new Error("Python Core emitted an invalid hc-ipc/1 response identifier");
  }
  if (typeof message.method !== "string" || !message.method || message.method.length > 120) {
    throw new Error("Python Core emitted an invalid hc-ipc/1 response method");
  }
  if (!isPlainObject(message.params) || typeof message.timestamp !== "string" || !message.timestamp || message.timestamp.length > 64) {
    throw new Error("Python Core emitted an invalid hc-ipc/1 response payload");
  }
  if (Object.hasOwn(message, "error") && !hasExactKeys(message.error, ["code", "message"])) {
    throw new Error("Python Core emitted an invalid hc-ipc/1 response error");
  }
  if (Object.hasOwn(message, "error") && (!message.error.code || !message.error.message || typeof message.error.code !== "string" || typeof message.error.message !== "string")) {
    throw new Error("Python Core emitted an invalid hc-ipc/1 response error");
  }
  return message;
}

class CoreSupervisor {
  constructor({ spawnProcess = spawn, timeoutMs = 8_000, command, args, env, cwd }) {
    this.spawnProcess = spawnProcess;
    this.timeoutMs = timeoutMs;
    this.command = command;
    this.args = args;
    this.env = env;
    this.cwd = cwd;
    this.process = null;
    this.pending = new Map();
    this.buffer = "";
    this.diagnosticRedactor = new DiagnosticRedactor();
  }

  start() {
    if (this.process) return;
    this.process = this.spawnProcess(this.command, this.args, {
      cwd: this.cwd,
      env: this.env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.process.stdout.setEncoding("utf8");
    this.process.stdout.on("data", (chunk) => this.#read(chunk));
    this.process.stderr.setEncoding("utf8");
    this.process.stderr.on("data", (chunk) => {
      const safe = this.diagnosticRedactor.redact(chunk);
      if (safe) console.error(`[human-codex-core] ${safe}`);
    });
    this.process.once("error", (error) => this.#failAll(new Error(`Python Core failed to start: ${error.message}`)));
    this.process.once("exit", (code, signal) => {
      const safe = this.diagnosticRedactor.flush();
      if (safe) console.error(`[human-codex-core] ${safe}`);
      this.process = null;
      this.#failAll(new Error(`Python Core exited unexpectedly (code=${code}, signal=${signal || "none"})`));
    });
  }

  async healthCheck() {
    return this.request("system.health", {});
  }

  request(method, params) {
    if (!this.process || !this.process.stdin.writable) return Promise.reject(new Error("Python Core is not running"));
    const id = `msg_${randomUUID().replaceAll("-", "")}`;
    const envelope = {
      protocol: PROTOCOL,
      kind: "request",
      id,
      correlation_id: id,
      method,
      params,
      timestamp: new Date().toISOString(),
    };
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Python Core timeout for ${method}`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timeout, method });
      this.process.stdin.write(`${JSON.stringify(envelope)}\n`, "utf8", (error) => {
        if (error) {
          clearTimeout(timeout);
          this.pending.delete(id);
          reject(new Error(`Python Core is not running (write failed: ${error.message})`));
        }
      });
    });
  }

  async stop() {
    if (!this.process) return;
    const child = this.process;
    try {
      await this.request("system.shutdown", {});
    } catch (_) {
      // The process is terminated below if a graceful request cannot be completed.
    }
    if (child.exitCode !== null || child.killed) return;
    await new Promise((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        if (child.exitCode === null) child.kill();
        finish();
      }, 3_000);
      child.once("exit", () => {
        finish();
      });
      if (child.exitCode !== null) finish();
    });
  }

  #read(chunk) {
    const chunkBytes = Buffer.byteLength(chunk, "utf8");
    if (chunkBytes > MAX_FRAME_BYTES || Buffer.byteLength(this.buffer, "utf8") + chunkBytes > MAX_FRAME_BYTES) {
      this.#rejectProtocol(new Error("Python Core emitted a frame exceeding the maximum size"));
      return;
    }
    this.buffer += chunk;
    while (true) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) return;
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line) continue;
      if (Buffer.byteLength(line, "utf8") > MAX_FRAME_BYTES) {
        this.#rejectProtocol(new Error("Python Core emitted a frame exceeding the maximum size"));
        return;
      }
      let message;
      try {
        message = validateCoreResponse(JSON.parse(line));
      } catch (error) {
        this.#rejectProtocol(error instanceof Error ? error : new Error("Python Core emitted malformed JSON on stdout"));
        return;
      }
      const pending = this.pending.get(message.correlation_id);
      if (!pending) continue;
      if (message.method !== pending.method) {
        this.#rejectProtocol(new Error("Python Core response method does not match its request"));
        return;
      }
      clearTimeout(pending.timeout);
      this.pending.delete(message.correlation_id);
      if (Object.hasOwn(message, "error")) pending.reject(new Error(`Python Core ${pending.method} failed: ${message.error.code}`));
      else pending.resolve(message.params);
    }
  }

  #rejectProtocol(error) {
    this.buffer = "";
    this.#failAll(error);
    const child = this.process;
    if (child && child.exitCode === null && !child.killed) child.kill();
  }

  #failAll(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.pending.clear();
  }
}

module.exports = { CoreSupervisor, MAX_FRAME_BYTES, PROTOCOL, validateCoreResponse };
