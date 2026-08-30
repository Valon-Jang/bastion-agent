"use strict";

const REDACTED = "[REDACTED_SECRET]";

function redactLine(value) {
  return String(value)
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, `${REDACTED}:openai_key`)
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, `${REDACTED}:aws_key`)
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/gi, `${REDACTED}:github_token`)
    .replace(/\bAIza[0-9A-Za-z_-]{30,}\b/g, `${REDACTED}:google_api_key`)
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{16,}\b/gi, `${REDACTED}:slack_token`)
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, `${REDACTED}:jwt`)
    .replace(/\bhttps?:\/\/[^\s/:@]{1,128}:[^\s/@]{8,128}@[^\s/]+/gi, `${REDACTED}:credential_url`)
    .replace(/(\b(?:Authorization\s*[:=]\s*)?(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/-]{12,}={0,2}/gi, `$1${REDACTED}:authorization`)
    .replace(/(\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|secret[_-]?key|authorization|bearer|token|secret)\b["']?\s*[:=]\s*["']?)[A-Za-z0-9_./+\-=:${}@]{12,512}/gi, `$1${REDACTED}:assignment`)
    .replace(/(?=[A-Za-z0-9+/=_-]{48,256}\b)(?=[A-Za-z0-9+/=_-]*[+/=])[A-Za-z0-9+/=_-]{48,256}/g, `${REDACTED}:encoded`);
}

class DiagnosticRedactor {
  constructor() {
    this.inPrivateKey = false;
    this.pending = "";
    this.discardUntilNewline = false;
  }

  redact(value) {
    let incoming = String(value);
    if (this.discardUntilNewline) {
      const newline = incoming.indexOf("\n");
      if (newline < 0) return "";
      incoming = incoming.slice(newline + 1);
      this.discardUntilNewline = false;
    }
    this.pending += incoming;
    const lines = this.pending.split(/\r?\n/);
    this.pending = lines.pop() || "";
    const output = [];
    for (const line of lines) {
      const safe = this.#redactCompleteLine(line);
      if (safe) output.push(safe);
    }
    if (this.pending.length > 16_384) {
      this.pending = "";
      this.discardUntilNewline = true;
      output.push(`${REDACTED}:oversized_diagnostic`);
    }
    return output.join("\n").trim();
  }

  flush() {
    if (this.discardUntilNewline || !this.pending) {
      this.pending = "";
      return "";
    }
    const line = this.pending;
    this.pending = "";
    return this.#redactCompleteLine(line);
  }

  #redactCompleteLine(line) {
      const upper = line.toUpperCase();
      if (this.inPrivateKey) {
        if (upper.includes("-----END") && upper.includes("PRIVATE KEY-----")) this.inPrivateKey = false;
        return "";
      }
      if (upper.includes("-----BEGIN") && upper.includes("PRIVATE KEY-----")) {
        if (!(upper.includes("-----END") && upper.includes("PRIVATE KEY-----"))) this.inPrivateKey = true;
        return `${REDACTED}:private_key`;
      }
      return redactLine(line);
  }
}

module.exports = { DiagnosticRedactor, redactLine };
