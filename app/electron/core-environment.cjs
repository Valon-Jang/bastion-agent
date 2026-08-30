"use strict";

const fs = require("node:fs");
const path = require("node:path");

const SAFE_OS_NAMES = new Set([
  "ALLUSERSPROFILE", "APPDATA", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)",
  "COMMONPROGRAMW6432", "COMSPEC", "DRIVERDATA", "HOMEDRIVE", "HOMEPATH", "HOME",
  "LANG", "LC_ALL", "LC_CTYPE", "LOCALAPPDATA", "NO_COLOR", "NUMBER_OF_PROCESSORS",
  "OS", "PATH", "PATHEXT", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
  "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "PROGRAMDATA", "PROGRAMFILES",
  "PROGRAMFILES(X86)", "PROGRAMW6432", "PUBLIC", "SHELL", "SYSTEMDRIVE",
  "SYSTEMROOT", "TEMP", "TERM", "TMP", "USERDOMAIN", "USERNAME", "USERPROFILE",
  "WINDIR",
]);
const SAFE_NETWORK_NAMES = new Set([
  "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS",
  "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE",
]);

function safeNetworkSetting(name, value) {
  if (!["ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"].includes(name)) return true;
  try {
    const parsed = new URL(value);
    return ["http:", "https:", "socks5:", "socks5h:"].includes(parsed.protocol)
      && Boolean(parsed.hostname)
      && !parsed.username
      && !parsed.password;
  } catch (_) {
    return false;
  }
}

function createCoreEnvironment(root, sourceEnvironment = process.env, options = {}) {
  const environment = {};
  for (const [name, value] of Object.entries(sourceEnvironment)) {
    if (typeof value !== "string") continue;
    const canonical = name.toUpperCase();
    if (SAFE_OS_NAMES.has(canonical)) environment[name] = value;
    if (SAFE_NETWORK_NAMES.has(canonical) && safeNetworkSetting(canonical, value)) {
      environment[canonical] = value;
    }
  }
  const explicitDataRoot = options.dataRoot;
  const ambientDataRoot = sourceEnvironment.HUMAN_CODEX_DATA_ROOT;
  if (typeof explicitDataRoot === "string" && path.isAbsolute(explicitDataRoot)) {
    const resolvedRoot = path.resolve(root);
    const resolvedData = path.resolve(explicitDataRoot);
    const relative = path.relative(resolvedRoot, resolvedData);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error("portable data root must be inside the installation folder");
    }
    environment.HUMAN_CODEX_DATA_ROOT = resolvedData;
  } else if (options.allowDataRoot === true && typeof ambientDataRoot === "string" && path.isAbsolute(ambientDataRoot)) {
    environment.HUMAN_CODEX_DATA_ROOT = path.resolve(ambientDataRoot);
  }
  environment.PYTHONPATH = path.join(root, "source", "core");
  environment.PYTHONNOUSERSITE = "1";
  environment.PYTHONDONTWRITEBYTECODE = "1";
  environment.PYTHONSAFEPATH = "1";
  environment.PYTHONIOENCODING = "utf-8";
  return environment;
}

function pythonCommand(root, exists = fs.existsSync) {
  const bundled = path.join(root, "runtime", "python", "python.exe");
  if (exists(bundled)) {
    return { command: bundled, args: ["-m", "human_codex", "core", "serve"] };
  }
  return { command: "py", args: ["-3.12", "-m", "human_codex", "core", "serve"] };
}

module.exports = { createCoreEnvironment, pythonCommand, safeNetworkSetting };
