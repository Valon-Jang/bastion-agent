"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { ALLOWED_METHODS, validateRendererCall } = require("../../app/electron/api-contract.cjs");
const { createCoreEnvironment, pythonCommand } = require("../../app/electron/core-environment.cjs");
const { RENDERER_ENTRY_URL, resolveRendererFile } = require("../../app/electron/renderer-protocol.cjs");

const root = path.resolve(__dirname, "..", "..");
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), "utf8");
const projectId = "123e4567-e89b-42d3-a456-426614174000";

test("preload API allowlist accepts only milestone methods and valid payloads", () => {
  assert.deepEqual([...ALLOWED_METHODS].sort(), ["approval.decide", "approval.list", "chat.create", "chat.delete", "chat.interrupt", "chat.list", "chat.open", "chat.send", "chat.timeline", "job.list", "project.create", "project.list", "project.open", "project.permission", "project.root.add", "project.roots", "recovery.resume", "skill.catalog", "skill.install", "skill.list", "snapshot.create", "snapshot.list", "system.health", "system.sandbox.corporate-test.start", "system.sandbox.corporate-test.status", "system.sandbox.corporate.activate", "system.sandbox.diagnose-unelevated", "system.sandbox.setup", "system.sandbox.status", "workspace.git.init", "workspace.status", "workspace.worktree.prepare"]);
  assert.deepEqual(validateRendererCall("project.list", {}), {});
  assert.deepEqual(validateRendererCall("project.create", { name: "Alpha" }), { name: "Alpha" });
  assert.deepEqual(validateRendererCall("chat.create", { project_id: projectId }), { project_id: projectId });
  assert.deepEqual(validateRendererCall("chat.open", { chat_id: projectId }), { chat_id: projectId });
  assert.deepEqual(validateRendererCall("chat.send", { chat_id: projectId, text: "hello" }), { chat_id: projectId, text: "hello" });
  assert.deepEqual(validateRendererCall("chat.delete", { chat_id: projectId }), { chat_id: projectId });
  assert.deepEqual(validateRendererCall("skill.list", {}), {});
  assert.deepEqual(validateRendererCall("skill.catalog", { query: "pdf" }), { query: "pdf" });
  assert.deepEqual(validateRendererCall("skill.install", { source: "pdf", approved: true }), { source: "pdf", approved: true });
  assert.deepEqual(validateRendererCall("job.list", { project_id: projectId }), { project_id: projectId });
  assert.deepEqual(validateRendererCall("recovery.resume", { chat_id: projectId }), { chat_id: projectId });
  assert.deepEqual(validateRendererCall("system.sandbox.status", {}), {});
  assert.deepEqual(validateRendererCall("system.sandbox.setup", { approved: true }), { approved: true });
  assert.deepEqual(validateRendererCall("system.sandbox.diagnose-unelevated", { approved: true }), { approved: true });
  assert.deepEqual(validateRendererCall("system.sandbox.corporate-test.status", {}), {});
  assert.deepEqual(validateRendererCall("system.sandbox.corporate-test.start", { approved: true }), { approved: true });
  assert.deepEqual(validateRendererCall("system.sandbox.corporate-test.start", { approved: true, project_id: projectId }), { approved: true, project_id: projectId });
  assert.deepEqual(validateRendererCall("system.sandbox.corporate.activate", { approved: true }), { approved: true });
  assert.throws(() => validateRendererCall("shell.execute", { command: "whoami" }));
  assert.throws(() => validateRendererCall("project.create", { name: "Alpha", command: "whoami" }));
  assert.throws(() => validateRendererCall("chat.list", { project_id: "not-an-id" }));
  assert.throws(() => validateRendererCall("chat.send", { chat_id: projectId, text: "x".repeat(32001) }));
  assert.throws(() => validateRendererCall("skill.install", { source: "pdf", approved: false }));
  assert.throws(() => validateRendererCall("project.root.add", { project_id: projectId, kind: "system", path: "C:\\Windows" }));
  assert.throws(() => validateRendererCall("project.root.add", { project_id: projectId, kind: "write", path: `C:\\${"x".repeat(4096)}` }));
  assert.throws(() => validateRendererCall("approval.decide", { id: projectId, decision: "approve", scope: "forever" }));
  assert.throws(() => validateRendererCall("workspace.git.init", { project_id: projectId, approved: false }));
  assert.throws(() => validateRendererCall("system.sandbox.setup", { approved: false }));
  assert.throws(() => validateRendererCall("system.sandbox.diagnose-unelevated", { approved: false }));
  assert.throws(() => validateRendererCall("system.sandbox.corporate-test.start", { approved: false }));
  assert.throws(() => validateRendererCall("system.sandbox.corporate.activate", { approved: false }));
});

test("Main BrowserWindow enforces security and loads only the trusted app origin", () => {
  const main = read("app", "electron", "main.cjs");
  assert.match(main, /nodeIntegration:\s*false/);
  assert.match(main, /contextIsolation:\s*true/);
  assert.match(main, /sandbox:\s*true/);
  assert.match(main, /webviewTag:\s*false/);
  assert.match(main, /loadURL\(RENDERER_ENTRY_URL\)/);
  assert.doesNotMatch(main, /loadFile\(/);
  assert.match(main, /setWindowOpenHandler\(\(\) => \(\{ action: "deny" \}\)\)/);
  assert.match(main, /setPermissionRequestHandler\(/);
  assert.match(main, /event\.senderFrame === mainWindow\.webContents\.mainFrame/);
  assert.match(main, /event\.senderFrame\.url === RENDERER_ENTRY_URL/);
  assert.match(main, /human-codex:choose-directory/);
  assert.match(main, /defaultPath:\s*app\.getPath\("downloads"\)/);
  assert.match(main, /properties:\s*\["openDirectory", "createDirectory", "dontAddToRecent"\]/);
  assert.match(main, /Notification\.isSupported\(\)/);
  assert.match(main, /core\.request\("job\.acknowledge"/);
  assert.match(main, /timeoutMs:\s*30_000/);
  assert.match(main, /HumanCodexData/);
  assert.match(main, /app\.setPath\("userData"/);
  assert.doesNotMatch(main, /\.\.\.process\.env/);
  const smoke = read("app", "electron", "smoke.cjs");
  assert.match(smoke, /app\.setPath\("userData"/);
  assert.match(smoke, /app\.setPath\("sessionData"/);
  const launcher = read("bootstrapper", "Launch-HumanCodex.bat");
  assert.match(launcher, /--portable-smoke/);
  assert.match(launcher, /HUMAN_CODEX_PORTABLE_SMOKE%"=="1"/);
});

test("Core launch uses bundled Python and drops ambient credential variables", () => {
  const bundled = path.join(root, "runtime", "python", "python.exe");
  assert.equal(pythonCommand(root, (candidate) => candidate === bundled).command, bundled);
  const environment = createCoreEnvironment(root, {
    SystemRoot: "C:\\Windows",
    PATH: "C:\\Windows\\System32",
    OPENAI_API_KEY: "must-not-pass",
    HC_PRIVATE_TOKEN: "must-not-pass",
    HTTP_PROXY: "http://proxy.example:8080",
    HTTPS_PROXY: "http://user:password@proxy.example:8080",
    HUMAN_CODEX_DATA_ROOT: "C:\\HumanCodexData",
    HUMAN_CODEX_PYTHON: "C:\\untrusted.exe",
  });
  assert.equal(environment.HTTP_PROXY, "http://proxy.example:8080");
  assert.equal(environment.HUMAN_CODEX_DATA_ROOT, undefined);
  assert.equal(environment.PYTHONNOUSERSITE, "1");
  assert.equal(environment.PYTHONSAFEPATH, "1");
  assert.equal(environment.OPENAI_API_KEY, undefined);
  assert.equal(environment.HC_PRIVATE_TOKEN, undefined);
  assert.equal(environment.HTTPS_PROXY, undefined);
  assert.equal(environment.HUMAN_CODEX_PYTHON, undefined);
  const smokeEnvironment = createCoreEnvironment(root, {
    SystemRoot: "C:\\Windows",
    HUMAN_CODEX_DATA_ROOT: "C:\\HumanCodexData",
  }, { allowDataRoot: true });
  assert.equal(smokeEnvironment.HUMAN_CODEX_DATA_ROOT, "C:\\HumanCodexData");
  const portableEnvironment = createCoreEnvironment(root, {}, {
    dataRoot: path.join(root, "HumanCodexData"),
  });
  assert.equal(portableEnvironment.HUMAN_CODEX_DATA_ROOT, path.join(root, "HumanCodexData"));
});

test("Renderer protocol confines requests to the built renderer directory", () => {
  const rendererRoot = path.join(root, "app", "renderer", "dist");
  assert.equal(resolveRendererFile(RENDERER_ENTRY_URL, rendererRoot), path.join(rendererRoot, "index.html"));
  assert.equal(resolveRendererFile("human-codex://renderer/%2e%2e%2fsecret.txt", rendererRoot), null);
  assert.equal(resolveRendererFile("human-codex://renderer/%zz", rendererRoot), null);
  assert.equal(resolveRendererFile("human-codex://renderer/assets", rendererRoot), null);
  assert.equal(resolveRendererFile("human-codex://untrusted/index.html", rendererRoot), null);
});

test("Renderer has no require, Node process, or raw ipcRenderer access", () => {
  const renderer = ["app/renderer/src/main.jsx", "app/renderer/src/App.jsx"].map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
  assert.doesNotMatch(renderer, /\brequire\s*\(/);
  assert.doesNotMatch(renderer, /\bipcRenderer\b/);
  assert.doesNotMatch(renderer, /\bprocess\./);
  const preload = read("app", "electron", "preload.cjs");
  assert.match(preload, /contextBridge\.exposeInMainWorld\("humanCodex", api\)/);
  assert.match(preload, /system\.sandbox\.setup/);
  assert.match(preload, /system\.sandbox\.diagnose-unelevated/);
  assert.match(preload, /system\.sandbox\.corporate-test\.start/);
  assert.doesNotMatch(preload, /exposeInMainWorld\([^\n]*ipcRenderer/);
  assert.doesNotMatch(preload, /require\(["']\.\.?\//);
});

test("Renderer exposes Korean sandbox progress and the project logo", () => {
  const renderer = read("app", "renderer", "src", "App.jsx");
  const styles = read("app", "renderer", "src", "styles.css");
  const main = read("app", "electron", "main.cjs");
  const document = read("app", "renderer", "index.html");
  assert.match(renderer, /보안 샌드박스 설정/);
  assert.match(renderer, /관리자 승인/);
  assert.match(renderer, /격리 환경 구성/);
  assert.match(renderer, /보안 실검증/);
  assert.match(renderer, /진행 중/);
  assert.match(renderer, /회사 PC 원인 진단/);
  assert.match(renderer, /실패 내용·원인 진단/);
  assert.match(renderer, /경고 확인 후 채팅 열기/);
  assert.match(renderer, /회사 PC 호환 검사/);
  assert.match(renderer, /웹 검색/);
  assert.match(renderer, /공개 문서 학습/);
  assert.match(renderer, /자가수리 \(다음 실행 적용\)/);
  assert.match(renderer, /대기열에 추가/);
  assert.match(renderer, /채팅 삭제/);
  assert.match(renderer, /공식·GitHub 스킬 검색/);
  assert.match(renderer, /Junction 우회 읽기 차단/);
  assert.match(renderer, /human-codex-logo\.png/);
  assert.match(styles, /\.sandbox-dialog/);
  assert.match(main, /icon:\s*path\.join\(rendererRoot, "human-codex-logo\.png"\)/);
  assert.match(document, /<html lang="ko">/);
  assert.ok(fs.statSync(path.join(root, "app", "renderer", "public", "human-codex-logo.png")).size > 0);
});

test("Renderer document defines a restrictive Content Security Policy", () => {
  const document = read("app", "renderer", "index.html");
  assert.match(document, /Content-Security-Policy/);
  assert.match(document, /default-src 'self'/);
  assert.match(document, /connect-src 'none'/);
  assert.match(document, /object-src 'none'/);
});

test("Windows verifier waits for command shims and requires fresh Electron smoke evidence", () => {
  const verifier = read("scripts", "VERIFY_M1.bat");
  assert.match(verifier, /call npm run build/);
  assert.match(verifier, /call "node_modules\\\.bin\\electron\.cmd"/);
  assert.match(verifier, /if exist "artifacts\\test\\m1-electron-smoke\.json" del/);
  assert.match(verifier, /if not exist "artifacts\\test\\m1-electron-smoke\.json" goto :artifact_failed/);
  assert.match(verifier, /:artifact_failed[\s\S]*exit \/b 2/);
});
