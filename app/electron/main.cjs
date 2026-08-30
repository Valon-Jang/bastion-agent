"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { app, BrowserWindow, dialog, ipcMain, net, Notification, protocol } = require("electron");
const { validateRendererCall } = require("./api-contract.cjs");
const { CoreSupervisor } = require("./core-supervisor.cjs");
const { createCoreEnvironment, pythonCommand } = require("./core-environment.cjs");
const { redactLine } = require("./redaction.cjs");
const {
  RENDERER_ENTRY_URL,
  installRendererProtocol,
  registerRendererScheme,
} = require("./renderer-protocol.cjs");

let mainWindow;
let core;
const root = path.resolve(__dirname, "..", "..");
const portableDataRoot = path.join(root, "HumanCodexData");
const electronStateRoot = path.join(portableDataRoot, "electron");
const rendererRoot = path.resolve(__dirname, "..", "renderer", "dist");

fs.mkdirSync(path.join(electronStateRoot, "session"), { recursive: true });
fs.mkdirSync(path.join(electronStateRoot, "cache"), { recursive: true });
fs.mkdirSync(path.join(root, "Workspace"), { recursive: true });
app.setPath("userData", electronStateRoot);
app.setPath("sessionData", path.join(electronStateRoot, "session"));
app.commandLine.appendSwitch("disk-cache-dir", path.join(electronStateRoot, "cache"));

registerRendererScheme(protocol);

function createCore() {
  const python = pythonCommand(root);
  return new CoreSupervisor({
    ...python,
    timeoutMs: 30_000,
    cwd: root,
    env: createCoreEnvironment(root, process.env, { dataRoot: portableDataRoot }),
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    title: "Human Codex",
    icon: path.join(rendererRoot, "human-codex-logo.png"),
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 620,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      webviewTag: false,
      nodeIntegrationInSubFrames: false,
      allowRunningInsecureContent: false,
    },
  });
  mainWindow.webContents.session.setPermissionCheckHandler(() => false);
  mainWindow.webContents.session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-navigate", (event) => event.preventDefault());
  mainWindow.webContents.on("will-attach-webview", (event) => event.preventDefault());
  mainWindow.loadURL(RENDERER_ENTRY_URL);
}

function isTrustedRenderer(event) {
  return Boolean(
    mainWindow
      && !mainWindow.isDestroyed()
      && event.sender === mainWindow.webContents
      && event.senderFrame === mainWindow.webContents.mainFrame
      && event.senderFrame.url === RENDERER_ENTRY_URL,
  );
}

function installIpc() {
  ipcMain.handle("human-codex:request", async (event, incoming) => {
    if (!isTrustedRenderer(event)) throw new Error("untrusted IPC sender");
    if (!incoming || typeof incoming !== "object") throw new Error("invalid IPC request");
    const params = validateRendererCall(incoming.method, incoming.params);
    const result = await core.request(incoming.method, params);
    if (incoming.method === "job.list") await notifyCompletedJobs(result.jobs);
    return result;
  });
  ipcMain.handle("human-codex:choose-directory", async (event) => {
    if (!isTrustedRenderer(event)) throw new Error("untrusted IPC sender");
    const result = await dialog.showOpenDialog(mainWindow, {
      title: "Human Codex 프로젝트 폴더 선택",
      defaultPath: app.getPath("downloads"),
      properties: ["openDirectory", "createDirectory", "dontAddToRecent"],
    });
    if (result.canceled || result.filePaths.length !== 1) return null;
    return result.filePaths[0];
  });
}

async function notifyCompletedJobs(jobs) {
  if (!Array.isArray(jobs)) return;
  for (const job of jobs) {
    if (!job || job.notification_pending !== true || typeof job.id !== "string") continue;
    if (Notification.isSupported()) {
      new Notification({
        title: "Human Codex 백그라운드 작업 완료",
        body: job.command ? `완료: ${job.command}` : "백그라운드 명령이 완료됐습니다.",
        silent: false,
      }).show();
    }
    await core.request("job.acknowledge", { id: job.id }).catch(() => {});
  }
}

async function startApplication() {
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return;
  }
  installRendererProtocol({ protocol, net, rendererRoot });
  core = createCore();
  core.start();
  await core.healthCheck();
  installIpc();
  createWindow();
}

app.whenReady().then(startApplication).catch(async (error) => {
  console.error(`Human Codex startup failed: ${redactLine(error.message)}`);
  await core?.stop();
  app.quit();
});

app.on("second-instance", () => {
  if (mainWindow) mainWindow.focus();
});
app.on("window-all-closed", () => app.quit());
app.on("before-quit", () => core?.stop());
