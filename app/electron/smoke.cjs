"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { app, BrowserWindow, ipcMain, net, protocol } = require("electron");
const { validateRendererCall } = require("./api-contract.cjs");
const { CoreSupervisor } = require("./core-supervisor.cjs");
const { createCoreEnvironment, pythonCommand } = require("./core-environment.cjs");
const { redactLine } = require("./redaction.cjs");
const {
  RENDERER_ENTRY_URL,
  installRendererProtocol,
  registerRendererScheme,
} = require("./renderer-protocol.cjs");

const root = path.resolve(__dirname, "..", "..");
const artifactPath = process.env.HUMAN_CODEX_SMOKE_ARTIFACT || path.join(root, "artifacts", "test", "m1-electron-smoke.json");
const channel = "human-codex:request";
registerRendererScheme(protocol);

const electronStateRoot = process.env.HUMAN_CODEX_ELECTRON_USER_DATA;
if (typeof electronStateRoot === "string" && path.isAbsolute(electronStateRoot)) {
  const userData = path.resolve(electronStateRoot);
  const sessionData = path.join(userData, "session");
  const diskCache = path.join(userData, "cache");
  fs.mkdirSync(sessionData, { recursive: true });
  fs.mkdirSync(diskCache, { recursive: true });
  app.setPath("userData", userData);
  app.setPath("sessionData", sessionData);
  app.commandLine.appendSwitch("disk-cache-dir", diskCache);
}

app.whenReady().then(async () => {
  const python = pythonCommand(root);
  const core = new CoreSupervisor({
    ...python,
    timeoutMs: 30_000,
    cwd: root,
    env: createCoreEnvironment(root, process.env, { allowDataRoot: true }),
  });
  let window;
  let exitCode = 0;
  try {
    core.start();
    const health = await core.healthCheck();
    installRendererProtocol({ protocol, net, rendererRoot: path.join(root, "app", "renderer", "dist") });
    window = new BrowserWindow({
      show: false,
      webPreferences: {
        preload: path.join(root, "app", "electron", "preload.cjs"),
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true,
        webviewTag: false,
      },
    });
    window.webContents.on("preload-error", (_event, preloadPath, error) => {
      console.error(`M1 preload failed: ${redactLine(error.message)}`);
    });
    ipcMain.handle(channel, async (event, incoming) => {
      if (event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame || event.senderFrame.url !== RENDERER_ENTRY_URL) {
        throw new Error("untrusted smoke IPC sender");
      }
      if (!incoming || typeof incoming !== "object") throw new Error("invalid smoke IPC request");
      return core.request(incoming.method, validateRendererCall(incoming.method, incoming.params));
    });
    await window.loadURL(RENDERER_ENTRY_URL);
    const renderer = await window.webContents.executeJavaScript(`({
      title: document.title,
      hasApi: Boolean(window.humanCodex),
      rootChildren: document.getElementById("root")?.children.length || 0,
    })`);
    const ipcHealth = await window.webContents.executeJavaScript("window.humanCodex.system.health()");
    if (renderer.title !== "Human Codex" || !renderer.hasApi || renderer.rootChildren < 1 || ipcHealth.status !== "pass") {
      throw new Error("Renderer/preload/Main/Core round trip did not reach the expected state");
    }
    const result = { status: "pass", electron: process.versions.electron, health, ipcHealth, renderer };
    fs.mkdirSync(path.dirname(artifactPath), { recursive: true });
    fs.writeFileSync(artifactPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(`M1 Electron smoke failed: ${redactLine(error.message)}`);
    exitCode = 2;
  } finally {
    ipcMain.removeHandler(channel);
    window?.destroy();
    await core.stop();
    app.exit(exitCode);
  }
});
