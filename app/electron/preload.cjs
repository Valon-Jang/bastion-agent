"use strict";

const { contextBridge, ipcRenderer } = require("electron");

const CHANNEL = "human-codex:request";

function call(method, params) {
  return ipcRenderer.invoke(CHANNEL, { method, params });
}

const api = Object.freeze({
  project: Object.freeze({
    list: () => call("project.list", {}),
    create: (name, mainRoot) => call("project.create", mainRoot ? { name, main_root: mainRoot } : { name }),
    open: (id) => call("project.open", { id }),
    chooseDirectory: () => ipcRenderer.invoke("human-codex:choose-directory"),
    roots: (projectId) => call("project.roots", { project_id: projectId }),
    addRoot: (projectId, kind, path) => call("project.root.add", { project_id: projectId, kind, path }),
    permission: (projectId) => call("project.permission", { project_id: projectId }),
  }),
  approval: Object.freeze({
    list: (projectId) => call("approval.list", { project_id: projectId }),
    decide: (id, decision, scope) => call("approval.decide", { id, decision, scope }),
  }),
  workspace: Object.freeze({
    status: (projectId) => call("workspace.status", { project_id: projectId }),
    initGit: (projectId, approved) => call("workspace.git.init", { project_id: projectId, approved }),
    prepareWorktree: (projectId, approved) => call("workspace.worktree.prepare", { project_id: projectId, approved }),
  }),
  snapshot: Object.freeze({
    list: (projectId) => call("snapshot.list", { project_id: projectId }),
    create: (projectId, reason) => call("snapshot.create", { project_id: projectId, reason }),
  }),
  job: Object.freeze({
    list: (projectId) => call("job.list", { project_id: projectId }),
    resumeRecovery: (chatId) => call("recovery.resume", { chat_id: chatId }),
  }),
  chat: Object.freeze({
    list: (projectId) => call("chat.list", { project_id: projectId }),
    create: (projectId, title) => call("chat.create", title === undefined ? { project_id: projectId } : { project_id: projectId, title }),
    open: (chatId) => call("chat.open", { chat_id: chatId }),
    timeline: (chatId) => call("chat.timeline", { chat_id: chatId }),
    send: (chatId, text) => call("chat.send", { chat_id: chatId, text }),
    interrupt: (chatId) => call("chat.interrupt", { chat_id: chatId }),
    delete: (chatId) => call("chat.delete", { chat_id: chatId }),
  }),
  skill: Object.freeze({
    list: () => call("skill.list", {}),
    catalog: (query = "") => call("skill.catalog", { query }),
    install: (source, approved) => call("skill.install", { source, approved }),
  }),
  system: Object.freeze({
    health: () => call("system.health", {}),
    sandboxStatus: () => call("system.sandbox.status", {}),
    setupSandbox: (approved) => call("system.sandbox.setup", { approved }),
    diagnoseUnelevatedSandbox: (approved) => call("system.sandbox.diagnose-unelevated", { approved }),
    corporateSandboxTestStatus: () => call("system.sandbox.corporate-test.status", {}),
    startCorporateSandboxTest: (approved, projectId) => call(
      "system.sandbox.corporate-test.start",
      projectId === undefined ? { approved } : { approved, project_id: projectId },
    ),
    activateCorporateSandbox: (approved) => call("system.sandbox.corporate.activate", { approved }),
  }),
});

contextBridge.exposeInMainWorld("humanCodex", api);
