"use strict";

const ALLOWED_METHODS = new Set([
  "project.list",
  "project.create",
  "project.open",
  "project.roots",
  "project.root.add",
  "project.permission",
  "chat.list",
  "chat.create",
  "chat.open",
  "chat.timeline",
  "chat.send",
  "chat.interrupt",
  "chat.delete",
  "skill.list",
  "skill.catalog",
  "skill.install",
  "approval.list",
  "approval.decide",
  "workspace.status",
  "workspace.git.init",
  "workspace.worktree.prepare",
  "snapshot.list",
  "snapshot.create",
  "job.list",
  "recovery.resume",
  "system.health",
  "system.sandbox.status",
  "system.sandbox.setup",
  "system.sandbox.diagnose-unelevated",
  "system.sandbox.corporate-test.status",
  "system.sandbox.corporate-test.start",
  "system.sandbox.corporate.activate",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function invalid(message) {
  const error = new Error(message);
  error.code = "HC_INVALID_IPC";
  throw error;
}

function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("params must be an object");
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    invalid("payload keys are invalid");
  }
}

function requiredString(value, key, maximum) {
  if (typeof value[key] !== "string" || !value[key].trim() || value[key].trim().length > maximum) {
    invalid(`${key} must be a non-empty string no longer than ${maximum} characters`);
  }
  return value[key].trim();
}

function projectId(value, key = "project_id") {
  const id = requiredString(value, key, 36);
  if (!UUID.test(id)) invalid(`${key} must be a UUID`);
  return id;
}

function chatId(value) {
  return projectId(value, "chat_id");
}

function validateRendererCall(method, params) {
  if (!ALLOWED_METHODS.has(method)) invalid("method is not allowed");
  if (method === "project.list" || method === "skill.list" || method === "system.health" || method === "system.sandbox.status" || method === "system.sandbox.corporate-test.status") {
    exactKeys(params, []);
    return {};
  }
  if (method === "system.sandbox.setup" || method === "system.sandbox.diagnose-unelevated" || method === "system.sandbox.corporate.activate") {
    exactKeys(params, ["approved"]);
    if (params.approved !== true) invalid("Windows sandbox operation requires explicit approval");
    return { approved: true };
  }
  if (method === "system.sandbox.corporate-test.start") {
    const keys = Object.keys(params || {});
    if (!keys.includes("approved") || keys.some((key) => key !== "approved" && key !== "project_id")) {
      invalid("Corporate sandbox test payload is invalid");
    }
    if (params.approved !== true) invalid("Windows sandbox operation requires explicit approval");
    const result = { approved: true };
    if (Object.hasOwn(params, "project_id")) result.project_id = projectId(params);
    return result;
  }
  if (method === "project.create") {
    const keys = Object.keys(params || {});
    if (!keys.includes("name") || keys.some((key) => key !== "name" && key !== "main_root")) invalid("project.create payload keys are invalid");
    const result = { name: requiredString(params, "name", 120) };
    if (Object.hasOwn(params, "main_root")) result.main_root = requiredString(params, "main_root", 4096);
    return result;
  }
  if (method === "project.open") {
    exactKeys(params, ["id"]);
    return { id: projectId(params, "id") };
  }
  if (method === "chat.list") {
    exactKeys(params, ["project_id"]);
    return { project_id: projectId(params) };
  }
  if (method === "chat.create") {
    const keys = Object.keys(params || {});
    if (!keys.includes("project_id") || keys.some((key) => key !== "project_id" && key !== "title")) {
      invalid("chat.create payload keys are invalid");
    }
    const result = { project_id: projectId(params) };
    if (Object.hasOwn(params, "title")) result.title = requiredString(params, "title", 160);
    return result;
  }
  if (method === "chat.open" || method === "chat.timeline" || method === "chat.interrupt" || method === "chat.delete") {
    exactKeys(params, ["chat_id"]);
    return { chat_id: chatId(params) };
  }
  if (method === "chat.send") {
    exactKeys(params, ["chat_id", "text"]);
    return { chat_id: chatId(params), text: requiredString(params, "text", 32000) };
  }
  if (method === "skill.catalog") {
    exactKeys(params, ["query"]);
    if (typeof params.query !== "string" || params.query.length > 120) invalid("skill query is invalid");
    return { query: params.query.trim() };
  }
  if (method === "skill.install") {
    exactKeys(params, ["source", "approved"]);
    if (params.approved !== true) invalid("skill installation requires explicit approval");
    return { source: requiredString(params, "source", 2048), approved: true };
  }
  if (["project.roots", "project.permission", "workspace.status", "snapshot.list", "job.list"].includes(method)) {
    exactKeys(params, ["project_id"]);
    return { project_id: projectId(params) };
  }
  if (method === "workspace.git.init" || method === "workspace.worktree.prepare") {
    exactKeys(params, ["project_id", "approved"]);
    if (params.approved !== true) invalid("workspace mutation requires explicit approval");
    return { project_id: projectId(params), approved: true };
  }
  if (method === "project.root.add") {
    exactKeys(params, ["project_id", "kind", "path"]);
    const kind = requiredString(params, "kind", 20);
    if (!["reference", "write", "output"].includes(kind)) invalid("root kind is invalid");
    return { project_id: projectId(params), kind, path: requiredString(params, "path", 4096) };
  }
  if (method === "approval.list") {
    exactKeys(params, ["project_id"]);
    return { project_id: projectId(params) };
  }
  if (method === "approval.decide") {
    exactKeys(params, ["id", "decision", "scope"]);
    const id = projectId(params, "id");
    const decision = requiredString(params, "decision", 10);
    const scope = requiredString(params, "scope", 10);
    if (!["approve", "deny"].includes(decision) || !["once", "task", "session"].includes(scope)) invalid("approval decision is invalid");
    return { id, decision, scope };
  }
  if (method === "snapshot.create") {
    exactKeys(params, ["project_id", "reason"]);
    return { project_id: projectId(params), reason: requiredString(params, "reason", 160) };
  }
  if (method === "recovery.resume") {
    exactKeys(params, ["chat_id"]);
    return { chat_id: chatId(params) };
  }
  invalid("method is not implemented");
}

module.exports = { ALLOWED_METHODS, validateRendererCall };
