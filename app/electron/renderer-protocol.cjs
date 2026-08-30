"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const RENDERER_SCHEME = "human-codex";
const RENDERER_HOST = "renderer";
const RENDERER_ENTRY_URL = `${RENDERER_SCHEME}://${RENDERER_HOST}/index.html`;

function registerRendererScheme(protocol) {
  protocol.registerSchemesAsPrivileged([
    {
      scheme: RENDERER_SCHEME,
      privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true },
    },
  ]);
}

function resolveRendererFile(requestUrl, rendererRoot) {
  try {
    const url = new URL(requestUrl);
    if (url.protocol !== `${RENDERER_SCHEME}:` || url.host !== RENDERER_HOST) return null;
    const requestedPath = decodeURIComponent(url.pathname).replace(/^\/+/, "") || "index.html";
    const root = fs.realpathSync(rendererRoot);
    const candidate = fs.realpathSync(path.resolve(root, requestedPath));
    const relative = path.relative(root, candidate);
    if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return null;
    if (!fs.statSync(candidate).isFile()) return null;
    return candidate;
  } catch (_) {
    return null;
  }
}

function installRendererProtocol({ protocol, net, rendererRoot }) {
  protocol.handle(RENDERER_SCHEME, async (request) => {
    const filePath = resolveRendererFile(request.url, rendererRoot);
    if (!filePath) return new Response("Not found", { status: 404 });
    try {
      return await net.fetch(pathToFileURL(filePath).toString());
    } catch (_) {
      return new Response("Not found", { status: 404 });
    }
  });
}

module.exports = {
  RENDERER_ENTRY_URL,
  RENDERER_SCHEME,
  installRendererProtocol,
  registerRendererScheme,
  resolveRendererFile,
};
