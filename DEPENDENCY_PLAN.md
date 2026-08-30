# Dependency Plan — Milestone 1

Status: approved, installed repository-locally, locked, and verified.

## Evidence

On 2026-08-27, the user approved fixed dependency installation. The repository now has local `node_modules` and `package-lock.json`; Electron 44.0.0, React/React DOM 19.1.1, Vite 7.3.6, and React plugin 5.0.2 are installed. Python 3.12 has project-pinned `cryptography==50.0.1`.

## Proposed npm dependencies

| Package | Fixed version candidate | Official source | License | Reason | Install location |
|---|---:|---|---|---|---|
| `electron` | `44.0.0` | npm package `electron` / Electron releases | MIT | Windows desktop Main/Preload runtime and BrowserWindow security validation | repository-local `node_modules` as a dev dependency |
| `react` | `19.1.1` | npm package `react` / React releases | MIT | Renderer UI components | repository-local `node_modules` as a dependency |
| `react-dom` | `19.1.1` | npm package `react-dom` / React releases | MIT | Renderer DOM mounting | repository-local `node_modules` as a dependency |
| `vite` | `7.3.6` | npm package `vite` / Vite releases | MIT | local-only renderer build and development server; patched against the audited Windows path/file disclosure issues affecting 7.1.7 | repository-local `node_modules` as a dev dependency |
| `@vitejs/plugin-react` | `5.0.2` | npm package `@vitejs/plugin-react` / Vite releases | MIT | React transformation for the local renderer build | repository-local `node_modules` as a dev dependency |

Electron `44.0.0` is the supported stable release selected to replace the previously proposed end-of-life Electron 37 line. Vite was updated from audited-vulnerable 7.1.7 to 7.3.6. Direct package licenses are MIT; `npm audit --audit-level=low` reports zero vulnerabilities, registry signature verification passes for 76 packages, and 41 packages have verified attestations.

## Existing Python dependency

| Package | Observed version | Use | Change scope |
|---|---:|---|---|
| `cryptography` | `50.0.1` | `AESGCM` only for vault ciphertext | exact project/runtime requirement; Windows wheel includes OpenSSL 4.0.2 |

`sqlite3`, `ctypes`, and `hashlib` are Python standard-library modules. DPAPI is called through Windows `crypt32.dll`; no `pywin32` project dependency is required.

## Approved installation command

Executed from the repository root after explicit approval:

```powershell
npm install --save-exact react@19.1.1 react-dom@19.1.1
npm install --save-dev --save-exact electron@44.0.0 vite@7.3.6 @vitejs/plugin-react@5.0.2
py -3.12 -m pip install --requirement requirements-m1.txt
```

`requirements-m1.txt` pins `cryptography==50.0.1`. npm install scripts are denied by default except the exact audited build dependency `esbuild@0.28.2` recorded in `package.json` `allowScripts`.

## Completed verification

1. Generated `package-lock.json`, exact direct versions, and MIT license metadata reviewed.
2. `npm audit --audit-level=low`, registry signature verification, and `pip check` PASS.
3. `scripts\VERIFY_M1.bat` PASS with Python 22/22, Node 10/10, Vite build, and Electron 44 Renderer → preload → Main → Python Core smoke.
4. Refreshed evidence preserved at `artifacts/test/m1-electron-smoke.json`.

## Removal and recovery

Remove only the explicitly added repository-local dependency files after validating their exact paths, then restore from the local M0/M1 checkpoint. Do not change global npm, Python, PATH, Registry, or remote Git state. User data stays in `%LOCALAPPDATA%\HumanCodex` and is never removed by dependency recovery.
