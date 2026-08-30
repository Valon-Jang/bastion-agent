# Architecture Decisions

기준: `HUMAN_CODEX_V0_1_MASTER_IMPLEMENTATION_SPEC.md` 0.1-R2. 체크는 구현 완료가 아니라 설계 반영 여부를 뜻하며, 구현 상태는 `IMPLEMENTATION_STATUS.md`에서 관리한다.

## 고정 결정

- [x] 공식 `codex app-server`를 유일한 필수 reasoning/coding provider로 사용한다.
- [x] ChatGPT 웹 DOM 자동화 및 Output scraping provider를 만들지 않는다.
- [x] 파일 및 이미지를 Codex attachment로 업로드하지 않고 로컬 텍스트/구조 경로만 사용한다.
- [x] Python Core가 stdio NDJSON JSON-RPC로 App Server를 소유·감시한다.
- [x] 연결마다 `initialize` 응답 후 `initialized`를 보내고 이후 `thread/start`를 호출한다.
- [x] 설치된 Codex 버전으로 stable JSON Schema/TypeScript bindings를 생성해 고정한다.
- [x] `CODEX_HOME`과 `CODEX_SQLITE_HOME`을 `%LOCALAPPDATA%\HumanCodex\codex-home`으로 분리한다.
- [x] `cli_auth_credentials_store = "keyring"`을 기본으로 하며 token을 프로젝트와 로그에 남기지 않는다.
- [x] Renderer는 향후 `nodeIntegration=false`, `contextIsolation=true`, `sandbox=true`로만 구성한다.
- [x] Renderer에는 raw IPC와 OS API를 노출하지 않고 preload whitelist만 제공한다.
- [x] Main ↔ Python Core는 stdout protocol/stderr log 경계를 갖는 구조화 IPC를 사용한다.
- [x] 모든 경로는 Windows case-insensitive canonical path 정책과 root boundary 검사를 거친다.
- [x] Codex sandbox와 Human Codex Risk Engine은 독립 계층이며 더 엄격한 판정을 적용한다.
- [x] GitHub 및 모든 remote 생성/push는 금지한다. 로컬 Git만 허용한다.
- [x] 사용자 dirty tree는 stage/commit하지 않고 큰 작업은 worktree 또는 snapshot으로 격리한다.
- [x] metadata SQLite와 DPAPI 보호 AES-GCM vault를 분리한다.
- [x] side effect는 action journal/idempotency/precondition/postcondition으로 복구한다.
- [x] v0.1은 Main Coding Thread만 활성화하고 specialist는 interface로만 둔다.
- [x] Browser/Vision/Office/Computer Use는 Smoke Test PASS 전까지 disabled로 유지한다.
- [x] Source/Runtime/User Data를 분리하고 현재 runtime 자동 덮어쓰기를 금지한다.

## Milestone 0 경계

- [x] 설치된 CLI help와 version-matched schema가 외부 문서보다 우선한다.
- [x] 환경 진단은 읽기와 일시적 write probe만 수행하며 설치·시스템 설정 변경을 하지 않는다.
- [x] App Server smoke는 `read-only`, `on-request`, ephemeral thread로 실행한다.
- [x] model 이름은 smoke에서 지정하지 않고 설치본/계정의 기본값을 사용한다.
- [x] ownership metadata가 없는 D 드라이브에서는 전역 Git 설정 대신 canonical repository path를 명령별 `safe.directory`로 지정한다.
- [ ] Electron/React와 secure preload는 Milestone 1에서 구현한다.
- [ ] SQLite/DPAPI/AES vault는 Milestone 1에서 구현한다.
- [ ] Turn/event persistence와 one-turn round trip은 Milestone 2에서 구현한다.
