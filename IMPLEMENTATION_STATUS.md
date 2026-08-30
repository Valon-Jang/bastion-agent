# Human Codex Implementation Status

- 기준 명세: `0.1-R2`
- 현재 단계: Milestone 6 회사 내부 테스트 RC 검증 완료, 공개 출시 HOLD (`company_test_go_public_hold`)
- 원격 저장소: 금지 / 등록 없음

## Milestone 0 — Repository와 Gate 0

- [x] 설치된 `codex --version`, `codex --help`, `codex app-server --help` 확인
- [x] 설치된 `generate-json-schema`와 `generate-ts` help 확인
- [x] Source/Runtime/User Data 경계 결정
- [x] Python 3.12 package scaffold
- [x] Portable path policy 구현
- [x] 환경 진단 CLI 구현
- [x] Codex runtime detection 구현
- [x] 앱 전용 `CODEX_HOME` 준비와 `codex login` launch flow 구현
- [x] version-matched stable schema 생성 도구 구현
- [x] App Server initialize/thread-start smoke 구현
- [x] schema와 TypeScript binding을 `0.147.0`으로 생성·고정
- [x] unit test PASS (9 tests)
- [x] 실제 환경 diagnostics artifact 생성
- [x] 실제 App Server initialize/thread-start smoke PASS
- [x] 앱 전용 `CODEX_HOME` ChatGPT 로그인 완료
- [x] Portable Python 3.12 runtime bundle 확보
- [x] Milestone 0 개발 Gate 완료 판정 (Portable bundle은 Milestone 6)

완료 조건은 설치된 CLI와 앱 전용 `CODEX_HOME`을 사용한 App Server initialize/thread-start 성공이다.

현재 Gate 0 결과:

- blocker 없음
- Codex CLI `0.147.0`, App Server 및 native sandbox 사용 가능
- schema pin 927 files 검증 PASS
- child process/Named Pipe/Git commit test PASS
- ChatGPT/OpenAI 443 연결 가능
- Portable Python/Electron/Codex runtime 번들 및 fresh-folder 검증 완료
- D 드라이브가 ownership metadata를 기록하지 않아 Git 명령에 정확한 경로의 `safe.directory` override가 필요함. 전역 설정은 변경하지 않음.

## Milestone 1 — UI/Core 최소 골격

- [x] Electron/React source shell (`human-codex://renderer` local-only origin, Sidebar/Project/Chat/empty Composer, disabled capability indicators)
- [x] secure preload IPC API contract, trusted-sender validation, CSP, and Node-only security tests
- [x] Python Core child-process supervisor and actual Node ↔ Python Core health handshake test
- [x] transactional SQLite metadata migration, Project/Chat creation/listing, restart persistence tests
- [x] DPAPI master-key and AES-GCM vault implementation with round-trip/tamper/context tests
- [x] `VERIFY_M1.bat`, `MILESTONE_1_PLAN.md`, and dependency plan
- [x] Electron 44 runtime build/BrowserWindow/Renderer→preload→Main→Python Core smoke

Milestone 1 validation: Python 22 tests PASS; Node security/supervisor 10 tests PASS; Vite 7.3.6 production build PASS; Electron 44.0.0 hidden BrowserWindow smoke PASS. The refreshed `artifacts/test/m1-electron-smoke.json` proves React mount, sandbox preload availability, trusted Renderer IPC, Main validation, and Python Core health response. `npm audit --audit-level=low`, registry signatures, and `pip check` PASS. Core IPC enforces 1 MiB frames and bounded list replies; the Main process validates all Core response envelopes and kills a child that violates framing. No PATH, Registry, global npm, remote, or push action was performed.

## Milestone 2 — Codex Thread Loop

- [x] thread start/resume
- [x] turn start/interrupt
- [x] agent/item/event persistence
- [x] one-turn round trip

구현 및 fake App Server 폐쇄루프가 PASS했고, 실제 0.147.0 App Server Turn도 `completed`/`M2_OK`로 PASS했다.

## Milestone 3 — Workspace/Policy/Git

- [x] Roots와 schema-supported workspace-write permission policy
- [x] Risk Engine과 App Server 승인 UI/암호화 감사 기록
- [x] Local Git 진단/승인 Init/dirty-safe Worktree/Snapshot/승인 Restore
- [x] 실제 로그인 상태의 제한 프로젝트 edit/test PASS

M3 validation: Python 33 tests PASS; Node security/supervisor 10 tests PASS; Vite build PASS; schema 0.147.0/927 files PASS. 실제 disposable-project smoke는 Turn completed, 승인 3건, Snapshot 3개, 파일/테스트/최종 응답 검증 PASS.

## Milestone 4 — Tool Cards/Jobs/Recovery

- [x] Tool cards와 background jobs
- [x] Checkpoint/crash recovery
- [x] Windows notifications

M4 validation: Python 35 tests PASS; Node security/IPC/supervisor contract 10 tests PASS; Vite build PASS; schema 0.147.0/927 files PASS. Controlled App Server protocol smoke는 background test job 완료, read-only/no-network 자동 follow-up Turn, 암호화 Checkpoint, startup interrupted recovery를 검증했다. 실제 Codex edit/test 실행의 회귀 검증은 M3 authenticated smoke를 유지한다.

## Milestone 5 — Tkinter Smoke Test

- [x] seeded tolerance app
- [x] hidden evaluator
- [x] E2E repair loop PASS

M5 validation: 실제 Codex 0.147.0 E2E에서 hidden evaluator의 초기 FAIL → 최종 PASS, 2회 repair Turn, public test, Tkinter startup health check, Snapshot/approval log, 완료 피드백을 검증했다. evaluator는 프로젝트 workspace 밖의 임시 MCP server로 노출됐고 종료 후 제거됐다. repaired-project evidence와 결과는 `artifacts/test/m5-e2e-smoke.json`에 기록된다.

## Milestone 6 — Packaging

- [x] 최소 Python runtime + exact dependency lock 빌더
- [x] 전체 파일 manifest + CycloneDX SBOM + deterministic ZIP/SHA-256 빌더
- [x] 패키지 밖의 절대 임시경로를 사용하는 non-mutating verifier
- [x] Bootstrapper 환경 격리 및 bytecode/user-site 차단
- [x] clean `0.1.0-rc.1` ZIP 독립 2회 생성 및 동일 해시 확인
- [x] 두 ZIP을 새 폴더에 안전 압축 해제 후 전체 VERIFY
- [x] 최종 release 감사 수행: 회사 내부 테스트 GO / 공개 출시 HOLD

최신 교정 소스로 만든 A/B ZIP은 크기와 SHA-256이 동일했고, 두 fresh extraction
모두 3,068개 파일 manifest/SBOM/cleanliness 및 Electron→Python Core smoke를
통과했다. 회사 내부 테스트 후보 SHA-256은
`8ad5f4ad50681e8372e2011b28d23252ac008156d70894c2de572f9b736124c8`다. 다만
Electron 실행 파일에 Human Codex publisher Authenticode 서명이 없으므로 공개
출시는 HOLD다.
