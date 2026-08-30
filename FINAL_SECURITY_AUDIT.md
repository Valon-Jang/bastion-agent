# Human Codex 0.1.0-rc.5 최종 보안·릴리스 감사

감사일: 2026-08-28 (Asia/Seoul)

## 판정

- 회사 내부 개인 사용 테스트: **조건부 GO**
- OS 격리가 필요한 회사 자료 처리: **HOLD**
- 공개 배포: **HOLD**

조건부 GO는 사용자가 명시적으로 요청한 **직접 실행 모드**에 한한다. rc.5는
Elevated/Unelevated 샌드박스 설치, 격리 명령 및 보안 실검증 Gate를 실행하지 않고
로그인 후 채팅을 바로 연다. 따라서 회사 GPO의 별도 샌드박스 사용자 로그온 제한과
충돌하지 않지만, 현재 Windows 사용자의 파일·프로세스·네트워크 권한이 로컬 명령에
그대로 적용된다.

최종 ZIP SHA-256:
`3832ba859c062014719de2073fd40cdbd03f963107fdb459da4697b196b500da`

## 유지되는 안전장치

- 프로젝트 선택과 프로젝트별 지침
- 위험 작업에 대한 사용자 승인 UI
- Snapshot과 복구
- 알려진 자격증명 패턴의 붙여넣기 사전검사
- 설치 폴더의 `HumanCodexData` 및 `Workspace`를 이용한 휴대용 상태 관리
- 공개 웹 검색 지원
- Codex 0.150.1의 필수 Code Mode host 포함 및 실행 검증

이 항목들은 유용한 제품 안전장치지만 Windows 보안 경계나 DLP로 간주하지 않는다.

## 의도적으로 제거한 Gate와 잔여 위험

- 앱 시작 전 `command/exec` 격리 probe를 호출하지 않는다.
- Elevated 별도 사용자, Unelevated 제한 토큰, 47개 회사 호환 검사에 채팅 시작을
  의존하지 않는다.
- 프로젝트 밖 읽기·쓰기, 로컬 네트워크·인터넷 접근, 자식 프로세스 권한을 OS 수준
  샌드박스로 차단하지 않는다.
- 현재 사용자가 접근 가능한 민감 파일을 에이전트 또는 실행 명령이 접근할 수 있다.
- 검색어와 대화에 입력한 내용은 외부 Codex 서비스로 전송될 수 있다.
- Electron 실행 파일에는 Human Codex 게시자 Authenticode 서명이 없어 회사의
  AppLocker·WDAC·EDR에서 IT 허용 등록이 필요할 수 있다.

따라서 기밀자료에 OS 격리가 필수인 환경에서는 rc.4를 사용하지 않는다. 회사 정책을
우회하지 않으며, 사용 권한이 있는 자료와 승인된 ChatGPT 워크스페이스에서만 시험한다.

## 검증 증거

- Python: 91 passed + subtests 5 passed
- Electron/Node 보안·IPC 계약: 13 passed
- Vite production build: passed
- npm production dependency audit: 0 vulnerabilities
- A/B ZIP: 각각 317,198,088 bytes, SHA-256 완전 동일
- 두 fresh package verifier: 5,011개 manifest, 번들 청결성, CycloneDX SBOM
  9개 구성요소, Python 3.12.10, Codex/App Server 0.150.1, Electron 44.0.0,
  Electron→Python Core IPC 모두 PASS
- 두 패키지 Core 직접 질의: `company-direct`, `can_start=true`,
  `verification=skipped(0/0)`, `native_isolation=false`
- 로그인된 실제 Codex App Server에서 `danger-full-access` ephemeral thread 생성 PASS,
  사전 `command/exec` probe 0회

rc.4에서 `codex-code-mode-host.exe`가 원본 Codex 배포의 `bin` 폴더에 있는데 빌더가
`codex-resources`만 확인해 누락하는 패키징 결함을 확인했다. rc.5는 이 helper를 필수
파일로 승격했으며 누락 시 빌드가 실패하고 verifier가 실제 `--help` 실행까지 확인한다.

전체 기록은 `R8_VERIFICATION_SUMMARY.md`에 정리했다.
