# Bastion Agent

> **보안 경계를 우회하지 않고, 그 안에서 일하는 AI 작업대.**

## 왜 만들었나

이 프로젝트는 회사처럼 보안 정책이 엄격한 PC에서 시작됐다. 공식 AI 데스크톱 앱을
설치할 수 없고 일반 개발 도구도 자유롭게 추가할 수 없지만, 웹 로그인과 허용된 로컬
파일 작업은 가능한 환경이었다. 단순한 웹 채팅을 넘어 프로젝트 파일을 읽고 결과물을
만들며, 중간에 고장 나더라도 다음 실행에서 복구할 수 있는 개인용 AI 작업대가 필요했다.

처음에는 대화만 겨우 이어지는 작은 도구였지만 실제 사용 중 마주친 로그인, Windows
권한, 기업 정책, 샌드박스 충돌, 파일 전달, UI 장애와 자가수리 문제를 하나씩 해결하면서
현재 구조로 발전했다. 목표는 회사 보안을 우회하거나 약화하는 것이 아니다. 사용자가
명시적으로 선택한 프로젝트를 AI의 기본 작업 범위로 삼고, 실행 환경의 제약이나 실패를
숨기지 않으며 복구 가능한 방식으로 실질적인 작업을 수행하게 하는 것이다.

Bastion Agent는 공식 AI 데스크톱 앱 설치, 관리자 권한 또는 일반적인 개발 환경을
사용하기 어려운 Windows PC를 위한 휴대용 로컬 에이전트 워크스페이스다. 현재는 공식
Codex App Server를 reasoning/coding engine으로 사용하며, 향후 Claude Code backend를
추가할 수 있는 실행 경계를 목표로 한다.

## 보안 모델

Bastion Agent는 **저장 경계**, **제품 안전장치**, **실행 권한**을 구분한다.

- 최신 활성 Runtime과 다음 설치 패키지의 파일 접근 허용 범위는 **현재 설치 폴더**와
  **사용자가 명시적으로 선택한 프로젝트 폴더**다. 로컬 도구와 그 자식 작업은 이 두
  경계 안에서만 파일을 읽고 쓸 수 있으며, 그 밖의 로컬 경로 접근은 차단한다.
- 앱 소스·런타임, 전용 `CODEX_HOME`, 로그·Snapshot·암호화 vault, 스킬과 임시
  작업공간은 `<설치 폴더>` 아래에 모은다. 자가수리와 후보 Runtime 업데이트도 이 경계
  안에 저장하고 검증한 뒤 다음 실행부터 적용한다.
- 설치 폴더와 프로젝트 폴더는 실행 시 실제 절대경로로 동적으로 연결한다. 서로 다른
  드라이브나 여러 단계 아래의 중첩 경로여도 되며 드라이브 최상위 폴더일 필요가 없다.
  Downloads는 설치 폴더 또는 사용자가 선택한 프로젝트가 그 아래에 있을 때 접근 범위에
  포함된다.
- 경로 정규화와 시스템 루트 거부, 프로젝트별 root 분류, 위험 작업 승인, Snapshot·복구,
  알려진 비밀값 패턴의 사전검사, 실행 환경의 자격증명 변수 축소, Electron Renderer
  sandbox·CSP·검증된 IPC 경계를 적용한다.
- 앱이 임의로 원격 저장소를 만들거나 `git push`하지 않으며, 회사의 SmartScreen,
  AppLocker, WDAC, EDR 또는 네트워크 정책을 우회하지 않는다.

이 접근 경계는 별도 Sandbox 사용자 로그온이 제한된 회사 PC에서도 채팅을 열 수 있도록
현재 로그인 세션과 양립하는 방식으로 적용한다. 다만 Bastion Agent 자체를 회사의 보안
제품이나 완전한 DLP로 간주해서는 안 된다. 공개 웹 검색과 Codex 통신은 의도적으로
지원하므로 사용자가 선택한 프로젝트의 내용이나 대화에 넣은 정보는 작업 수행을 위해 Codex
서비스로 전송될 수 있다. 기밀자료는 조직이 승인한 계정·워크스페이스와 사용 범위 안에서만
다뤄야 한다. 자세한 내용은 [`SECURITY.md`](SECURITY.md)와
[`README_PORTABLE.md`](README_PORTABLE.md)에 있다.

## 포터블인 이유

- ZIP을 쓰기 가능한 NTFS/ReFS 폴더에 풀고 배치 파일로 로그인·실행한다.
- 필요한 Python, Electron, Codex와 Code Mode host를 패키지 안에 함께 두므로 전역
  Python·npm·Codex 설치나 관리자 권한, 시스템 `PATH`·Registry 변경이 필요 없다.
- 로그인 보조 데이터, 앱 상태, 로그, Snapshot, 스킬과 작업공간을 설치 폴더 아래에 모아
  일반 설치 프로그램이 남기는 전역 상태를 최소화한다.
- 설치 위치와 프로젝트 위치를 고정 드라이브로 가정하지 않는다. `C:\Tools\Bastion`에
  설치하고 `E:\Work\Team\Project`를 연결하는 식으로 절대경로를 각각 관리한다.
- 빌드는 전체 파일 manifest, SBOM, 외부 SHA-256과 반복 빌드 해시 일치를 검사할 수 있다.

포터블은 “무설치에 가까운 배포·회수와 위치 독립성”을 뜻하며 “보안 격리가 자동으로
강해진다”는 뜻은 아니다. `HumanCodexData`에는 로그인·인증 관련 데이터가 포함될 수 있어
설치 폴더 전체를 공유해서는 안 되며, 다른 PC로 옮기면 다시 로그인이 필요할 수 있다.

이 프로젝트는 **Human Codex**라는 이름으로 시작했다. 첫 공개 소스에서는 기존 데이터와
스크립트 호환성을 위해 `human_codex`, `HumanCodexData`, `human-codex://` 같은 내부
식별자를 유지한다. OpenAI 또는 Anthropic의 공식 제품이 아니며 양사와 제휴하거나
보증받지 않은 독립 프로젝트다.

> [!IMPORTANT]
> 이 공개 저장소의 실행 소스 기준선은 `0.1.0-rc.6`이다. 아래 `c3` Runtime의 UI 및
> Attachment 업데이트는 별도 활성 Runtime에서 확인된 상태 기록이며, 해당 upgrade
> source는 아직 이 공개 기준선에 동기화되지 않았다. 따라서 공개 소스나 rc.6 패키지가
> 해당 기능을 포함한다고 해석하면 안 된다. 최신 활성 Runtime, 보안 경계와 설치 패키지의
> 공개 동기화는 **2026년 9월 1일**로 예정되어 있다. 오늘 공개본은 정리된 rc.6 기준
> 소스와 최신 개발·보안 상태 문서를 먼저 제공한다.

## Recent Updates

### 대규모 UI/UX 개선

- ChatGPT 스타일의 넓은 Assistant 영역과 좁은 User bubble
- 사용자가 이해하기 쉬운 한글 작업 진행 표시와 Background Job 통합
- 내용에 따라 높이가 자동으로 조정되는 Composer
- `Enter` 전송, `Shift+Enter` 줄바꿈
- 모델 선택 UI 폭 최적화
- 답변 및 코드 블록 복사
- Markdown/Table 렌더링과 rich clipboard 복사
- 생성 파일 카드와 사용자 결과 파일 versioning
- Chat별 Draft 자동 저장
- 실행 중/완료/오류 Chat 상태 표시
- 대기 메시지 우클릭 삭제
- Chat 전환 시 input 자동 focus
- 파일 Drag & Drop overlay

### Attachment 시스템 기반 추가

- 파일 첨부와 Drag & Drop
- `Ctrl+V` 이미지·스크린샷 첨부
- Composer attachment preview
- Chat별 Attachment Registry
- Chat attachment를 Project asset으로 승격할 수 있는 구조

Attachment의 UI, Registry, 파일·이미지 Preview까지는 동작한다. 다만 실제 Codex
Turn으로 이미지를 전달하는 전체 전송 경로는 아직 안정화 중이므로 Attachment를
**fully working** 또는 **complete** 상태로 간주하지 않는다. Preview UI는 앞으로 큰
카드 대신 compact square thumbnail 중심으로 정리할 예정이다.

### 프로젝트 지식과 상태 복원

- 프로젝트의 지속 지식을 `HUMAN_CODEX.md`와 `.human-codex/` 구조로 관리하는 방향 적용
- 앱 재시작 및 Chat 전환 후 프로젝트·대화 상태 복원 구조 강화

### 최근 UI Brick 장애 복구

- 최신 활성 Runtime Slot: `c3`
- `attachment-registry.js`가 `addButton.disabled`를 변경하고, 같은 `disabled`
  attribute를 MutationObserver가 다시 감시하면서 Renderer self-trigger loop가 발생하는
  회귀가 재발했다.
- `addButton.disabled`는 실제 값이 달라질 때만 갱신하도록 idempotent 처리하여 앱/UI
  brick을 복구했다.
- 동일 self-trigger loop는 향후 Promotion Gate에서 candidate Runtime을 자동 차단해야
  하는 필수 회귀검사 항목으로 취급한다.

## Current Status

### 현재 구현되어 사용 가능한 기능

- 개선된 Chat UI, 자동 높이 Composer, 키보드 전송·줄바꿈 및 Chat별 Draft
- Markdown/Table 표시, 답변·코드 복사 및 rich clipboard
- 생성 파일 카드와 사용자 결과 파일 versioning
- Background Job과 Chat 실행 상태 표시
- 대기 메시지 삭제, Chat 전환 focus 및 Drag & Drop overlay
- Attachment 선택, Registry 등록, Composer Preview와 Project asset 승격 기반
- `HUMAN_CODEX.md` + `.human-codex/` 기반 프로젝트 지속 지식 방향
- Runtime Slot 기반 promotion, rollback, LKG 및 Safe Mode 복구 원칙
- `c3` Runtime에서 Attachment Registry self-trigger Renderer loop 복구

### 현재 안정화 중인 기능

#### Attachment E2E 전송

파일 및 이미지 Preview까지는 정상 동작하지만 전송 시 다음 오류가 현재 재현된다.

```text
Python Core chat.draft.save failed (invalid_request): sent attachment cannot be added to a draft
```

원인은 `draft.save`와 `chat.send` 사이의 race다. 전송이 완료되어 `message_id`가 생긴
attachment를 늦게 실행된 draft save가 다시 draft attachment로 저장하려고 시도한다.

또한 UI와 DB에 attachment가 존재하더라도 Python Core가 만드는 실제 Codex
`turn/start.input`에는 현재 텍스트만 들어간다. 따라서 첨부 이미지는 아직 모델에
전달되지 않으며, 모델의 이미지 인식 E2E도 완료되지 않았다.

Attachment 완료 판정에는 다음 Gate를 모두 통과해야 한다.

- `draft.save` / `chat.send` race 제거
- 실제 Codex Turn input으로 이미지 전달
- 모델이 첨부 이미지 내용을 실제로 인식하는지 E2E 확인
- 성공 후 pending attachment 정리
- 실패 시 Draft와 Attachment 보존
- Drag & Drop, `Ctrl+V`, Chat 전환 회귀검증
- Safe Mode 회귀검증
- Attachment Registry self-trigger Renderer loop 회귀검증
- 현재 Runtime뿐 아니라 다음 Runtime Slot을 만드는 upgrade source에도 동일 수정 반영

#### Model / Reasoning 계층

모델명과 reasoning effort를 추측해 하드코딩하지 않고 Codex App Server가 제공하는 실제
capability와 model 정보를 Source of Truth로 사용하는 구조를 적용·검증 중이다. 과거
hardcoded model 설정으로 ChatGPT account에서 지원하지 않는 model ID가 선택되어 Chat이
응답하지 못한 경험을 회귀 조건으로 반영한다.

지향하는 경로는 다음과 같다.

```text
Kernel → Reasoning Policy → Capability Resolver → Codex App Server → Verification
```

구조는 불필요하게 거대한 상태 머신으로 만들지 않고, 지원 capability 확인, 최소 routing,
실행 검증과 안전한 기본값 복귀에 필요한 policy만 유지한다.

### 향후 계획 및 Promotion Gate

- Attachment Preview를 compact square thumbnail 중심으로 개선
- Attachment E2E Gate 전체 자동화
- 잘못된 model/reasoning 설정의 자동 거부 및 마지막 정상값 복귀
- Runtime candidate의 Renderer loop, startup, Draft, Attachment, Safe Mode smoke 강화
- Codex 외 실행 엔진을 수용할 수 있는 최소 backend adapter 경계 정리
- 향후 Claude Code backend 지원 검토

### Self-Improvement / Runtime 안전성

Human Codex는 자기 Source를 개선할 수 있지만 Active Runtime을 무방비하게 직접
수정하지 않는 원칙을 유지한다.

```text
Source 수정
→ build / test
→ isolated candidate Runtime
→ startup / E2E smoke
→ promotion
→ 실패 시 LKG rollback 또는 Safe Mode
```

모든 수정은 현재 활성 Slot에만 임시 적용해서는 안 된다. 검증을 통과한 변경은 다음
Runtime Slot을 생성하는 upgrade source에도 반영해야 하며, Runtime Slot 기반
promotion/rollback 구조를 계속 유지한다.

## Milestone 0 실행

Python 3.12에서 저장소 루트를 현재 폴더로 두고 실행한다.

```powershell
py -3.12 -m pip install -e .
human-codex-m0 diagnostics --json
human-codex-m0 schema generate
human-codex-m0 app-server smoke --json
```

설치하지 않을 때:

```powershell
$env:PYTHONPATH = "source/core"
py -3.12 -m human_codex diagnostics --json
```

앱 전용 ChatGPT 로그인이 필요하면 다음 명령을 사용한다. 휴대용 릴리스의 앱 상태와
전용 `CODEX_HOME`은 설치 폴더의 `HumanCodexData`에 저장된다. 프로젝트 폴더에는
인증정보를 저장하지 않는다.

```powershell
human-codex-m0 codex login
human-codex-m0 codex status --json
```

## 테스트

```powershell
$env:PYTHONPATH = "source/core"
py -3.12 -m unittest discover -s tests -v
```

`scripts\VERIFY_M0.bat`은 unit test, schema pin 확인, 환경 진단, App Server initialize/thread-start smoke를 순서대로 실행한다.

## Milestone 1 개발 검증

Milestone 1은 `human-codex://renderer` local-only Electron/React shell과 Python Core metadata IPC를 추가한다. Renderer는 CSP, sandbox, 최소 preload API, trusted IPC sender 검증을 사용한다. 휴대용 릴리스의 사용자 데이터는 설치 폴더의 `HumanCodexData\data\human_codex.db`에 저장하며 source/runtime 폴더에는 저장하지 않는다.

승인된 Electron/React/Vite 의존성은 저장소 로컬에 exact version과 lockfile로 설치되어 있다. 다음 명령은 Python/Node 테스트, production build, 실제 Electron BrowserWindow와 Python Core IPC smoke를 모두 실행한다.

```powershell
$env:PYTHONPATH = "source/core"
py -3.12 -m unittest discover -s tests -v
node --test tests/node/*.test.cjs
```

정확한 버전, 출처, 라이선스, 감사 및 제거 절차는 `DEPENDENCY_PLAN.md`에 있다. 전체 검증 명령은 다음과 같다.

```powershell
scripts\VERIFY_M1.bat
```

## 저장 경계

- 소스와 version-matched schema: 이 저장소
- 사용자 데이터와 전용 `CODEX_HOME`: `<설치 폴더>\HumanCodexData`
- 앱 작업·임시 공간: `<설치 폴더>\Workspace`
- 사용자 프로젝트: 사용자가 선택한 절대경로. 설치 폴더와 다른 드라이브 및 중첩 폴더 지원
- 앱이 사용자 대신 원격 저장소를 생성하거나 `git push`하지 않음. 이 공개 upstream
  저장소 사용 여부와 push 권한은 사용자가 별도로 결정
- Vision/Office/Browser/Computer Use: Milestone 0에서 구현하지 않음

## Portable release (Milestone 6)

교정된 빌더는 `0.1.0-rc.6` 폴더, ZIP, 외부 SHA-256, 전체 manifest와 SBOM을
생성한다. 최신 A/B 빌드는 동일 해시와 두 fresh-folder 검증을 통과해야 회사 내부
테스트 GO로 판정한다. 공개 출시는 publisher Authenticode 서명 전까지 HOLD다. 회사
테스트 ZIP은 Windows 10/11 64-bit PC의 쓰기 가능한 NTFS/ReFS 폴더에 풀고
`Login-HumanCodex.bat`으로 로그인한 다음 `Launch-HumanCodex.bat`을 실행한다.
전역 Python, npm, Codex 설치나 PATH 변경은 필요하지 않다.

로그인, 로그, Snapshot, 암호화 vault은 설치 폴더의 `HumanCodexData`에 저장된다.
폴더 선택기는 Downloads에서 시작하며 Downloads 자체 또는 그 하위 폴더도 프로젝트로
선택할 수 있다. 설치 폴더와 프로젝트 폴더는 서로 다른 드라이브여도 되지만 각 드라이브가
NTFS/ReFS여야 한다. 자세한 배포·운영 지침은 `README_PORTABLE.md`, 전체 fresh-folder
검증은 `scripts\VERIFY_M6.bat`을 사용한다.

### rc.6 회사 사용 편의 기능

- 실행 중에도 메시지를 입력할 수 있으며 현재 응답 완료 후 FIFO 순서로 자동 전송
- 채팅 목록 우클릭 메뉴에서 완료된 채팅 삭제
- 여러 프로젝트 생성 및 서로 다른 드라이브의 프로젝트 폴더 선택
- 완료된 명령/도구 기록을 해당 응답에 접어 넣고 완료 작업 카드의 하단 누적 제거
- 회사 직접 실행 모드에서 설치 폴더를 진단·자가수리 작업 범위에 포함
- OpenAI 공식 목록 검색 또는 GitHub 경로로 추가 스킬을 설치 폴더의
  `HumanCodexData\codex-home\skills`에 저장(설치 단계에서 스크립트 실행 없음)
- 필요한 기능이 없으면 공개 검색어로 공식·GitHub 스킬을 찾아 자동 설치하는
  회사 직접 모드. 사내 파일 내용·경로·식별자는 검색어로 보내지 않음
