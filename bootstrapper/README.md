# Human Codex 시작 스크립트

`Launch-HumanCodex.bat`은 릴리스 루트에 복사된다. 동봉된 Python, Codex와 Electron을
확인한 뒤 프로세스 범위의 `PATH`와 `PYTHONPATH`로 앱을 실행한다.

다운로드, 별도 설치, 레지스트리 수정이나 전역 PATH 변경은 하지 않는다. 사용자
상태와 전용 Codex home은 `<설치 폴더>\HumanCodexData`, 앱 작업 공간은
`<설치 폴더>\Workspace`에 둔다. 따라서 전체 설치 폴더는 현재 사용자가 쓸 수 있는
NTFS/ReFS 위치여야 하며 Downloads 아래의 중첩 폴더도 지원한다.

테스트 harness는 일반 환경변수만으로 선택할 수 없다. 격리 verifier가
`--portable-smoke`와 프로세스 범위 marker를 함께 전달할 때만 실행되며, 일반 실행은
항상 production Main process를 시작한다.
