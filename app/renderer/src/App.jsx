import React, { useEffect, useMemo, useRef, useState } from "react";

const enabledCapabilities = ["웹 검색", "공개 문서 학습", "오피스 문서", "추가 스킬", "자가수리 (다음 실행 적용)"];
const disabledCapabilities = ["이미지 인식", "대화형 브라우저", "컴퓨터 제어"];
const EMPTY_TIMELINE = { messages: [], items: [], turns: [], queued_messages: [] };
const ACTIVE_SANDBOX_PHASES = new Set(["requesting", "installing", "verifying"]);

function localizeError(value) {
  const message = String(value || "");
  const lower = message.toLowerCase();
  if (lower.includes("name must be a non-empty string")) return "프로젝트 이름을 1~120자로 입력하세요.";
  if (lower.includes("project name already exists")) return "같은 이름의 프로젝트가 이미 있습니다. 다른 이름을 사용하세요.";
  if (lower.includes("running chat cannot be deleted")) return "응답이 끝나거나 중지된 뒤 채팅을 삭제할 수 있습니다.";
  if (lower.includes("chat message queue is full")) return "대기 메시지가 너무 많습니다. 앞선 응답이 끝난 뒤 다시 보내세요.";
  if (lower.includes("skill") || lower.includes("github")) return message;
  if (lower.includes("windows sandbox setup could not be started")) return "Windows 보안 샌드박스 설정을 시작하지 못했습니다.";
  if (lower.includes("windows sandbox setup did not start")) return "Windows 보안 샌드박스 설정이 시작되지 않았습니다.";
  if (lower.includes("windows sandbox readiness check failed")) return "Windows 보안 샌드박스 상태를 확인하지 못했습니다.";
  if (lower.includes("windows sandbox setup timed out")) return "5분 동안 완료 응답이 없어 설정을 중단했습니다. 앱을 다시 연 뒤 상태를 확인하거나 회사 관리자에게 설치 권한을 문의하세요.";
  if (lower.includes("sandbox_live_verification_timed_out")) return "보안 실검증이 90초 안에 끝나지 않았습니다. 회사 보안 프로그램이 격리 도우미 실행을 지연하거나 차단하는지 IT 담당자에게 확인하세요.";
  if (lower.includes("sandbox_live_verification_could_not_start")) return "첫 번째 격리 명령을 시작하지 못했습니다. 회사의 실행 차단 정책이나 사용자 폴더 권한을 확인하세요.";
  if (lower.includes("sandbox_live_verification_failed")) return "보안 실검증을 통과하지 못했습니다. 회사 보안정책에서 Human Codex의 격리 도우미 실행이 허용되는지 확인하세요.";
  if (lower.includes("unelevated sandbox diagnostic is already running")) return "회사 PC 원인 진단이 이미 실행 중입니다.";
  if (lower.includes("unelevated sandbox diagnostic")) return "회사 PC 원인 진단을 실행하지 못했습니다.";
  if (lower.includes("corporate_sandbox_test_timed_out")) return "회사 PC 테스트 모드가 2분 안에 끝나지 않아 중단 처리됐습니다.";
  if (lower.includes("corporate sandbox activation could not be saved")) return "회사 제한 샌드박스 승인 정보를 저장하지 못했습니다.";
  if (lower.includes("corporate sandbox activation requires explicit approval")) return "회사 제한 샌드박스를 사용하려면 명시적으로 승인해야 합니다.";
  if (lower.includes("corporate sandbox test must finish before activation")) return "회사 PC 보안 검사를 먼저 완료하세요.";
  if (lower.includes("corporate_sandbox_required_checks_failed")) return "채팅을 여는 데 필요한 핵심 보안 검사를 모두 통과하지 못했습니다.";
  if (lower.includes("corporate sandbox test requires a project folder")) return "검사할 프로젝트 폴더를 먼저 선택하세요.";
  if (lower.includes("corporate sandbox test") || lower.includes("corporate_sandbox_test")) return "회사 PC 테스트 모드를 실행하지 못했습니다.";
  if (lower.includes("secure sandbox setup did not pass") || lower.includes("secure_sandbox_required")) return "보안 샌드박스 실검증을 통과해야 채팅을 시작할 수 있습니다.";
  if (lower.includes("require an ntfs or refs drive")) return "보안 격리를 사용하려면 설치 폴더와 프로젝트 폴더를 각각 NTFS 또는 ReFS 드라이브에 두세요. 서로 다른 드라이브여도 되지만 exFAT/FAT는 지원하지 않습니다.";
  if (lower.includes("filesystem could not be verified")) return "프로젝트 드라이브의 보안 권한 지원 여부를 확인하지 못했습니다. NTFS 또는 ReFS 폴더를 선택하세요.";
  if (lower.includes("login")) return "ChatGPT 로그인 상태를 확인하세요.";
  return "작업을 완료하지 못했습니다. 잠시 후 다시 시도하세요.";
}

function sandboxStatusLabel(status) {
  return ({ ready: "준비됨", notConfigured: "설정 필요", updateRequired: "업데이트 필요" })[status] || "확인 불가";
}

function sandboxCheckLabel(check) {
  const labels = {
    probe_completed: "격리 명령 완료",
    error_AppServerError: "Codex 격리 명령 실행",
    error_OSError: "Windows 파일 또는 프로세스 접근",
    error_TimeoutError: "격리 명령 제한시간",
    workspace_read: "프로젝트 파일 읽기",
    workspace_write: "프로젝트 파일 쓰기",
    metadata_read: "Git 메타데이터 읽기",
    metadata_write_denied: "Git 메타데이터 쓰기 차단",
    outside_workspace_denied: "프로젝트 밖 접근 차단",
    codex_home_command_failed: "Codex 설정 폴더 접근 차단",
    read_only_workspace_read: "읽기 전용 폴더 읽기",
    read_only_workspace_write_denied: "읽기 전용 폴더 쓰기 차단",
  };
  if (labels[check]) return labels[check];
  if (check.startsWith("secret_")) return `비밀 경로 차단 (${check.slice(7)})`;
  return "격리 보안 항목";
}

function sandboxDiagnosticCopy(result) {
  const copies = {
    sandbox_user_logon_policy_confirmed: {
      title: "원인 확인: 샌드박스 사용자 로그온 정책 차단",
      detail: "샌드박스 로그에서 Windows 오류 1385가 발견됐습니다. 회사 IT에 CodexSandbox 사용자에게 필요한 로그온 형식이 차단됐다고 전달하세요.",
    },
    elevated_verification_failed_unelevated_available: {
      title: "회사 호환 실행 가능 · Elevated 원인은 미확정",
      detail: "현재 제한 토큰 명령은 정상 실행됐습니다. Elevated 실검증 실패만으로 회사 그룹 정책이나 샌드박스 사용자 로그온 차단을 판단할 수 없습니다. 회사 PC 호환 검사를 실행해 핵심 항목이 통과하면 채팅을 열 수 있습니다.",
    },
    unelevated_available: {
      title: "회사 호환 명령 실행 가능",
      detail: "현재 제한 토큰 명령은 정상 실행됐습니다. 이 결과만으로 Elevated 상태나 회사 정책 원인을 판정하지 않습니다. 필요하면 Elevated를 다시 검사하거나 회사 PC 호환 검사를 계속하세요.",
    },
    // Older cores used these inference-only classifications. Never present them
    // as Group Policy evidence when an explicit Windows 1385 error is absent.
    sandbox_user_logon_policy_likely: {
      title: "회사 호환 실행 가능 · Elevated 원인은 미확정",
      detail: "현재 제한 토큰 명령은 정상 실행됐지만 회사 그룹 정책 차단을 입증하는 오류는 확인되지 않았습니다. 회사 PC 호환 검사를 계속할 수 있습니다.",
    },
    elevated_only_failure_likely: {
      title: "회사 호환 실행 가능 · Elevated 원인은 미확정",
      detail: "현재 제한 토큰 명령은 정상 실행됐지만 Elevated 실패 원인은 확인되지 않았습니다. 회사 PC 호환 검사를 계속할 수 있습니다.",
    },
    application_control_likely: {
      title: "AppLocker 또는 WDAC 차단 흔적 발견",
      detail: "Unelevated 명령도 시작하지 못했고 로그에 응용 프로그램 제어 흔적이 있습니다. Human Codex의 codex-command-runner 실행 허용 여부를 IT에 문의하세요.",
    },
    both_modes_execution_blocked: {
      title: "두 실행 방식 모두 명령 시작 실패",
      detail: "별도 사용자 로그온만의 문제로 좁혀지지 않았습니다. AppLocker·WDAC·EDR 또는 codex-command-runner 실행 차단을 확인해야 합니다.",
    },
  };
  return copies[result?.classification] || {
    title: "진단 결과를 분류하지 못했습니다",
    detail: "회사 IT에 샌드박스 로그와 실행 차단 기록 확인을 요청하세요.",
  };
}

function corporateStageLabel(stage) {
  return ({
    preflight: "실행 환경 확인",
    filesystem: "파일 경계 공격 테스트",
    child_process: "자식 프로세스 권한 승계 테스트",
    read_only: "읽기 전용 경계 테스트",
    network_privilege: "네트워크·권한·레지스트리 테스트",
    permission_profile: "Human Codex 실제 권한 프로필 테스트",
    cleanup: "임시 항목 정리 확인",
    complete: "검사 완료",
  })[stage] || "검사 준비";
}

function corporateCheckLabel(check) {
  const labels = {
    windows_host: "Windows 환경",
    codex_executable: "Codex 실행 파일",
    acl_filesystem: "NTFS/ReFS 권한 지원",
    provider_environment_scrubbed: "상위 프로세스 비밀 환경변수 제거",
    test_root_created: "격리용 임시 폴더 생성",
    direct_command_launch: "제한 토큰 명령 시작",
    direct_command_finished: "제한 토큰 명령 정상 종료",
    workspace_read: "허용 폴더 읽기",
    workspace_write: "허용 폴더 쓰기",
    outside_read_denied: "허용 폴더 밖 읽기 차단",
    outside_write_denied: "허용 폴더 밖 쓰기 차단",
    codex_home_read_denied: "Codex 설정 폴더 읽기 차단",
    codex_home_write_denied: "Codex 설정 폴더 쓰기 차단",
    secret_env_read_denied: ".env 읽기 차단",
    secret_key_read_denied: "개인키 읽기 차단",
    metadata_read: "Git 메타데이터 읽기",
    metadata_write_denied: "Git 메타데이터 쓰기 차단",
    junction_read_denied: "Junction 우회 읽기 차단",
    junction_write_denied: "Junction 우회 쓰기 차단",
    hardlink_read_denied: "Hard link 우회 읽기 차단",
    hardlink_write_denied: "Hard link 우회 쓰기 차단",
    child_command_launch: "자식 프로세스 시작",
    child_workspace_write: "자식 프로세스 허용 폴더 쓰기",
    child_outside_read_denied: "자식 프로세스 외부 읽기 차단",
    child_outside_write_denied: "자식 프로세스 외부 쓰기 차단",
    child_secret_read_denied: "자식 프로세스 비밀 읽기 차단",
    readonly_command_launch: "읽기 전용 명령 시작",
    readonly_workspace_read: "읽기 전용 폴더 읽기",
    readonly_workspace_write_denied: "읽기 전용 폴더 쓰기 차단",
    readonly_outside_read_denied: "읽기 전용 모드 외부 읽기 차단",
    readonly_child_write_denied: "읽기 전용 자식 쓰기 차단",
    powershell_probe_launch: "PowerShell 공격 검사 시작",
    outbound_ipv4_denied: "외부 IPv4 직접 연결 차단",
    dns_denied: "DNS 조회 차단",
    loopback_denied: "로컬 루프백 연결 차단",
    administrator_token_denied: "관리자 토큰 사용 차단",
    registry_write_denied: "현재 사용자 레지스트리 쓰기 차단",
    profile_command_launch: "실제 Human Codex 프로필 시작",
    profile_workspace_read: "실제 프로필 허용 폴더 읽기",
    profile_workspace_write: "실제 프로필 허용 폴더 쓰기",
    profile_secret_env_denied: "실제 프로필 .env 읽기 차단",
    profile_secret_key_denied: "실제 프로필 개인키 읽기 차단",
    profile_metadata_write_denied: "실제 프로필 Git 쓰기 차단",
    profile_outside_read_denied: "실제 프로필 외부 읽기 차단",
    configuration_unchanged: "기존 보안 설정 무변경",
    registry_cleanup: "임시 레지스트리 정리",
    filesystem_cleanup: "임시 파일·폴더 정리",
  };
  return labels[check] || "보안 경계 검사";
}

function corporateCheckState(status) {
  return ({ passed: "통과", failed: "실패", unavailable: "검사 불가", dependency_failed: "선행 단계 실패" })[status] || "대기";
}

function rootKindLabel(kind) {
  return ({ main: "기본 폴더", reference: "읽기 폴더", write: "쓰기 폴더" })[kind] || kind;
}

function stateLabel(state) {
  return ({
    completed: "완료", inProgress: "진행 중", interrupted: "중단됨", failed: "실패",
    pending: "대기 중", running: "실행 중", approved: "승인됨", denied: "거부됨",
  })[state] || state;
}

function roleLabel(role) {
  return ({ user: "사용자", assistant: "어시스턴트", system: "시스템" })[role] || role;
}

function activityKindLabel(kind) {
  return ({
    webSearch: "웹 검색",
    commandExecution: "명령 실행",
    fileChange: "파일 변경",
    agentMessage: "응답 작성",
  })[kind] || "도구 작업";
}

function activityText(item) {
  const value = item.payload?.output || item.payload?.command || item.payload;
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function ActivityGroup({ items, turnStatus }) {
  if (!items.length) return null;
  const active = turnStatus === "inProgress" || items.some((item) => item.status === "inProgress");
  return <details className="activity turn-activity" open={active}>
    <summary>도구 작업 {items.length}개 · {active ? "진행 중" : "완료"}</summary>
    <div className="turn-activity-items">{items.map((item) => <details className="tool-card" key={item.id}>
      <summary>{activityKindLabel(item.kind)} · {stateLabel(item.status)}</summary>
      <pre>{activityText(item)}</pre>
    </details>)}</div>
  </details>;
}

function formatElapsed(seconds) {
  if (seconds < 60) return `${seconds}초`;
  return `${Math.floor(seconds / 60)}분 ${seconds % 60}초`;
}

export function App() {
  const [projects, setProjects] = useState([]);
  const [activeProject, setActiveProject] = useState(null);
  const [chats, setChats] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [timeline, setTimeline] = useState(EMPTY_TIMELINE);
  const [roots, setRoots] = useState([]);
  const [git, setGit] = useState(null);
  const [snapshots, setSnapshots] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [name, setName] = useState("");
  const [mainRoot, setMainRoot] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");
  const [chatMenu, setChatMenu] = useState(null);
  const [skills, setSkills] = useState([]);
  const [skillCatalog, setSkillCatalog] = useState([]);
  const [skillQuery, setSkillQuery] = useState("");
  const [skillSource, setSkillSource] = useState("");
  const [skillBusy, setSkillBusy] = useState(false);
  const [skillRoot, setSkillRoot] = useState("");
  const [sandbox, setSandbox] = useState(null);
  const [sandboxBusy, setSandboxBusy] = useState(false);
  const [sandboxPolling, setSandboxPolling] = useState(false);
  const [sandboxPhase, setSandboxPhase] = useState("idle");
  const [sandboxFailedStep, setSandboxFailedStep] = useState(1);
  const [sandboxStartedAt, setSandboxStartedAt] = useState(null);
  const [sandboxElapsed, setSandboxElapsed] = useState(0);
  const [sandboxDialogVisible, setSandboxDialogVisible] = useState(false);
  const [sandboxDiagnostic, setSandboxDiagnostic] = useState(null);
  const [sandboxDiagnosticBusy, setSandboxDiagnosticBusy] = useState(false);
  const [sandboxDiagnosticError, setSandboxDiagnosticError] = useState("");
  const [corporateTest, setCorporateTest] = useState(null);
  const [corporateTestPolling, setCorporateTestPolling] = useState(false);
  const [corporateTestError, setCorporateTestError] = useState("");
  const [corporateActivationBusy, setCorporateActivationBusy] = useState(false);
  const activeChatId = useRef(null);
  const running = useMemo(() => timeline.turns.some((turn) => turn.status === "inProgress"), [timeline.turns]);
  const sandboxSetupActive = ACTIVE_SANDBOX_PHASES.has(sandboxPhase);

  const refreshProjects = async () => setProjects((await window.humanCodex.project.list()).projects);
  const refreshSkills = async () => {
    const value = await window.humanCodex.skill.list();
    setSkills(value.skills);
    setSkillRoot(value.install_root);
  };
  const refreshSandbox = async () => {
    const value = await window.humanCodex.system.sandboxStatus();
    setSandbox(value);
    return value;
  };
  const refreshTimeline = async (chatId) => {
    const value = await window.humanCodex.chat.timeline(chatId);
    if (activeChatId.current === chatId) setTimeline(value);
  };
  const refreshProjectContext = async (projectId) => {
    const [rootResult, gitResult, snapshotResult, approvalResult, jobResult] = await Promise.all([
      window.humanCodex.project.roots(projectId),
      window.humanCodex.workspace.status(projectId),
      window.humanCodex.snapshot.list(projectId),
      window.humanCodex.approval.list(projectId),
      window.humanCodex.job.list(projectId),
    ]);
    setRoots(rootResult.roots);
    setGit(gitResult.git);
    setSnapshots(snapshotResult.snapshots);
    setApprovals(approvalResult.approvals);
    setJobs(jobResult.jobs);
  };

  function applySandboxProgress(value) {
    if (value.can_start) {
      setSandboxPhase("complete");
      setSandboxPolling(false);
      return;
    }
    if (value.setup?.success === false) {
      setSandboxFailedStep(1);
      setSandboxPhase("failed");
      setSandboxPolling(false);
      return;
    }
    if (value.verification?.state === "failed") {
      setSandboxFailedStep(2);
      setSandboxPhase("failed");
      setSandboxPolling(false);
      return;
    }
    if (value.verification?.state === "running") {
      setSandboxPhase("verifying");
      return;
    }
    if (value.setup?.success === true) {
      setSandboxPhase("verifying");
      return;
    }
    setSandboxPhase("installing");
  }

  useEffect(() => {
    refreshProjects().catch((reason) => setError(reason.message));
    refreshSkills().catch((reason) => setError(reason.message));
    refreshSandbox().then((value) => {
      if (value.can_start) {
        setSandboxPhase("complete");
        if (value.active_mode === "corporate-restricted") {
          window.humanCodex.system.corporateSandboxTestStatus()
            .then(setCorporateTest)
            .catch((reason) => setCorporateTestError(reason.message));
        }
      }
      else if (value.setup?.success === false) {
        setSandboxFailedStep(1);
        setSandboxPhase("failed");
      } else if (value.verification?.state === "failed") {
        setSandboxFailedStep(2);
        setSandboxPhase("failed");
      } else if (value.verification?.state === "running") {
        setSandboxPhase("verifying");
        setSandboxStartedAt(Date.now());
        setSandboxPolling(true);
      }
    }).catch((reason) => setError(reason.message));
  }, []);

  useEffect(() => {
    if (!chatMenu) return undefined;
    const close = () => setChatMenu(null);
    const onKey = (event) => { if (event.key === "Escape") close(); };
    window.addEventListener("click", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [chatMenu]);

  useEffect(() => {
    if (!sandboxPolling) return undefined;
    let checking = false;
    let cancelled = false;
    const timer = window.setInterval(async () => {
      if (checking) return;
      checking = true;
      try {
        const value = await refreshSandbox();
        if (!cancelled) applySandboxProgress(value);
      } catch (reason) {
        if (!cancelled) {
          setError(reason.message);
          setSandboxFailedStep(2);
          setSandboxPhase("failed");
          setSandboxPolling(false);
        }
      } finally {
        checking = false;
      }
    }, 1_200);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [sandboxPolling]);

  useEffect(() => {
    if (!sandboxSetupActive || !sandboxStartedAt) return undefined;
    const update = () => setSandboxElapsed(Math.max(0, Math.floor((Date.now() - sandboxStartedAt) / 1_000)));
    update();
    const timer = window.setInterval(update, 1_000);
    return () => window.clearInterval(timer);
  }, [sandboxSetupActive, sandboxStartedAt]);

  useEffect(() => {
    if (!corporateTestPolling) return undefined;
    let checking = false;
    let cancelled = false;
    const timer = window.setInterval(async () => {
      if (checking) return;
      checking = true;
      try {
        const value = await window.humanCodex.system.corporateSandboxTestStatus();
        if (!cancelled) {
          setCorporateTest(value);
          if (value.state !== "running") setCorporateTestPolling(false);
        }
      } catch (reason) {
        if (!cancelled) {
          setCorporateTestError(reason.message);
          setCorporateTestPolling(false);
        }
      } finally {
        checking = false;
      }
    }, 750);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [corporateTestPolling]);

  useEffect(() => {
    setActiveChat(null); activeChatId.current = null; setTimeline(EMPTY_TIMELINE);
    setRoots([]); setGit(null); setSnapshots([]); setApprovals([]); setJobs([]);
    if (!activeProject) return setChats([]);
    window.humanCodex.chat.list(activeProject.id).then(({ chats: value }) => setChats(value)).catch((reason) => setError(reason.message));
    refreshProjectContext(activeProject.id).catch((reason) => setError(reason.message));
  }, [activeProject]);

  useEffect(() => {
    if (!activeChat) return undefined;
    const timer = window.setInterval(() => refreshTimeline(activeChat.id).catch((reason) => setError(reason.message)), 600);
    return () => window.clearInterval(timer);
  }, [activeChat]);

  useEffect(() => {
    if (!activeProject) return undefined;
    const timer = window.setInterval(() => {
      window.humanCodex.approval.list(activeProject.id).then(({ approvals: value }) => setApprovals(value)).catch((reason) => setError(reason.message));
      window.humanCodex.job.list(activeProject.id).then(({ jobs: value }) => setJobs(value)).catch((reason) => setError(reason.message));
    }, 600);
    return () => window.clearInterval(timer);
  }, [activeProject]);

  async function chooseFolder() {
    setError("");
    const selected = await window.humanCodex.project.chooseDirectory();
    if (selected) {
      setMainRoot(selected);
      if (!name.trim()) {
        const parts = selected.replace(/[\\/]+$/, "").split(/[\\/]/);
        setName(parts[parts.length - 1] || "새 프로젝트");
      }
    }
  }

  async function createProject(event) {
    event.preventDefault(); setError("");
    try {
      const { project } = await window.humanCodex.project.create(name, mainRoot || undefined);
      setName(""); setMainRoot(""); await refreshProjects(); setActiveProject(project);
    } catch (reason) { setError(reason.message); }
  }

  async function addRoot(kind) {
    if (!activeProject) return;
    try {
      const selected = await window.humanCodex.project.chooseDirectory();
      if (!selected) return;
      await window.humanCodex.project.addRoot(activeProject.id, kind, selected);
      await refreshProjectContext(activeProject.id);
    } catch (reason) { setError(reason.message); }
  }

  async function selectChat(chat) {
    setBusy(true); setError("");
    try {
      const opened = await window.humanCodex.chat.open(chat.id);
      activeChatId.current = chat.id; setActiveChat(opened.chat); await refreshTimeline(chat.id);
    } catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }

  async function createChat() {
    if (!activeProject) return;
    setBusy(true); setError("");
    try {
      const { chat } = await window.humanCodex.chat.create(activeProject.id);
      setChats((await window.humanCodex.chat.list(activeProject.id)).chats); await selectChat(chat);
    } catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }

  async function sendMessage(event) {
    event.preventDefault();
    if (!activeChat || !message.trim() || sending) return;
    const outgoing = message; setSending(true); setError("");
    try { await window.humanCodex.chat.send(activeChat.id, outgoing); setMessage(""); await refreshTimeline(activeChat.id); }
    catch (reason) { setError(reason.message); }
    finally { setSending(false); }
  }

  async function deleteChat(chat) {
    setChatMenu(null);
    if (!window.confirm(`'${chat.title}' 채팅을 삭제할까요? 이 채팅 기록은 복구할 수 없습니다.`)) return;
    setError("");
    try {
      await window.humanCodex.chat.delete(chat.id);
      const value = (await window.humanCodex.chat.list(chat.project_id)).chats;
      setChats(value);
      if (activeChat?.id === chat.id) {
        activeChatId.current = null;
        setActiveChat(null);
        setTimeline(EMPTY_TIMELINE);
      }
    } catch (reason) { setError(reason.message); }
  }

  async function searchSkills(event) {
    event.preventDefault();
    setSkillBusy(true); setError("");
    try { setSkillCatalog((await window.humanCodex.skill.catalog(skillQuery)).skills); }
    catch (reason) { setError(reason.message); }
    finally { setSkillBusy(false); }
  }

  async function installSkill(source) {
    if (!source.trim() || !window.confirm(`다음 스킬 파일을 설치 폴더에 내려받을까요?\n\n${source}\n\n설치 중 스크립트는 실행하지 않습니다.`)) return;
    setSkillBusy(true); setError("");
    try {
      await window.humanCodex.skill.install(source, true);
      await refreshSkills();
      if (skillCatalog.length) setSkillCatalog((await window.humanCodex.skill.catalog(skillQuery)).skills);
      setSkillSource("");
    } catch (reason) { setError(reason.message); }
    finally { setSkillBusy(false); }
  }

  async function interrupt() {
    if (!activeChat || !running) return;
    try { await window.humanCodex.chat.interrupt(activeChat.id); }
    catch (reason) { setError(reason.message); }
  }

  async function decideApproval(id, decision, scope = "once") {
    try {
      await window.humanCodex.approval.decide(id, decision, scope);
      setApprovals((value) => value.filter((approval) => approval.id !== id));
    } catch (reason) { setError(reason.message); }
  }

  async function createSnapshot() {
    if (!activeProject) return;
    try {
      await window.humanCodex.snapshot.create(activeProject.id, "수동 체크포인트");
      setSnapshots((await window.humanCodex.snapshot.list(activeProject.id)).snapshots);
    } catch (reason) { setError(reason.message); }
  }

  async function initializeGit() {
    if (!activeProject || !window.confirm("이 프로젝트에 로컬 Git 저장소를 만드시겠습니까? 원격 저장소는 생성하지 않습니다.")) return;
    try { await window.humanCodex.workspace.initGit(activeProject.id, true); await refreshProjectContext(activeProject.id); }
    catch (reason) { setError(reason.message); }
  }

  async function prepareWorktree() {
    if (!activeProject || !window.confirm("로컬 브랜치와 격리된 Worktree 하나를 만드시겠습니까? 기존의 커밋되지 않은 파일은 변경하지 않습니다.")) return;
    try { await window.humanCodex.workspace.prepareWorktree(activeProject.id, true); await refreshProjectContext(activeProject.id); }
    catch (reason) { setError(reason.message); }
  }

  async function resumeRecovery(chatId) {
    try {
      const opened = await window.humanCodex.job.resumeRecovery(chatId);
      activeChatId.current = chatId; setActiveChat(opened.chat); await refreshTimeline(chatId);
      if (activeProject) await refreshProjectContext(activeProject.id);
    } catch (reason) { setError(reason.message); }
  }

  function openSandboxSetup() {
    setError("");
    setSandboxPhase("confirm");
    setSandboxFailedStep(1);
    setSandboxElapsed(0);
    setSandboxStartedAt(null);
    setSandboxDialogVisible(true);
  }

  async function beginSandboxSetup() {
    setSandboxBusy(true);
    setSandboxDiagnostic(null);
    setSandboxDiagnosticError("");
    setSandboxPhase("requesting");
    setSandboxElapsed(0);
    setSandboxStartedAt(Date.now());
    setError("");
    try {
      const result = await window.humanCodex.system.setupSandbox(true);
      const current = await refreshSandbox();
      if (current.can_start) {
        setSandboxPhase("complete");
      } else if (current.setup?.success === false || !result.started) {
        setSandboxFailedStep(1);
        setSandboxPhase("failed");
      } else {
        setSandboxPhase(current.setup?.success === true ? "verifying" : "installing");
        setSandboxPolling(true);
      }
    } catch (reason) {
      setError(reason.message);
      setSandboxFailedStep(0);
      setSandboxPhase("failed");
      setSandboxPolling(false);
    } finally { setSandboxBusy(false); }
  }

  async function checkSandboxNow() {
    setSandboxBusy(true); setError("");
    try {
      const current = await refreshSandbox();
      applySandboxProgress(current);
    } catch (reason) {
      setError(reason.message);
      setSandboxFailedStep(2);
      setSandboxPhase("failed");
      setSandboxPolling(false);
    } finally { setSandboxBusy(false); }
  }

  async function diagnoseCompanySandbox() {
    if (!window.confirm("현재 사용자 제한 토큰으로 테스트 파일만 실행해 Elevated 실패 원인을 구분합니다. 영구 설정은 바뀌지 않고, 성공해도 채팅 잠금은 해제되지 않습니다. 진단할까요?")) return;
    setSandboxDiagnosticBusy(true);
    setSandboxDiagnostic(null);
    setSandboxDiagnosticError("");
    setError("");
    try {
      const result = await window.humanCodex.system.diagnoseUnelevatedSandbox(true);
      setSandboxDiagnostic(result);
    } catch (reason) {
      setSandboxDiagnosticError(reason.message);
      setError(reason.message);
    } finally {
      setSandboxDiagnosticBusy(false);
    }
  }

  async function startCorporateSandboxTest() {
    if (!activeProject) {
      setCorporateTestError("Corporate sandbox test requires a project folder");
      return;
    }
    if (!window.confirm("선택한 프로젝트 폴더 안에 임시 검사 공간을 만들고, 현재 사용자 제한 토큰으로 파일 경계·자식 프로세스·네트워크·권한을 실제 검사합니다. 검사가 끝나면 임시 항목을 삭제합니다. 시작할까요?")) return;
    setCorporateTestError("");
    setSandboxDiagnosticError("");
    setError("");
    try {
      const value = await window.humanCodex.system.startCorporateSandboxTest(true, activeProject.id);
      setCorporateTest(value);
      setCorporateTestPolling(value.state === "running");
    } catch (reason) {
      setCorporateTestError(reason.message);
      setError(reason.message);
    }
  }

  async function activateCorporateSandbox() {
    if (!window.confirm("핵심 보안 검사를 통과한 회사 제한 샌드박스를 사용합니다. 이 방식은 현재 계정의 제한 토큰과 선택한 프로젝트 폴더 경계를 사용하며 Elevated 샌드박스와 동급은 아닙니다. 경고 항목을 확인했고 채팅을 열까요?")) return;
    setCorporateActivationBusy(true);
    setCorporateTestError("");
    setError("");
    try {
      const value = await window.humanCodex.system.activateCorporateSandbox(true);
      setSandbox(value);
      setSandboxPhase("complete");
      setSandboxPolling(false);
      setCorporateTest((current) => current ? { ...current, chat_unlocked: true, result: current.result ? { ...current.result, chat_unlocked: true } : current.result } : current);
    } catch (reason) {
      setCorporateTestError(reason.message);
      setError(reason.message);
    } finally {
      setCorporateActivationBusy(false);
    }
  }

  function sandboxStepClass(index) {
    const phaseIndex = ({ requesting: 0, installing: 1, verifying: 2, complete: 3 })[sandboxPhase];
    if (sandboxPhase === "failed") {
      if (index < sandboxFailedStep) return "done";
      if (index === sandboxFailedStep) return "failed";
      return "pending";
    }
    if (phaseIndex === undefined) return "pending";
    if (index < phaseIndex) return "done";
    if (index === phaseIndex) return "active";
    return "pending";
  }

  const sandboxProgressMessage = ({
    confirm: "Windows 관리자 권한으로 격리 환경을 구성하고 실제 접근 차단을 확인합니다.",
    requesting: "격리 설정을 요청하고 있습니다. 필요한 PC에서만 Windows 관리자 승인 창이 표시됩니다.",
    installing: "Windows 격리 환경을 구성하고 있습니다. 창을 닫지 마세요.",
    verifying: "2개의 격리 프로세스에서 프로젝트 접근과 비밀 경로 차단 30개 항목을 검사하고 있습니다.",
    complete: "보안 샌드박스 검증이 완료됐습니다. 이제 채팅을 시작할 수 있습니다.",
    failed: "보안 샌드박스 설정 또는 실검증을 통과하지 못했습니다.",
  })[sandboxPhase] || "보안 샌드박스 상태를 확인하고 있습니다.";

  const liveAgentItems = timeline.items.filter((item) => item.kind === "agentMessage" && item.status === "inProgress" && item.payload?.text);
  const turnStatus = new Map(timeline.turns.map((turn) => [turn.id, turn.status]));
  const activityByTurn = new Map();
  timeline.items.filter((item) => item.kind !== "agentMessage").forEach((item) => {
    const group = activityByTurn.get(item.turn_id) || [];
    group.push(item);
    activityByTurn.set(item.turn_id, group);
  });
  const renderedActivityTurns = new Set();
  const conversation = [];
  timeline.messages.forEach((entry) => {
    const activities = activityByTurn.get(entry.turn_id) || [];
    if (entry.role === "assistant" && activities.length && !renderedActivityTurns.has(entry.turn_id)) {
      conversation.push(<ActivityGroup key={`activity-${entry.turn_id}`} items={activities} turnStatus={turnStatus.get(entry.turn_id)} />);
      renderedActivityTurns.add(entry.turn_id);
    }
    conversation.push(<article className={`message ${entry.role}`} key={entry.id}><small>{roleLabel(entry.role)}</small><p>{entry.content.text}</p></article>);
  });
  liveAgentItems.forEach((item) => {
    const activities = activityByTurn.get(item.turn_id) || [];
    if (activities.length && !renderedActivityTurns.has(item.turn_id)) {
      conversation.push(<ActivityGroup key={`activity-${item.turn_id}`} items={activities} turnStatus={turnStatus.get(item.turn_id)} />);
      renderedActivityTurns.add(item.turn_id);
    }
    conversation.push(<article className="message assistant streaming" key={item.id}><small>어시스턴트 · 응답 작성 중</small><p>{item.payload.text}</p></article>);
  });
  activityByTurn.forEach((items, turnId) => {
    if (!renderedActivityTurns.has(turnId)) {
      conversation.push(<ActivityGroup key={`activity-${turnId}`} items={items} turnStatus={turnStatus.get(turnId)} />);
    }
  });
  const visibleJobs = jobs.filter((job) => job.status === "running" || job.status === "interrupted");
  const corporateActive = sandbox?.active_mode === "corporate-restricted";
  const directActive = sandbox?.active_mode === "company-direct";
  const corporateWarnings = sandbox?.corporate?.warning_checks?.length || 0;

  return <>
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><img src="./human-codex-logo.png" alt="Human Codex" /><strong>Human Codex</strong></div>
        <section className={`security-card ${directActive ? "direct" : sandbox?.can_start ? "verified" : "blocked"}`}>
          <strong>{directActive ? "회사 직접 실행 모드" : corporateActive ? "회사 제한 샌드박스" : "보안 샌드박스"}</strong>
          <span>{directActive ? "채팅 사용 가능 · Windows 격리 검사 없음" : corporateActive ? `사용 가능 · 제한 토큰 · 경고 ${corporateWarnings}개` : sandbox?.can_start ? "검증 완료 · 프로젝트 폴더만 접근" : sandboxSetupActive || sandboxPolling ? "설정 진행 중" : sandbox ? `사용 불가 · ${sandboxStatusLabel(sandbox.status)}` : "상태 확인 중…"}</span>
          {!sandbox?.can_start && <p>Windows 격리와 비밀 경로 차단을 모두 확인할 때까지 채팅이 비활성화됩니다.</p>}
          {directActive && <p>요청에 따라 격리 명령 없이 현재 Windows 사용자 권한으로 실행합니다. 프로젝트 범위 안내·승인·스냅샷은 유지되지만 프로젝트 밖 접근을 운영체제가 차단하지는 않습니다.</p>}
          {corporateActive && <p>사용자가 승인한 회사 PC 호환 모드입니다. 선택한 프로젝트 폴더에서 작업하며 Elevated 샌드박스와 동급은 아닙니다.</p>}
          {sandbox?.can_start && !corporateActive && !directActive && <p>비밀 탐지는 여러 단계로 수행되지만 모든 인증정보 형식을 완벽하게 보장하지는 않습니다.</p>}
          {!sandbox?.can_start && <button type="button" className="secondary" disabled={!sandbox || (sandboxBusy && !sandboxSetupActive)} onClick={sandboxSetupActive || sandboxPolling || sandboxPhase === "failed" ? () => setSandboxDialogVisible(true) : openSandboxSetup}>{sandboxSetupActive || sandboxPolling ? "진행 상황 보기" : sandboxPhase === "failed" ? "실패 내용·원인 진단" : "보안 샌드박스 설정…"}</button>}
          {corporateActive && <button type="button" className="secondary" onClick={() => setSandboxDialogVisible(true)}>검사 결과 보기</button>}
        </section>
        <form className="project-form" onSubmit={createProject}>
          <input aria-label="프로젝트 이름" value={name} onChange={(event) => { setName(event.target.value); setError(""); }} placeholder="새 프로젝트 이름" />
          <button type="button" className="secondary" onClick={chooseFolder}>폴더 선택…</button><button disabled={!name.trim()}>만들기</button>
        </form>
        <small>다운로드 폴더에서 시작하며, 설치 폴더와 다른 드라이브의 중첩 프로젝트 폴더도 선택할 수 있습니다.</small>
        {mainRoot && <span className="path" title={mainRoot}>{mainRoot}</span>}
        <h2>프로젝트</h2>
        {projects.map((project) => <button className={`list-item ${activeProject?.id === project.id ? "active" : ""}`} key={project.id} onClick={() => setActiveProject(project)}>{project.name}</button>)}
        {activeProject && <section className="workspace-info">
          <h2>작업 공간</h2>
          {roots.map((root) => <span className="path" key={root.id} title={root.path}><b>{rootKindLabel(root.kind)}</b> · {root.path}</span>)}
          <div className="button-row"><button className="secondary" onClick={() => addRoot("reference")}>+ 읽기 폴더</button><button className="secondary" onClick={() => addRoot("write")}>+ 쓰기 폴더</button></div>
          <span className="status">Git: {git?.repository ? `${git.dirty ? "변경 있음" : "깨끗함"} · ${git.head?.slice(0, 8) || "첫 커밋 전"}` : "스냅샷 방식"}</span>
          {!git?.repository && <button className="secondary snapshot-button" onClick={initializeGit}>로컬 Git 만들기…</button>}
          {git?.repository && git?.head && <button className="secondary snapshot-button" onClick={prepareWorktree}>Worktree 준비…</button>}
          <button className="secondary snapshot-button" onClick={createSnapshot}>스냅샷 ({snapshots.length})</button>
        </section>}
        <h2>기능</h2>{enabledCapabilities.map((capability) => <span className="status" key={capability}>{capability} — 활성화</span>)}{disabledCapabilities.map((capability) => <span className="disabled" key={capability}>{capability} — 비활성화</span>)}
        <details className="skill-manager">
          <summary>추가 스킬 관리 ({skills.length})</summary>
          <small className="path" title={skillRoot}>저장 위치 · {skillRoot || "확인 중"}</small>
          {skills.map((skill) => <span className="installed-skill" key={skill.folder} title={skill.description}>{skill.name}</span>)}
          <form onSubmit={searchSkills}><input aria-label="공식 및 GitHub 스킬 검색" value={skillQuery} onChange={(event) => setSkillQuery(event.target.value)} placeholder="공식·GitHub 스킬 검색" /><button disabled={skillBusy}>{skillBusy ? "확인 중" : "검색"}</button></form>
          <div className="skill-results">{skillCatalog.map((skill) => <div key={skill.url}><span>{skill.name}<small>{skill.source_type === "github" ? `GitHub · ${skill.repository}` : "OpenAI 공식"}</small></span><button type="button" className="secondary" disabled={skillBusy || skill.installed} onClick={() => installSkill(skill.source)}>{skill.installed ? "설치됨" : "설치"}</button></div>)}</div>
          <input aria-label="GitHub 스킬 주소" value={skillSource} onChange={(event) => setSkillSource(event.target.value)} placeholder="GitHub /tree/ref/skill 주소" />
          <button type="button" className="secondary skill-install-url" disabled={skillBusy || !skillSource.trim()} onClick={() => installSkill(skillSource)}>GitHub 스킬 설치…</button>
          <small>다운로드 파일을 검사해 저장하며 설치 중 스크립트는 실행하지 않습니다.</small>
        </details>
      </aside>
      <section className="chat-panel">
        <header><div><strong>{activeProject?.name || "프로젝트를 선택하세요"}</strong><p>{directActive ? "직접 실행 · 사용자 승인 · 체크포인트 · 복구" : "제한된 도구 · 백그라운드 작업 · 체크포인트 · 복구"}</p></div><button disabled={!activeProject || busy || !sandbox?.can_start} onClick={createChat}>새 채팅</button></header>
        <nav className="chat-list" title="채팅을 우클릭하면 삭제할 수 있습니다">{chats.map((chat) => <button className={activeChat?.id === chat.id ? "active" : ""} key={chat.id} onClick={() => selectChat(chat)} onContextMenu={(event) => { event.preventDefault(); setChatMenu({ chat, x: event.clientX, y: event.clientY }); }}>{chat.title}</button>)}</nav>
        <div className="timeline" aria-live="polite">
          {approvals.map((approval) => <article className="approval-card" key={approval.id}>
            <strong>승인 필요 · {approval.risk_level}</strong><p>{approval.reason}</p>
            <dl><dt>작업</dt><dd>{approval.details.action}</dd><dt>영향</dt><dd>{approval.details.side_effect}</dd><dt>복구</dt><dd>{approval.details.snapshot_id ? `스냅샷 ${approval.details.snapshot_id.slice(0, 8)}` : "자동 스냅샷 없음"}</dd>{approval.details.command && <><dt>명령</dt><dd><code>{approval.details.command}</code></dd></>}</dl>
            <div className="approval-actions"><button onClick={() => decideApproval(approval.id, "approve", "once")}>한 번 승인</button>{approval.details.allowed_scopes.includes("task") && <button onClick={() => decideApproval(approval.id, "approve", "task")}>이번 작업</button>}{approval.details.allowed_scopes.includes("session") && <button onClick={() => decideApproval(approval.id, "approve", "session")}>현재 세션</button>}<button className="stop" onClick={() => decideApproval(approval.id, "deny")}>거부</button></div>
          </article>)}
          {visibleJobs.map((job) => <article className={`job-card ${job.status}`} key={job.id}>
            <div><strong>백그라운드 작업 · {stateLabel(job.status)}</strong><span>{job.followup_state === "completed" ? "후속 작업 완료" : `후속 작업: ${stateLabel(job.followup_state)}`}</span></div>
            {job.command && <code>{job.command}</code>}<small>출력 {job.output_chars}자 · 시작 {job.started_at}</small>
            {job.status === "interrupted" && <button className="secondary" onClick={() => resumeRecovery(job.chat_id)}>채팅 복구 계속하기</button>}
          </article>)}
          {!activeChat && <div className="empty-chat"><h2>{chats.length ? "채팅을 선택하세요" : "아직 채팅이 없습니다"}</h2><p>새 채팅을 만들거나 기존 채팅을 선택하세요.</p></div>}
          {conversation}
          {timeline.queued_messages.map((entry, index) => <article className={`message user queued ${entry.status}`} key={entry.id}><small>사용자 · {entry.status === "failed" ? "자동 전송 실패" : `대기 ${index + 1}번`}</small><p>{entry.content.text}</p></article>)}
        </div>
        {error && <div className="error" role="alert">{localizeError(error)}</div>}
        {running && <div className="queue-hint">응답 중에도 메시지를 보낼 수 있습니다. 현재 응답이 끝나면 순서대로 자동 전송됩니다.</div>}
        <form className="composer" onSubmit={sendMessage}><button type="button" disabled>+</button><input aria-label="메시지" maxLength={32000} value={message} onChange={(event) => setMessage(event.target.value)} disabled={!activeChat} placeholder={activeChat ? running ? "다음에 보낼 메시지 입력" : "Human Codex에 메시지 보내기" : "채팅을 선택하세요"} /><div className="composer-actions">{running && <button type="button" className="stop" onClick={interrupt}>중지</button>}<button disabled={!activeChat || sending || !message.trim()}>{sending ? "전송 중" : running ? "대기열에 추가" : "보내기"}</button></div></form>
      </section>
    </main>

    {chatMenu && <div className="chat-context-menu" role="menu" style={{ left: Math.min(chatMenu.x, window.innerWidth - 180), top: Math.min(chatMenu.y, window.innerHeight - 70) }} onClick={(event) => event.stopPropagation()}>
      <button type="button" role="menuitem" className="danger" onClick={() => deleteChat(chatMenu.chat)}>채팅 삭제</button>
    </div>}

    {sandboxDialogVisible && !directActive && <div className="modal-backdrop" role="presentation">
      <section className="sandbox-dialog" role="dialog" aria-modal="true" aria-labelledby="sandbox-dialog-title">
        <div className="sandbox-dialog-header">
          <img src="./human-codex-logo.png" alt="" />
          <div><h2 id="sandbox-dialog-title">보안 샌드박스 설정</h2><p>{sandboxProgressMessage}</p></div>
        </div>
        <ol className="sandbox-steps" aria-live="polite">
          <li className={sandboxStepClass(0)}><span className="step-icon" /><div><strong>설정 권한 확인</strong><small>필요한 PC에서만 Windows UAC 창 표시</small></div></li>
          <li className={sandboxStepClass(1)}><span className="step-icon" /><div><strong>격리 환경 구성</strong><small>Windows 네이티브 샌드박스 준비</small></div></li>
          <li className={sandboxStepClass(2)}><span className="step-icon" /><div><strong>보안 실검증</strong><small>프로젝트 접근 허용 · 비밀 경로 차단 확인</small></div></li>
        </ol>
        {sandboxSetupActive && <div className="sandbox-live-status"><span className="setup-spinner" /><strong>진행 중 · {formatElapsed(sandboxElapsed)} 경과</strong></div>}
        {sandboxPhase === "verifying" && sandbox?.verification && <p className="sandbox-check-count">보안 검사 진행 {sandbox.verification.checks_completed}/{sandbox.verification.checks_total}</p>}
        {sandboxSetupActive && sandboxElapsed >= 60 && <p className="sandbox-warning">1분 이상 걸리고 있습니다. 회사 보안 프로그램이 격리 도우미를 검사 중일 수 있습니다. 실검증은 90초가 지나면 자동으로 실패 처리됩니다.</p>}
        {sandboxPhase === "failed" && <p className="sandbox-failure">{localizeError(sandbox?.verification?.error || sandbox?.setup?.error || error)}</p>}
        {sandboxPhase === "failed" && sandbox?.verification?.failed_checks?.length > 0 && <p className="sandbox-failure">실패 항목: {sandbox.verification.failed_checks.map(sandboxCheckLabel).join(", ")}</p>}
        {sandboxDiagnosticBusy && <div className="sandbox-live-status"><span className="setup-spinner" /><strong>회사 PC 원인 진단 중 · 최대 25초</strong></div>}
        {sandboxDiagnosticError && <p className="sandbox-failure">{localizeError(sandboxDiagnosticError)}</p>}
        {sandboxDiagnostic && <section className="sandbox-diagnostic-result" aria-live="polite">
          <strong>{sandboxDiagnosticCopy(sandboxDiagnostic).title}</strong>
          <p>{sandboxDiagnosticCopy(sandboxDiagnostic).detail}</p>
          <small>회사 호환 명령 시작 {sandboxDiagnostic.command_launch ? "통과" : "실패"} · 폴더 밖 쓰기 차단 {sandboxDiagnostic.outside_write_denied ? "통과" : "실패"}</small>
          <em>명시적인 Windows 오류 1385가 없으면 회사 그룹 정책 문제로 단정하지 않습니다. 회사 PC 호환 검사의 핵심 항목이 통과하면 별도로 채팅을 열 수 있습니다.</em>
        </section>}
        {corporateTest && corporateTest.state !== "idle" && <section className="corporate-test-result" aria-live="polite">
          <div className="corporate-test-heading"><strong>회사 PC 제한 샌드박스</strong><span>{corporateTest.checks_completed}/{corporateTest.checks_total}</span></div>
          <progress max={corporateTest.checks_total || 1} value={corporateTest.checks_completed || 0} />
          {corporateTest.state === "running" && <p><span className="setup-spinner" /> {corporateStageLabel(corporateTest.stage)} · {formatElapsed(corporateTest.elapsed_seconds || 0)} 경과</p>}
          {corporateTest.error && <p className="sandbox-failure">{localizeError(corporateTest.error)}</p>}
          {corporateTest.result && <>
            <strong className={corporateTest.result.activation_eligible ? "test-candidate" : "test-blocked"}>{corporateTest.chat_unlocked || corporateTest.result.chat_unlocked ? "회사 제한 샌드박스가 활성화됐습니다" : corporateTest.result.verdict === "candidate" ? "전체 검사를 통과했습니다" : corporateTest.result.activation_eligible ? "핵심 보안 검사를 통과했습니다 · 경고 확인 후 사용 가능" : "채팅에 필요한 핵심 보안 검사를 통과하지 못했습니다"}</strong>
            <p>핵심 {corporateTest.result.required_checks_passed}/{corporateTest.result.required_checks_total} · 전체 {corporateTest.result.checks_passed}/{corporateTest.result.checks_total} 통과 · 기존 설정 변경 {corporateTest.result.configuration_changed ? "감지됨" : "없음"}</p>
            {corporateTest.result.warning_checks?.length > 0 && <p className="sandbox-warning">경고 항목: {corporateTest.result.warning_checks.map(corporateCheckLabel).join(", ")}</p>}
            {corporateTest.result.activation_eligible && !corporateTest.chat_unlocked && !corporateTest.result.chat_unlocked && <button type="button" disabled={corporateActivationBusy} onClick={activateCorporateSandbox}>{corporateActivationBusy ? "활성화 중…" : "경고 확인 후 채팅 열기"}</button>}
            <details open={!corporateTest.result.activation_eligible}>
              <summary>검사 결과 전체 보기</summary>
              <ul className="corporate-check-list">{corporateTest.result.checks.map((check) => <li className={check.status} key={check.id}><span>{corporateCheckLabel(check.id)}</span><b>{corporateCheckState(check.status)}</b></li>)}</ul>
            </details>
            <em>회사 모드는 현재 사용자 제한 토큰과 선택한 프로젝트 폴더를 사용합니다. 강한 분할 읽기 프로필과 DNS 차단은 경고이며 Elevated 샌드박스와 동급을 의미하지 않습니다.</em>
          </>}
        </section>}
        {corporateTestError && <p className="sandbox-failure">{localizeError(corporateTestError)}</p>}
        <div className="sandbox-dialog-actions">
          {sandboxPhase === "confirm" && <><button className="secondary" onClick={() => setSandboxDialogVisible(false)}>취소</button><button onClick={beginSandboxSetup}>설정 시작</button></>}
          {sandboxSetupActive && <><button className="secondary" disabled={sandboxBusy} onClick={() => setSandboxDialogVisible(false)}>창 숨기기</button><button disabled={sandboxBusy} onClick={checkSandboxNow}>{sandboxBusy ? "확인 중…" : "상태 다시 확인"}</button></>}
          {sandboxPhase === "complete" && <button onClick={() => setSandboxDialogVisible(false)}>확인</button>}
          {sandboxPhase === "failed" && <><button className="secondary" onClick={() => setSandboxDialogVisible(false)}>닫기</button><button className="secondary" disabled={sandboxDiagnosticBusy || corporateTestPolling} onClick={diagnoseCompanySandbox}>{sandboxDiagnosticBusy ? "진단 중…" : "빠른 원인 진단"}</button><button className="secondary" disabled={sandboxDiagnosticBusy || corporateTestPolling || !activeProject} onClick={startCorporateSandboxTest}>{corporateTestPolling ? "테스트 진행 중…" : activeProject ? "회사 PC 호환 검사" : "프로젝트 선택 후 검사"}</button><button disabled={sandboxDiagnosticBusy || corporateTestPolling} onClick={beginSandboxSetup}>다시 시도</button></>}
        </div>
      </section>
    </div>}
  </>;
}
