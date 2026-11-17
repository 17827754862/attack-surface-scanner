import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  CircleAlert,
  Crosshair,
  Gauge,
  Info,
  KeyRound,
  Layers3,
  Play,
  ScanSearch,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  Wifi,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import AppShell from "../components/AppShell";
import PageHeader from "../components/PageHeader";


const MODES = [
  { value: "passive", label: "被动侦察", note: "不发送主动探测请求" },
  { value: "active", label: "主动验证", note: "Web 扫描与安全验证" },
  { value: "full", label: "完整评估", note: "包含主机层与深度验证" },
];

const TOOL_PROFILES = [
  { value: "full_agent", label: "完整 Agent", note: "编排全部可用引擎" },
  { value: "validation_only", label: "仅通用验证", note: "跳过重型 Web 扫描" },
  { value: "zap_wapiti_nuclei", label: "Web 三引擎", note: "ZAP + Wapiti + Nuclei" },
  { value: "nuclei", label: "模板扫描", note: "仅运行 Nuclei" },
];

export default function Submit() {
  const [target, setTarget] = useState("");
  const [authRef, setAuthRef] = useState("none");
  const [maxRps, setMaxRps] = useState(5);
  const [mode, setMode] = useState("active");
  const [validationLevel, setValidationLevel] = useState("safe");
  const [oastEnabled, setOastEnabled] = useState(false);
  const [toolProfile, setToolProfile] = useState("full_agent");
  const [customAuthType, setCustomAuthType] = useState("auto");
  const [loginUrl, setLoginUrl] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [verificationUrl, setVerificationUrl] = useState("");
  const [loggedInIndicator, setLoggedInIndicator] = useState("");
  const [tokenJsonPath, setTokenJsonPath] = useState("authentication.token");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [capabilities, setCapabilities] = useState({});
  const [aiConfig, setAiConfig] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    api("/api/capabilities").then(setCapabilities).catch(() => {});
    api("/api/ai/config").then(setAiConfig).catch(() => {});
  }, []);

  const capabilityEntries = Object.entries(capabilities);
  const availableCount = capabilityEntries.filter(([, item]) => item.available).length;

  const selectedMode = useMemo(
    () => MODES.find((item) => item.value === mode) || MODES[1],
    [mode],
  );
  const selectedProfile = useMemo(
    () => TOOL_PROFILES.find((item) => item.value === toolProfile) || TOOL_PROFILES[0],
    [toolProfile],
  );
  const aiRouting = Boolean(
    aiConfig?.enabled && aiConfig?.base_url && aiConfig?.model,
  );
  const hasCustomCredentials = Boolean(
    loginUrl.trim() && loginUsername.trim() && loginPassword,
  );
  const useTemporaryAuth = authRef === "custom";
  const authLabel = useTemporaryAuth ? "账号登录" : "无需登录";

  function selectAuthMode(value) {
    setAuthRef(value);
    if (value === "custom") {
      setLoginUrl((current) => current || target);
    }
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    if (!authorizationConfirmed) {
      setError("请先确认目标归属或明确扫描授权。");
      return;
    }
    if (authRef === "custom" && !hasCustomCredentials) {
      setError("请填写本次扫描使用的登录页、账号和密码。");
      return;
    }
    setSubmitting(true);
    try {
      const task = await api("/api/tasks", {
        method: "POST",
        body: JSON.stringify({
          target,
          auth_ref: useTemporaryAuth ? "custom" : authRef,
          max_rps: Number(maxRps),
          mode,
          tool_profile: toolProfile,
          validation_level: validationLevel,
          oast_enabled: oastEnabled,
          authorization_confirmed: authorizationConfirmed,
          custom_auth: useTemporaryAuth
            ? {
                type: customAuthType,
                login_url: loginUrl.trim(),
                username: loginUsername.trim(),
                password: loginPassword,
                verification_url: verificationUrl.trim(),
                logged_in_indicator: loggedInIndicator.trim(),
                token_json_path: tokenJsonPath.trim(),
              }
            : null,
        }),
      });
      navigate(`/tasks/${task.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AppShell>
      <main className="page-shell">
        <PageHeader
          eyebrow="New authorized assessment"
          title="扫描控制台"
          description="定义目标、认证方式与扫描策略。所有主动请求将在授权确认后进入隔离的扫描执行面。"
          actions={(
            <div className="notice-banner flex items-center gap-2">
              <Wifi size={14} />
              {availableCount}/{capabilityEntries.length || 13} 引擎可用
            </div>
          )}
        />

        <div className="two-column">
          <form className="panel !overflow-visible" onSubmit={submit}>
            <div className="panel-header">
              <div>
                <h2 className="panel-title">评估配置</h2>
                <p className="panel-kicker">Assessment configuration</p>
              </div>
              <SlidersHorizontal size={17} className="text-[#7890af]" />
            </div>

            <section className="form-section">
              <div className="section-heading">
                <span className="section-index">01</span>
                <div>
                  <h3 className="section-title">目标与认证</h3>
                  <p className="section-description">输入完整 URL，选择账号登录或无需登录。</p>
                </div>
              </div>
              <div className="form-grid">
                <label className="field span-2">
                  目标地址 / Target
                  <span className="relative block">
                    <Crosshair
                      size={15}
                      className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#72839d]"
                    />
                    <input
                      value={target}
                      onChange={(event) => setTarget(event.target.value)}
                      placeholder="http://dvwa.test"
                      className="input input-mono input-with-icon"
                      required
                    />
                  </span>
                  <span className="field-hint">
                    本地靶机可使用 http://dvwa.test/ 或 http://webgoat.test/
                  </span>
                </label>
                <label className="field span-2">
                  登录方式 / Authentication
                  <select
                    value={authRef}
                    onChange={(event) => selectAuthMode(event.target.value)}
                    className="select"
                  >
                    <option value="custom">账号登录 / Authenticated account</option>
                    <option value="none">无需登录 / No authentication</option>
                  </select>
                </label>
              </div>
              {authRef === "custom" && (
                <div className="mt-4 border border-[#203550] bg-[#07101b] p-4">
                  <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold text-[#9ab4d3]">
                    <KeyRound size={14} />
                    本次任务临时凭据
                    <span className="font-normal text-[#526a86]">不写入报告</span>
                  </div>
                  <div className="form-grid">
                    <label className="field">
                      登录方式
                      <select
                        value={customAuthType}
                        onChange={(event) => setCustomAuthType(event.target.value)}
                        className="select"
                      >
                        <option value="auto">网页表单 / 自动识别</option>
                        <option value="form">网页表单 / 标准字段</option>
                        <option value="json">JSON 登录接口</option>
                      </select>
                    </label>
                    <label className="field">
                      登录页 / API 地址
                      <input
                        value={loginUrl}
                        onChange={(event) => setLoginUrl(event.target.value)}
                        placeholder="https://example.com/login"
                        className="input input-mono"
                        required={authRef === "custom"}
                      />
                    </label>
                    <label className="field">
                      登录账号
                      <input
                        value={loginUsername}
                        onChange={(event) => setLoginUsername(event.target.value)}
                        autoComplete="username"
                        className="input"
                        required={authRef === "custom"}
                      />
                    </label>
                    <label className="field">
                      登录密码
                      <input
                        type="password"
                        value={loginPassword}
                        onChange={(event) => setLoginPassword(event.target.value)}
                        autoComplete="current-password"
                        className="input"
                        required={authRef === "custom"}
                      />
                    </label>
                    {customAuthType === "json" && (
                      <label className="field">
                        Token JSON 路径
                        <input
                          value={tokenJsonPath}
                          onChange={(event) => setTokenJsonPath(event.target.value)}
                          placeholder="authentication.token"
                          className="input input-mono"
                        />
                      </label>
                    )}
                  </div>
                  <details className="mt-3 border-t border-[#172943] pt-3">
                    <summary className="cursor-pointer text-[10px] text-[#7890ab]">
                      登录成功验证（可选）
                    </summary>
                    <div className="form-grid mt-3">
                      <label className="field">
                        登录后页面
                        <input
                          value={verificationUrl}
                          onChange={(event) => setVerificationUrl(event.target.value)}
                          placeholder="留空时验证目标首页"
                          className="input input-mono"
                        />
                      </label>
                      <label className="field">
                        成功页面包含文字
                        <input
                          value={loggedInIndicator}
                          onChange={(event) => setLoggedInIndicator(event.target.value)}
                          placeholder="例如：退出、用户邮箱"
                          className="input"
                        />
                      </label>
                    </div>
                  </details>
                </div>
              )}
            </section>

            <section className="form-section">
              <div className="section-heading">
                <span className="section-index">02</span>
                <div>
                  <div className="section-title-row">
                    <h3 className="section-title">扫描策略</h3>
                    <button
                      type="button"
                      className="info-hint"
                      aria-label="查看扫描策略说明"
                    >
                      <Info size={15} />
                      <span className="info-hint-popover" role="tooltip">
                        <strong>如何选择扫描策略</strong>
                        <span className="info-hint-copy">
                          <b>被动侦察</b>：识别资产、端口和服务，不进入 Web 漏洞扫描。
                        </span>
                        <span className="info-hint-copy">
                          <b>主动验证</b>：运行 Web 扫描和安全验证，适合日常测试。
                        </span>
                        <span className="info-hint-copy">
                          <b>完整评估</b>：在主动验证之外增加 OpenVAS 主机漏洞扫描。
                        </span>
                        <span className="info-hint-divider" />
                        <span className="info-hint-copy">
                          <b>工具组合</b>：完整 Agent 调用全部可用引擎；仅通用验证跳过重型扫描；Web 三引擎运行 ZAP、Wapiti 和 Nuclei；模板扫描只运行 Nuclei。
                        </span>
                      </span>
                    </button>
                  </div>
                  <p className="section-description">选择请求强度和工具编排组合。</p>
                </div>
              </div>
              <div className="segmented">
                {MODES.map((item) => (
                  <button
                    type="button"
                    key={item.value}
                    className={`segment${mode === item.value ? " active" : ""}`}
                    onClick={() => setMode(item.value)}
                  >
                    <strong>{item.label}</strong>
                    <span>{item.note}</span>
                  </button>
                ))}
              </div>
              <div className="option-grid">
                {TOOL_PROFILES.map((item) => (
                  <button
                    type="button"
                    key={item.value}
                    className={`option-tile${toolProfile === item.value ? " active" : ""}`}
                    onClick={() => setToolProfile(item.value)}
                  >
                    <strong>{item.label}</strong>
                    <span>{item.note}</span>
                  </button>
                ))}
              </div>
            </section>

            <section className="form-section">
              <div className="section-heading">
                <span className="section-index">03</span>
                <div>
                  <h3 className="section-title">请求控制</h3>
                  <p className="section-description">控制每主机请求速率与请求安全上限。</p>
                </div>
              </div>
              <div className="form-grid">
                <label className="field span-2">
                  最大速率 / Max RPS
                  <input
                    type="number"
                    min="1"
                    max="5"
                    value={maxRps}
                    onChange={(event) => setMaxRps(event.target.value)}
                    className="input"
                  />
                  <span className="field-hint">安全上限为每主机每秒 5 个请求。</span>
                </label>
              </div>
            </section>

            <section className="form-section">
              <div className="section-heading">
                <span className="section-index">04</span>
                <div>
                  <h3 className="section-title">主动验证</h3>
                  <p className="section-description">控制参数差分、会话分析和带外回调验证。</p>
                </div>
              </div>
              <div className="form-grid">
                <div className="field">
                  <div className="field-label-row">
                    <label htmlFor="validation-level">验证级别</label>
                    <button
                      type="button"
                      className="info-hint"
                      aria-label="查看验证级别说明"
                    >
                      <Info size={15} />
                      <span className="info-hint-popover" role="tooltip">
                        <strong>验证级别说明</strong>
                        <span className="info-hint-copy">
                          <b>关闭 / Off</b>：不执行主动参数验证和登录会话分析，只保留发现过程与已选扫描引擎。
                        </span>
                        <span className="info-hint-copy">
                          <b>安全验证 / Safe</b>：执行低影响的 SQL 错误与布尔差分检查，并进行登录会话安全分析。
                        </span>
                        <span className="info-hint-copy">
                          <b>深度验证 / Deep</b>：增加命令回显标记、危险扩展名上传探测，以及可选的 OAST 盲 SSRF、XXE 和命令执行验证；OAST 需要单独开启。
                        </span>
                      </span>
                    </button>
                  </div>
                  <select
                    id="validation-level"
                    value={validationLevel}
                    onChange={(event) => {
                      setValidationLevel(event.target.value);
                      if (event.target.value !== "deep") setOastEnabled(false);
                    }}
                    className="select"
                  >
                    <option value="off">关闭 / Off</option>
                    <option value="safe">安全验证 / Safe</option>
                    <option value="deep">深度验证 / Deep</option>
                  </select>
                </div>
                <div className="field">
                  OAST 回调验证
                  <div className="flex h-10 items-center justify-between border border-[#29415f] bg-[#060c16] px-3">
                    <span className="text-[9px] font-normal text-[#60748e]">
                      盲 SSRF / XXE / 命令执行
                    </span>
                    <label className="switch" aria-label="启用 OAST 回调验证">
                      <input
                        type="checkbox"
                        checked={oastEnabled}
                        disabled={validationLevel !== "deep" || !capabilities.oast?.available}
                        onChange={(event) => setOastEnabled(event.target.checked)}
                      />
                      <span className="switch-track" />
                    </label>
                  </div>
                </div>
              </div>
            </section>

            <section className="form-section form-section-risk">
              <div className="risk-banner">
                <div className="risk-icon"><CircleAlert size={20} /></div>
                <div>
                  <h2 className="risk-title">扫描风险与授权声明</h2>
                  <p className="risk-copy">
                    主动扫描会向目标发送真实请求，可能触发安全设备、影响服务稳定性或产生访问日志。
                    仅可扫描自有系统，或已取得目标负责人明确授权的网站。未经授权的扫描可能违反法律、合同或学校规定。
                  </p>
                </div>
                <label className="risk-consent">
                  <input
                    type="checkbox"
                    checked={authorizationConfirmed}
                    onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
                    className="mt-0.5 h-4 w-4 shrink-0 accent-[#0a59f7]"
                  />
                  <span>我确认拥有该目标，或已取得明确授权，并承担本次扫描的操作责任。</span>
                </label>
              </div>
            </section>

            {error && <div className="error-banner mx-5 mt-4">{error}</div>}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#17263b] p-5">
              <div className="flex items-center gap-2 text-[8px] text-[#536981]">
                <ShieldCheck size={14} />
                所有扫描调用均通过 JWT、Scope Guard 和速率门禁
              </div>
              <button
                className="btn btn-primary"
                disabled={submitting || !authorizationConfirmed || !target.trim()}
              >
                {submitting ? <Sparkles size={15} className="spin" /> : <Play size={15} />}
                {submitting ? "正在创建任务" : "开始安全扫描"}
                {!submitting && <ArrowRight size={14} />}
              </button>
            </div>
          </form>

          <aside className="side-stack">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">执行摘要</h2>
                  <p className="panel-kicker">Runtime summary</p>
                </div>
                <TerminalSquare size={17} className="text-[#7890af]" />
              </div>
              <div className="panel-body">
                <div className="summary-list">
                  <div className="summary-row">
                    <span className="summary-label">目标主机</span>
                    <span className="summary-value">{target || "等待填写"}</span>
                  </div>
                  <div className="summary-row">
                    <span className="summary-label">登录态</span>
                    <span className={`summary-value ${useTemporaryAuth ? "text-[#7db3ff]" : ""}`}>
                      {authLabel}
                    </span>
                  </div>
                  <div className="summary-row">
                    <span className="summary-label">扫描模式</span>
                    <span className="summary-value">{selectedMode.label}</span>
                  </div>
                  <div className="summary-row">
                    <span className="summary-label">引擎组合</span>
                    <span className="summary-value">{selectedProfile.label}</span>
                  </div>
                  <div className="summary-row">
                    <span className="summary-label">扫描编排</span>
                    <span className={`summary-value ${aiRouting ? "text-[#7db3ff]" : ""}`}>
                      {aiRouting ? "AI 动态选择" : "固定安全流程"}
                    </span>
                  </div>
                  <div className="summary-row">
                    <span className="summary-label">请求速率</span>
                    <span className="summary-value">{maxRps} req/s</span>
                  </div>
                  <div className="summary-row">
                    <span className="summary-label">授权状态</span>
                    <span className={`summary-value ${authorizationConfirmed ? "text-[#07856e]" : "text-[#b66a08]"}`}>
                      {authorizationConfirmed ? "CONFIRMED" : "PENDING"}
                    </span>
                  </div>
                </div>
              </div>
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">扫描引擎矩阵</h2>
                  <p className="panel-kicker">Capability discovery</p>
                </div>
                <Layers3 size={17} className="text-[#7890af]" />
              </div>
              <div className="panel-body">
                <div className="tool-grid">
                  {capabilityEntries.map(([name, capability]) => (
                    <div
                      key={name}
                      className="tool-chip"
                      title={capability.error || capability.version || ""}
                    >
                      <span className="tool-chip-name">{name}</span>
                      <span className={`tool-state${capability.available ? " available" : ""}`} />
                    </div>
                  ))}
                  {!capabilityEntries.length && (
                    <div className="empty-state col-span-2 !min-h-[120px]">
                      <div>
                        <ScanSearch size={24} />
                        正在探测执行节点工具能力
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </section>

            <section className="grid grid-cols-2 gap-2">
              <div className="metric">
                <div className="metric-label">请求上限</div>
                <strong className="metric-value">{maxRps}</strong>
                <div className="metric-note"><Gauge size={10} className="inline" /> requests / second</div>
              </div>
              <div className="metric">
                <div className="metric-label">可用引擎</div>
                <strong className="metric-value">{availableCount}</strong>
                <div className="metric-note"><Layers3 size={10} className="inline" /> of {capabilityEntries.length || 14} discovered</div>
              </div>
            </section>
          </aside>
        </div>
      </main>
    </AppShell>
  );
}
