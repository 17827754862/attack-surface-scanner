import { useState } from "react";
import {
  Activity,
  ArrowRight,
  Eye,
  EyeOff,
  LockKeyhole,
  ScanLine,
  ShieldCheck,
} from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, setToken } from "../api";


export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("changeme");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const location = useLocation();

  async function submit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const data = await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setToken(data.access_token);
      navigate(location.state?.from || "/", { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-visual">
        <div className="login-brand">
          <span className="brand-mark" aria-hidden="true" />
          <span>
            <strong className="brand-name">Surface Scanner</strong>
            <span className="brand-subtitle">Security Control Plane</span>
          </span>
        </div>
        <div className="login-headline">
          <div className="login-index">Authorized security operations</div>
          <h1>
            See every surface.
            <span>Control every signal.</span>
          </h1>
          <p>
            从资产发现、认证会话到漏洞验证与证据留痕，让每一次授权扫描都成为可复核、可恢复、可解释的安全评估。
          </p>
        </div>
        <div className="login-signal">
          <div className="signal-cell">
            <span>Execution graph</span>
            <strong>19 nodes</strong>
          </div>
          <div className="signal-cell">
            <span>Scan engines</span>
            <strong>Multi-engine</strong>
          </div>
          <div className="signal-cell">
            <span>Evidence trail</span>
            <strong>SHA-256</strong>
          </div>
        </div>
      </section>
      <section className="login-form-side">
        <form className="login-form" onSubmit={submit}>
          <div className="login-form-label">Local console access</div>
          <h2>登录控制台</h2>
          <p>使用管理员凭据进入本地扫描编排环境。</p>
          <div className="login-fields">
            <label className="field">
              用户名
              <input
                className="input"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
              />
            </label>
            <label className="field">
              密码
              <span className="password-wrap">
                <input
                  className="input"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword((value) => !value)}
                  aria-label={showPassword ? "隐藏密码" : "显示密码"}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </span>
            </label>
          </div>
          {error && <p className="error-banner mt-4">{error}</p>}
          <button className="btn btn-primary login-submit" disabled={submitting}>
            {submitting ? (
              <>
                <Activity size={15} className="spin" />
                正在验证
              </>
            ) : (
              <>
                <LockKeyhole size={15} />
                安全登录
                <ArrowRight size={14} />
              </>
            )}
          </button>
          <div className="login-footnote">
            <div className="flex items-center gap-2">
              <ShieldCheck size={13} />
              JWT 会话保护 · 本地 Docker 隔离执行
            </div>
            <div className="mt-2 flex items-center gap-2">
              <ScanLine size={13} />
              仅允许扫描自有资产或已取得明确授权的目标
            </div>
          </div>
        </form>
      </section>
    </main>
  );
}
