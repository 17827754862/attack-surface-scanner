import { useEffect, useState } from "react";
import {
  BrainCircuit,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  PlugZap,
  Save,
  ServerCog,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { api } from "../api";
import AppShell from "../components/AppShell";
import PageHeader from "../components/PageHeader";


export default function AISettings() {
  const [form, setForm] = useState({
    enabled: false,
    base_url: "",
    model: "deepseek-chat",
    api_key: "",
  });
  const [configured, setConfigured] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api("/api/ai/config").then((config) => {
      setConfigured(config.api_key_configured);
      setForm((current) => ({
        ...current,
        enabled: config.enabled,
        base_url: config.base_url,
        model: config.model,
      }));
    }).catch((err) => setError(err.message));
  }, []);

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function save(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    setSaving(true);
    try {
      const payload = { ...form };
      if (!payload.api_key) delete payload.api_key;
      const saved = await api("/api/ai/config", { method: "PUT", body: JSON.stringify(payload) });
      setConfigured(saved.api_key_configured);
      setForm((current) => ({ ...current, api_key: "" }));
      setMessage("AI 配置已安全保存");
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  async function testConnection() {
    setError("");
    setMessage("");
    setTesting(true);
    try {
      const result = await api("/api/ai/test", {
        method: "POST",
        body: JSON.stringify({
          ...form,
          api_key: form.api_key || null,
        }),
      });
      setMessage(`连接成功 · ${result.model}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setTesting(false);
    }
  }

  return (
    <AppShell>
      <main className="page-shell">
        <PageHeader
          eyebrow="Narrative intelligence layer"
          title="AI 研判设置"
          description="通过 OpenAI 兼容接口动态选择下一扫描器，并增强风险归并、漏洞解读与复测建议。AI 只能在候选工具中选择，不能生成命令或绕过授权范围。"
          actions={(
            <span className={`status-badge ${form.enabled ? "completed" : "skipped"}`}>
              <span className="status-dot" />
              {form.enabled ? "AI 已启用" : "AI 已关闭"}
            </span>
          )}
        />

        <div className="two-column">
          <form className="panel" onSubmit={save}>
            <div className="panel-header">
              <div>
                    <h2 className="panel-title">模型接入与动态编排</h2>
                    <p className="panel-kicker">Adaptive routing · OpenAI-compatible endpoint</p>
              </div>
              <BrainCircuit size={17} className="text-[#7890af]" />
            </div>
            <div className="panel-body grid gap-5">
              <div className="flex items-center justify-between gap-5 border border-[#1d3048] bg-[#07101d] p-4">
                <div>
                  <div className="flex items-center gap-2 text-[13px] font-semibold text-white">
                    <Sparkles size={14} className="text-[#0a59f7]" />
                    启用 AI 动态编排与辅助研判
                  </div>
                  <p className="mt-1 text-[10px] leading-5 text-[#60748e]">
                    根据前一个扫描器的结果选择下一个候选工具；未接入模型时自动回退固定安全流程。
                  </p>
                </div>
                <label className="switch" aria-label="启用 AI 辅助研判">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(event) => update("enabled", event.target.checked)}
                  />
                  <span className="switch-track" />
                </label>
              </div>

              <label className="field">
                API Base URL
                <span className="relative block">
                  <ServerCog
                    size={15}
                    className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#72839d]"
                  />
                  <input
                    value={form.base_url}
                    onChange={(event) => update("base_url", event.target.value)}
                    placeholder="https://api.deepseek.com/v1"
                    className="input input-mono input-with-icon"
                  />
                </span>
                <span className="field-hint">也支持本地 OpenAI 兼容服务地址。</span>
              </label>

              <div className="form-grid">
                <label className="field">
                  模型名称 / Model
                  <input
                    value={form.model}
                    onChange={(event) => update("model", event.target.value)}
                    className="input input-mono"
                  />
                </label>
                <label className="field">
                  API Key {configured ? "（已配置）" : ""}
                  <span className="relative block">
                    <KeyRound
                      size={15}
                      className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#72839d]"
                    />
                    <input
                      type={showKey ? "text" : "password"}
                      value={form.api_key}
                      onChange={(event) => update("api_key", event.target.value)}
                      placeholder={configured ? "••••••••  留空不修改" : "sk-..."}
                      className="input input-mono input-with-icon input-with-trailing-icon"
                    />
                    <button
                      type="button"
                      className="password-toggle"
                      onClick={() => setShowKey((value) => !value)}
                      aria-label={showKey ? "隐藏 API Key" : "显示 API Key"}
                    >
                      {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </span>
                </label>
              </div>

              {message && (
                <div className="notice-banner flex items-center gap-2">
                  <CheckCircle2 size={14} />
                  {message}
                </div>
              )}
              {error && <div className="error-banner">{error}</div>}

              <div className="flex flex-wrap gap-2 border-t border-[#17263b] pt-4">
                <button className="btn btn-primary" disabled={saving}>
                  <Save size={14} />
                  {saving ? "保存中..." : "保存配置"}
                </button>
                <button type="button" className="btn" onClick={testConnection} disabled={testing}>
                  <PlugZap size={14} />
                  {testing ? "正在测试..." : "测试连接"}
                </button>
              </div>
            </div>
          </form>

          <aside className="side-stack">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">安全边界</h2>
                  <p className="panel-kicker">Deterministic first</p>
                </div>
                <ShieldCheck size={17} className="text-[#7890af]" />
              </div>
              <div className="panel-body">
                <div className="space-y-4 text-[10px] leading-6 text-[#60748e]">
                  <p>AI 仅接收脱敏后的扫描摘要与证据样本，不接收登录凭据或原始会话 Cookie。</p>
                  <p>AI 失败或超时会静默降级，扫描结果、风险组和报告主链路不受影响。</p>
                  <p>AI 只能在已通过 scope、profile 和条件检查的候选节点中选择，不能调用列表外的工具。</p>
                  <p>当前 API Key 经加密后保存在服务端，读取接口不会回显明文。</p>
                </div>
              </div>
            </section>
            <section className="notice-banner">
              <div className="flex items-center gap-2 font-semibold">
                <BrainCircuit size={14} />
                当前能力
              </div>
              <div className="mt-3 grid gap-2 text-[10px]">
                <span>· 根据前一节点结果选择下一扫描器</span>
                <span>· 同一风险语义归并与置信度增强</span>
                <span>· 中英双语漏洞解读</span>
                <span>· 低影响复测与误报检查建议</span>
              </div>
            </section>
          </aside>
        </div>
      </main>
    </AppShell>
  );
}
