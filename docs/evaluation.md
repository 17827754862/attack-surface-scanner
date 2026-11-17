# DVWA 3×3 消融实验

测量日期：2026-10-28  
目标：`http://dvwa`，DVWA Low  
Ground truth：`evaluation/ground_truth_dvwa.yaml`  
原始结果：`evaluation/results.csv`

## 实验方法

- 每组运行 3 次，共 9 次真实任务，全部 `completed`。
- `nuclei`：`mode=active`、`tool_profile=nuclei`。
- `zap_wapiti_nuclei`：`mode=active`、`tool_profile=zap_wapiti_nuclei`。
- `full_agent`：`mode=full`、`tool_profile=full_agent`。
- 三轮使用同一 DVWA 状态、认证配置、`max_rps=5` 和 ZAP 10 分钟上限。
- 先按工具组过滤 Finding，再按统一别名映射计算类别 Recall、严格 Precision、
  严格误报率和覆盖类别比例。
- DVWA 的三个 XSS ground-truth 类别归一为同一个 `cross_site_scripting` 类别，
  因此最终 ground truth 为 12 个唯一类别。

## 汇总

| 组别 | 次数 | 平均 Findings | Mean Recall | Mean Precision | Mean FP Rate | Mean Seconds | Mean Coverage |
|---|---:|---:|---:|---:|---:|---:|---:|
| 单 Nuclei | 3 | 0.0 | 0.000 | 0.000 | 0.000 | 35.30 | 0.000 |
| ZAP + Wapiti + Nuclei | 3 | 103.0 | 0.417 | 0.527 | 0.473 | 647.57 | 0.417 |
| 完整 Agent | 3 | 104.0 | 0.417 | 0.527 | 0.473 | 647.62 | 0.417 |

三组结果在各自组内完全稳定，说明重复运行没有出现随机波动。

## 运行记录

| 组别 | Run | Task ID |
|---|---:|---|
| nuclei | 1 | `b6aeb958-3658-4073-8d33-f9967eb3078a` |
| nuclei | 2 | `2757f36f-a359-47ac-89bd-36e7df1e408a` |
| nuclei | 3 | `075b8558-6898-4668-93ac-6db400945fb2` |
| zap_wapiti_nuclei | 1 | `79bdbcf3-dcaa-45b3-b36e-ea7488f22666` |
| zap_wapiti_nuclei | 2 | `3b6c8937-5e69-4b58-b086-e84e0804d04a` |
| zap_wapiti_nuclei | 3 | `3023545e-23d9-4744-94f9-4b1047ecfdb6` |
| full_agent | 1 | `85f58e29-77e9-40a0-9069-c51f8de808de` |
| full_agent | 2 | `a9f6b1d2-2998-4e5b-a6c2-d60c3af00054` |
| full_agent | 3 | `0ef3e324-a168-4a6c-a947-7a9bdace98df` |

## 解读

- 单 Nuclei 在固定模板集和 medium/high/critical 严重度条件下未命中 DVWA
  ground-truth 类别，耗时约 35 秒。结果不能说明 Nuclei 无效，只说明其固定模板
  与当前本地 DVWA 场景重合度低。
- ZAP + Wapiti + Nuclei 将唯一类别 Recall 从 0 提升到 41.7%。ZAP 是主要贡献者，
  Wapiti 提供参数级交叉结果。
- 完整 Agent 比三引擎组平均多 1 条总 Finding，主要来自基础信息收集和端口服务；
  OpenVAS 当前未启用，因此没有主机 CVE 增量。
- 严格 Precision 为 52.7%，因为指标只把 ground truth 类别视为正确，Cookie 属性、
  信息暴露、服务器配置等其他真实安全问题也被计作误报。因此这里的 FP Rate 是
  “相对固定 ground truth 的未匹配率”，不是人工复核后的真实误报率。

## 覆盖边界

- 未覆盖需要多步业务逻辑组合的漏洞。
- 当前未启用 OpenVAS，网络层 CVE 和主机配置覆盖不在本次指标内。
- Nuclei 只覆盖固定模板版本和指定严重度。
- ZAP 结果受 10 分钟整次上限影响；超时后保留已生成告警，剩余规则不再执行。
- DVWA 的 XSS 子类被规范化合并，因此 Recall 按 12 个唯一类别计算。

复现命令：

```powershell
python evaluation/run_ablation.py --repetitions 3 --task-timeout 2400
```

## 2026-10-29 认证扫描复验

为验证 ZAP Cookie 注入、Wapiti 登录态复用、OpenVAS full profile 和多引擎融合，
在重置后的 DVWA Low 环境执行了一次新的完整任务：

- Task ID：`1e269b9b-b426-4139-ae73-e0b001480fad`
- 状态：`completed`
- Finding：88
- 风险组：20
- 严重度：critical 1、high 2、medium 40、low 42、info 3
- 工具来源：ZAP 84、Wapiti 3、Nmap 1
- 认证指标：`authenticated=true`、`wapiti_authenticated=true`、登录后覆盖 48 URL
- OpenVAS：`done`，本次主机层返回 0 条 Finding，无错误
- 扫描结束后 DVWA 仍可用 `admin/password` 登录

按同一 Ground Truth 和严格类别匹配口径重新计算：

| 指标 | 结果 |
|---|---:|
| Recall | 0.500 |
| Precision | 0.588 |
| Strict FP Rate | 0.412 |
| Coverage | 0.500 |

已命中的 ground-truth 类别为：`cleartext_login`、`cross_site_scripting`、
`csrf`、`file_inclusion`、`missing_security_headers`、`sensitive_file_exposure`。
其中 Wapiti 提供了 `/vulnerabilities/fi/?page=/etc/passwd` 对应的 critical
文件包含 Finding，ZAP 提供了两条 high DOM XSS。

本次仍未稳定命中 `brute_force`、`command_injection`、`default_credentials`、
`file_upload`、`sql_injection` 和 `weak_session_id`。这些类别分别需要登录失败
策略建模、命令执行验证、默认口令确认、文件执行链验证、参数化注入验证或会话随机性
分析，未用测试专用硬编码规则冒充通用扫描结果。逐行结果见
`evaluation/results-final.csv`。

LLM 摘要节点本次返回了不完整 JSON，按设计降级为 `skipped` 且
`llm_degraded`，扫描 Finding、风险组、证据和 HTML/PNG 报告均正常生成。

## 通用验证与预算回归

后续通用验证器回归使用 `validation_only` profile，不再为 DVWA 增加路径规则：

- 有效任务：`a1ac45e1-d0f4-489b-ad99-854429ef3e83`
- 结果：6 条 Finding，包含 SQL 注入、命令注入、文件上传、默认口令、会话固定和开放端口
- SQL 注入来自通用 form/filter 参数差分；命令标记会先用无命令控制值验证，避免反射误报
- OAST 服务已通过独立回调 token 命中验证
- 60 秒预算任务 `d4fdbb0d-04a5-4df6-944c-dfa5e1a984df` 返回 `partial`，保留已有
  Finding 并生成报告
- AI 大结果按风险组分批请求；单批失败只降级该批，确定性风险组仍保留
