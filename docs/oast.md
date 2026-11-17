# 可选 OAST 回调验证

OAST 用于确认盲 SSRF、XXE 和命令执行，不替代普通 Web 扫描。服务通过
`OAST_SECRET` 保护 token 创建和查询接口，回调入口不需要凭据。

```powershell
$headers = @{ "X-OAST-Secret" = "local-oast-secret" }
$token = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:18001/api/tokens `
  -Headers $headers -ContentType application/json -Body '{"label":"demo"}'
$token.callback_url
```

任务必须使用 `validation_level=deep` 且设置 `oast_enabled=true`。在工作流中，
目标必须能够访问 `OAST_PUBLIC_BASE_URL`；Docker 内部可以用
`http://oast:8001`，真实外部目标必须配置可达的 HTTPS 反向代理地址。

没有命中时不会产生 Finding；OAST 不可用会在 `active_validation` 的
`state.errors` 中记录 `oast_unavailable`，不会阻塞确定性扫描和报告。
