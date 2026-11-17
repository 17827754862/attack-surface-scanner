# 执行时间策略

任务不设置执行时长上限。以下位置均不再使用任务 deadline 或阶段预算：

- Subfinder、dnsx、httpx、Nmap、Nuclei、Nikto、Gitleaks、Kubescape、
  Schemathesis 和 Wapiti 子进程
- ZAP Spider、AJAX Spider 和 Active Scan 轮询
- OpenVAS GMP 任务轮询
- 主动验证和 OAST 回调等待

任务只会因为全部工具执行完成、发生未处理异常或被用户手动取消而结束。请求速率
`max_rps`、授权 Scope Guard、安全路径排除和主动验证请求数量约束仍然保留。
