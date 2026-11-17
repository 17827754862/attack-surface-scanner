# Kubernetes 配置风险

## 立即处置
- 对高风险工作负载限制权限、网络和宿主资源访问。

## 根因修复
- 禁用 privileged、hostNetwork 和过高 capability。
- 设置资源限制、只读根文件系统、非 root 运行和 NetworkPolicy。

## 复测方法
- 重新运行 Kubescape 基线和策略检查。
- 在测试命名空间验证容器无法获得被禁止权限。

## 长期加固
- 使用准入控制器和策略即代码阻止不合规工作负载上线。
