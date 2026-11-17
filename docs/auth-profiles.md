# 通用认证档案

扫描器只从授权文件读取认证元数据，不在扫描适配器中写入 DVWA 或其他目标路径。

```yaml
auth_refs:
  portal:
    scope: [portal.corp.local]
    authentication:
      type: form
      target_hint: https://portal.corp.local
      target_hosts: [portal.corp.local]
      login_url: https://portal.corp.local/login
      verification_url: https://portal.corp.local/home
      username_env: PORTAL_USERNAME
      password_env: PORTAL_PASSWORD
      username_field: username
      password_field: password
      csrf_field: csrf_token
      submit_field: submit
      submit_value: Login
      logged_in_indicator: Logout
      safe_path_denylist: [logout, setup]
      active_scan_exclude: [account/delete]
```

支持 `form`、`cookie`、`bearer`、`basic` 和 `none`。密钥只通过环境变量或密钥
管理系统注入；API 的 `/api/auth-profiles` 只返回非敏感元数据。

`safe_path_denylist` 同时用于抓取和主动扫描的安全排除；`active_scan_exclude`
允许页面被抓取，但不允许主动提交。两者都应按目标应用配置，不能假定某个产品的
默认路径。
