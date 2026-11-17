# Security Boundaries

This repository is a local authorized-assessment product, not a public SaaS platform.

## Implemented boundaries

- Every API except login and `/health` requires a JWT.
- Active tasks require explicit `authorization_confirmed=true` and `max_rps <= 5`.
- The UI requires the operator to acknowledge the legal and operational scan risks before submission.
- A task without a configured authentication preset uses `auth_ref=none`; its per-task
  scope is derived from the submitted target host instead of a global allowlist.
- Initial targets, redirects, discovered OpenAPI servers and scanner-result URLs are scope checked.
- Optional allowed CIDRs provide a basic DNS rebinding boundary.
- Worker runs without host ports, with a read-only root filesystem, `cap_drop: ALL`, and tmpfs.
- GPL/AGPL tools are external processes or independent services, never imported into application code.
- Evidence files include SHA-256 hashes and are verified before download.
- Passwords, tokens, cookies and API keys are redacted from event payloads and errors.
- AI configuration is disabled by default. Stored API keys are encrypted with a key
  derived from `JWT_SECRET` and are never returned by the configuration API.
- Audit records capture username, action, target and task ID.
- ZAP scans have configurable whole-scan and per-rule duration limits.

## Not implemented

- Public HTTPS termination and certificate management.
- Multi-tenant RBAC and per-user asset ownership.
- Organization-wide quotas and distributed rate limiting.
- Centralized audit export, SIEM integration and retention litigation hold.
- Internet-facing SSE. The current SSE endpoint accepts a JWT query parameter and should be moved to an authenticated reverse-proxy header flow before public exposure.
- Production secret management. `.env` is for local deployment only.
- External AI data-governance controls. Enabling the optional LLM sends redacted risk
  summaries and evidence samples to the configured API endpoint.
- ARM64 verification. The Worker bundle and acceptance flow are currently tested on Linux AMD64.

## Required production changes

1. Put the product behind an HTTPS reverse proxy and disable direct API exposure.
2. Replace `.env` secrets with a secret manager.
3. Add OIDC or enterprise SSO, RBAC and tenant isolation.
4. Move SSE authentication to same-origin secure cookies or proxy-injected headers.
5. Add append-only audit storage, alerting and retention controls.
6. Run a separate authorized network segment for scan targets.
7. Review every tool license and organizational policy before commercial deployment.
