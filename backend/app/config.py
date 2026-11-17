from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = (
        "postgresql+psycopg://scanner:scanner@postgres:5432/scanner"
    )
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 720
    admin_username: str = "admin"
    admin_password: str = "changeme"
    authorization_file: str = "samples/auth.example.yaml"
    default_scope: str = "dvwa,127.0.0.1,localhost"
    max_rps: int = 5
    output_dir: str = "/output"
    evidence_retention_days: int = 30
    vuln_alias_file: str = "config/vuln_alias.json"
    playbook_dir: str = "report/playbooks"
    zap_url: str = "http://zap:8090"
    zap_host: str = "zap"
    zap_port: int = 8090
    zap_api_key: str = "local-zap-key"
    nuclei_tags: str = "spring,exposure,misconfiguration,default-login"
    nuclei_severity: str = "high,critical"
    nuclei_max_targets: int = 3
    openvas_enabled: bool = False
    openvas_host: str = "openvas"
    openvas_port: int = 9390
    openvas_username: str = "admin"
    openvas_password: str = "admin"
    safe_scan_denylist: str = (
        "logout.php,logout,signout,setup.php,install.php,reset.php,delete.php"
    )
    validation_max_pages: int = 25
    validation_max_parameters: int = 80
    validation_max_requests: int = 400
    lab_benchmark_enabled: bool = True
    weak_credentials_file: str = "config/weak_credentials.txt"
    ephemeral_auth_ttl_seconds: int = 1800
    llm_enabled: bool = False
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = "deepseek-chat"
    llm_batch_size: int = 6
    llm_max_tokens: int = 4096
    oast_url: str = "http://oast:8001"
    oast_public_base_url: str = "http://oast:8001"
    oast_secret: str = "local-oast-secret"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
