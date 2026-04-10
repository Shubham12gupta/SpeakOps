import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, EmailStr, field_validator, model_validator


# ═══════════════════════════════════════════════════════
# PYDANTIC MODELS — one per section of voice.config.yaml
# ═══════════════════════════════════════════════════════


# -------------------------------
# 1. META
# ------------------------------- 
class MetaConfig(BaseModel):
    project_name: str
    version: str
    owner_email: Optional[str] = None
    description: Optional[str] = None

    @field_validator("project_name")
    @classmethod
    def project_name_valid(cls, v):
        if not v or not v.strip():
            raise ValueError("project_name cannot be empty")
        if not re.match(r"^[\w\-]+$", v):
            raise ValueError("project_name must be alphanumeric with hyphens only")
        return v.strip()

    @field_validator("version")
    @classmethod
    def version_valid(cls, v):
        if not v or not v.strip():
            raise ValueError("version cannot be empty")
        return v.strip()

    @field_validator("owner_email")
    @classmethod
    def email_valid(cls, v):
        if v and "@" not in v:
            raise ValueError("owner_email must be a valid email address")
        return v


# -------------------------------
# 2. ENVIRONMENT
# -------------------------------
class EnvironmentConfig(BaseModel):
    namespace: Optional[str] = "default"
    restrictions: Optional[bool] = False
    auto_confirm: Optional[bool] = True
    restricted_hours: Optional[str] = None

    @field_validator("restricted_hours")
    @classmethod
    def hours_format(cls, v):
        if v is None:
            return v
        pattern = r"^\d{2}:\d{2}-\d{2}:\d{2}$"
        if not re.match(pattern, v):
            raise ValueError("restricted_hours must be in format HH:MM-HH:MM")
        start, end = v.split("-")
        sh, sm = map(int, start.split(":"))
        eh, em = map(int, end.split(":"))
        if not (0 <= sh <= 23 and 0 <= sm <= 59):
            raise ValueError("Invalid start time in restricted_hours")
        if not (0 <= eh <= 23 and 0 <= em <= 59):
            raise ValueError("Invalid end time in restricted_hours")
        return v


# -------------------------------
# 3. CONNECTORS
# -------------------------------
class HelmConfig(BaseModel):
    type: Optional[str] = "helm"
    release_name: Optional[str] = None
    chart_path: Optional[str] = None
    values_file: Optional[str] = None


class KubernetesConnector(BaseModel):
    type: Optional[str] = "eks"
    cluster: Optional[str] = None
    auth: Optional[str] = "kubeconfig"
    api_key: Optional[str] = None
    package_manager: Optional[HelmConfig] = None

    @field_validator("api_key")
    @classmethod
    def api_key_not_hardcoded(cls, v):
        if v and not v.startswith("${"):
            raise ValueError(
                "api_key must use environment variable format: ${VAR_NAME}. "
                "Never hardcode credentials in config."
            )
        return v


class JenkinsConnector(BaseModel):
    url: Optional[str] = None
    api_key: Optional[str] = None
    jobs: Optional[Dict[str, str]] = None

    @field_validator("api_key")
    @classmethod
    def api_key_not_hardcoded(cls, v):
        if v and not v.startswith("${") and not str(v).startswith("vault://"):
            raise ValueError(
                "api_key must use ${VAR_NAME} or vault://path format"
            )
        return v


class ArgocdConnector(BaseModel):
    url: Optional[str] = None
    api_key: Optional[str] = None
    apps: Optional[Dict[str, str]] = None

    @field_validator("api_key")
    @classmethod
    def api_key_not_hardcoded(cls, v):
        if v and not v.startswith("${") and not str(v).startswith("vault://"):
            raise ValueError(
                "api_key must use ${VAR_NAME} or vault://path format"
            )
        return v


class GrafanaConnector(BaseModel):
    url: Optional[str] = None
    api_key: Optional[str] = None
    dashboards: Optional[Dict[str, str]] = None

    @field_validator("api_key")
    @classmethod
    def api_key_not_hardcoded(cls, v):
        if v and not v.startswith("${") and not str(v).startswith("vault://"):
            raise ValueError(
                "api_key must use ${VAR_NAME} or vault://path format"
            )
        return v


class VaultConnector(BaseModel):
    address: Optional[str] = None
    api_key: Optional[str] = None
    path: Optional[str] = None


class ConnectorsConfig(BaseModel):
    kubernetes: Optional[KubernetesConnector] = None
    jenkins: Optional[JenkinsConnector] = None
    argocd: Optional[ArgocdConnector] = None
    grafana: Optional[GrafanaConnector] = None
    vault: Optional[VaultConnector] = None

    @model_validator(mode="after")
    def at_least_one_connector(self):
        if not any([
            self.kubernetes,
            self.jenkins,
            self.argocd,
            self.grafana,
        ]):
            raise ValueError("At least one connector must be defined")
        return self


# -------------------------------
# 4. RBAC
# -------------------------------
class RoleConfig(BaseModel):
    access: str
    allowed_operations: Optional[List[str]] = []
    denied_operations: Optional[List[str]] = []
    require_confirm_for: Optional[List[str]] = []
    bypass_confirm: Optional[bool] = False

    @field_validator("access")
    @classmethod
    def access_valid(cls, v):
        if v not in ["read", "read_write"]:
            raise ValueError("access must be 'read' or 'read_write'")
        return v


class RBACConfig(BaseModel):
    junior_engineer: Optional[RoleConfig] = None
    senior_engineer: Optional[RoleConfig] = None
    admin: Optional[RoleConfig] = None

    @model_validator(mode="after")
    def at_least_one_role(self):
        if not any([self.junior_engineer, self.senior_engineer, self.admin]):
            raise ValueError("At least one role must be defined in rbac")
        return self


# -------------------------------
# 5. VOICE COMMANDS
# -------------------------------
class ExecutionConfig(BaseModel):
    mode: Optional[str] = "execute"
    confirm_in: Optional[List[str]] = []
    timeout: Optional[int] = 60

    @field_validator("mode")
    @classmethod
    def mode_valid(cls, v):
        if v not in ["execute", "read"]:
            raise ValueError("execution.mode must be 'execute' or 'read'")
        return v

    @field_validator("timeout")
    @classmethod
    def timeout_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError("execution.timeout must be greater than 0")
        return v


class CommandSafetyConfig(BaseModel):
    blast_radius_check: Optional[bool] = True
    max_replicas: Optional[int] = 20
    block_scale_to_zero: Optional[bool] = True


class CommandRBACConfig(BaseModel):
    allowed_roles: Optional[List[str]] = []


class CommandAuditConfig(BaseModel):
    log: Optional[bool] = True
    level: Optional[str] = "info"

    @field_validator("level")
    @classmethod
    def level_valid(cls, v):
        if v not in ["info", "warning", "error"]:
            raise ValueError("audit.level must be 'info', 'warning', or 'error'")
        return v


class VoiceCommandConfig(BaseModel):
    intent: List[str]
    connector: str
    operation: str
    params: Optional[Dict[str, Any]] = {}
    execution: Optional[ExecutionConfig] = None
    safety: Optional[CommandSafetyConfig] = None
    rbac: Optional[CommandRBACConfig] = None
    audit: Optional[CommandAuditConfig] = None

    @field_validator("intent")
    @classmethod
    def intent_not_empty(cls, v):
        if not v:
            raise ValueError("intent list cannot be empty")
        for i in v:
            if not i or not i.strip():
                raise ValueError("intent phrases cannot be empty strings")
        return v

    @field_validator("operation")
    @classmethod
    def operation_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("operation cannot be empty")
        return v

    @field_validator("connector")
    @classmethod
    def connector_valid(cls, v):
        valid = ["kubernetes", "jenkins", "argocd", "grafana", "vault", "incident"]
        if v not in valid:
            raise ValueError(f"connector must be one of {valid}")
        return v


# -------------------------------
# 6. SAFETY
# -------------------------------
class SafetyConfig(BaseModel):
    dry_run_mode: Optional[bool] = False
    blast_radius_check: Optional[bool] = True
    max_replicas_voice: Optional[int] = 20
    forbidden_operations: Optional[List[str]] = []
    block_in_production: Optional[List[str]] = []

    @field_validator("max_replicas_voice")
    @classmethod
    def max_replicas_range(cls, v):
        if v is not None and not (1 <= v <= 100):
            raise ValueError("max_replicas_voice must be between 1 and 100")
        return v


# -------------------------------
# 7. SECURITY
# -------------------------------
class PerEnvironmentAuth(BaseModel):
    required: Optional[bool] = True
    threshold: Optional[float] = 0.85

    @field_validator("threshold")
    @classmethod
    def threshold_range(cls, v):
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError("threshold must be between 0.0 and 1.0")
        return v


class PerOperationAuth(BaseModel):
    required: Optional[bool] = True
    threshold: Optional[float] = None

    @field_validator("threshold")
    @classmethod
    def threshold_range(cls, v):
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError("threshold must be between 0.0 and 1.0")
        return v


class VoiceAuthConfig(BaseModel):
    enabled: Optional[bool] = True
    enrollment_samples: Optional[int] = 3
    similarity_threshold: Optional[float] = 0.85
    per_environment: Optional[Dict[str, PerEnvironmentAuth]] = {}
    per_operation: Optional[Dict[str, PerOperationAuth]] = {}

    @field_validator("similarity_threshold")
    @classmethod
    def threshold_range(cls, v):
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError("similarity_threshold must be between 0.0 and 1.0")
        return v

    @field_validator("enrollment_samples")
    @classmethod
    def samples_range(cls, v):
        if v is not None and not (1 <= v <= 10):
            raise ValueError("enrollment_samples must be between 1 and 10")
        return v


class SecurityConfig(BaseModel):
    voice_auth: Optional[VoiceAuthConfig] = None


# -------------------------------
# 8. AUDIT
# -------------------------------
class AuditConfig(BaseModel):
    backend: Optional[str] = "local"
    log_fields: Optional[List[str]] = []
    retention_days: Optional[int] = 90

    @field_validator("backend")
    @classmethod
    def backend_valid(cls, v):
        if v not in ["local", "s3", "elasticsearch"]:
            raise ValueError("audit.backend must be 'local', 's3', or 'elasticsearch'")
        return v

    @field_validator("retention_days")
    @classmethod
    def retention_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError("audit.retention_days must be greater than 0")
        return v


# -------------------------------
# 9. NOTIFICATIONS
# -------------------------------
class NotificationEvent(BaseModel):
    voice_response: Optional[bool] = True
    slack_alert: Optional[bool] = False
    slack_channel: Optional[str] = None

    @field_validator("slack_channel")
    @classmethod
    def channel_format(cls, v):
        if v and not v.startswith("#"):
            raise ValueError("slack_channel must start with '#'")
        return v


class NotificationsConfig(BaseModel):
    on_success: Optional[NotificationEvent] = None
    on_failure: Optional[NotificationEvent] = None
    on_production_change: Optional[NotificationEvent] = None


# -------------------------------
# ROOT CONFIG
# -------------------------------
class SpeakOpsConfig(BaseModel):
    meta: MetaConfig
    environments: Dict[str, EnvironmentConfig]
    connectors: ConnectorsConfig
    rbac: Optional[RBACConfig] = None
    voiceCommands: Optional[Dict[str, Dict[str, VoiceCommandConfig]]] = None
    safety: Optional[SafetyConfig] = None
    security: Optional[SecurityConfig] = None
    audit: Optional[AuditConfig] = None
    notifications: Optional[NotificationsConfig] = None

    @model_validator(mode="after")
    def environments_not_empty(self):
        if not self.environments:
            raise ValueError("At least one environment must be defined")
        return self


# ═══════════════════════════════════════════════════════
# LOAD AND VALIDATE
# ═══════════════════════════════════════════════════════
def load_and_validate(path: str = "voice.config.yaml") -> SpeakOpsConfig:

    config_path = Path(path)

    # file exists?
    if not config_path.exists():
        raise FileNotFoundError(
            f"voice.config.yaml not found at '{path}'\n"
            f"Run 'speakops init' to create one."
        )

    # valid YAML?
    try:
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML syntax in config file:\n{e}")

    # empty file?
    if not raw:
        raise ValueError(
            "voice.config.yaml is empty. "
            "Run 'speakops init' to generate a template."
        )

    # pydantic validation
    try:
        config = SpeakOpsConfig(**raw)
    except Exception as e:
        raise ValueError(f"Config validation failed:\n{e}")

    return config


# ═══════════════════════════════════════════════════════
# HELPER FUNCTIONS — used by other modules
# ═══════════════════════════════════════════════════════

def get_environment(config: SpeakOpsConfig, env_name: str) -> Optional[EnvironmentConfig]:
    return config.environments.get(env_name)


def get_connector(config: SpeakOpsConfig, connector_name: str) -> Optional[Any]:
    return getattr(config.connectors, connector_name, None)


def get_role(config: SpeakOpsConfig, role_name: str) -> Optional[RoleConfig]:
    if not config.rbac:
        return None
    return getattr(config.rbac, role_name, None)


def get_command(
    config: SpeakOpsConfig,
    connector_name: str,
    command_name: str
) -> Optional[VoiceCommandConfig]:
    if not config.voiceCommands:
        return None
    connector_cmds = config.voiceCommands.get(connector_name, {})
    return connector_cmds.get(command_name)


def get_all_intents(config: SpeakOpsConfig) -> List[Dict]:
    intents = []
    if not config.voiceCommands:
        return intents
    for connector_name, commands in config.voiceCommands.items():
        for command_name, command in commands.items():
            for intent in command.intent:
                intents.append({
                    "connector"   : command.connector,
                    "operation"   : command.operation,
                    "intent"      : intent,
                    "command_name": command_name,
                })
    return intents


def get_similarity_threshold(
    config: SpeakOpsConfig,
    environment: str,
    operation_mode: str = "write"
) -> float:
    if not config.security or not config.security.voice_auth:
        return 0.85

    auth = config.security.voice_auth
    base = auth.similarity_threshold or 0.85

    # environment override
    env_auth = (auth.per_environment or {}).get(environment)
    if env_auth and env_auth.threshold:
        base = env_auth.threshold

    # operation override
    op_auth = (auth.per_operation or {}).get(operation_mode)
    if op_auth and op_auth.threshold:
        base = op_auth.threshold

    return base


# ═══════════════════════════════════════════════════════
# CLI TEST
# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    try:
        config = load_and_validate("voice.config.yaml")

        print("\n✅  Config loaded and validated successfully")
        print(f"    Project     : {config.meta.project_name}")
        print(f"    Version     : {config.meta.version}")
        print(f"    Owner       : {config.meta.owner_email}")
        print(f"    Environments: {list(config.environments.keys())}")

        connectors = []
        if config.connectors.kubernetes: connectors.append("kubernetes")
        if config.connectors.jenkins: connectors.append("jenkins")
        if config.connectors.argocd: connectors.append("argocd")
        if config.connectors.grafana: connectors.append("grafana")
        print(f"    Connectors  : {connectors}")

        intents = get_all_intents(config)
        print(f"    Total intents loaded: {len(intents)}")

    except FileNotFoundError as e:
        print(f"\n📁  File Error: {e}")

    except ValueError as e:
        print(f"\n❌  Validation Error: {e}")