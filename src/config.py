from dataclasses import dataclass, field
import os
from pathlib import Path
from src.secrets_provider import SecretsProvider  # noqa: E402

BASE_DIR: Path = Path(__file__).resolve().parent.parent
SANDBOX_DIR: Path = BASE_DIR / "sandbox_docs"
AUDIT_LOG_PATH: Path = Path(os.getenv("FINSEC_AUDIT_LOG", str(BASE_DIR / "security_audit.jsonl")))


_SECRETS = SecretsProvider()


@dataclass(frozen=True)
class ModelConfig:
    base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    chat_model: str = os.getenv("FINSEC_CHAT_MODEL", "llama3.2:3b")
    embed_model: str = os.getenv("FINSEC_EMBED_MODEL", "nomic-embed-text")
    temperature: float = float(os.getenv("FINSEC_TEMPERATURE", "0.0"))
    request_timeout_sec: float = float(os.getenv("FINSEC_TIMEOUT_SEC", "30.0"))


@dataclass(frozen=True)
class SecurityPolicyConfig:
    max_prompt_chars: int = int(os.getenv("FINSEC_MAX_PROMPT_CHARS", "2000"))
    max_rpm: int = int(os.getenv("FINSEC_MAX_RPM", "20"))
    corpus_hmac_key: str = field(
        default_factory=lambda: _SECRETS.resolve_secret("FINSEC_CORPUS_HMAC_KEY", fallback_bytes=32),
        repr=False,
    )
    system_canary_token: str = field(
        default_factory=lambda: _SECRETS.resolve_secret("FINSEC_CANARY_TOKEN", fallback_bytes=12, prefix="CANARY_"),
        repr=False,
    )

    def __post_init__(self) -> None:
        if len(self.corpus_hmac_key) < 32:
            raise ValueError("Configuration Error: FINSEC_CORPUS_HMAC_KEY must be at least 32 characters.")
        if self.max_prompt_chars <= 0:
            raise ValueError("Configuration Error: FINSEC_MAX_PROMPT_CHARS must be positive.")


MODEL_CFG = ModelConfig()
POLICY_CFG = SecurityPolicyConfig()