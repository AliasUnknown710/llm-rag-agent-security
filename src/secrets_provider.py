import os
from pathlib import Path
import secrets
from typing import Protocol


class SecretBackend(Protocol):
    """Protocol interface for pluggable enterprise secrets managers (Vault, AWS/Azure/GCP KMS, K8s mounts)."""

    def get_secret(self, secret_name: str) -> str | None:
        ...


class ContainerMountSecretBackend:
    """Reads secrets mounted via Kubernetes Secrets or Docker Swarm (/run/secrets/<name>)."""

    def __init__(self, mount_dir: Path = Path("/run/secrets")) -> None:
        self.mount_dir = mount_dir

    def get_secret(self, secret_name: str) -> str | None:
        secret_file = self.mount_dir / secret_name.lower()
        if secret_file.is_file():
            return secret_file.read_text(encoding="utf-8").strip()
        return None


class EnvVarSecretBackend:
    """Reads runtime-injected secrets from CI/CD or orchestrator environment variables."""

    def get_secret(self, secret_name: str) -> str | None:
        value = os.getenv(secret_name)
        return value.strip() if value else None


class SecretsProvider:
    """Layered enterprise secrets resolver with container-mount, env-var, and ephemeral CSPRNG fallback."""

    def __init__(self, backends: list[SecretBackend] | None = None) -> None:
        self.backends: list[SecretBackend] = backends or [
            ContainerMountSecretBackend(),
            EnvVarSecretBackend(),
        ]

    def resolve_secret(self, secret_name: str, fallback_bytes: int = 32, prefix: str = "") -> str:
        for backend in self.backends:
            value = backend.get_secret(secret_name)
            if value:
                return value
        return f"{prefix}{secrets.token_hex(fallback_bytes)}"