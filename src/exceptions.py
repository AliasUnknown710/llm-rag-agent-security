class FinSecSecurityError(Exception):
    """Base exception for all OWASP LLM runtime policy violations."""

    def __init__(self, owasp_id: str, message: str, http_status: int = 403) -> None:
        self.owasp_id = owasp_id
        self.http_status = http_status
        super().__init__(f"[{owasp_id}] {message}")


class PromptInjectionError(FinSecSecurityError):
    def __init__(self, message: str) -> None:
        super().__init__("LLM01", message, http_status=400)


class AccessControlViolationError(FinSecSecurityError):
    def __init__(self, message: str) -> None:
        super().__init__("LLM02", message, http_status=403)


class CorpusIntegrityError(FinSecSecurityError):
    def __init__(self, owasp_id: str, message: str) -> None:
        super().__init__(owasp_id, message, http_status=422)


class OutputPolicyViolationError(FinSecSecurityError):
    def __init__(self, owasp_id: str, message: str) -> None:
        super().__init__(owasp_id, message, http_status=422)


class ToolSandboxViolationError(FinSecSecurityError):
    def __init__(self, message: str) -> None:
        super().__init__("LLM06", message, http_status=403)


class ResourceBudgetExceededError(FinSecSecurityError):
    def __init__(self, message: str, http_status: int = 429) -> None:
        super().__init__("LLM10", message, http_status=http_status)


class InferenceBackendUnavailableError(Exception):
    """Raised when the underlying Ollama / LLM inference endpoint is unreachable or times out."""