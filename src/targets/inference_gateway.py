import httpx
from langchain_ollama import ChatOllama
from src.config import MODEL_CFG, POLICY_CFG
from src.exceptions import InferenceBackendUnavailableError, ResourceBudgetExceededError
from src.security.audit_logger import log_security_event
from src.security.resource_limiter import ResourceBudgetLimiter


class InferenceGateway:
    """LLM gateway enforcing character/token budgets and sliding-window rate limits (LLM10)."""

    def __init__(
        self,
        max_chars: int = POLICY_CFG.max_prompt_chars,
        max_rpm: int = POLICY_CFG.max_rpm,
    ) -> None:
        self.llm = ChatOllama(
            model=MODEL_CFG.chat_model,
            base_url=MODEL_CFG.base_url,
            temperature=MODEL_CFG.temperature,
            client_kwargs={"timeout": MODEL_CFG.request_timeout_sec},
        )
        self.limiter = ResourceBudgetLimiter(max_chars=max_chars, max_requests_per_minute=max_rpm)

    def invoke_vulnerable(self, prompt: str) -> str:
        """VULNERABLE: Forwards unbounded input payloads directly to the model without budget checks."""
        return self.llm.invoke(prompt).text()

    def invoke_hardened(self, actor_id: str, prompt: str) -> str:
        """HARDENED: Validates input size budget and per-actor rate limits before model invocation."""
        try:
            self.limiter.validate_request(actor_id=actor_id, prompt=prompt)
        except ResourceBudgetExceededError as exc:
            log_security_event(
                owasp_id=exc.owasp_id,
                event_type="RESOURCE_BUDGET_BLOCKED",
                component="InferenceGateway",
                actor_role=actor_id,
                status="BLOCKED",
                details=str(exc),
            )
            raise

        log_security_event(
            owasp_id="LLM10",
            event_type="RESOURCE_BUDGET_ALLOWED",
            component="InferenceGateway",
            actor_role=actor_id,
            status="ALLOWED",
            details=f"Request within budget ({len(prompt)} chars).",
        )
        try:
            return self.llm.invoke(prompt).text()
        except (httpx.ConnectError, httpx.TimeoutException, ConnectionError) as exc:
            raise InferenceBackendUnavailableError(
                f"Inference backend unavailable at {MODEL_CFG.base_url}: {exc}"
            ) from exc