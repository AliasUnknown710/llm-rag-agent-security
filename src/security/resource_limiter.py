from collections import deque
import time
from src.config import POLICY_CFG
from src.exceptions import ResourceBudgetExceededError


class ResourceBudgetLimiter:
    """Enforces input length budgets and sliding-window rate limits (LLM10)."""

    def __init__(
        self,
        max_chars: int = POLICY_CFG.max_prompt_chars,
        max_requests_per_minute: int = POLICY_CFG.max_rpm,
    ) -> None:
        self.max_chars = max_chars
        self.max_requests_per_minute = max_requests_per_minute
        self._request_timestamps: dict[str, deque[float]] = {}

    def validate_request(self, actor_id: str, prompt: str) -> None:
        if len(prompt) > self.max_chars:
            raise ResourceBudgetExceededError(
                f"Input length ({len(prompt)} chars) exceeds budget ({self.max_chars}).",
                http_status=413,
            )

        now = time.monotonic()
        window_start = now - 60.0
        history = self._request_timestamps.setdefault(actor_id, deque())

        while history and history[0] < window_start:
            history.popleft()

        if len(history) >= self.max_requests_per_minute:
            raise ResourceBudgetExceededError(
                f"Rate limit exceeded for actor '{actor_id}' ({self.max_requests_per_minute} req/min).",
                http_status=429,
            )

        history.append(now)