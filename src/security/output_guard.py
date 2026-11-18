import html
import re
from src.config import POLICY_CFG
from src.exceptions import OutputPolicyViolationError

DOWNSTREAM_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"<\s*script\b[^>]*>",
        r"javascript\s*:",
        r"\bon(error|load|click|mouseover)\s*=",
        r"\b(DROP|TRUNCATE|ALTER)\s+TABLE\b",
        r"\b(INSERT\s+INTO|DELETE\s+FROM)\b",
        r";\s*--",
    ]
]


def sanitize_llm_output(
    raw_output: str,
    canary_secret: str = POLICY_CFG.system_canary_token,
) -> str:
    """Blocks system prompt canary leakage (LLM07) and dangerous downstream payloads (LLM05)."""
    if canary_secret and canary_secret in raw_output:
        raise OutputPolicyViolationError("LLM07", "System prompt canary token leaked in model output.")

    for pattern in DOWNSTREAM_INJECTION_PATTERNS:
        if pattern.search(raw_output):
            raise OutputPolicyViolationError(
                "LLM05",
                f"Unsafe downstream executable/injection payload blocked ({pattern.pattern}).",
            )

    return html.escape(raw_output)