import pytest
from src.exceptions import ResourceBudgetExceededError
from src.targets.inference_gateway import InferenceGateway


def test_llm10_gateway_blocks_oversized_payload_and_rate_flood() -> None:
    gateway = InferenceGateway(max_chars=500, max_rpm=2)

    # 1. Context-window flooding blocked
    oversized_prompt = "A" * 1200
    with pytest.raises(ResourceBudgetExceededError, match="LLM10") as size_exc:
        gateway.invoke_hardened(actor_id="test-user", prompt=oversized_prompt)
    assert size_exc.value.owasp_id == "LLM10"
    assert size_exc.value.http_status == 413

    # 2. Sliding-window rate limit enforced
    gateway.invoke_hardened(actor_id="rate-user", prompt="Hello")
    gateway.invoke_hardened(actor_id="rate-user", prompt="Status check")
    with pytest.raises(ResourceBudgetExceededError, match="LLM10") as rate_exc:
        gateway.invoke_hardened(actor_id="rate-user", prompt="Third rapid request")
    assert rate_exc.value.owasp_id == "LLM10"
    assert rate_exc.value.http_status == 429