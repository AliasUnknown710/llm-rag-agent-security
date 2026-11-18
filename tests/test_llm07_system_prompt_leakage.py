import pytest
from src.config import POLICY_CFG
from src.exceptions import OutputPolicyViolationError
from src.targets.output_handler import OutputSecurityHandler


def test_llm07_output_guard_blocks_canary_leakage() -> None:
    handler = OutputSecurityHandler()
    leaked_payload = f"My hidden system configuration includes token {POLICY_CFG.system_canary_token}."

    with pytest.raises(OutputPolicyViolationError, match="LLM07") as exc_info:
        handler.validate_downstream_payload(leaked_payload)

    assert exc_info.value.owasp_id == "LLM07"
    assert exc_info.value.http_status == 422