import subprocess
import sys
from datetime import datetime, timezone


def main() -> int:
    print("=" * 72)
    print("FINSEC LABS | OWASP TOP 10 FOR LLM APPLICATIONS SECURITY EVALUATION SUITE")
    print(f"Timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)
    print("Evaluating Targets:")
    print("  [LLM01] Indirect Prompt Injection      -> MCPContextBridge")
    print("  [LLM02] Sensitive Info Disclosure      -> CorporateRAGService (RBAC)")
    print("  [LLM04] Data & Corpus Poisoning        -> CorporateRAGService (Content Scan)")
    print("  [LLM05] Improper Output Handling       -> OutputSecurityHandler")
    print("  [LLM06] Excessive Agency               -> FileAgentService (Pydantic Sandbox)")
    print("  [LLM07] System Prompt Leakage          -> OutputSecurityHandler (Canary Guard)")
    print("  [LLM08] Vector & Embedding Weaknesses  -> CorporateRAGService (HMAC Provenance)")
    print("  [LLM10] Unbounded Consumption          -> InferenceGateway (Budget & Rate Limit)")
    print("-" * 72)

    result = subprocess.run([sys.executable, "-m", "pytest", "-v"], check=False)

    print("-" * 72)
    if result.returncode == 0:
        print("EVALUATION RESULT: PASS (All 8 OWASP LLM runtime controls verified)")
    else:
        print("EVALUATION RESULT: FAIL (Review failed test assertions above)")
    print("=" * 72)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())