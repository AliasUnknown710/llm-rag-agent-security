# LLM, RAG & Agentic Security Evaluation Lab (OWASP Top 10 & CWE Benchmark)

An enterprise-grade, modular Python security evaluation harness and reference architecture demonstrating realistic **OWASP Top 10 for LLM Applications** and **MITRE CWE** vulnerabilities alongside hardened remediation controls, multi-turn agent sandboxing, and automated `pytest` adversarial benchmarks.

Built and maintained by **FinSec Labs Ltd.** using **Python 3.13**, **LangChain**, **Ollama (`llama3.2:3b` & `nomic-embed-text`)**, **ChromaDB**, and **Pydantic**.

---

## Architecture Overview

The repository enforces strict separation of concerns across **configuration & secrets management** (`src/config.py`, `src/secrets_provider.py`), **typed domain exceptions** (`src/exceptions.py`), **reusable security middleware** (`src/security/`), **vulnerable vs. hardened target systems** (`src/targets/`), **automated adversarial regression suites** (`tests/`), and a **CI/CD security gate** (`.github/workflows/security-eval.yml`):

```text
llm-rag-agent-security-lab/
├── .github/
│   └── workflows/
│       └── security-eval.yml      # Automated GitHub Actions CI/CD security evaluation gate
├── pyproject.toml                 # Package metadata, Pytest & Pyright configuration
├── requirements.txt               # Pinned dependencies for reproducible execution
├── run_eval_suite.py              # CLI benchmark runner executing the full adversarial suite
├── src/
│   ├── __init__.py
│   ├── config.py                  # Immutable 12-factor model & policy configuration
│   ├── exceptions.py              # Typed FinSecSecurityError hierarchy with OWASP & HTTP mapping
│   ├── secrets_provider.py        # Pluggable secrets resolver (K8s mounts, env vars, CSPRNG)
│   ├── security/                  # Framework-agnostic defense-in-depth guardrail middleware
│   │   ├── __init__.py
│   │   ├── audit_logger.py        # Thread-safe RotatingFileHandler JSONL SIEM telemetry
│   │   ├── content_sanitizer.py   # LLM01 / CWE-74: Heuristic detection & XML delimiter isolation
│   │   ├── rbac_filter.py         # LLM02 / CWE-284, CWE-863: Pre-retrieval RBAC metadata filter
│   │   ├── corpus_validator.py    # LLM04 & LLM08 / CWE-345: HMAC-SHA256 provenance & poisoning scan
│   │   ├── output_guard.py        # LLM05 & LLM07 / CWE-79, CWE-89, CWE-200: Egress & canary guard
│   │   ├── tool_sandbox.py        # LLM06 / CWE-22, CWE-250, CWE-269: Pydantic allowlist & path jail
│   │   └── resource_limiter.py    # LLM10 / CWE-400, CWE-770: Token budget & sliding-window rate limit
│   └── targets/                   # Vulnerable baseline vs. hardened target services
│       ├── __init__.py
│       ├── mcp_tool_bridge.py     # External MCP/tool context ingestion bridge
│       ├── rag_pipeline.py        # Multi-tenant ChromaDB RAG pipeline
│       ├── output_handler.py      # Downstream output & system-prompt handler
│       ├── file_agent.py          # Bounded multi-turn ReAct tool-calling file agent
│       └── inference_gateway.py   # Budget-enforced model inference gateway
└── tests/                         # Automated red-team regression tests (pytest)
    ├── __init__.py
    ├── conftest.py                # File-handle teardown & cleanup of ephemeral test artifacts
    ├── test_llm01_prompt_injection.py
    ├── test_llm02_sensitive_disclosure.py
    ├── test_llm04_data_poisoning.py
    ├── test_llm05_improper_output.py
    ├── test_llm06_excessive_agency.py
    ├── test_llm07_system_prompt_leakage.py
    ├── test_llm08_vector_weaknesses.py
    └── test_llm10_unbounded_consumption.py
```

---

## OWASP Top 10 for LLM & CWE Coverage Matrix

| OWASP ID | CWE Mapping | Vulnerability Category | Target Component | Vulnerable Baseline (`*_vulnerable`) | Hardened Remediation (`*_hardened`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **LLM01** | `CWE-74` `CWE-94` | Prompt Injection (Indirect & Second-Order) | `MCPContextBridge` `FileAgentService` | Concatenates external MCP/tool payloads directly into prompt context | Compiled regex heuristic alerting + tag-escape neutralization + `<untrusted_external_data>` XML boundary isolation |
| **LLM02** | `CWE-200` `CWE-201` `CWE-284` `CWE-863` | Sensitive Information Disclosure | `CorporateRAGService` | Unfiltered vector similarity search across all document sensitivity tiers | Pre-retrieval RBAC metadata filtering (`$in` role hierarchy) enforced at ChromaDB query layer prior to context assembly |
| **LLM04** | `CWE-345` `CWE-74` | Data & Corpus Poisoning | `CorporateRAGService` | Ingests arbitrary text chunks into vector store without content inspection | Pre-ingestion adversarial directive scanning blocking poisoned behavioral instructions (`CorpusIntegrityError`) |
| **LLM05** | `CWE-79` `CWE-89` | Improper Output Handling | `OutputSecurityHandler` | Passes raw LLM output directly to downstream UI/SQL sinks | Blocking of `<script>`, JS event handlers, and destructive SQL statements + `html.escape()` encoding (`OutputPolicyViolationError`) |
| **LLM06** | `CWE-22` `CWE-250` `CWE-269` | Excessive Agency | `FileAgentService` | Exposes raw `open(filename)` tool without path or turn restrictions | Pydantic `BaseModel` allowlist validation + `Path.resolve()` canonical directory confinement + bounded multi-turn loop (`max_turns=5`) |
| **LLM07** | `CWE-200` `CWE-532` | System Prompt Leakage | `OutputSecurityHandler` | Embeds secrets in system prompt without egress inspection or `repr` masking | Dual-layer system confidentiality policy + high-entropy canary egress detection + `repr=False` config redaction |
| **LLM08** | `CWE-345` `CWE-208` | Vector & Embedding Weaknesses | `CorporateRAGService` | Accepts unsigned chunks from unverified ingestion sources | Trusted signer allowlist + constant-time `hmac.compare_digest()` SHA-256 provenance verification |
| **LLM10** | `CWE-400` `CWE-770` | Unbounded Consumption | `InferenceGateway` `FileAgentService` | Forwards arbitrary-length prompts and unbounded agent tool loops | Per-request character budget (`HTTP 413`) + `time.monotonic()` sliding-window rate limiter (`HTTP 429`) + max-turn circuit breaker |

> **Scope Note (`LLM03` & `LLM09`):** `LLM03` (Model Supply Chain—compromised weights/serialization) and `LLM09` (Misinformation/Hallucinations—factual accuracy benchmarking) govern upstream training/artifact supply chains and statistical truthfulness rather than runtime application authorization boundaries, and are intentionally excluded from runtime middleware tests.

---

## Why Static Scanners (CodeQL / Semgrep) Miss These Flaws

Pattern-based SAST tools excel at detecting syntactic source-to-sink flows (e.g., `eval()` or `os.system()`), but frequently produce false negatives on GenAI logic and authorization flaws:
1. **Missing Pre-Retrieval Authorization (`LLM02` / `CWE-863`):** `vectorstore.similarity_search(query)` is syntactically valid API usage; static rules cannot infer whether a multi-tenant metadata `filter={...}` is missing for a given caller role.
2. **Semantic Trust Boundaries (`LLM01` / `CWE-74`):** String interpolation of tool outputs looks identical to benign prompt formatting unless data provenance is tracked across agent turns (`ToolMessage` -> `AIMessage`).
3. **Dynamic Tool Registries (`LLM06` / `CWE-269`):** Excessive privilege arises from broad schema definitions and missing canonical path checks inside registered LangChain `@tool` callables.

---

## Quickstart & Local Execution

### 1. Prerequisites
* **Python 3.10+**
* **Ollama** installed and running locally (`http://localhost:11434`) with the required models:
  ```bash
  ollama pull llama3.2:3b
  ollama pull nomic-embed-text
  ```

### 2. Installation & Benchmark Execution
```bash
git clone https://github.com
cd llm-rag-agent-security-lab
python -m venv .venv
source .venv/bin/activate  # On Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_eval_suite.py
```