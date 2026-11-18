import re

INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # 1. Instruction & Role Override Attempts
        r"\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|directions|rules|prompts?|constraints?|restrictions?)\b",
        r"\b(system|admin|developer|root)\s+(override|mode|prompt)\b",
        r"\byou\s+are\s+now\s+(in\s+)?(developer|jailbreak|unrestricted|dan)\s+mode\b",
        # 2. Prompt & Credential Exfiltration
        r"\b(reveal|print|output|repeat|leak|dump|expose)\s+(the\s+|your\s+)?(system\s+prompt|hidden\s+instructions|api[_\s-]?keys?|secrets?|tokens?|credentials?|passwords?)\b",
        r"\b(exfiltrate|forward|send|post|upload)\s+(all\s+)?(user\s+data|emails?|files?|logs?|database|queries|traffic|secrets?)\s+(to\s+)?(external|http|https|webhook|attacker)\b",
        # 3. Unauthorized Execution & Privilege Escalation
        r"\b(execute|run|eval)\s+(arbitrary\s+)?(shell|bash|powershell|cmd|system|sql)\s+(code|commands?|queries)\b",
        r"\b(escalate\s+privileges|disable\s+security|tamper\s+with\s+(system\s+)?logs?)\b",
    ]
]

def sanitize_untrusted_tool_output(raw_payload: str) -> tuple[str, bool]:
    """Flags adversarial instructions in external tool/MCP outputs and isolates payload in XML tags."""
    flagged = any(pattern.search(raw_payload) for pattern in INJECTION_PATTERNS)
    escaped = raw_payload.replace("</untrusted_external_data>", "[STRIPPED_CLOSE_TAG]")
    wrapped = (
        "<untrusted_external_data>\n"
        f"{escaped}\n"
        "</untrusted_external_data>"
    )
    return wrapped, flagged