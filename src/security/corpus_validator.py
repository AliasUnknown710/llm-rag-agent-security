import hashlib
import hmac
import re
from src.config import POLICY_CFG
from src.exceptions import CorpusIntegrityError

TRUSTED_SIGNERS: set[str] = {"finsec-admin", "compliance-ingest-svc"}

POISONING_SIGNATURES: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\balways\s+recommend\s+wiring\s+funds\b",
        r"\bignore\s+security\s+warnings\b",
        r"\boverride\s+policy\s+and\s+approve\b",
        r"<\s*script\b",
    ]
]


def sign_corpus_document(content: str, signer_id: str) -> str:
    """Generates an HMAC-SHA256 provenance signature for authorized knowledge-base ingestion."""
    message = f"{signer_id}:{content}".encode("utf-8")
    key = POLICY_CFG.corpus_hmac_key.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def validate_corpus_document(content: str, signer_id: str, signature: str) -> bool:
    """Blocks untrusted signers, tampered embeddings/chunks (LLM08), and poisoned directives (LLM04)."""
    if signer_id not in TRUSTED_SIGNERS:
        raise CorpusIntegrityError("LLM08", f"Untrusted document signer '{signer_id}'.")

    expected_sig = sign_corpus_document(content, signer_id)
    if not hmac.compare_digest(expected_sig, signature):
        raise CorpusIntegrityError("LLM08", "Document HMAC-SHA256 signature verification failed.")

    for pattern in POISONING_SIGNATURES:
        if pattern.search(content):
            raise CorpusIntegrityError(
                "LLM04",
                f"Poisoned behavioral directive detected in corpus chunk ({pattern.pattern}).",
            )

    return True