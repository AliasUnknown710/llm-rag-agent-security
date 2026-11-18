import pytest
from src.exceptions import CorpusIntegrityError
from src.security.corpus_validator import sign_corpus_document
from src.targets.rag_pipeline import CorporateRAGService


def test_llm08_corpus_ingestion_blocks_untrusted_and_tampered_chunks() -> None:
    rag = CorporateRAGService(collection_name="test_llm08_rag")
    clean_doc = "Approved Expense Policy: Meals are reimbursed up to $75/day."
    valid_sig = sign_corpus_document(clean_doc, signer_id="finsec-admin")

    # 1. Untrusted signer rejected
    with pytest.raises(CorpusIntegrityError, match="LLM08") as signer_exc:
        rag.ingest_document_hardened(
            doc_id="VEC-001",
            content=clean_doc,
            access_tier="employee",
            signer_id="rogue-contributor",
            signature=valid_sig,
        )
    assert signer_exc.value.owasp_id == "LLM08"
    assert signer_exc.value.http_status == 422

    # 2. Tampered content with mismatched HMAC rejected
    with pytest.raises(CorpusIntegrityError, match="LLM08") as tamper_exc:
        rag.ingest_document_hardened(
            doc_id="VEC-002",
            content="Tampered Policy: Meals are reimbursed up to $7,500/day.",
            access_tier="employee",
            signer_id="finsec-admin",
            signature=valid_sig,
        )
    assert tamper_exc.value.owasp_id == "LLM08"
    assert tamper_exc.value.http_status == 422

    # 3. Valid signed chunk succeeds
    rag.ingest_document_hardened(
        doc_id="VEC-003",
        content=clean_doc,
        access_tier="employee",
        signer_id="finsec-admin",
        signature=valid_sig,
    )
