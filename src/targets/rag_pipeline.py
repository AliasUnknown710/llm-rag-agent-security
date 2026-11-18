import httpx
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_ollama import ChatOllama, OllamaEmbeddings
from src.config import MODEL_CFG
from src.exceptions import (
    AccessControlViolationError,
    CorpusIntegrityError,
    InferenceBackendUnavailableError,
)
from src.security.audit_logger import log_security_event
from src.security.corpus_validator import validate_corpus_document
from src.security.rbac_filter import build_chroma_rbac_filter


class CorporateRAGService:
    """Multi-tenant RAG pipeline demonstrating RBAC retrieval enforcement and corpus ingestion signing."""

    def __init__(self, collection_name: str = "finsec_eval_rag") -> None:
        self.embeddings = OllamaEmbeddings(model=MODEL_CFG.embed_model, base_url=MODEL_CFG.base_url)
        self.llm = ChatOllama(
            model=MODEL_CFG.chat_model,
            base_url=MODEL_CFG.base_url,
            temperature=MODEL_CFG.temperature,
            client_kwargs={"timeout": MODEL_CFG.request_timeout_sec},
        )
        self.store = Chroma(collection_name=collection_name, embedding_function=self.embeddings)
        self._seed_verified_corpus()

    def _seed_verified_corpus(self) -> None:
        seed_records = [
            ("HR-101", "Standard employee PTO policy grants 15 days annually.", "employee"),
            ("EXEC-001", "CONFIDENTIAL EXECUTIVE MEMO: Q4 layoffs affect 12% of staff; CFO severance is $450,000.", "executive"),
        ]
        docs = [
            Document(page_content=text, metadata={"doc_id": doc_id, "access_tier": access_tier})
            for doc_id, text, access_tier in seed_records
        ]
        ids = [doc_id for doc_id, _, _ in seed_records]
        self.store.add_documents(documents=docs, ids=ids)

    def _invoke_resilient(self, prompt: str) -> str:
        try:
            return self.llm.invoke(prompt).text()
        except (httpx.ConnectError, httpx.TimeoutException, ConnectionError) as exc:
            raise InferenceBackendUnavailableError(
                f"Inference backend unavailable at {MODEL_CFG.base_url}: {exc}"
            ) from exc

    def ingest_document_vulnerable(self, doc_id: str, content: str, access_tier: str) -> None:
        """VULNERABLE: Ingests arbitrary chunks without provenance signatures or poisoning inspection."""
        doc = Document(page_content=content, metadata={"doc_id": doc_id, "access_tier": access_tier})
        self.store.add_documents(documents=[doc], ids=[doc_id])

    def ingest_document_hardened(
        self,
        doc_id: str,
        content: str,
        access_tier: str,
        signer_id: str,
        signature: str,
    ) -> None:
        """HARDENED: Enforces HMAC provenance verification (LLM08) and directive scanning (LLM04)."""
        try:
            validate_corpus_document(content=content, signer_id=signer_id, signature=signature)
        except CorpusIntegrityError as exc:
            log_security_event(
                owasp_id=exc.owasp_id,
                event_type="CORPUS_INGESTION_REJECTED",
                component="CorporateRAGService",
                actor_role=signer_id,
                status="BLOCKED",
                details=str(exc),
            )
            raise

        doc = Document(page_content=content, metadata={"doc_id": doc_id, "access_tier": access_tier})
        self.store.add_documents(documents=[doc], ids=[doc_id])
        log_security_event(
            owasp_id="LLM08",
            event_type="CORPUS_INGESTION_VERIFIED",
            component="CorporateRAGService",
            actor_role=signer_id,
            status="ALLOWED",
            details=f"Verified document '{doc_id}' ingested into tier '{access_tier}'.",
        )

    def query_vulnerable(self, question: str, user_role: str) -> str:
        """VULNERABLE: Performs unfiltered similarity search across all access tiers."""
        docs = self.store.similarity_search(question, k=2)
        context = "\n".join(d.page_content for d in docs)
        return self._invoke_resilient(f"Context:\n{context}\n\nQuestion: {question}")

    def query_hardened(self, question: str, user_role: str) -> str:
        """HARDENED: Applies pre-retrieval RBAC metadata filter before generating response."""
        try:
            rbac_filter = build_chroma_rbac_filter(user_role)
        except AccessControlViolationError as exc:
            log_security_event(
                owasp_id=exc.owasp_id,
                event_type="RBAC_FILTER_DENIED",
                component="CorporateRAGService",
                actor_role=user_role,
                status="BLOCKED",
                details=str(exc),
            )
            raise

        docs = self.store.similarity_search(question, k=2, filter=rbac_filter)  # type: ignore[arg-type]
        log_security_event(
            owasp_id="LLM02",
            event_type="RBAC_RAG_QUERY",
            component="CorporateRAGService",
            actor_role=user_role,
            status="ALLOWED",
            details=f"Retrieved {len(docs)} RBAC-authorized documents.",
        )
        context = "\n".join(d.page_content for d in docs)
        prompt = (
            "You are a restricted corporate assistant. Answer strictly using the verified context below. "
            "If the context does not contain the answer, refuse and state insufficient privileges.\n\n"
            f"Verified Context:\n{context}\n\nQuestion: {question}"
        )
        return self._invoke_resilient(prompt)