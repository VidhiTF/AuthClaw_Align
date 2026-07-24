from retriever import retrieve_context


def test_internal_rag_retrieves_gdpr_retention_context():
    context = retrieve_context(
        "Explain GDPR retention requirements and show the supporting evidence."
    )

    assert "Storage limitation and retention" in context
    assert "Article 5(1)(e)" in context
    assert "EUR-Lex" in context


def test_internal_rag_retrieves_hipaa_audit_context():
    context = retrieve_context("HIPAA audit logs")

    assert "HIPAA Security Rule" in context
    assert "audit logs" in context


def test_internal_rag_returns_empty_context_for_unrelated_query():
    assert retrieve_context("quantum entanglement neutrino") == ""
