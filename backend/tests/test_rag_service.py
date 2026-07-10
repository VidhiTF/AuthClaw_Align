from app.rag import service as rag_service


def test_retrieves_hipaa_technical_safeguards_for_ephi_question():
    chunks = rag_service.retrieve_from_payload(
        "Which HIPAA technical safeguards apply to ePHI access controls and transmission security?",
        limit=3,
    )

    assert chunks
    assert all(chunk.framework == "HIPAA" for chunk in chunks)
    citation_ids = {chunk.citation_id() for chunk in chunks}
    assert "HIPAA-164-312" in citation_ids


def test_retrieves_gdpr_minimization_and_security_with_citations():
    chunks = rag_service.retrieve_from_payload(
        "How should GDPR handle data minimization and security for personal data?",
        limit=4,
    )
    answer = rag_service.compose_grounded_answer("How should GDPR handle data minimization?", chunks)

    assert chunks
    assert any(chunk.citation_id() == "GDPR-ART-5" for chunk in chunks)
    assert any(chunk.citation_id() == "GDPR-ART-32" for chunk in chunks)
    assert "[GDPR-ART-5]" in answer


def test_retrieves_soc2_change_management_controls():
    chunks = rag_service.retrieve_from_payload(
        "What SOC 2 evidence is needed for change management and controlled deployment?",
        limit=3,
    )

    assert chunks
    assert all(chunk.framework == "SOC2" for chunk in chunks)
    assert chunks[0].citation_id() == "SOC2-CC8"


def test_remediation_guidance_is_guardrailed_to_retrieved_evidence():
    question = "What should we fix for HIPAA audit logging and access review?"
    chunks = rag_service.retrieve_from_payload(question, limit=3)
    answer = rag_service.compose_grounded_answer(question, chunks)

    assert "Guardrailed remediation guidance:" in answer
    assert "do not execute changes unless the finding maps to this cited requirement" in answer
    assert any(f"[{chunk.citation_id()}]" in answer for chunk in chunks)


def test_model_answer_without_citation_gets_grounding_footer():
    chunks = rag_service.retrieve_from_payload("Explain GDPR privacy by design", limit=2)
    answer = rag_service.ensure_cited_answer("You should minimize data collection.", chunks)

    assert "Grounding citations:" in answer
    assert "[GDPR-ART-25]" in answer
