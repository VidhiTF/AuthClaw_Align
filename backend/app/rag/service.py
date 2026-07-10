"""Deterministic regulatory RAG service for citation-grounded agent answers."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import RAGCorpusChunk, RAGCorpusVersion


CORPUS_FILE = Path(__file__).parent / "corpus" / "regulatory_corpus.json"
SUPPORTED_FRAMEWORKS = {"GDPR", "HIPAA", "SOC2"}

STOPWORDS = {
    "a", "about", "an", "and", "are", "as", "at", "be", "by", "can", "do", "does",
    "for", "from", "how", "i", "in", "is", "it", "of", "on", "or", "our", "should",
    "the", "their", "this", "to", "us", "we", "what", "when", "where", "which", "with",
}


@dataclass(frozen=True)
class RetrievedChunk:
    id: str
    framework: str
    section_id: str
    title: str
    citation_label: str
    source_name: str
    source_url: str
    text: str
    score: float

    def citation_id(self) -> str:
        section_id = self.section_id.upper().replace("_", "-")
        framework = self.framework.upper()
        if section_id.startswith(f"{framework}-"):
            return section_id
        return f"{framework}-{section_id}"

    def to_citation(self) -> dict[str, Any]:
        return {
            "id": self.citation_id(),
            "framework": self.framework,
            "section_id": self.section_id,
            "label": self.citation_label,
            "title": self.title,
            "source_name": self.source_name,
            "url": self.source_url,
            "score": round(self.score, 4),
        }

    def to_context(self) -> dict[str, Any]:
        payload = self.to_citation()
        payload["text"] = self.text
        return payload


def _load_corpus_file() -> dict[str, Any]:
    with CORPUS_FILE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _checksum(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _chunk_hash(*parts: str) -> str:
    joined = "\n".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _tokenize(text: str) -> set[str]:
    tokens = {token.lower() for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_\-]{1,}", text or "")}
    normalized = set()
    for token in tokens:
        token = token.replace("-", "")
        if token and token not in STOPWORDS:
            normalized.add(token)
    if "soc" in normalized or "soc2" in normalized:
        normalized.add("soc2")
    return normalized


def detect_frameworks(question: str) -> list[str]:
    text = question.lower()
    frameworks = []
    if "gdpr" in text or "data protection" in text:
        frameworks.append("GDPR")
    if "hipaa" in text or "phi" in text or "ephi" in text:
        frameworks.append("HIPAA")
    if "soc 2" in text or "soc2" in text or "trust services" in text:
        frameworks.append("SOC2")
    return frameworks


def sync_corpus(db: Session) -> dict[str, Any]:
    """Idempotently load the checked-in regulatory corpus into PostgreSQL."""
    payload = _load_corpus_file()
    corpus_key = payload["corpus_key"]
    version = payload["corpus_version"]
    checksum = _checksum(payload)

    existing = db.query(RAGCorpusVersion).filter(
        RAGCorpusVersion.corpus_key == corpus_key,
        RAGCorpusVersion.version == version,
    ).first()
    if existing and existing.checksum == checksum:
        if not existing.is_active:
            db.query(RAGCorpusVersion).filter(RAGCorpusVersion.corpus_key == corpus_key).update({"is_active": False})
            existing.is_active = True
            db.commit()
        return {
            "corpus_key": corpus_key,
            "version": version,
            "checksum": checksum,
            "chunk_count": db.query(RAGCorpusChunk).filter(RAGCorpusChunk.corpus_version_id == existing.id).count(),
            "status": "already_current",
        }

    corpus_version = RAGCorpusVersion(
        id=uuid.uuid4(),
        corpus_key=corpus_key,
        version=version,
        checksum=checksum,
        description=payload.get("description"),
        is_active=True,
    )

    db.query(RAGCorpusVersion).filter(RAGCorpusVersion.corpus_key == corpus_key).update({"is_active": False})
    db.add(corpus_version)

    chunk_count = 0
    for document in payload.get("documents", []):
        framework = str(document["framework"]).upper()
        source_name = document["source_name"]
        source_url = document["source_url"]
        for section in document.get("sections", []):
            text = section["text"].strip()
            keywords = [str(item).lower() for item in section.get("keywords", [])]
            db.add(RAGCorpusChunk(
                id=uuid.uuid4(),
                corpus_version_id=corpus_version.id,
                framework=framework,
                section_id=section["section_id"],
                title=section["title"],
                citation_label=section["citation_label"],
                source_name=source_name,
                source_url=source_url,
                chunk_text=text,
                keywords=keywords,
                chunk_hash=_chunk_hash(version, framework, section["section_id"], text),
            ))
            chunk_count += 1

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        current = db.query(RAGCorpusVersion).filter(
            RAGCorpusVersion.corpus_key == corpus_key,
            RAGCorpusVersion.version == version,
        ).first()
        return {
            "corpus_key": corpus_key,
            "version": version,
            "checksum": checksum,
            "chunk_count": db.query(RAGCorpusChunk).filter(RAGCorpusChunk.corpus_version_id == current.id).count() if current else 0,
            "status": "concurrent_sync_observed",
        }

    return {
        "corpus_key": corpus_key,
        "version": version,
        "checksum": checksum,
        "chunk_count": chunk_count,
        "status": "synced",
    }


def active_corpus_version(db: Session) -> RAGCorpusVersion | None:
    payload = _load_corpus_file()
    return db.query(RAGCorpusVersion).filter(
        RAGCorpusVersion.corpus_key == payload["corpus_key"],
        RAGCorpusVersion.is_active.is_(True),
    ).order_by(RAGCorpusVersion.loaded_at.desc()).first()


def corpus_status(db: Session) -> dict[str, Any]:
    sync = sync_corpus(db)
    active = active_corpus_version(db)
    return {
        "corpus_key": sync["corpus_key"],
        "version": active.version if active else sync["version"],
        "checksum": active.checksum if active else sync["checksum"],
        "chunk_count": db.query(RAGCorpusChunk).filter(RAGCorpusChunk.corpus_version_id == active.id).count() if active else sync["chunk_count"],
        "loaded_at": active.loaded_at.isoformat() if active and active.loaded_at else None,
        "status": sync["status"],
    }


def _score_values(
    query_tokens: set[str],
    requested_frameworks: set[str],
    framework: str,
    section_id: str,
    title: str,
    text: str,
    keywords: Iterable[str],
) -> float:
    keyword_tokens = _tokenize(" ".join(keywords or []))
    title_tokens = _tokenize(title)
    body_tokens = _tokenize(text)
    section_tokens = _tokenize(section_id)

    score = 0.0
    score += 4.0 * len(query_tokens & keyword_tokens)
    score += 2.5 * len(query_tokens & title_tokens)
    score += 1.0 * len(query_tokens & body_tokens)
    score += 1.5 * len(query_tokens & section_tokens)
    if requested_frameworks and framework in requested_frameworks:
        score += 6.0
    if not requested_frameworks:
        score += 0.25
    return score / math.sqrt(max(len(body_tokens), 1))


def _score_chunk(query_tokens: set[str], requested_frameworks: set[str], chunk: RAGCorpusChunk) -> float:
    return _score_values(
        query_tokens,
        requested_frameworks,
        chunk.framework,
        chunk.section_id,
        chunk.title,
        chunk.chunk_text,
        chunk.keywords or [],
    )


def retrieve_from_payload(
    question: str,
    limit: int = 5,
    frameworks: Iterable[str] | None = None,
    payload: dict[str, Any] | None = None,
) -> list[RetrievedChunk]:
    """Rank the checked-in corpus without DB access for deterministic retrieval evaluation."""
    payload = payload or _load_corpus_file()
    requested = {item.upper().replace("SOC 2", "SOC2") for item in (frameworks or detect_frameworks(question))}
    requested &= SUPPORTED_FRAMEWORKS
    query_tokens = _tokenize(question)

    ranked: list[tuple[float, RetrievedChunk]] = []
    for document in payload.get("documents", []):
        framework = str(document["framework"]).upper()
        if requested and framework not in requested:
            continue
        for section in document.get("sections", []):
            text = section["text"].strip()
            score = _score_values(
                query_tokens,
                requested,
                framework,
                section["section_id"],
                section["title"],
                text,
                section.get("keywords", []),
            )
            if score <= 0:
                continue
            ranked.append((
                score,
                RetrievedChunk(
                    id=_chunk_hash(payload["corpus_version"], framework, section["section_id"], text),
                    framework=framework,
                    section_id=section["section_id"],
                    title=section["title"],
                    citation_label=section["citation_label"],
                    source_name=document["source_name"],
                    source_url=document["source_url"],
                    text=text,
                    score=score,
                ),
            ))

    ranked.sort(key=lambda item: item[0], reverse=True)
    return [chunk for _, chunk in ranked[:limit]]


def retrieve(db: Session, question: str, limit: int = 5, frameworks: Iterable[str] | None = None) -> list[RetrievedChunk]:
    sync_corpus(db)
    active = active_corpus_version(db)
    if not active:
        return []

    requested = {item.upper().replace("SOC 2", "SOC2") for item in (frameworks or detect_frameworks(question))}
    requested &= SUPPORTED_FRAMEWORKS
    query = db.query(RAGCorpusChunk).filter(RAGCorpusChunk.corpus_version_id == active.id)
    if requested:
        query = query.filter(RAGCorpusChunk.framework.in_(sorted(requested)))

    query_tokens = _tokenize(question)
    ranked = []
    for chunk in query.all():
        score = _score_chunk(query_tokens, requested, chunk)
        if score > 0:
            ranked.append((score, chunk))

    ranked.sort(key=lambda item: item[0], reverse=True)
    return [
        RetrievedChunk(
            id=str(chunk.id),
            framework=chunk.framework,
            section_id=chunk.section_id,
            title=chunk.title,
            citation_label=chunk.citation_label,
            source_name=chunk.source_name,
            source_url=chunk.source_url,
            text=chunk.chunk_text,
            score=score,
        )
        for score, chunk in ranked[:limit]
    ]


def build_grounded_prompt(question: str, chunks: list[RetrievedChunk]) -> str:
    context = "\n\n".join(
        f"[{chunk.citation_id()}] {chunk.citation_label} - {chunk.title}\n{chunk.text}\nSource: {chunk.source_url}"
        for chunk in chunks
    )
    return (
        "You are AuthClaw's compliance agent. Answer using only the cited regulatory context below. "
        "Every factual claim or remediation recommendation must include a bracket citation ID from the context. "
        "If the context is insufficient, say what evidence is missing.\n\n"
        f"Question:\n{question}\n\n"
        f"Regulatory context:\n{context}\n\n"
        "Answer:"
    )


def compose_grounded_answer(question: str, chunks: list[RetrievedChunk]) -> str:
    if not chunks:
        return (
            "I could not find enough regulatory corpus evidence to answer safely. "
            "Ask about GDPR, HIPAA, or SOC 2 controls, or sync the regulatory corpus."
        )

    frameworks = ", ".join(sorted({chunk.framework for chunk in chunks}))
    lines = [f"Grounded answer for {frameworks}:"]
    for chunk in chunks[:3]:
        lines.append(f"- {chunk.text} [{chunk.citation_id()}]")

    lower = question.lower()
    if any(term in lower for term in ["remediate", "remediation", "fix", "implement", "should we"]):
        lines.append("")
        lines.append("Guardrailed remediation guidance:")
        for chunk in chunks[:3]:
            lines.append(
                f"- Tie any remediation to evidence for {chunk.citation_label}; do not execute changes unless the finding maps to this cited requirement. [{chunk.citation_id()}]"
            )

    return "\n".join(lines)


def ensure_cited_answer(answer: str, chunks: list[RetrievedChunk]) -> str:
    if not chunks:
        return answer
    citation_ids = [chunk.citation_id() for chunk in chunks]
    if any(f"[{citation_id}]" in answer for citation_id in citation_ids):
        return answer
    citations = ", ".join(f"[{citation_id}]" for citation_id in citation_ids[:3])
    return f"{answer.rstrip()}\n\nGrounding citations: {citations}"


def answer_question(db: Session, question: str, model_answer: str | None = None, limit: int = 5) -> dict[str, Any]:
    chunks = retrieve(db, question, limit=limit)
    active = active_corpus_version(db)
    answer = ensure_cited_answer(model_answer, chunks) if model_answer else compose_grounded_answer(question, chunks)
    return {
        "answer": answer,
        "citations": [chunk.to_citation() for chunk in chunks],
        "retrieved_chunks": [chunk.to_context() for chunk in chunks],
        "corpus_version": active.version if active else None,
        "corpus_checksum": active.checksum if active else None,
        "grounded": bool(chunks),
        "prompt": build_grounded_prompt(question, chunks) if chunks else question,
    }
