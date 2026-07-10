"""Regulatory RAG corpus endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_scopes
from app.rag import service as rag_service

router = APIRouter()


class RAGSearchResponse(BaseModel):
    query: str
    corpus_version: Optional[str]
    citations: list[dict]
    retrieved_chunks: list[dict]


@router.get("/corpus/status", dependencies=[require_scopes(["read"])])
def get_corpus_status(db: Session = Depends(get_tenant_db)):
    """Return active regulatory corpus version and chunk count."""
    return rag_service.corpus_status(db)


@router.post("/corpus/sync", dependencies=[require_scopes(["admin"])])
def sync_corpus(db: Session = Depends(get_tenant_db)):
    """Idempotently sync checked-in corpus files into the DB index."""
    return rag_service.sync_corpus(db)


@router.get("/search", response_model=RAGSearchResponse, dependencies=[require_scopes(["read"])])
def search_corpus(
    q: str = Query(..., min_length=2),
    limit: int = Query(default=5, ge=1, le=10),
    db: Session = Depends(get_tenant_db),
):
    """Search the active regulatory corpus and return citation-bearing chunks."""
    chunks = rag_service.retrieve(db, q, limit=limit)
    active = rag_service.active_corpus_version(db)
    return RAGSearchResponse(
        query=q,
        corpus_version=active.version if active else None,
        citations=[chunk.to_citation() for chunk in chunks],
        retrieved_chunks=[chunk.to_context() for chunk in chunks],
    )
