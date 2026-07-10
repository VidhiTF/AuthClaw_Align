import json
from sqlalchemy import text
from database import engine
from rag.embeddings import generate_embedding

def save_document_chunks(doc_id: int, chunks: list[str], tenant_id: int = None):
    """
    Generates embeddings for all chunks of a document and saves them to knowledge_chunks table.
    """
    with engine.connect() as conn:
        for i, chunk in enumerate(chunks):
            # Generate embedding vector
            vector = generate_embedding(chunk)
            vector_json = json.dumps(vector)
            
            # Format preview
            preview = f"[{', '.join(f'{x:.2f}' for x in vector[:3])}, ...]"
            
            # Insert chunk record
            conn.execute(
                text("""
                INSERT INTO knowledge_chunks (tenant_id, document_id, content, embedding_preview, embedding_vector)
                VALUES (:tenant_id, :doc_id, :content, :preview, :vector)
                """),
                {
                    "tenant_id": tenant_id,
                    "doc_id": doc_id,
                    "content": chunk,
                    "preview": preview,
                    "vector": vector_json
                }
            )
        conn.commit()

def cosine_similarity(v1: list[float], v2: list[float]) -> float:
    """
    Computes cosine similarity between two float vectors.
    """
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot_product = sum(a * b for a, b in zip(v1, v2))
    norm_a = sum(a * a for a in v1) ** 0.5
    norm_b = sum(b * b for b in v2) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot_product / (norm_a * norm_b)

def search_similarity(query_vector: list[float], top_k: int = 5, document_id: int = None, tenant_id: int = None) -> list[dict]:
    """
    Retrieves matching document chunks based on Python-based cosine similarity calculation.
    If document_id is provided, limits search results to that specific document.
    """
    with engine.connect() as conn:
        if document_id is not None:
            res = conn.execute(
                text("""
                SELECT kc.id, kc.document_id, kc.content, kc.embedding_vector, kd.name as doc_name
                FROM knowledge_chunks kc
                JOIN knowledge_documents kd ON kc.document_id = kd.id
                WHERE kc.document_id = :doc_id
                  AND (:tenant_id IS NULL OR (kc.tenant_id = :tenant_id AND kd.tenant_id = :tenant_id))
                """),
                {"doc_id": document_id, "tenant_id": tenant_id}
            )
        else:
            res = conn.execute(
                text("""
                SELECT kc.id, kc.document_id, kc.content, kc.embedding_vector, kd.name as doc_name
                FROM knowledge_chunks kc
                JOIN knowledge_documents kd ON kc.document_id = kd.id
                WHERE (:tenant_id IS NULL OR (kc.tenant_id = :tenant_id AND kd.tenant_id = :tenant_id))
                """)
                ,
                {"tenant_id": tenant_id}
            )
        rows = res.fetchall()

    hits = []
    for row in rows:
        chunk_id = row[0]
        doc_id = row[1]
        content = row[2]
        emb_vector_str = row[3]
        doc_name = row[4]
        
        if not emb_vector_str:
            continue
            
        try:
            emb_vector = json.loads(emb_vector_str)
            score = cosine_similarity(query_vector, emb_vector)
            hits.append({
                "chunk_id": chunk_id,
                "document_id": doc_id,
                "doc_name": doc_name,
                "content": content,
                "score": score
            })
        except Exception:
            # Skip corrupted entries
            continue
            
    # Sort by score descending
    hits.sort(key=lambda x: x["score"], reverse=True)
    return hits[:top_k]
