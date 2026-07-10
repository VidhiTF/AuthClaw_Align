from rag.embeddings import generate_embedding
from rag.vector_store import search_similarity

def retrieve_context(query: str, top_k: int = 3, document_id: int = None, tenant_id: int = None) -> list[dict]:
    """
    Generates embedding for a query and searches the vector store for top-k similar chunks.
    """
    query_vector = generate_embedding(query)
    hits = search_similarity(query_vector, top_k=top_k, document_id=document_id, tenant_id=tenant_id)
    return hits

def retrieve_formatted_context(query: str, top_k: int = 3, document_id: int = None, tenant_id: int = None) -> tuple[str, list[dict]]:
    """
    Returns a unified context string for injection into LLM prompts, along with raw citations list.
    """
    hits = retrieve_context(query, top_k=top_k, document_id=document_id, tenant_id=tenant_id)
    
    if not hits:
        return "No relevant context found in documents.", []
        
    context_parts = []
    citations = []
    
    for i, hit in enumerate(hits):
        context_parts.append(
            f"--- Context Segment #{i+1} from {hit['doc_name']} (Similarity Score: {hit['score']:.4f}) ---\n"
            f"{hit['content']}\n"
        )
        citations.append({
            "source": hit["doc_name"],
            "score": hit["score"],
            "text": hit["content"]
        })
        
    return "\n".join(context_parts), citations
