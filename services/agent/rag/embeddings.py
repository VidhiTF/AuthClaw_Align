import os
import hashlib
import random
import re
import requests
import logging

logger = logging.getLogger("authclaw.rag.embeddings")

_remote_embeddings_disabled = False

def get_deterministic_fallback_embedding(text: str) -> list[float]:
    """
    Generates a deterministic 768-dimensional word-aware embedding vector.
    Uses Random Indexing / LSH projection so word overlaps translate to similarity.
    Requires no external dependencies and runs 100% offline.
    """
    # Normalize text and extract lowercase alphanumeric tokens
    words = re.findall(r'[a-z0-9]+', text.lower())
    
    vector = [0.0] * 768
    
    if not words:
        # Fallback for empty strings
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()
        rng = random.Random(int(h[:16], 16))
        vector = [rng.uniform(-1.0, 1.0) for _ in range(768)]
    else:
        for word in words:
            # Generate a deterministic pseudo-random unit vector for each word
            h = hashlib.sha256(word.encode("utf-8")).hexdigest()
            rng = random.Random(int(h[:16], 16))
            word_vector = [rng.uniform(-1.0, 1.0) for _ in range(768)]
            
            # Accumulate word vector
            for i in range(768):
                vector[i] += word_vector[i]
                
    # Normalize the accumulated vector to unit length (L2 norm)
    magnitude = sum(x * x for x in vector) ** 0.5
    if magnitude > 0:
        vector = [x / magnitude for x in vector]
        
    return vector

def generate_embedding(text: str) -> list[float]:
    """
    Generates a 768-dimensional embedding vector.
    Tries the Gemini Embeddings API first if GOOGLE_API_KEY is configured.
    Falls back to a local, deterministic, word-overlap projection embedding if offline.
    """
    global _remote_embeddings_disabled

    if os.getenv("AUTHCLAW_DISABLE_REMOTE_EMBEDDINGS", "").lower() in {"1", "true", "yes", "on"}:
        return get_deterministic_fallback_embedding(text)

    if _remote_embeddings_disabled:
        return get_deterministic_fallback_embedding(text)

    api_key = os.getenv("GOOGLE_API_KEY")
    api_url = os.getenv("GOOGLE_API_URL", "https://generativelanguage.googleapis.com")
    
    is_key_valid = api_key and api_key not in ("dummy", "dummy-api-key", "")
    
    if is_key_valid:
        try:
            model = os.getenv("GEMINI_EMBEDDING_MODEL", "gemini-embedding-001")
            url = f"{api_url}/v1beta/models/{model}:embedContent?key={api_key}"
            payload = {
                "model": f"models/{model}",
                "content": {
                    "parts": [{"text": text}]
                }
            }
            res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
            if res.status_code == 200:
                data = res.json()
                embedding = data.get("embedding", {}).get("values", [])
                # Gemini embedding vectors might be 768 dimensions (or padded/truncated)
                # Let's pad or truncate to exactly 768 if the API returns a different length
                if embedding:
                    if len(embedding) == 768:
                        return [float(x) for x in embedding]
                    elif len(embedding) < 768:
                        return [float(x) for x in embedding] + [0.0] * (768 - len(embedding))
                    else:
                        return [float(x) for x in embedding[:768]]
            else:
                logger.warning(f"Gemini API returned status {res.status_code}: {res.text}")
                if res.status_code in {400, 401, 403, 404, 429}:
                    _remote_embeddings_disabled = True
                    logger.warning(
                        "Remote embeddings disabled for this process after Gemini status %s. "
                        "Using deterministic local embeddings until restart.",
                        res.status_code,
                    )
        except Exception as e:
            logger.warning(f"Gemini embedding generation failed: {str(e)}")
            _remote_embeddings_disabled = True
            
    # Local deterministic offline fallback
    return get_deterministic_fallback_embedding(text)
