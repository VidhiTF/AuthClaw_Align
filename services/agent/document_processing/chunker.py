import logging
from typing import List

logger = logging.getLogger("authclaw.document_processing.chunker")

def split_text_into_chunks(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    """
    Partitions raw document text into character segments with overlap.
    """
    text = text.strip()
    if not text:
        return []
        
    chunks = []
    text_len = len(text)
    start = 0
    
    while start < text_len:
        end = min(start + chunk_size, text_len)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
            
        if end >= text_len:
            break
            
        start += (chunk_size - overlap)
        # Prevent infinite loops
        if chunk_size - overlap <= 0:
            start += chunk_size
            
    return chunks
