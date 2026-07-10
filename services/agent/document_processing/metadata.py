import io
import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger("authclaw.document_processing.metadata")

def extract_file_metadata(file_bytes: bytes, filename: str, source_location: str = "local") -> Dict[str, Any]:
    """
    Extracts core metadata (Author, Page Count, Timestamps, Size) from file headers and properties.
    """
    ext = os.path.splitext(filename)[1].lower()
    size_bytes = len(file_bytes)
    
    # Initialize defaults
    metadata = {
        "filename": filename,
        "author": "system",
        "created_date": datetime.now(timezone.utc).isoformat(),
        "modified_date": datetime.now(timezone.utc).isoformat(),
        "page_count": 1,
        "size_bytes": size_bytes,
        "source_location": source_location
    }
    
    # PDF specific metadata extraction
    if ext == ".pdf":
        try:
            import pypdf
            pdf_file = io.BytesIO(file_bytes)
            reader = pypdf.PdfReader(pdf_file)
            metadata["page_count"] = len(reader.pages)
            
            # Read metadata
            pdf_meta = reader.metadata
            if pdf_meta:
                if pdf_meta.author:
                    metadata["author"] = pdf_meta.author
                if pdf_meta.get("/CreationDate"):
                    # Format standard PDF date string D:YYYYMMDDHHMMSS
                    raw_date = pdf_meta.get("/CreationDate")
                    metadata["created_date"] = parse_pdf_date(raw_date)
                if pdf_meta.get("/ModDate"):
                    raw_date = pdf_meta.get("/ModDate")
                    metadata["modified_date"] = parse_pdf_date(raw_date)
        except Exception as e:
            logger.warning(f"Failed to parse PDF metadata: {e}")
            
    # DOCX specific metadata extraction
    elif ext == ".docx":
        try:
            import docx
            doc_file = io.BytesIO(file_bytes)
            doc = docx.Document(doc_file)
            props = doc.core_properties
            if props:
                if props.author:
                    metadata["author"] = props.author
                if props.created:
                    metadata["created_date"] = props.created.isoformat()
                if props.modified:
                    metadata["modified_date"] = props.modified.isoformat()
                # Document paragraph count approximation for pages (350 words per page)
                word_count = sum(len(p.text.split()) for p in doc.paragraphs)
                metadata["page_count"] = max(1, word_count // 350)
        except Exception as e:
            logger.warning(f"Failed to parse DOCX metadata: {e}")
            
    # XLSX sheet count
    elif ext in (".xlsx", ".xls"):
        try:
            file_like = io.BytesIO(file_bytes)
            import zipfile
            with zipfile.ZipFile(file_like) as z:
                sheet_files = [name for name in z.namelist() if name.startswith("xl/worksheets/sheet")]
                metadata["page_count"] = len(sheet_files) if sheet_files else 1
        except Exception:
            pass
            
    return metadata

def parse_pdf_date(date_str: str) -> str:
    """Formats PDF date strings like D:20260612153000Z to ISO 8601."""
    try:
        clean = date_str.replace("D:", "").replace("Z", "")
        # Extract YYYYMMDDHHMMSS
        if len(clean) >= 14:
            dt = datetime.strptime(clean[:14], "%Y%m%d%H%M%S")
            return dt.isoformat()
    except Exception:
        pass
    return date_str
