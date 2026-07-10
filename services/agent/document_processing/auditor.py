import json
import hashlib
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine

GENESIS_HASH = "0" * 64

def calculate_audit_hash(record: dict, previous_hash: str) -> str:
    """
    Computes a deterministic SHA-256 hash for a document audit record.
    """
    timestamp_str = record["timestamp"]
    if hasattr(timestamp_str, "isoformat"):
        # Ensure timezone info is converted to local system naive representation
        if timestamp_str.tzinfo is not None:
            timestamp_str = timestamp_str.astimezone().replace(tzinfo=None)
        timestamp_str = timestamp_str.isoformat()
    else:
        timestamp_str = str(timestamp_str)
        
    hash_data = {
        "document_id": int(record["document_id"]),
        "action": record["action"],
        "actor": record["actor"],
        "details": record["details"],
        "timestamp": timestamp_str,
        "previous_hash": previous_hash
    }
    if record.get("tenant_id") is not None:
        hash_data["tenant_id"] = int(record["tenant_id"])
    
    serialized = json.dumps(hash_data, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def create_document_audit(document_id: int, action: str, actor: str, details: str, tenant_id: int = None) -> str:
    """
    Inserts a new cryptographically chained audit block for a specific document.
    """
    now = datetime.now()
    
    with engine.connect() as conn:
        # 1. Fetch the previous block's integrity hash for this document
        prev_row = conn.execute(
            text("""
            SELECT integrity_hash 
            FROM document_audits 
            WHERE document_id = :doc_id
              AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
            ORDER BY id DESC LIMIT 1
            """),
            {"doc_id": document_id, "tenant_id": tenant_id}
        ).fetchone()
        
        previous_hash = prev_row[0] if prev_row and prev_row[0] else GENESIS_HASH
        
        # 2. Formulate the record dictionary
        record = {
            "document_id": document_id,
            "action": action,
            "actor": actor,
            "details": details,
            "timestamp": now,
            "tenant_id": tenant_id,
        }
        
        # 3. Compute integrity hash
        integrity_hash = calculate_audit_hash(record, previous_hash)
        
        # 4. Insert into database
        conn.execute(
            text("""
            INSERT INTO document_audits (tenant_id, document_id, timestamp, action, actor, details, integrity_hash, previous_hash)
            VALUES (:tenant_id, :document_id, :timestamp, :action, :actor, :details, :integrity_hash, :previous_hash)
            """),
            {
                "tenant_id": tenant_id,
                "document_id": document_id,
                "timestamp": now,
                "action": action,
                "actor": actor,
                "details": details,
                "integrity_hash": integrity_hash,
                "previous_hash": previous_hash
            }
        )
        conn.commit()
        
    return integrity_hash

def verify_document_audit_chain(document_id: int, tenant_id: int = None) -> dict:
    """
    Verifies the integrity of the cryptographic chain for a specific document.
    """
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
            SELECT id, document_id, timestamp, action, actor, details, integrity_hash, previous_hash, tenant_id
            FROM document_audits
            WHERE document_id = :doc_id
              AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
            ORDER BY id ASC
            """),
            {"doc_id": document_id, "tenant_id": tenant_id}
        ).fetchall()
        
    if not rows:
        return {"valid": True, "records_checked": 0, "reason": "No audit records found."}
        
    records_checked = 0
    prev_hash = None
    
    for row in rows:
        rec_id = row[0]
        doc_id = row[1]
        timestamp = row[2]
        action = row[3]
        actor = row[4]
        details = row[5]
        integrity_hash = row[6]
        previous_hash = row[7]
        row_tenant_id = row[8]
        
        # Check continuity
        expected_prev = GENESIS_HASH if prev_hash is None else prev_hash
        if previous_hash != expected_prev:
            return {
                "valid": False,
                "records_checked": records_checked,
                "failed_record_id": rec_id,
                "reason": "Broken cryptographic hash chain linkage."
            }
            
        # Recompute hash
        record = {
            "document_id": doc_id,
            "action": action,
            "actor": actor,
            "details": details,
            "timestamp": timestamp,
            "tenant_id": row_tenant_id,
        }
        computed_hash = calculate_audit_hash(record, previous_hash)
        if integrity_hash != computed_hash:
            return {
                "valid": False,
                "records_checked": records_checked,
                "failed_record_id": rec_id,
                "reason": "Block integrity hash mismatch. Content may have been tampered with."
            }
            
        prev_hash = integrity_hash
        records_checked += 1
        
    return {
        "valid": True,
        "records_checked": records_checked,
        "latest_hash": prev_hash
    }
