import os
import time
import logging
import threading
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine

from document_processing.orchestrator import run_document_scan_pipeline
from document_processing.auditor import create_document_audit
from document_processing.connectors import (
    is_real_connectors_enabled,
    discover_s3_buckets,
    scan_s3_bucket_security,
    list_cloud_source_files,
    fetch_s3_document,
    fetch_gdrive_document,
    fetch_onedrive_document,
    fetch_sharepoint_document,
    fetch_dropbox_document
)

logger = logging.getLogger("authclaw.document_processing.monitoring")

WATCH_DIR = "watched_documents"
_stop_event = threading.Event()
_monitor_thread = None

# Track last sync time globally for stats APIs
last_sync_time = "N/A"

def get_watched_directory() -> str:
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
        with open(os.path.join(WATCH_DIR, "readme.txt"), "w") as f:
            f.write("AuthClaw Real-Time Document Compliance Watched Directory.\nPlace documents here to auto-scan.\n")
    return WATCH_DIR

def start_background_monitoring():
    """Starts the folder watcher and cloud poll background thread."""
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        logger.warning("Background document monitor is already running.")
        return
        
    get_watched_directory()
    _stop_event.clear()
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True, name="AuthClawDocMonitor")
    _monitor_thread.start()
    logger.info("Background document compliance monitor started.")

def stop_background_monitoring():
    """Signals the monitoring loop to stop."""
    _stop_event.set()
    logger.info("Signaled document monitor thread to stop.")

def trigger_manual_sync() -> dict:
    """Trigger sync instantly."""
    global last_sync_time
    logger.info("Manual synchronization triggered.")
    sync_sources()
    last_sync_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {"status": "success", "synced_at": last_sync_time}

def sync_sources():
    """Executes a single pass of file and config syncing across local and cloud sources."""
    # 1. Local watched documents directory
    try:
        get_watched_directory()
        local_files = [f for f in os.listdir(WATCH_DIR) if os.path.isfile(os.path.join(WATCH_DIR, f)) and not f.startswith(".")]
        for filename in local_files:
            if filename.lower() == "readme.txt":
                continue
            filepath = os.path.join(WATCH_DIR, filename)
            size = os.path.getsize(filepath)
            
            # Check DB
            with engine.connect() as conn:
                doc = conn.execute(
                    text("SELECT id, size_bytes, status FROM documents WHERE filename = :name AND source = 'watched'"),
                    {"name": filename}
                ).fetchone()
                
            if not doc:
                # Insert and scan
                with engine.connect() as conn:
                    res = conn.execute(
                        text("""
                        INSERT INTO documents (filename, source, size_bytes, status)
                        VALUES (:name, 'watched', :size, 'pending')
                        RETURNING id
                        """),
                        {"name": filename, "size": size}
                    )
                    doc_id = res.fetchone()[0]
                    conn.commit()
                with open(filepath, "rb") as f:
                    run_document_scan_pipeline(doc_id, f.read(), filename, source="watched")
            elif doc[1] != size:
                # Rescan modified
                with engine.connect() as conn:
                    conn.execute(
                        text("UPDATE documents SET size_bytes = :size, status = 'scanning' WHERE id = :id"),
                        {"size": size, "id": doc[0]}
                    )
                    conn.commit()
                with open(filepath, "rb") as f:
                    run_document_scan_pipeline(doc[0], f.read(), filename, source="watched")
    except Exception as e:
        logger.error(f"Error syncing local watched folder: {e}")

    # 2. Cloud Sources
    cloud_sources = ["s3", "gdrive", "onedrive", "sharepoint", "dropbox"]
    for src in cloud_sources:
        try:
            # S3 bucket configuration security check
            if src == "s3" and is_real_connectors_enabled():
                buckets = discover_s3_buckets()
                for b in buckets:
                    # Run configuration security scan
                    findings = scan_s3_bucket_security(b)
                    if findings:
                        # Register S3 config finding as a system virtual document
                        v_filename = f"s3://{b}/configuration"
                        with engine.connect() as conn:
                            doc = conn.execute(
                                text("SELECT id FROM documents WHERE filename = :name AND source = 's3_config'"),
                                {"name": v_filename}
                            ).fetchone()
                            
                        if not doc:
                            with engine.connect() as conn:
                                res = conn.execute(
                                    text("""
                                    INSERT INTO documents (filename, source, size_bytes, status, risk_score, severity)
                                    VALUES (:name, 's3_config', 0, 'completed', 100, 'LOW')
                                    RETURNING id
                                    """),
                                    {"name": v_filename}
                                )
                                doc_id = res.fetchone()[0]
                                conn.commit()
                        else:
                            doc_id = doc[0]
                            
                        # Save bucket misconfiguration findings
                        with engine.connect() as conn:
                            # Clear old
                            conn.execute(text("DELETE FROM document_findings WHERE document_id = :id"), {"id": doc_id})
                            # Write new
                            for f in findings:
                                conn.execute(
                                    text("""
                                    INSERT INTO document_findings (document_id, finding_type, matched_pattern, matched_text, risk_level, recommendation, impact, priority, location_evidence)
                                    VALUES (:doc_id, :ftype, :pattern, :text, :risk, :rec, :impact, :priority, :loc)
                                    """),
                                    {
                                        "doc_id": doc_id,
                                        "ftype": f["finding_type"],
                                        "pattern": f["matched_pattern"],
                                        "text": f["matched_text"],
                                        "risk": f["risk_level"],
                                        "rec": f["recommendation"],
                                        "impact": f["impact"],
                                        "priority": f["priority"],
                                        "loc": "Bucket Configuration Settings"
                                    }
                                )
                            conn.commit()
                            
            # Sync files
            discovered_files = list_cloud_source_files(src)
            discovered_ids = {f["id"] for f in discovered_files}
            
            # Check deletions
            with engine.connect() as conn:
                existing_docs = conn.execute(
                    text("SELECT id, filename FROM documents WHERE source = :src AND status NOT IN ('deleted', 's3_deleted')"),
                    {"src": src}
                ).fetchall()
                
            for doc_id, filename in existing_docs:
                # Key is filename or custom ID
                expected_id = f"{filename}" if src != "s3" else filename
                # If existing doc in DB is missing from the list of cloud files, it has been deleted
                is_deleted = True
                for f in discovered_files:
                    if f["id"] == expected_id or f["name"] == filename:
                        is_deleted = False
                        break
                        
                if is_deleted:
                    logger.warning(f"File deletion detected from cloud source {src}: {filename}")
                    with engine.connect() as conn:
                        conn.execute(
                            text("UPDATE documents SET status = :status WHERE id = :id"),
                            {"status": f"{src}_deleted", "id": doc_id}
                        )
                        conn.commit()
                    create_document_audit(
                        doc_id,
                        "document_deleted",
                        "system",
                        f"Document '{filename}' was deleted from the cloud source: {src}."
                    )
                    # Trigger snap to alert on drift drop
                    try:
                        from document_processing.drift import record_compliance_snapshot
                        record_compliance_snapshot()
                    except Exception as drift_err:
                        logger.error(f"Failed to record compliance snapshot: {drift_err}")
            
            # Process discovered files
            for f in discovered_files:
                filename = f["name"]
                size = f["size_bytes"]
                file_id = f["id"]
                
                with engine.connect() as conn:
                    doc = conn.execute(
                        text("SELECT id, size_bytes FROM documents WHERE filename = :name AND source = :src"),
                        {"name": filename, "src": src}
                    ).fetchone()
                    
                if not doc:
                    # New File
                    with engine.connect() as conn:
                        res = conn.execute(
                            text("""
                            INSERT INTO documents (filename, source, size_bytes, status)
                            VALUES (:name, :src, :size, 'pending')
                            RETURNING id
                            """),
                            {"name": filename, "src": src, "size": size}
                        )
                        doc_id = res.fetchone()[0]
                        conn.commit()
                        
                    # Fetch and scan
                    file_bytes = b""
                    try:
                        if src == "s3":
                            # ID is "bucket/key"
                            parts = file_id.split("/", 1)
                            file_bytes = fetch_s3_document(parts[0], parts[1])
                        elif src == "gdrive":
                            file_bytes = fetch_gdrive_document(file_id)
                        elif src == "onedrive":
                            file_bytes = fetch_onedrive_document(file_id)
                        elif src == "sharepoint":
                            parts = file_id.split("/", 1)
                            file_bytes = fetch_sharepoint_document(parts[0], parts[1])
                        elif src == "dropbox":
                            file_bytes = fetch_dropbox_document(file_id)
                    except Exception as fetch_err:
                        logger.error(f"Failed to fetch content for {filename} from {src}: {fetch_err}")
                        
                    if file_bytes:
                        run_document_scan_pipeline(doc_id, file_bytes, filename, source=src)
                        
                elif doc[1] != size:
                    # Modified File
                    with engine.connect() as conn:
                        conn.execute(
                            text("UPDATE documents SET size_bytes = :size, status = 'scanning' WHERE id = :id"),
                            {"size": size, "id": doc[0]}
                        )
                        conn.commit()
                        
                    file_bytes = b""
                    try:
                        if src == "s3":
                            parts = file_id.split("/", 1)
                            file_bytes = fetch_s3_document(parts[0], parts[1])
                        elif src == "gdrive":
                            file_bytes = fetch_gdrive_document(file_id)
                        elif src == "onedrive":
                            file_bytes = fetch_onedrive_document(file_id)
                        elif src == "sharepoint":
                            parts = file_id.split("/", 1)
                            file_bytes = fetch_sharepoint_document(parts[0], parts[1])
                        elif src == "dropbox":
                            file_bytes = fetch_dropbox_document(file_id)
                    except Exception as fetch_err:
                        logger.error(f"Failed to fetch updated content for {filename} from {src}: {fetch_err}")
                        
                    if file_bytes:
                        run_document_scan_pipeline(doc[0], file_bytes, filename, source=src)
                        
        except Exception as src_err:
            logger.error(f"Failed sync execution on cloud source {src}: {src_err}")

def _monitor_loop():
    """
    Main loop polling files and cloud configurations at set intervals.
    """
    global last_sync_time
    logger.info("Continuous cloud and local document monitor loop activated.")
    
    # Perform initial sync
    sync_sources()
    last_sync_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    while not _stop_event.is_set():
        try:
            # Poll every 30 seconds
            time.sleep(30)
            if _stop_event.is_set():
                break
                
            sync_sources()
            last_sync_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
        except Exception as e:
            logger.error(f"Error in document monitoring thread: {e}")
            time.sleep(10)
            
    logger.info("Background document compliance monitor thread terminated.")
