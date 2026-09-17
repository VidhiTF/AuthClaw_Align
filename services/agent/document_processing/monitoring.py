import os
import time
import logging
import threading
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine
from services.tenant_context import get_current_request_id, get_current_tenant_id, tenant_context
from services.quota_service import QuotaExceeded, QuotaUnavailable, record_unavailable
from services.document_monitor_status import monitor_status, update_monitor_status

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
MONITOR_REQUESTER_ID = "service:document-monitor"
_stop_event = threading.Event()
_monitor_thread = None

# Track last sync time globally for stats APIs
last_sync_time = "N/A"


def _scan_request_context(doc_id: int, requested_by: str = None) -> dict:
    return {
        "request_id": get_current_request_id() or f"document-monitor-{doc_id}-{time.time_ns()}",
        "requested_by": requested_by or MONITOR_REQUESTER_ID,
    }

def get_watched_directory() -> str:
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
        with open(os.path.join(WATCH_DIR, "readme.txt"), "w") as f:
            f.write("AuthClaw Real-Time Document Compliance Watched Directory.\nPlace documents here to auto-scan.\n")
    return WATCH_DIR

def start_background_monitoring(tenant_id=None):
    """Start an explicitly tenant-bound folder and cloud polling thread."""
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        logger.warning("Background document monitor is already running.")
        return

    configured_tenant = str(tenant_id or os.getenv("AUTHCLAW_BACKGROUND_MONITOR_TENANT_ID", "")).strip()
    if not configured_tenant or not configured_tenant.isascii() or not configured_tenant.isdigit() or int(configured_tenant) <= 0:
        update_monitor_status(enabled=False, status="disabled", tenant_configured=False)
        raise ValueError("Background document monitoring requires an explicitly authorized positive tenant ID")

    get_watched_directory()
    _stop_event.clear()
    update_monitor_status(enabled=True, status="starting", tenant_configured=True, last_error_type=None)
    _monitor_thread = threading.Thread(
        target=_monitor_loop, args=(configured_tenant,), daemon=True, name="AuthClawDocMonitor"
    )
    _monitor_thread.start()
    logger.info("Tenant-scoped background document compliance monitor started.")

def stop_background_monitoring():
    """Signals the monitoring loop to stop."""
    _stop_event.set()
    update_monitor_status(enabled=False, status="stopping")
    logger.info("Signaled document monitor thread to stop.")

def trigger_manual_sync(requested_by: str) -> dict:
    """Trigger sync instantly."""
    global last_sync_time
    logger.info("Manual synchronization triggered.")
    if not requested_by or not requested_by.strip():
        raise ValueError("Manual document synchronization requires requester identity.")
    sync_sources(requested_by=requested_by.strip())
    last_sync_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {"status": "success", "synced_at": last_sync_time}

def sync_sources(requested_by: str = None):
    """Executes a single pass of file and config syncing across local and cloud sources."""
    tenant_id = get_current_tenant_id()
    if tenant_id is None:
        record_unavailable()
        raise QuotaUnavailable("Document synchronization requires a verified tenant")
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
                    text("SELECT id, size_bytes, status FROM documents WHERE filename = :name AND source = 'watched' AND tenant_id = :tenant_id"),
                    {"name": filename, "tenant_id": tenant_id}
                ).fetchone()
                
            if not doc:
                # Insert and scan
                with engine.connect() as conn:
                    res = conn.execute(
                        text("""
                        INSERT INTO documents (tenant_id, filename, source, size_bytes, status)
                        VALUES (:tenant_id, :name, 'watched', :size, 'pending')
                        RETURNING id
                        """),
                        {"name": filename, "size": size, "tenant_id": tenant_id}
                    )
                    doc_id = res.fetchone()[0]
                    conn.commit()
                with open(filepath, "rb") as f:
                    run_document_scan_pipeline(doc_id, f.read(), filename, source="watched", tenant_id=tenant_id, **_scan_request_context(doc_id, requested_by))
            elif doc[1] != size:
                # Rescan modified
                with engine.connect() as conn:
                    conn.execute(
                        text("UPDATE documents SET size_bytes = :size, status = 'scanning' WHERE id = :id AND tenant_id = :tenant_id"),
                        {"size": size, "id": doc[0], "tenant_id": tenant_id}
                    )
                    conn.commit()
                with open(filepath, "rb") as f:
                    run_document_scan_pipeline(doc[0], f.read(), filename, source="watched", tenant_id=tenant_id, **_scan_request_context(doc[0], requested_by))
    except (QuotaExceeded, QuotaUnavailable):
        raise
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
                                text("SELECT id FROM documents WHERE filename = :name AND source = 's3_config' AND tenant_id = :tenant_id"),
                                {"name": v_filename, "tenant_id": tenant_id}
                            ).fetchone()
                            
                        if not doc:
                            with engine.connect() as conn:
                                res = conn.execute(
                                    text("""
                                    INSERT INTO documents (tenant_id, filename, source, size_bytes, status, risk_score, severity)
                                    VALUES (:tenant_id, :name, 's3_config', 0, 'completed', 100, 'LOW')
                                    RETURNING id
                                    """),
                                    {"name": v_filename, "tenant_id": tenant_id}
                                )
                                doc_id = res.fetchone()[0]
                                conn.commit()
                        else:
                            doc_id = doc[0]
                            
                        # Save bucket misconfiguration findings
                        with engine.connect() as conn:
                            # Clear old
                            conn.execute(text("DELETE FROM document_findings WHERE document_id = :id AND tenant_id = :tenant_id"), {"id": doc_id, "tenant_id": tenant_id})
                            # Write new
                            for f in findings:
                                conn.execute(
                                    text("""
                                    INSERT INTO document_findings (tenant_id, document_id, finding_type, matched_pattern, matched_text, risk_level, recommendation, impact, priority, location_evidence)
                                    VALUES (:tenant_id, :doc_id, :ftype, :pattern, :text, :risk, :rec, :impact, :priority, :loc)
                                    """),
                                    {
                                        "doc_id": doc_id,
                                        "tenant_id": tenant_id,
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
                    text("SELECT id, filename FROM documents WHERE source = :src AND status NOT IN ('deleted', 's3_deleted') AND tenant_id = :tenant_id"),
                    {"src": src, "tenant_id": tenant_id}
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
                            text("UPDATE documents SET status = :status WHERE id = :id AND tenant_id = :tenant_id"),
                            {"status": f"{src}_deleted", "id": doc_id, "tenant_id": tenant_id}
                        )
                        conn.commit()
                    create_document_audit(
                        doc_id,
                        "document_deleted",
                        "system",
                        f"Document '{filename}' was deleted from the cloud source: {src}.",
                        tenant_id=tenant_id,
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
                        text("SELECT id, size_bytes FROM documents WHERE filename = :name AND source = :src AND tenant_id = :tenant_id"),
                        {"name": filename, "src": src, "tenant_id": tenant_id}
                    ).fetchone()
                    
                if not doc:
                    # New File
                    with engine.connect() as conn:
                        res = conn.execute(
                            text("""
                            INSERT INTO documents (tenant_id, filename, source, size_bytes, status)
                            VALUES (:tenant_id, :name, :src, :size, 'pending')
                            RETURNING id
                            """),
                            {"name": filename, "src": src, "size": size, "tenant_id": tenant_id}
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
                        run_document_scan_pipeline(doc_id, file_bytes, filename, source=src, tenant_id=tenant_id, **_scan_request_context(doc_id, requested_by))
                        
                elif doc[1] != size:
                    # Modified File
                    with engine.connect() as conn:
                        conn.execute(
                            text("UPDATE documents SET size_bytes = :size, status = 'scanning' WHERE id = :id AND tenant_id = :tenant_id"),
                            {"size": size, "id": doc[0], "tenant_id": tenant_id}
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
                        run_document_scan_pipeline(doc[0], file_bytes, filename, source=src, tenant_id=tenant_id, **_scan_request_context(doc[0], requested_by))
                        
        except (QuotaExceeded, QuotaUnavailable):
            raise
        except Exception as src_err:
            logger.error(f"Failed sync execution on cloud source {src}: {src_err}")

def _monitor_loop(tenant_id):
    """
    Main loop polling files and cloud configurations at set intervals.
    """
    global last_sync_time
    logger.info("Continuous cloud and local document monitor loop activated.")
    
    while not _stop_event.is_set():
        try:
            with tenant_context(tenant_id, request_id="document-monitor", required=True):
                sync_sources()
            succeeded_at = datetime.now(timezone.utc)
            last_sync_time = succeeded_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            update_monitor_status(
                enabled=True,
                status="healthy",
                tenant_configured=True,
                last_error_type=None,
                last_success_timestamp=int(succeeded_at.timestamp()),
            )
            if _stop_event.wait(30):
                break
        except Exception as e:
            state = monitor_status()
            update_monitor_status(
                enabled=True,
                status="degraded",
                tenant_configured=True,
                failures_total=state["failures_total"] + 1,
                last_error_type=type(e).__name__,
            )
            if isinstance(e, (QuotaExceeded, QuotaUnavailable)):
                logger.warning("Tenant-scoped document monitor deferred by quota admission")
            else:
                logger.error("Error in document monitoring thread: %s", type(e).__name__)
            if _stop_event.wait(10):
                break

    update_monitor_status(enabled=False, status="stopped")
    logger.info("Background document compliance monitor thread terminated.")
