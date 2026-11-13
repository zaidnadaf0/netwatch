"""Ingestion endpoints with streaming upload support and proper error handling."""

import json
import gzip
import uuid
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ingestion.parser import FlowLogParser, ParseResult
from app.core.config import settings
from app.db.session import get_db
from app.db.crud import create_flow_logs, create_detection_events
from app.db.models.flow_log import FlowLog
from detection.rules import DetectionEngine, DetectionResult as EngineDetectionResult, get_default_rules
from app.core.config import settings
from shared.netwatch_core.schemas.flow_log import FlowLogEntry

router = APIRouter()


class IngestionJob(BaseModel):
    """Ingestion job model."""
    id: str
    status: str
    source: str
    records_processed: int
    records_failed: int
    created_at: str
    completed_at: Optional[str] = None


class IngestionResponse(BaseModel):
    """Ingestion response model."""
    job: IngestionJob
    message: str
    errors: List[str] = []


# Configuration
UPLOAD_DIR = Path(r"D:\NetWatch\.tmp")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 1024 * 1024  # 1 MB chunks for streaming


# Initialize detection engine with config from settings
detection_engine = DetectionEngine(
    rules=get_default_rules(
        ssh_rdp_private_check=True,
        port_scan_threshold=getattr(settings, 'DETECTION_PORT_SCAN_THRESHOLD', 20),
        brute_force_threshold=getattr(settings, 'DETECTION_BRUTE_FORCE_THRESHOLD', 10),
        data_exfil_threshold=getattr(settings, 'DETECTION_DATA_EXFIL_THRESHOLD_BYTES', 10_000_000),
        time_window_seconds=getattr(settings, 'DETECTION_TIME_WINDOW_SECONDS', 3600)
    )
)


@router.post("/flow-logs", response_model=IngestionResponse)
async def ingest_flow_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Ingest VPC Flow Logs from uploaded file with streaming processing."""
    # Validate file extension
    allowed_extensions = (".json", ".log", ".gz", ".jsonl")
    if not file.filename.lower().endswith(allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format. Use {', '.join(allowed_extensions)}"
        )

    # Create temporary file for streaming upload
    temp_file = UPLOAD_DIR / f"upload_{uuid.uuid4().hex}{Path(file.filename).suffix}"
    total_size = 0

    try:
        # Stream upload to temporary file in chunks
        with open(temp_file, "wb") as f:
            while chunk := await file.read(settings.CHUNK_SIZE if hasattr(settings, 'CHUNK_SIZE') else 1024 * 1024):
                total_size += len(chunk)
                if total_size > settings.MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large: {total_size} bytes (max {settings.MAX_FILE_SIZE})"
                    )
                f.write(chunk)

        # Parse using FlowLogParser with file path (streaming)
        parser = FlowLogParser()
        result: ParseResult = parser.parse_file(str(temp_file))

        # Check record count limit
        if result.parsed_lines > settings.MAX_RECORDS:
            raise HTTPException(
                status_code=413,
                detail=f"Too many records: {result.parsed_lines} (max {settings.MAX_RECORDS})"
            )

        # Check for parse errors - if all lines failed, it's a client error
        if result.total_lines > 0 and result.parsed_lines == 0:
            raise HTTPException(
                status_code=400,
                detail=f"All records failed to parse: {'; '.join(result.errors[:5])}"
            )

        # Store flow logs in database
        flow_logs = []
        if result.entries:
            from app.db.crud import create_flow_logs
            flow_logs = create_flow_logs(db, result.entries, file.filename)

        # Run detection on parsed entries
        detection_results = []
        if result.entries:
            engine_results = detection_engine.analyze(result.entries)
            detection_results = engine_results
            
            # Store detection events in database
            if flow_logs and engine_results:
                from app.db.crud import create_detection_events
                create_detection_events(db, engine_results, flow_logs)

        # Determine job status
        if result.failed_lines == 0:
            status = "completed"
        elif result.parsed_lines == 0:
            status = "failed"
        else:
            status = "partial"

        # Create job with real metadata
        now = datetime.now(timezone.utc).isoformat()
        job = IngestionJob(
            id=uuid.uuid4().hex[:12],
            status=status,
            source=file.filename,
            records_processed=result.parsed_lines,
            records_failed=result.failed_lines,
            created_at=now,
            completed_at=now
        )

        message = f"Parsed {result.parsed_lines} records"
        if result.failed_lines > 0:
            message += f", {result.failed_lines} failed"

        return IngestionResponse(
            job=job,
            message=message,
            errors=result.errors
        )

    except HTTPException:
        raise
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    except gzip.BadGzipFile as e:
        raise HTTPException(status_code=400, detail=f"Invalid GZIP file: {str(e)}")
    except UnicodeDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Encoding error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")
    finally:
        # Cleanup temporary file
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass


@router.get("/flow-logs", response_model=dict)
async def list_flow_logs(
    skip: int = 0,
    limit: int = 100,
    src_addr: Optional[str] = None,
    dst_addr: Optional[str] = None,
    dst_port: Optional[int] = None,
    action: Optional[str] = None,
    start_time: Optional[int] = None,
    end_time: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """List flow logs with pagination and filtering."""
    from app.db.crud import get_flow_logs
    flow_logs, total = get_flow_logs(
        db, skip=skip, limit=limit,
        src_addr=src_addr, dst_addr=dst_addr,
        dst_port=dst_port, action=action,
        start_time=start_time, end_time=end_time
    )
    return {
        "items": [
            {
                "id": fl.id,
                "version": fl.version,
                "account_id": fl.account_id,
                "interface_id": fl.interface_id,
                "src_addr": fl.src_addr,
                "dst_addr": fl.dst_addr,
                "src_port": fl.src_port,
                "dst_port": fl.dst_port,
                "protocol": fl.protocol,
                "packets": fl.packets,
                "bytes": fl.bytes,
                "start_time": fl.start_time,
                "end_time": fl.end_time,
                "action": fl.action,
                "log_status": fl.log_status,
                "created_at": fl.created_at.isoformat() if fl.created_at else None,
            }
            for fl in flow_logs
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/detection-events", response_model=List[dict])
async def list_detection_events(
    skip: int = 0,
    limit: int = 100,
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List detection events with pagination and filtering."""
    from app.db.crud import get_detection_events
    from datetime import datetime
    
    start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00')) if start_time else None
    end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00')) if end_time else None
    
    detection_events, total = get_detection_events(
        db, skip=skip, limit=limit,
        rule_id=rule_id, severity=severity,
        start_time=start_dt, end_time=end_dt
    )
    return {
        "items": [
            {
                "id": de.id,
                "rule_id": de.rule_id,
                "rule_name": de.rule_name,
                "severity": de.severity,
                "flow_log_id": de.flow_log_id,
                "details": de.details,
                "timestamp": de.timestamp.isoformat() if de.timestamp else None,
            }
            for de in detection_events
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/jobs", response_model=List[IngestionJob])
async def list_ingestion_jobs():
    """List ingestion jobs."""
    return [
        IngestionJob(
            id="job-001",
            status="completed",
            source="sample-flow-logs.json",
            records_processed=150,
            records_failed=0,
            created_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z"
        )
    ]