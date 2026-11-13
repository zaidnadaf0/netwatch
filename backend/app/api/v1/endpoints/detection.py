"""Detection endpoints."""

from fastapi import APIRouter, Body, Depends
from typing import List, Union, Annotated, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from pydantic import BaseModel

from shared.netwatch_core.schemas.flow_log import FlowLogEntry, FlowLogEntryBatch
from detection.rules import DetectionEngine, DetectionResult as EngineDetectionResult, Severity, get_default_rules
from app.core.config import settings
from app.db.session import get_db
from app.db.models.flow_log import FlowLog, DetectionEvent
from app.db.crud import create_flow_logs, create_detection_events

router = APIRouter()


class DetectionResult(BaseModel):
    """API-compatible detection result."""
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    flow_log: FlowLogEntry
    details: str


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


# Accept both legacy list and new batch format
FlowLogInput = Annotated[
    Union[List[FlowLogEntry], FlowLogEntryBatch],
    Body(description="Flow log entries to analyze (legacy list or new batch format)"),
]


def _convert_engine_result(result: EngineDetectionResult) -> DetectionResult:
    """Convert engine DetectionResult to API DetectionResult."""
    return DetectionResult(
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        severity=result.severity.value if isinstance(result.severity, Severity) else result.severity,
        timestamp=result.timestamp,
        flow_log=result.flow_log,
        details=result.details
    )


@router.post("/analyze", response_model=List[DetectionResult])
async def analyze_flow_logs(payload: FlowLogInput, db: Session = Depends(get_db)):
    """Analyze VPC Flow Logs for threats.
    
    Accepts either:
    - A list of flow log entries (legacy format)
    - A batch object with 'entries' field (new format)
    """
    if isinstance(payload, FlowLogEntryBatch):
        entries = payload.entries
    else:
        entries = payload
    
    # Store flow logs in database
    flow_logs = create_flow_logs(db, entries, "api-detection")
    
    # Run detection
    engine_results = detection_engine.analyze(entries)
    results = [_convert_engine_result(r) for r in engine_results]
    
    # Store detection events in database
    if engine_results:
        create_detection_events(db, engine_results, flow_logs)
    
    return results


@router.get("/rules")
async def list_detection_rules():
    """List available detection rules."""
    return {
        "rules": [
            {"id": "SSH_EXPOSURE", "name": "SSH Exposed to Internet", "severity": "HIGH", "enabled": True},
            {"id": "RDP_EXPOSURE", "name": "RDP Exposed to Internet", "severity": "HIGH", "enabled": True},
            {"id": "DATA_EXFILTRATION", "name": "Potential Data Exfiltration", "severity": "MEDIUM", "enabled": True},
            {"id": "PORT_SCAN", "name": "Port Scanning Detection", "severity": "MEDIUM", "enabled": True},
            {"id": "BRUTE_FORCE", "name": "Brute Force Attack", "severity": "HIGH", "enabled": True},
        ]
    }


@router.get("/events", response_model=dict)
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