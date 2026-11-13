"""Database operations for flow logs, detection events, and security group audits."""

from typing import List, Optional, Union
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.db.models.flow_log import FlowLog, DetectionEvent, SecurityGroupAudit
from shared.netwatch_core.schemas.flow_log import FlowLogEntry
from detection.rules import DetectionResult as EngineDetectionResult


def _to_flow_log_entry(entry: Union[FlowLogEntry, dict]) -> FlowLogEntry:
    """Convert dict or FlowLogEntry to FlowLogEntry."""
    if isinstance(entry, FlowLogEntry):
        return entry
    return FlowLogEntry(**entry)


def create_flow_logs(db: Session, entries: List[Union[FlowLogEntry, dict]], source_filename: str) -> List[FlowLog]:
    """Create flow log records in database. Accepts both FlowLogEntry objects and dicts."""
    flow_logs = []
    for entry in entries:
        entry_obj = _to_flow_log_entry(entry)
        flow_log = FlowLog(
            version=entry_obj.version,
            account_id=entry_obj.account_id,
            interface_id=entry_obj.interface_id,
            src_addr=entry_obj.src_addr,
            dst_addr=entry_obj.dst_addr,
            src_port=entry_obj.src_port,
            dst_port=entry_obj.dst_port,
            protocol=entry_obj.protocol,
            packets=entry_obj.packets,
            bytes=entry_obj.bytes,
            start_time=entry_obj.start_time,
            end_time=entry_obj.end_time,
            action=entry_obj.action,
            log_status=entry_obj.log_status,
        )
        db.add(flow_log)
        flow_logs.append(flow_log)
    
    db.flush()
    return flow_logs


def create_detection_events(db: Session, results: list, flow_logs: List[FlowLog]) -> List[DetectionEvent]:
    """Create detection event records in database."""
    detection_events = []
    
    # Create a mapping from flow log attributes to flow_log_id
    # We match by the unique combination of attributes
    flow_log_map = {}
    for fl in flow_logs:
        key = (fl.src_addr, fl.dst_addr, fl.src_port, fl.dst_port, fl.protocol, fl.start_time, fl.end_time)
        flow_log_map[key] = fl.id
    
    for result in results:
        # Find the matching flow log
        flow_log_entry = result.flow_log
        key = (
            flow_log_entry.src_addr,
            flow_log_entry.dst_addr,
            flow_log_entry.src_port,
            flow_log_entry.dst_port,
            flow_log_entry.protocol,
            flow_log_entry.start_time,
            flow_log_entry.end_time
        )
        flow_log_id = flow_log_map.get(key)
        
        if flow_log_id:
            detection_event = DetectionEvent(
                rule_id=result.rule_id,
                rule_name=result.rule_name,
                severity=result.severity.value if hasattr(result.severity, 'value') else result.severity,
                flow_log_id=flow_log_id,
                details=result.details,
                timestamp=result.timestamp,
            )
            db.add(detection_event)
            detection_events.append(detection_event)
    
    db.flush()
    return detection_events


def create_security_group_audits(db: Session, findings: list, group_id: str, group_name: str) -> List[SecurityGroupAudit]:
    """Create security group audit records in database."""
    audits = []
    for finding in findings:
        # Parse timestamp if it's a string
        timestamp = finding.get('timestamp', datetime.now(timezone.utc))
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.now(timezone.utc)

        audit = SecurityGroupAudit(
            group_id=finding.get('resource_id', ''),
            group_name=group_name,
            finding_id=finding.get('id', ''),
            severity=finding.get('severity', ''),
            title=finding.get('title', ''),
            description=finding.get('description', ''),
            remediation=finding.get('remediation', ''),
            direction=finding.get('direction'),
            timestamp=timestamp,
        )
        db.add(audit)
        audits.append(audit)

    db.flush()
    return audits


def get_flow_logs(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    src_addr: Optional[str] = None,
    dst_addr: Optional[str] = None,
    dst_port: Optional[int] = None,
    action: Optional[str] = None,
    start_time: Optional[int] = None,
    end_time: Optional[int] = None,
) -> tuple[List[FlowLog], int]:
    """Get flow logs with pagination and filtering."""
    query = db.query(FlowLog)
    
    if src_addr:
        query = query.filter(FlowLog.src_addr == src_addr)
    if dst_addr:
        query = query.filter(FlowLog.dst_addr == dst_addr)
    if dst_port:
        query = query.filter(FlowLog.dst_port == dst_port)
    if action:
        query = query.filter(FlowLog.action == action)
    if start_time:
        query = query.filter(FlowLog.start_time >= start_time)
    if end_time:
        query = query.filter(FlowLog.end_time <= end_time)
    
    total = query.count()
    query = query.order_by(desc(FlowLog.start_time)).offset(skip).limit(limit)
    
    return query.all(), total


def get_detection_events(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> tuple[List[DetectionEvent], int]:
    """Get detection events with pagination and filtering."""
    query = db.query(DetectionEvent)
    
    if rule_id:
        query = query.filter(DetectionEvent.rule_id == rule_id)
    if severity:
        query = query.filter(DetectionEvent.severity == severity)
    if start_time:
        query = query.filter(DetectionEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(DetectionEvent.timestamp <= end_time)
    
    total = query.count()
    query = query.order_by(desc(DetectionEvent.timestamp)).offset(skip).limit(limit)
    
    return query.all(), total


def get_security_group_audits(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    group_id: Optional[str] = None,
    severity: Optional[str] = None,
    direction: Optional[str] = None,
) -> tuple[List[SecurityGroupAudit], int]:
    """Get security group audits with pagination and filtering."""
    query = db.query(SecurityGroupAudit)
    
    if group_id:
        query = query.filter(SecurityGroupAudit.group_id == group_id)
    if severity:
        query = query.filter(SecurityGroupAudit.severity == severity)
    if direction:
        query = query.filter(SecurityGroupAudit.direction == direction)
    
    total = query.count()
    query = query.order_by(desc(SecurityGroupAudit.timestamp)).offset(skip).limit(limit)
    
    return query.all(), total


def get_detection_stats(db: Session) -> dict:
    """Get detection statistics."""
    total_events = db.query(DetectionEvent).count()
    by_severity = db.query(DetectionEvent.severity, func.count(DetectionEvent.id)).group_by(DetectionEvent.severity).all()
    by_rule = db.query(DetectionEvent.rule_id, func.count(DetectionEvent.id)).group_by(DetectionEvent.rule_id).all()
    
    return {
        "total_events": total_events,
        "by_severity": dict(by_severity),
        "by_rule": dict(by_rule),
    }


def get_audit_stats(db: Session) -> dict:
    """Get security group audit statistics."""
    total_audits = db.query(SecurityGroupAudit).count()
    by_severity = db.query(SecurityGroupAudit.severity, func.count(SecurityGroupAudit.id)).group_by(SecurityGroupAudit.severity).all()
    by_direction = db.query(SecurityGroupAudit.direction, func.count(SecurityGroupAudit.id)).group_by(SecurityGroupAudit.direction).all()
    
    return {
        "total_audits": total_audits,
        "by_severity": dict(by_severity),
        "by_direction": dict(by_direction),
    }