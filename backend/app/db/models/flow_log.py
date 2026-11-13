"""Flow log model."""

from sqlalchemy import Column, Integer, String, BigInteger, DateTime, Index, ForeignKey
from app.db.session import Base
from datetime import datetime


class FlowLog(Base):
    __tablename__ = "flow_logs"

    id = Column(Integer, primary_key=True, index=True)
    version = Column(Integer, nullable=False)
    account_id = Column(String(20), nullable=False, index=True)
    interface_id = Column(String(50), nullable=False, index=True)
    src_addr = Column(String(45), nullable=False, index=True)
    dst_addr = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False, index=True)
    protocol = Column(Integer, nullable=False)
    packets = Column(BigInteger, nullable=False)
    bytes = Column(BigInteger, nullable=False)
    start_time = Column(BigInteger, nullable=False)
    end_time = Column(BigInteger, nullable=False)
    action = Column(String(10), nullable=False)
    log_status = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_flow_log_src_dst", "src_addr", "dst_addr"),
        Index("idx_flow_log_time", "start_time"),
    )


class DetectionEvent(Base):
    __tablename__ = "detection_events"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(50), nullable=False, index=True)
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    flow_log_id = Column(Integer, ForeignKey("flow_logs.id"), nullable=False, index=True)
    details = Column(String(500))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class SecurityGroupAudit(Base):
    __tablename__ = "security_group_audits"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(String(50), nullable=False, index=True)
    group_name = Column(String(100), nullable=False)
    finding_id = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(String(500))
    remediation = Column(String(500))
    direction = Column(String(20), nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)