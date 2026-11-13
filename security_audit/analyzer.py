"""Security group analyzer."""

from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityGroupRule:
    """Security group rule."""
    ip_protocol: str
    from_port: int
    to_port: int
    cidr_ipv4: Optional[str] = None
    cidr_ipv6: Optional[str] = None
    referenced_group_id: Optional[str] = None
    description: Optional[str] = None


@dataclass
class SecurityGroup:
    """Security group."""
    group_id: str
    group_name: str
    description: str
    vpc_id: str
    rules: List[SecurityGroupRule]


@dataclass
class AuditFinding:
    """Audit finding."""
    id: str
    severity: Severity
    title: str
    description: str
    resource_id: str
    resource_type: str
    remediation: str
    timestamp: datetime


class SecurityGroupAnalyzer:
    """Analyzer for AWS Security Groups."""

    def __init__(self):
        self.findings: List[AuditFinding] = []

    def analyze(self, groups: List[SecurityGroup]) -> List[AuditFinding]:
        """Analyze security groups for misconfigurations."""
        self.findings = []
        for sg in groups:
            self._analyze_security_group(sg)
        return self.findings

    def _analyze_security_group(self, sg: SecurityGroup):
        """Analyze a single security group."""
        for rule in sg.rules:
            if rule.cidr_ipv4 == "0.0.0.0/0":
                self._check_open_to_world(sg, rule)
            if rule.cidr_ipv6 == "::/0":
                self._check_open_to_world_ipv6(sg, rule)

    def _check_open_to_world(self, sg: SecurityGroup, rule: SecurityGroupRule):
        """Check for rules open to 0.0.0.0/0."""
        # SSH
        if rule.from_port <= 22 <= rule.to_port and rule.ip_protocol in ("tcp", "-1"):
            self.findings.append(AuditFinding(
                id=f"SG-{sg.group_id}-SSH-OPEN",
                severity=Severity.CRITICAL,
                title="SSH Open to World",
                description=f"Security group {sg.group_name} ({sg.group_id}) allows SSH from 0.0.0.0/0",
                resource_id=sg.group_id,
                resource_type="security_group",
                remediation="Restrict SSH access to specific IP ranges or use bastion host",
                timestamp=datetime.utcnow()
            ))

        # RDP
        if rule.from_port <= 3389 <= rule.to_port and rule.ip_protocol in ("tcp", "-1"):
            self.findings.append(AuditFinding(
                id=f"SG-{sg.group_id}-RDP-OPEN",
                severity=Severity.CRITICAL,
                title="RDP Open to World",
                description=f"Security group {sg.group_name} ({sg.group_id}) allows RDP from 0.0.0.0/0",
                resource_id=sg.group_id,
                resource_type="security_group",
                remediation="Restrict RDP access to specific IP ranges or use bastion host",
                timestamp=datetime.utcnow()
            ))

        # FTP
        if rule.from_port <= 21 <= rule.to_port and rule.ip_protocol in ("tcp", "-1"):
            self.findings.append(AuditFinding(
                id=f"SG-{sg.group_id}-FTP-OPEN",
                severity=Severity.HIGH,
                title="FTP Open to World",
                description=f"Security group {sg.group_name} ({sg.group_id}) allows FTP from 0.0.0.0/0",
                resource_id=sg.group_id,
                resource_type="security_group",
                remediation="Remove FTP or restrict to specific IPs; use SFTP instead",
                timestamp=datetime.utcnow()
            ))

        # Telnet
        if rule.from_port <= 23 <= rule.to_port and rule.ip_protocol in ("tcp", "-1"):
            self.findings.append(AuditFinding(
                id=f"SG-{sg.group_id}-TELNET-OPEN",
                severity=Severity.HIGH,
                title="Telnet Open to World",
                description=f"Security group {sg.group_name} ({sg.group_id}) allows Telnet from 0.0.0.0/0",
                resource_id=sg.group_id,
                resource_type="security_group",
                remediation="Disable Telnet; use SSH instead",
                timestamp=datetime.utcnow()
            ))

        # Database ports
        db_ports = {1433, 1521, 3306, 5432, 6379, 27017}
        if any(port in db_ports for port in range(rule.from_port, rule.to_port + 1)) and rule.ip_protocol in ("tcp", "-1"):
            self.findings.append(AuditFinding(
                id=f"SG-{sg.group_id}-DB-OPEN",
                severity=Severity.HIGH,
                title="Database Port Open to World",
                description=f"Security group {sg.group_name} ({sg.group_id}) allows database access from 0.0.0.0/0",
                resource_id=sg.group_id,
                resource_type="security_group",
                remediation="Restrict database access to application security groups only",
                timestamp=datetime.utcnow()
            ))

        # All ports
        if rule.from_port == 0 and rule.to_port == 65535:
            self.findings.append(AuditFinding(
                id=f"SG-{sg.group_id}-ALL-PORTS-OPEN",
                severity=Severity.CRITICAL,
                title="All Ports Open to World",
                description=f"Security group {sg.group_name} ({sg.group_id}) allows all ports from 0.0.0.0/0",
                resource_id=sg.group_id,
                resource_type="security_group",
                remediation="Restrict to only required ports and IP ranges",
                timestamp=datetime.utcnow()
            ))

    def _check_open_to_world_ipv6(self, sg: SecurityGroup, rule: SecurityGroupRule):
        """Check for rules open to ::/0 (IPv6)."""
        # Similar checks for IPv6
        if rule.from_port <= 22 <= rule.to_port:
            self.findings.append(AuditFinding(
                id=f"SG-{sg.group_id}-SSH-OPEN-IPV6",
                severity=Severity.CRITICAL,
                title="SSH Open to World (IPv6)",
                description=f"Security group {sg.group_name} ({sg.group_id}) allows SSH from ::/0",
                resource_id=sg.group_id,
                resource_type="security_group",
                remediation="Restrict SSH access to specific IP ranges",
                timestamp=datetime.utcnow()
            ))

    def get_rules(self) -> List[dict]:
        """Get available audit rules."""
        return [
            {"id": "SG_SSH_OPEN", "name": "SSH Open to World", "severity": "CRITICAL", "enabled": True},
            {"id": "SG_RDP_OPEN", "name": "RDP Open to World", "severity": "CRITICAL", "enabled": True},
            {"id": "SG_FTP_OPEN", "name": "FTP Open to World", "severity": "HIGH", "enabled": True},
            {"id": "SG_TELNET_OPEN", "name": "Telnet Open to World", "severity": "HIGH", "enabled": True},
            {"id": "SG_DB_OPEN", "name": "Database Port Open to World", "severity": "HIGH", "enabled": True},
            {"id": "SG_ALL_PORTS_OPEN", "name": "All Ports Open to World", "severity": "CRITICAL", "enabled": True},
            {"id": "SG_UNRESTRICTED_EGRESS", "name": "Unrestricted Egress", "severity": "MEDIUM", "enabled": True},
            {"id": "SG_UNUSED", "name": "Unused Security Groups", "severity": "LOW", "enabled": True},
        ]