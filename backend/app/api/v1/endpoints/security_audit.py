"""Security audit endpoints with egress support."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.crud import create_security_group_audits, get_security_group_audits

router = APIRouter()


class SecurityGroupRule(BaseModel):
    """Security group rule model."""
    ip_protocol: str
    from_port: int
    to_port: int
    cidr_ipv4: Optional[str] = None
    cidr_ipv6: Optional[str] = None
    referenced_group_id: Optional[str] = None
    description: Optional[str] = None
    is_egress: bool = False  # True for egress rules, False for ingress


class SecurityGroup(BaseModel):
    """Security group model."""
    group_id: str
    group_name: str
    description: str
    vpc_id: str
    rules: List[SecurityGroupRule]


class AuditFinding(BaseModel):
    """Audit finding model."""
    id: str
    severity: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    remediation: str
    timestamp: datetime
    direction: str = "ingress"  # "ingress" or "egress"


# Database ports that should not be exposed to the world
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 27017}

# Auth ports for brute force / sensitive access
AUTH_PORTS = {22, 3389, 21, 23, 5900, 5901}


def _protocol_matches(rule_protocol: str) -> bool:
    """Check if rule protocol matches TCP or ALL (-1)."""
    return rule_protocol in ("tcp", "6", "-1")


def _port_in_range(port: int, from_port: int, to_port: int) -> bool:
    """Check if port is within the rule's port range."""
    return from_port <= port <= to_port


def _is_private_ipv4(ip: str) -> bool:
    """Check if IPv4 address is private (RFC1918)."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
        return (
            first == 10 or
            (first == 172 and 16 <= second <= 31) or
            (first == 192 and second == 168)
        )
    except ValueError:
        return False


def _is_private_ipv6(ip: str) -> bool:
    """Check if IPv6 address is private (ULA, link-local, loopback)."""
    ip_lower = ip.lower()
    # Loopback
    if ip_lower == "::1":
        return True
    # Link-local (fe80::/10)
    if ip_lower.startswith("fe80:"):
        return True
    # Unique Local Address (fc00::/7)
    if ip_lower.startswith("fc") or ip_lower.startswith("fd"):
        return True
    return False


def _is_public_ip(ip: str) -> bool:
    """Check if IP is likely public (not private/reserved)."""
    if ':' in ip:
        return not _is_private_ipv6(ip)
    else:
        return not _is_private_ipv4(ip)


def _check_sensitive_port_exposure(
    sg: SecurityGroup,
    rule: SecurityGroupRule,
    findings: List[dict],
    direction: str,
    cidr: str,
    ip_version: str
):
    """Check for sensitive port exposure in a rule."""
    proto_match = _protocol_matches(rule.ip_protocol)
    if not proto_match:
        return

    suffix = f"-{ip_version}" if ip_version else ""
    direction_label = "Egress" if direction == "egress" else "Ingress"

    # SSH
    if _port_in_range(22, rule.from_port, rule.to_port):
        severity = "CRITICAL" if _is_public_ip(cidr) else "MEDIUM"
        findings.append({
            "id": f"SG-{sg.group_id}-SSH-OPEN{suffix}",
            "severity": severity,
            "title": f"SSH Open to World ({direction_label}, {ip_version})",
            "description": f"Security group {sg.group_name} ({sg.group_id}) allows SSH from {cidr}",
            "resource_id": sg.group_id,
            "resource_type": "security_group",
            "remediation": "Restrict SSH access to specific IP ranges or use bastion host",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction
        })

    # RDP
    if _port_in_range(3389, rule.from_port, rule.to_port):
        severity = "CRITICAL" if _is_public_ip(cidr) else "MEDIUM"
        findings.append({
            "id": f"SG-{sg.group_id}-RDP-OPEN{suffix}",
            "severity": severity,
            "title": f"RDP Open to World ({direction_label}, {ip_version})",
            "description": f"Security group {sg.group_name} ({sg.group_id}) allows RDP from {cidr}",
            "resource_id": sg.group_id,
            "resource_type": "security_group",
            "remediation": "Restrict RDP access to specific IP ranges or use bastion host",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction
        })

    # FTP
    if _port_in_range(21, rule.from_port, rule.to_port):
        severity = "HIGH" if _is_public_ip(cidr) else "LOW"
        findings.append({
            "id": f"SG-{sg.group_id}-FTP-OPEN{suffix}",
            "severity": severity,
            "title": f"FTP Open to World ({direction_label}, {ip_version})",
            "description": f"Security group {sg.group_name} ({sg.group_id}) allows FTP from {cidr}",
            "resource_id": sg.group_id,
            "resource_type": "security_group",
            "remediation": "Remove FTP or restrict to specific IPs; use SFTP instead",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction
        })

    # Telnet
    if _port_in_range(23, rule.from_port, rule.to_port):
        severity = "HIGH" if _is_public_ip(cidr) else "LOW"
        findings.append({
            "id": f"SG-{sg.group_id}-TELNET-OPEN{suffix}",
            "severity": severity,
            "title": f"Telnet Open to World ({direction_label}, {ip_version})",
            "description": f"Security group {sg.group_name} ({sg.group_id}) allows Telnet from {cidr}",
            "resource_id": sg.group_id,
            "resource_type": "security_group",
            "remediation": "Disable Telnet; use SSH instead",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction
        })

    # Database ports
    for db_port in DATABASE_PORTS:
        if _port_in_range(db_port, rule.from_port, rule.to_port):
            severity = "HIGH" if _is_public_ip(cidr) else "MEDIUM"
            findings.append({
                "id": f"SG-{sg.group_id}-DB-OPEN{suffix}",
                "severity": severity,
                "title": f"Database Port Open to World ({direction_label}, {ip_version})",
                "description": f"Security group {sg.group_name} ({sg.group_id}) allows database port {db_port} from {cidr}",
                "resource_id": sg.group_id,
                "resource_type": "security_group",
                "remediation": "Restrict database access to application security groups only",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "direction": direction
            })
            break  # Only report once per rule

    # All ports
    if rule.from_port == 0 and rule.to_port == 65535:
        severity = "CRITICAL" if _is_public_ip(cidr) else "MEDIUM"
        findings.append({
            "id": f"SG-{sg.group_id}-ALL-PORTS-OPEN{suffix}",
            "severity": severity,
            "title": f"All Ports Open to World ({direction_label}, {ip_version})",
            "description": f"Security group {sg.group_name} ({sg.group_id}) allows all ports from {cidr}",
            "resource_id": sg.group_id,
            "resource_type": "security_group",
            "remediation": "Restrict to only required ports and IP ranges",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction
        })


def _check_ingress_rules(sg: SecurityGroup, rule: SecurityGroupRule, findings: List[dict]):
    """Check ingress rules for 0.0.0.0/0 and ::/0 exposure."""
    cidr_ipv4 = rule.cidr_ipv4
    cidr_ipv6 = rule.cidr_ipv6
    proto_match = _protocol_matches(rule.ip_protocol)

    if not proto_match:
        return

    # IPv4 checks
    if cidr_ipv4 == "0.0.0.0/0":
        _check_sensitive_port_exposure(sg, rule, findings, "ingress", "0.0.0.0/0", "IPv4")

    # IPv6 checks
    if cidr_ipv6 == "::/0":
        _check_sensitive_port_exposure(sg, rule, findings, "ingress", "::/0", "IPv6")


def _check_egress_rules(sg: SecurityGroup, rule: SecurityGroupRule, findings: List[dict]):
    """Check egress rules for unrestricted outbound access."""
    if not rule.is_egress:
        return

    cidr_ipv4 = rule.cidr_ipv4
    cidr_ipv6 = rule.cidr_ipv6
    proto_match = _protocol_matches(rule.ip_protocol)

    if not proto_match:
        return

    # IPv4 egress checks
    if cidr_ipv4 == "0.0.0.0/0":
        # Unrestricted egress to internet
        findings.append({
            "id": f"SG-{sg.group_id}-UNRESTRICTED-EGRESS-IPV4",
            "severity": "MEDIUM",
            "title": "Unrestricted Egress to Internet (IPv4)",
            "description": f"Security group {sg.group_name} ({sg.group_id}) allows all outbound traffic to 0.0.0.0/0",
            "resource_id": sg.group_id,
            "resource_type": "security_group",
            "remediation": "Restrict egress to required destinations only",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": "egress"
        })

        # Also check for sensitive ports in egress (data exfiltration risk)
        for port in AUTH_PORTS | DATABASE_PORTS:
            if _port_in_range(port, rule.from_port, rule.to_port):
                findings.append({
                    "id": f"SG-{sg.group_id}-EGRESS-SENSITIVE-PORT{port}",
                    "severity": "HIGH",
                    "title": f"Egress to Sensitive Port {port} (IPv4)",
                    "description": f"Security group {sg.group_name} ({sg.group_id}) allows outbound traffic to sensitive port {port}",
                    "resource_id": sg.group_id,
                    "resource_type": "security_group",
                    "remediation": "Restrict egress to required destinations only; monitor for data exfiltration",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "direction": "egress"
                })

    # IPv6 egress checks
    if cidr_ipv6 == "::/0":
        findings.append({
            "id": f"SG-{sg.group_id}-UNRESTRICTED-EGRESS-IPV6",
            "severity": "MEDIUM",
            "title": "Unrestricted Egress to Internet (IPv6)",
            "description": f"Security group {sg.group_name} ({sg.group_id}) allows all outbound traffic to ::/0",
            "resource_id": sg.group_id,
            "resource_type": "security_group",
            "remediation": "Restrict egress to required destinations only",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": "egress"
        })

        for port in AUTH_PORTS | DATABASE_PORTS:
            if _port_in_range(port, rule.from_port, rule.to_port):
                findings.append({
                    "id": f"SG-{sg.group_id}-EGRESS-SENSITIVE-PORT{port}-IPV6",
                    "severity": "HIGH",
                    "title": f"Egress to Sensitive Port {port} (IPv6)",
                    "description": f"Security group {sg.group_name} ({sg.group_id}) allows outbound traffic to sensitive port {port}",
                    "resource_id": sg.group_id,
                    "resource_type": "security_group",
                    "remediation": "Restrict egress to required destinations only; monitor for data exfiltration",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "direction": "egress"
                })


@router.post("/security-groups/analyze", response_model=List[dict])
async def analyze_security_groups(groups: List[SecurityGroup], db: Session = Depends(get_db)):
    """Analyze security groups for misconfigurations (ingress and egress)."""
    findings = []
    for sg in groups:
        for rule in sg.rules:
            _check_ingress_rules(sg, rule, findings)
            _check_egress_rules(sg, rule, findings)
    
    # Store findings in database
    if findings:
        from app.db.crud import create_security_group_audits
        create_security_group_audits(db, findings, findings[0].get("resource_id", "unknown"), findings[0].get("resource_id", "unknown"))
    
    return findings


@router.get("/security-groups", response_model=dict)
async def list_security_group_audits(
    skip: int = 0,
    limit: int = 100,
    group_id: Optional[str] = None,
    severity: Optional[str] = None,
    direction: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List security group audit findings with pagination and filtering."""
    from app.db.crud import get_security_group_audits
    
    audits, total = get_security_group_audits(
        db, skip=skip, limit=limit,
        group_id=group_id, severity=severity
    )
    return {
        "items": [
            {
                "id": a.id,
                "group_id": a.group_id,
                "group_name": a.group_name,
                "finding_id": a.finding_id,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "remediation": a.remediation,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "direction": getattr(a, 'direction', 'ingress'),
            }
            for a in audits
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/rules")
async def list_audit_rules():
    """List available audit rules."""
    return {
        "rules": [
            {"id": "SG_SSH_OPEN", "name": "SSH Open to World", "severity": "CRITICAL", "enabled": True},
            {"id": "SG_RDP_OPEN", "name": "RDP Open to World", "severity": "CRITICAL", "enabled": True},
            {"id": "SG_FTP_OPEN", "name": "FTP Open to World", "severity": "HIGH", "enabled": True},
            {"id": "SG_TELNET_OPEN", "name": "Telnet Open to World", "severity": "HIGH", "enabled": True},
            {"id": "SG_DB_OPEN", "name": "Database Port Open to World", "severity": "HIGH", "enabled": True},
            {"id": "SG_ALL_PORTS_OPEN", "name": "All Ports Open to World", "severity": "CRITICAL", "enabled": True},
            {"id": "SG_UNRESTRICTED_EGRESS", "name": "Unrestricted Egress", "severity": "MEDIUM", "enabled": True},
            {"id": "SG_UNUSED", "name": "Unused Security Groups", "severity": "LOW", "enabled": False},
        ]
    }