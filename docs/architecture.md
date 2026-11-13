# NetWatch Architecture

## Overview

NetWatch is a network threat detection and security audit platform designed to analyze AWS VPC Flow Logs and Security Groups for security misconfigurations and threats.

## System Context

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   AWS VPC   │────▶│  Ingestion  │────▶│  Detection  │
│ Flow Logs   │     │   Service   │     │   Engine    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Security   │────▶│    Audit    │────▶│  Findings   │
│  Groups     │     │  Analyzer   │     │  & Alerts   │
└─────────────┘     └─────────────┘     └─────────────┘
```

## Components

### Frontend (React + TypeScript + Tailwind)
- **Technology**: React 18, TypeScript 5, Vite 5, Tailwind CSS 4
- **Structure**: Component-based, tabbed interface for Detection/Ingestion/Audit
- **State**: React hooks for local state, fetch API for backend communication

### Backend (Python + FastAPI)
- **Technology**: FastAPI 0.104+, Python 3.12, Pydantic 2, SQLAlchemy 2
- **API Design**: RESTful with OpenAPI 3.1 spec
- **Database**: PostgreSQL with async support (psycopg3)
- **Testing**: pytest + pytest-asyncio + httpx

### Detection Engine
- **Rules**: 5 built-in rules (SSH, RDP, Data Exfiltration, Port Scan, Brute Force)
- **Extensibility**: Plugin architecture for custom rules
- **Performance**: Streaming analysis, O(n) per rule

### Ingestion Service
- **Formats**: JSON, JSONL, GZIP
- **Parser**: Streaming with error recovery
- **Validation**: Schema validation with detailed error reporting

### Security Audit Analyzer
- **Rules**: 8 built-in rules for common misconfigurations
- **Coverage**: SSH, RDP, FTP, Telnet, Database ports, All ports, IPv6
- **Output**: Structured findings with remediation guidance

## Data Models

### FlowLogEntry
```python
version: int
account_id: str
interface_id: str
src_addr: str
dst_addr: str
src_port: int
dst_port: int
protocol: int
packets: int
bytes: int
start_time: int
end_time: int
action: str  # ACCEPT | REJECT
log_status: str
```

### DetectionResult
```python
rule_id: str
rule_name: str
severity: Severity
timestamp: datetime
flow_log: FlowLogEntry
details: str
```

### AuditFinding
```python
id: str
severity: Severity
title: str
description: str
resource_id: str
resource_type: str
remediation: str
timestamp: datetime
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| POST | /api/v1/detection/analyze | Analyze flow logs |
| GET | /api/v1/detection/rules | List detection rules |
| POST | /api/v1/ingestion/flow-logs | Ingest flow log file |
| GET | /api/v1/ingestion/jobs | List ingestion jobs |
| POST | /api/v1/security-audit/security-groups/analyze | Analyze security groups |
| GET | /api/v1/security-audit/rules | List audit rules |

## Security Considerations

- No secrets in code (use .env)
- CORS configured for known origins only
- Input validation via Pydantic models
- SQL injection prevention via SQLAlchemy ORM
- Rate limiting (to be implemented)
- Audit logging (to be implemented)

## Deployment Architecture (Future)

```
┌─────────────────────────────────────────────────────────────┐
│                        AWS Account                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   ALB    │─▶│  ECS     │─▶│  RDS     │  │   S3     │   │
│  │          │  │  Fargate │  │PostgreSQL│  │  Logs    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Decision Records

See `docs/adr/` for Architecture Decision Records.