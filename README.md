# NetWatch

Network threat detection and security audit platform for AWS VPC Flow Logs and Security Groups.

## Architecture

```
D:\NetWatch
├── frontend              # React + TypeScript + Tailwind CSS (Vite)
├── backend               # Python + FastAPI
│   └── app/
│       ├── api/v1/       # REST API endpoints
│       ├── core/         # Configuration
│       ├── db/           # Database models & session
│       └── main.py       # Application entry
├── detection             # Rule-based threat detection engine
├── ingestion             # VPC Flow Log parser
├── security_audit        # Security Group analyzer
├── database              # Database migrations (Alembic)
├── infrastructure/
│   └── terraform         # IaC definitions
├── datasets/
│   └── samples           # Synthetic flow log samples
├── tests                 # Unit & integration tests
├── scripts               # Utility scripts
└── docs                  # Documentation
```

## Quick Start

### Backend

```bash
cd D:\NetWatch\backend
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
uvicorn app.main:app --reload
```

API will be available at `http://localhost:8000`
- Health: `GET /health`
- Detection: `POST /api/v1/detection/analyze`
- Ingestion: `POST /api/v1/ingestion/flow-logs`
- Security Audit: `POST /api/v1/security-audit/security-groups/analyze`

### Frontend

```bash
cd D:\NetWatch\frontend
npm install
npm run dev
```

Frontend will be available at `http://localhost:5173`

## Features

### Threat Detection
- SSH/RDP exposure detection
- Data exfiltration detection
- Port scanning detection
- Brute force attack detection
- Extensible rule engine

### Flow Log Ingestion
- JSON/JSONL/GZIP format support
- Streaming parser for large files
- Validation and error reporting

### Security Group Audit
- Open to world (0.0.0.0/0) detection
- SSH, RDP, FTP, Telnet, Database ports
- Unrestricted egress detection
- Unused security group identification

## Development

### Backend Tests
```bash
cd D:\NetWatch\backend
pytest -v
pytest --cov=app
```

### Frontend Build
```bash
cd D:\NetWatch\frontend
npm run build
npm run preview
```

### Linting
```bash
# Backend
cd D:\NetWatch\backend
ruff check .
black .
mypy app

# Frontend
cd D:\NetWatch\frontend
npm run lint
```

## Sample Data

Synthetic VPC Flow Logs available at:
- `datasets/samples/sample-flow-logs.json`

## Configuration

Backend configuration via `.env`:
```env
NETWATCH_DEBUG=true
NETWATCH_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/netwatch
NETWATCH_CORS_ORIGINS=["http://localhost:5173"]
NETWATCH_AWS_REGION=us-east-1
```

## API Documentation

When backend is running:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Project Status

**Phase 3 Complete**: Local project foundation established
- [x] Modular directory structure
- [x] Backend with FastAPI, SQLAlchemy, Pydantic
- [x] Frontend with React, TypeScript, Tailwind CSS
- [x] Detection engine with 5 default rules
- [x] Flow log parser (JSON/JSONL/GZIP)
- [x] Security group analyzer with 8 rules
- [x] Unit tests (11 passing)
- [x] Sample datasets
- [x] Configuration templates

**Next Phases** (require separate approval):
- PostgreSQL integration
- AWS integration (VPC Flow Logs, Security Groups)
- Infrastructure deployment (Terraform)
- Production hardening