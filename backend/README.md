# NetWatch Backend

Network threat detection and security audit API built with FastAPI.

## Quick Start

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Copy environment template
cp .env.example .env

# Run development server
uvicorn app.main:app --reload
```

## Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── core/
│   │   └── config.py        # Configuration management
│   ├── api/
│   │   └── v1/
│   │       ├── router.py    # API router
│   │       └── endpoints/   # API endpoints
│   └── db/
│       ├── session.py       # Database session
│       └── models/          # SQLAlchemy models
├── tests/
├── pyproject.toml
├── requirements.txt
└── .env.example
```

## API Endpoints

- `GET /health` - Health check
- `POST /api/v1/detection/analyze` - Analyze flow logs
- `GET /api/v1/detection/rules` - List detection rules
- `POST /api/v1/ingestion/flow-logs` - Ingest flow logs
- `POST /api/v1/security-audit/security-groups/analyze` - Analyze security groups

## Development

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=app

# Lint
ruff check .

# Format
black .

# Type check
mypy app
```