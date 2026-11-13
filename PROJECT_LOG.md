# NetWatch PROJECT LOG

## Project Overview

**Project Name:** NetWatch  
**Description:** Network threat detection and security audit platform for AWS VPC Flow Logs and Security Groups  
**Workspace:** `D:\NetWatch`  
**Started:** November 9, 2026 (based on file creation timestamps)  
**Platform:** Windows 10/11, Python 3.12, Node.js 24, npm 11  

### Objectives
Build a network threat detection and security audit platform that analyzes AWS VPC Flow Logs and Security Groups for security misconfigurations and threats.

### Technology Stack
- **Frontend:** React 18 + TypeScript 5 + Vite 5 + Tailwind CSS 4
- **Backend:** Python 3.12 + FastAPI 0.104+ + Pydantic 2 + SQLAlchemy 2
- **Database:** PostgreSQL 16 (planned, not yet implemented) with psycopg3 (async)
- **Testing:** pytest + pytest-asyncio (backend), Vitest (frontend)
- **Linting:** Ruff + Black + mypy (backend), ESLint + Prettier (frontend)

### Folder Structure (Actual)
```
D:\NetWatch
├── .gitignore
├── README.md
├── .coverage
├── .tmp/                          # Temporary upload storage
├── .venv/                         # Python virtual environment
├── .pytest_cache/
├── backend/                       # FastAPI backend
│   ├── app/
│   │   ├── main.py               # FastAPI entry point
│   │   ├── api/v1/
│   │   │   ├── router.py
│   │   │   └── endpoints/        # detection.py, ingestion.py, security_audit.py, health.py
│   │   ├── core/config.py        # Pydantic Settings configuration
│   │   ├── db/
│   │   │   ├── session.py        # SQLAlchemy session
│   │   │   └── models/flow_log.py # SQLAlchemy models
│   │   └── schemas/flow_log.py   # Pydantic schemas (API-level)
│   ├── tests/                     # 84 tests passing
│   ├── pyproject.toml
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
├── frontend/                      # React + TypeScript + Vite
│   ├── src/
│   │   ├── App.tsx               # Main app with 3 tabs (Detection/Ingestion/Security Audit)
│   │   ├── main.tsx
│   │   ├── index.css             # Tailwind CSS v4 import
│   │   └── App.css
│   ├── dist/                      # Production build output
│   ├── package.json
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── tsconfig.json
│   └── vite.config.ts
├── detection/                     # Rule-based threat detection engine
│   ├── rules.py                   # 5 detection rules + engine
│   └── __init__.py
├── ingestion/                     # VPC Flow Log parser
│   ├── parser.py                  # Streaming parser (JSON/JSONL/GZIP)
│   └── __init__.py
├── security_audit/                # Security Group analyzer
│   ├── analyzer.py                # 8 audit rules (ingress + egress)
│   └── __init__.py
├── database/                      # Database migrations (planned, empty)
├── datasets/
│   └── samples/
│       └── sample-flow-logs.json  # 8 synthetic flow log entries
├── docs/
│   ├── architecture.md
│   ├── requirements.md
│   ├── security.md
│   └── adr/
│       └── 001-006.md             # 6 Architecture Decision Records
├── infrastructure/
│   └── terraform/                 # Empty (planned)
├── scripts/                       # Empty (planned)
├── security_audit/                # Security Group analyzer (duplicate? see security_audit/)
├── shared/
│   └── netwatch_core/             # Shared canonical schema package
│       ├── schemas/flow_log.py    # Canonical FlowLogEntry schema
│       ├── pyproject.toml
│       └── README.md
├── tests/                         # (empty - tests are in backend/tests/)
├── .gitignore
├── README.md
├── .coverage
└── .pytest_cache/
```

---

## Completed Development Milestones

### Phase 1-3: Local Project Foundation (Completed ~Nov 9, 2026)
**Objective:** Prepare NetWatch project workspace and establish initial architecture.

**Completed:**
- Created modular directory structure
- Backend with FastAPI, SQLAlchemy, Pydantic
- Frontend with React, TypeScript, Tailwind CSS
- Detection engine with 5 default rules
- Flow log parser (JSON/JSONL/GZIP)
- Security group analyzer with 8 rules
- Unit tests (initially 11 passing)
- Sample datasets
- Configuration templates

**Files Created (Phase 1-3):**
- All directory structure
- Backend: `app/main.py`, `app/core/config.py`, `app/api/v1/*`, `app/db/*`, `app/schemas/flow_log.py`
- Frontend: `src/App.tsx`, `src/main.tsx`, `src/index.css`, `tailwind.config.js`, `postcss.config.js`
- Detection: `detection/rules.py`, `detection/__init__.py`
- Ingestion: `ingestion/parser.py`, `ingestion/__init__.py`
- Security Audit: `security_audit/analyzer.py`, `security_audit/__init__.py`
- Database models: `backend/app/db/models/flow_log.py`
- Tests: `backend/tests/test_*.py` (initial 11 tests)
- Config: `backend/.env.example`, `backend/pyproject.toml`, `backend/requirements.txt`
- Shared schema: `shared/netwatch_core/schemas/flow_log.py`
- Documentation: `README.md`, `docs/architecture.md`, `docs/requirements.md`, `docs/security.md`, `docs/adr/001-006.md`
- Config: `.gitignore`, `.env.example`

---

### Phase 5A: Core Reliability Improvement (Completed ~Nov 9, 2026)
**Objective:** Deep code audit and functional verification of Phase 3 foundation.

**Acceptance Gaps Resolved:**

| # | Issue | Resolution |
|---|-------|------------|
| 1 | Canonical schema location | Moved from `backend/app/schemas/` to `shared/netwatch_core/schemas/` as shared package `netwatch-core` |
| 2 | Streaming GZIP decompression | Implemented `IncrementalGZIPReader` class for streaming decompression without full in-memory copy |
| 3 | Upload limit configurable | Added `NETWATCH_MAX_FILE_SIZE`, `NETWATCH_MAX_RECORDS`, `NETWATCH_CHUNK_SIZE` to config |
| 4 | IP classification semantics | Separated `is_globally_routable()` (excludes docs) from `is_public_ip()` (includes docs for exposure detection) |
| 5 | Brute-force grouping | Changed from `(src, port)` to `(src, dst, port)` grouping |
| 6 | Ingestion error handling | Invalid JSON→400, Invalid GZIP→400, Empty file→400, Partial success→200 |
| 7 | Temp file cleanup | Verified cleanup on success, error, and exception paths |

**Files Modified (Phase 5A):**
- `ingestion/parser.py` - Added `IncrementalGZIPReader`, fixed EOFError handling
- `detection/rules.py` - Added `IPClassification` class, fixed `is_public_ip()`, corrected brute-force grouping
- `backend/app/core/config.py` - Added configurable upload limits
- `backend/app/api/v1/endpoints/ingestion.py` - Uses config, proper error handling
- `backend/app/api/v1/endpoints/detection.py` - Uses shared schema
- `backend/app/api/v1/endpoints/security_audit.py` - Egress support, IPv6, protocol -1
- `backend/app/core/config.py` - Added `MAX_FILE_SIZE`, `MAX_RECORDS`, `CHUNK_SIZE`
- `backend/.env.example` - Added ingestion limit env vars
- `backend/tests/test_ip_classification.py` - Updated tests for new semantics
- `detection/rules.py` - `is_public_ip()` clarification
- `ingestion/parser.py` - `IncrementalGZIPReader` with EOFError handling

**Files Created (Phase 5A):**
- `shared/netwatch_core/` - Complete shared package with pyproject.toml
- `backend/tests/test_ip_classification.py` - 45 tests
- `backend/tests/test_detection_engine.py` - 10 tests
- `backend/tests/test_ingestion_advanced.py` - 13 tests

---

## Phase 5B.1 Critical Defect Corrections (Completed ~Nov 10, 2026)
**Objective:** Independently verify and repair Phase 5B.1 (Database Persistence) implementation discovered defects.

**Defects Found & Fixed:**

| # | Defect | Root Cause | Fix | Files Changed |
|---|--------|-----------|-----|---------------|
| 1 | `shared/__init__.py` unimportable (null bytes) | UTF-16 LE BOM encoding | Re-saved as plain UTF-8 without BOM | `shared/__init__.py` |
| 2 | Writes never persisted | CRUD `flush()` only, no `commit()` | `get_db()` commits on success, rolls back on exception, closes session | `backend/app/db/session.py` |
| 3 | `SecurityGroupAudit.direction` missing | Column absent from model/migration | Added `direction` column + index; CRUD stores/filters/stats by it | `backend/app/db/models/flow_log.py`, `backend/app/db/crud.py` |
| 4 | `DetectionEvent.flow_log_id` no FK | Missing `ForeignKey` | Added `ForeignKey("flow_logs.id")` | `backend/app/db/models/flow_log.py` |
| 5 | Dev DB schema/version mismatch | `alembic_version` at head but no tables | Stamped base, upgraded head; all tables created, no data lost | `D:/NetWatch/netwatch.db` |
| 6 | Test DB polluted dev DB | CWD-relative test DB, mutated settings singleton | Isolated tempdir test DB; `get_db` dependency override | `backend/tests/conftest.py`, `backend/tests/test_database.py` |
| 7 | List endpoints 500 validation error | `response_model=List[dict]` returned dict | Changed `response_model` to `dict` | 3 endpoint files |

**New corrective Alembic migration:**
- `backend/alembic/versions/3f4a7b2c9d1e_add_direction_to_security_group_audits_.py`: adds `direction` column to `security_group_audits` and `flow_logs.id` FK to `detection_events`. Verified upgrade/downgrade/re-upgrade on disposable DB.

**New test file:**
- `backend/tests/test_database_corrections.py`: shared import, FastAPI import, commit persistence, rollback, cross-session persistence, direction filtering, audit stats, FK enforcement, migration lifecycle, dev DB protection, API regression.

**Verification Results:**
- Backend tests: 110 collected, 110 passed, 0 failed, 0 skipped
- Frontend build: SUCCESS
- Alembic upgrade/downgrade/re-upgrade: PASS (disposable DB)
- Dev DB: version `3f4a7b2c9d1e` (head), all 3 tables present, empty, untouched by tests

---

## Current Project State (as of 2026-11-09)

### Verified Working
- **Backend Tests:** 84 tests passing, 0 failed, 0 skipped (1 deprecation warning for pytest-asyncio)
- **Frontend Build:** Successful production build
- **Detection Engine:** All 5 rules functional (SSH, RDP, Data Exfiltration, Port Scan, Brute Force)
- **Ingestion:** JSON, JSONL, GZIP streaming parsing with proper error handling
- **Security Audit:** 8 rules (ingress + egress), IPv4/IPv6, protocol -1 support
- **IP Classification:** Proper separation of `is_globally_routable()` (excludes docs) vs `is_public_ip()` (includes docs for exposure detection)
- **Brute Force Grouping:** `(src, dst, port)` - separate targets don't combine
- **Upload Limits:** Configurable via `NETWATCH_MAX_FILE_SIZE` (default 500MB), `NETWATCH_MAX_RECORDS` (50000), `CHUNK_SIZE` (1MB)
- **Temp File Cleanup:** Verified on success, error, and exception paths
- **Temp File Cleanup on Client Cancellation:** Not testable with TestClient; `finally` block handles `CancelledError`

### Known Limitations
1. **Database layer not implemented** - Models exist but no persistence, migrations, or DI
2. **Authentication/Authorization** - Not implemented
3. **Rate limiting** - Not implemented
4. **Audit logging** - Not implemented
5. **Large JSON array parsing** - Loads entire document into memory (use JSONL for streaming)
6. **No authentication/authorization** - Phase 5B+
7. **No rate limiting** - Phase 5B+
8. **No audit logging** - Phase 5B+
9. **Brute-force/Port-scan state is per-request** - No persistence across requests
10. **GZIP decompression memory** - Chunked but full decompression before parsing (incremental line-by-line)
11. **Client cancellation not testable** with TestClient; `finally` block handles `CancelledError`

---
 
## Current Project State (as of 2026-11-10)
 
### Verified Working
- **Backend Tests:** 110 tests passing, 0 failed, 0 skipped (independently verified after Phase 5B.1 corrections)
- **Frontend Build:** Successful production build
- **Detection Engine:** All 5 rules functional (SSH, RDP, Data Exfiltration, Port Scan, Brute Force)
- **Ingestion:** JSON, JSONL, GZIP streaming parsing with proper error handling
- **Security Audit:** 8 rules (ingress + egress), IPv4/IPv6, protocol -1 support
- **Database Persistence:** SQLite with Alembic migrations, CRUD operations with commit/rollback, retrieval endpoints with pagination/filtering
- **IP Classification:** Proper separation of `is_globally_routable()` (excludes docs) vs `is_public_ip()` (includes docs for exposure detection)
- **Brute Force Grouping:** `(src, dst, port)` - separate targets don't combine
- **Upload Limits:** Configurable via `NETWATCH_MAX_FILE_SIZE` (default 500MB), `NETWATCH_MAX_RECORDS` (50000), `CHUNK_SIZE` (1MB)
- **Temp File Cleanup:** Verified on success, error, and exception paths
- **Temp File Cleanup on Client Cancellation:** Not testable with TestClient; `finally` block handles `CancelledError`
 
### Known Limitations
1. **Authentication/Authorization** - Not implemented (Phase 5B.2)
2. **Rate limiting** - Not implemented (Phase 5B.3)
3. **Audit logging** - Not implemented (Phase 5B.4)
5. **Large JSON array parsing** - Loads entire document into memory (use JSONL for streaming)
6. **No AWS integration** - Phase 5C+
6. **Brute-force/Port-scan state** - Per-request only
7. **Client cancellation not testable** with TestClient; `finally` block handles `CancelledError`
 
---
 
## Current Task
**Phase 5B.1 Complete - Independently verified and corrected - Ready for Phase 5B.2 Approval**
 
All Phase 5B.1 acceptance criteria satisfied. Ready for Phase 5B.2 (Authentication & Authorization) planning.
 
---
 
## Ordered Next Steps (Phase 5B.2+)
 
1. **Authentication & Authorization** (Phase 5B.2)
   - JWT-based authentication
   - API key support
   - Role-based access control (Admin, Analyst, Viewer)
 
2. **Rate Limiting** (Phase 5B.3)
   - Per-endpoint rate limits
   - Configurable via settings
 
3. **Audit Logging** (Phase 5B.4)
   - Structured request/response logging
   - Correlation IDs for traceability
 
4. **AWS Integration** (Phase 5C+)
   - S3 VPC Flow Log ingestion
   - EC2 Security Group API integration
   - Cross-account role support
   - Event-driven via SQS/Lambda
 
---
 
## Architecture & Technology Decisions
 
| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Frontend Framework** | React 18 + TypeScript + Vite | Modern, fast HMR, good TS support |
| **Styling** | Tailwind CSS 4 | Utility-first, small bundle, no runtime |
| **Backend Framework** | FastAPI | Fast, auto OpenAPI, Pydantic integration |
| **Validation** | Pydantic v2 | Fast, strict, good error messages |
| **ORM** | SQLAlchemy 2.0 | Sync support, mature, flexible |
| **Database** | PostgreSQL (prod) / SQLite (dev) | ACID, JSON support, mature |
| **Testing** | pytest + pytest-asyncio | Async support, fixtures, good ecosystem |
| **Shared Schema** | Separate `netwatch-core` package | Single source of truth, decoupled from backend |
| **Parsing** | Streaming JSONL + incremental GZIP | Memory efficient for large files |
| **Detection** | Rule-based with plugin architecture | Extensible, testable, explainable |
| **IP Classification** | Explicit special-use ranges | Accurate, uses `ipaddress` stdlib |
 
---
 
## Bugs, Defects & Fixes
 
| Issue | Root Cause | Fix |
|-------|------------|-----|
| GZIP full decompression | `_parse_gzipped_bytes` used `gz.read().decode()` | `IncrementalGZIPReader` streaming line-by-line |
| Brute-force overcounting | Grouped by `(src, port)` only | Group by `(src, dst, port)` |
| Documentation IPs flagged as public | `is_globally_routable` included docs | Separate `is_public_ip()` for exposure detection |
| Invalid JSON returned 200 | JSON decode error caught but returned partial | Return 400 for completely malformed input |
| Invalid GZIP returned 500 | `BadGzipFile` not caught | Catch `gzip.BadGzipFile` → 400 |
| Temp file not cleaned on error | No `finally` block | Added `finally` block with cleanup |
| Brute-force across time window | No timestamp pruning | `TimeWindowCounter` with `_prune()` |
| Port scan duplicate counting | Counted total REJECTs | Count distinct `dst_port` per source |
| Test count discrepancy | Miscalculated | Actual collected: 84 (not 85) |
| Security audit timestamp | ISO string passed to DateTime | Parse ISO string to datetime in CRUD |
| Missing tables in tests | Lifespan not triggered in tests | Added `setup_database` fixture with `create_all` |
 
---
 
## Outstanding Limitations & Deferred Work
 
1. **Authentication/Authorization** - Phase 5B.2
2. **Rate Limiting** - Phase 5B.3
3. **Audit Logging** - Phase 5B.4
4. **Large JSON Array Parsing** - Full memory load (use JSONL)
5. **AWS Integration** - Phase 5C+
6. **Brute-force/Port-scan State** - Per-request only
7. **Client Cancellation** - Not testable with TestClient
 
---
 
## Test Commands & Results
 
```bash
# Backend tests
cd D:\NetWatch\backend
.\.venv\Scripts\python -m pytest -v --tb=short
 
# With coverage
.\.venv\Scripts\python -m pytest --cov=app --cov-report=term-missing
 
# Frontend build
cd D:\NetWatch\frontend
npm run build
```
 
**Results:**
- 110 tests collected, 110 passed, 0 failed, 0 skipped (independently verified)
- Frontend build: SUCCESS (236KB JS, 17KB CSS gzipped)
- Alembic upgrade/downgrade/re-upgrade: PASS (disposable DB)
- Dev DB: version `3f4a7b2c9d1e` (head), all 3 tables present, empty, untouched by tests
 
---
 
*Last Updated: 2026-11-10*  
*Last Task Completed: Phase 5B.1 Database Persistence - Critical Defect Corrections (independently verified)*  
*Next Task: Phase 5B.2 Authentication & Authorization*