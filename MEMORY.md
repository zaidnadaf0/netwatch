# NetWatch Project Memory

## Project Purpose
Network threat detection and security audit platform for AWS VPC Flow Logs and Security Groups.

## Workspace Location
`D:\NetWatch`

## Technology Stack
- **Frontend:** React 18 + TypeScript 5 + Vite 5 + Tailwind CSS 4
- **Backend:** Python 3.12 + FastAPI 0.104+ + Pydantic 2 + SQLAlchemy 2
- **Database:** PostgreSQL 16 (planned) with psycopg3 (async)
- **Testing:** pytest + pytest-asyncio (backend), Vitest (frontend)
- **Linting:** Ruff + Black + mypy (backend), ESLint + Prettier (frontend)

## Current Status
- **Completed:** Phases 1-3 (Local Foundation), Phase 5A (Core Reliability), Phase 5B.1 (Database Persistence)
- **Backend Tests:** 110 passing, 0 failed, 0 skipped
- **Frontend Build:** Successful
- **Phase 5B.1:** COMPLETE and independently verified - ready for Phase 5B.2 approval

## Last Completed Task
**Phase 5B.1 Database Persistence Implementation - Critical Defect Corrections (2026-11-10)**
- All 110 backend tests passing (was 84 reported but non-collectable due to encoding defect)
- Frontend production build successful
- SQLite development database with Alembic migrations reconciled (version 3f4a7b2c9d1e = head)
- Incremental GZIP decompression implemented
- Configurable upload limits (default 500MB)
- IP classification semantics corrected
- Brute-force grouping fixed to `(src, dst, port)`
- Temp file cleanup verified on all paths
- Database persistence for flow logs, detection events, security group audits (commit on success)
- Alembic migrations with SQLite/PostgreSQL compatibility (upgrade/downgrade/re-upgrade verified)
- Retrieval endpoints with pagination and filtering (response_model fixed to match paginated dict return)

## Critical Defects Fixed (Phase 5B.1 correction)
| # | Defect | Fix | Files Changed |
|---|--------|-----|---------------|
| 1 | `shared/__init__.py` UTF-16 LE BOM with null bytes blocked all imports | Re-saved as plain UTF-8 without BOM | `shared/__init__.py` |
| 2 | CRUD `flush()` only, no `commit()` — writes never persisted | `get_db()` now commits on success / rolls back on exception / always closes | `backend/app/db/session.py` |
| 3 | `SecurityGroupAudit` missing `direction` column (referenced by CRUD/endpoints) | Added `direction` column + index; CRUD stores/filters it; `get_audit_stats` groups by it | `backend/app/db/models/flow_log.py`, `backend/app/db/crud.py` |
| 4 | `DetectionEvent.flow_log_id` no ForeignKey | Added `ForeignKey("flow_logs.id")` | `backend/app/db/models/flow_log.py` |
| 5 | Dev DB `alembic_version` stamped at head but no tables existed | Stamped to base, upgraded to head (created tables + applied corrective migration). No data lost. | `D:/NetWatch/netwatch.db` |
| 6 | Test DB CWD-relative, mutated `settings.DATABASE_URL` singleton, wrong alembic assertion | Isolated tempdir test DB; `get_db` dependency override; fixed isolation test | `backend/tests/conftest.py`, `backend/tests/test_database.py` |
| 7 | List endpoints `response_model=List[dict]` but returned paginated dict | Changed `response_model` to `dict` | 3 endpoint files |

### New corrective Alembic migration
- `backend/alembic/versions/3f4a7b2c9d1e_add_direction_to_security_group_audits_.py`: adds `direction` column to `security_group_audits` and `flow_logs.id` FK to `detection_events`. Verified upgrade/downgrade/re-upgrade on disposable DB.

### New test file
- `backend/tests/test_database_corrections.py`: shared import, FastAPI import, commit persistence (flow log/detection/audit), rollback, cross-session persistence, direction filtering, audit stats, FK enforcement, migration upgrade/downggrade/re-upgrade, dev DB protection, API regression.

## Current Task
**Phase 5B.1 Complete - Awaiting Phase 5B.2 Approval**

## Next Phase: Phase 5B.2
**Planned Steps:**
1. Authentication & Authorization (JWT + API Keys + RBAC)
2. Rate Limiting (per-endpoint)
3. Audit Logging (structured logging + correlation IDs)
5. AWS Integration (S3, EC2, SQS, Lambda) - Phase 5C+

## Architecture Decisions (Key)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Shared Schema | `shared/netwatch_core/schemas/flow_log.py` | Single source of truth, decoupled from backend |
| Parsing | Streaming JSONL + Incremental GZIP | Memory efficient for large files |
| Detection | Rule-based plugin architecture | Extensible, testable, explainable |
| IP Classification | Explicit special-use ranges via `ipaddress` | Accurate, stdlib-based |
| Brute Force Grouping | `(src, dst, port)` | Separate targets don't combine |
| Ingestion | Streaming upload to temp file + streaming parse | Bounded memory |

## Critical Restrictions
- **NO** Docker/PostgreSQL installation without approval
- **NO** AWS credentials/configuration without approval  
- **NO** Deployment without approval
- **NO** Git commits/pushes without approval
- **NO** New dependencies without approval
- **MODIFY ONLY** `D:\NetWatch`

## How to Resume Development

1. **Read this MEMORY.md** first
2. **Read PROJECT_LOG.md** for full history
3. **Check Git status** (though not a git repo currently)
4. **Inspect relevant source files** for the task
5. **Run tests** to verify baseline: `cd D:\NetWatch\backend && .\.venv\Scripts\python -m pytest -v`
6. **Check frontend build**: `cd D:\NetWatch\frontend && npm run build`

## Key Commands
```bash
# Backend tests
cd D:\NetWatch\backend
.\.venv\Scripts\python -m pytest -v --tb=short

# With coverage
.\.venv\Scripts\python -m pytest --cov=app --cov-report=term-missing

# Frontend build
cd D:\NetWatch\frontend
npm run build

# Run backend server
cd D:\NetWatch\backend
.\.venv\Scripts\python -m uvicorn app.main:app --reload
```

## Environment Setup
- Python 3.12.10 in `D:\NetWatch\.venv`
- Node.js 24.11.0 in `D:\NetWatch\frontend\node_modules`
- Virtual environment: `D:\NetWatch\.venv\Scripts\activate`

## Important File Paths
- Canonical schema: `D:\NetWatch\shared\netwatch_core\schemas\flow_log.py`
- Detection engine: `D:\NetWatch\detection\rules.py`
- Ingestion parser: `D:\NetWatch\ingestion\parser.py`
- Security audit: `D:\NetWatch\security_audit\analyzer.py`
- Backend config: `D:\NetWatch\backend\app\core\config.py`
- API endpoints: `D:\NetWatch\backend\app\api\v1\endpoints\`
- Tests: `D:\NetWatch\backend\tests\`
- Frontend: `D:\NetWatch\frontend\src\App.tsx`

## Verification Checklist (Phase 5B.1 Complete & Verified)
- [x] 110 backend tests passing (0 failed, 0 skipped)
- [x] Frontend builds successfully
- [x] Incremental GZIP decompression implemented
- [x] Configurable upload limits (default 500MB)
- [x] IP classification semantics correct
- [x] Brute-force grouping by (src, dst, port)
- [x] Temp file cleanup on all paths
- [x] JSONL streaming, GZIP incremental, JSON array full-load
- [x] SQLite development database with Alembic migrations (version 3f4a7b2c9d1e = head)
- [x] Database persistence: commit on success, rollback on exception, sessions closed
- [x] Alembic migrations upgrade/downgrade/re-upgrade verified on disposable DB
- [x] Retrieval endpoints with pagination, filtering, ordering (response_model fixed)
- [x] Dev DB tables and migration state agree; dev DB untouched by tests
- [x] Test database isolated in tempdir, separate from netwatch.db

## Unresolved Issues / Risks
1. **No authentication** - Phase 5B.2
2. **No rate limiting** - Phase 5B.3
3. **No audit logging** - Phase 5B.4
4. **JSON array full-load** - Use JSONL for large files
5. **No AWS integration** - Future phase
4. **Client cancellation** - Not testable with TestClient
5. **Brute-force/Port-scan state** - Per-request only

---

*Last Updated: 2026-11-10*  
*Phase 5B.1 Complete - Ready for Phase 5B.2*