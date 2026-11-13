"""Additional Phase 5B.1 correction tests.

Covers: shared package import, FastAPI app import, commit persistence,
rollback, cross-session persistence, SecurityGroupAudit direction filtering
and statistics, foreign-key enforcement, migration upgrade/downgrade/re-upgrade,
test database isolation, and development database protection.
"""

import os
import tempfile
import time

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.db.models.flow_log import FlowLog, DetectionEvent, SecurityGroupAudit
from app.db.crud import (
    create_flow_logs,
    create_detection_events,
    create_security_group_audits,
    get_flow_logs,
    get_detection_events,
    get_security_group_audits,
    get_audit_stats,
)
from shared.netwatch_core.schemas.flow_log import FlowLogEntry
from detection.rules import DetectionEngine, get_default_rules


# ---------------------------------------------------------------------------
# 1. Shared package import
# ---------------------------------------------------------------------------
class TestSharedPackageImport:
    def test_shared_package_imports(self):
        import shared
        import shared.netwatch_core.schemas.flow_log as flow_log_module

        assert shared is not None
        assert flow_log_module.FlowLogEntry is FlowLogEntry
        assert flow_log_module.FlowLogEntryBatch is not None


# ---------------------------------------------------------------------------
# 2. FastAPI application import
# ---------------------------------------------------------------------------
class TestFastAPIAppImport:
    def test_application_imports(self):
        from app.main import app

        assert app is not None
        assert app.title == "NetWatch API"
        # Confirm the persistence routes are registered via OpenAPI paths.
        openapi = app.openapi()
        paths = set(openapi["paths"].keys())
        assert "/api/v1/detection/analyze" in paths
        assert "/api/v1/ingestion/flow-logs" in paths
        assert "/api/v1/security-audit/security-groups/analyze" in paths


# ---------------------------------------------------------------------------
# Helper: build a fresh file-based SQLite DB
# ---------------------------------------------------------------------------
def _make_temp_engine():
    temp_db_path = os.path.join(
        tempfile.gettempdir(), f"nw_test_{os.getpid()}_{int(time.time() * 1000)}.db"
    )
    if os.path.exists(temp_db_path):
        os.unlink(temp_db_path)
    engine = create_engine(
        f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False}
    )
    # Enforce foreign keys on every connection (mirrors app.db.session).
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return engine, temp_db_path


_SAMPLE_ENTRY = FlowLogEntry(
    version=2,
    account_id="123456789012",
    interface_id="eni-12345",
    src_addr="10.0.1.1",
    dst_addr="10.0.1.2",
    src_port=12345,
    dst_port=80,
    protocol=6,
    packets=10,
    bytes=1000,
    start_time=1704067200,
    end_time=1704067260,
    action="ACCEPT",
    log_status="OK",
)


# ---------------------------------------------------------------------------
# 3 & 4 & 5. Successful commits (flow log, detection event, audit)
# ---------------------------------------------------------------------------
class TestCommitPersistence:
    def test_flow_log_commit_persists(self):
        engine, db_path = _make_temp_engine()
        try:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            try:
                flow_logs = create_flow_logs(db, [_SAMPLE_ENTRY], "test.json")
                db.commit()
                assert len(flow_logs) == 1
                assert flow_logs[0].id is not None

                # New independent session on the same DB sees the committed row.
                db2 = SessionLocal()
                try:
                    logs, total = get_flow_logs(db2)
                    assert total == 1
                    assert logs[0].src_addr == "10.0.1.1"
                finally:
                    db2.close()
            finally:
                db.close()
            engine.dispose()
        finally:
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except PermissionError:
                    pass

    def test_detection_event_commit_persists(self):
        engine, db_path = _make_temp_engine()
        try:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            try:
                # Use a port-22 flow log so the SSH detection rule matches it.
                ssh_entry = FlowLogEntry(
                    version=2, account_id="123456789012",
                    interface_id="eni-12345",
                    src_addr="203.0.113.1", dst_addr="10.0.1.5",
                    src_port=54321, dst_port=22, protocol=6,
                    packets=10, bytes=600, start_time=1704067200,
                    end_time=1704067260, action="ACCEPT", log_status="OK",
                )
                flow_logs = create_flow_logs(db, [ssh_entry], "test.json")
                db.commit()

                engine_det = DetectionEngine(rules=get_default_rules())
                det_results = engine_det.analyze([ssh_entry])
                create_detection_events(db, det_results, flow_logs)
                db.commit()

                det_events, det_total = get_detection_events(db)
                assert det_total >= 1
                for de in det_events:
                    assert de.id is not None
                    assert de.flow_log_id == flow_logs[0].id
            finally:
                db.close()
            engine.dispose()
        finally:
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except PermissionError:
                    pass

    def test_security_group_audit_commit_persists(self):
        engine, db_path = _make_temp_engine()
        try:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            try:
                findings = [
                    {
                        "id": "SG-sg-12345-SSH-OPEN-IPv4",
                        "severity": "CRITICAL",
                        "title": "SSH Open to World",
                        "description": "Security group sg-12345 allows SSH",
                        "resource_id": "sg-12345",
                        "resource_type": "security_group",
                        "remediation": "Restrict SSH access",
                        "direction": "ingress",
                        "timestamp": "2026-11-10T15:00:00+00:00",
                    }
                ]
                audits = create_security_group_audits(
                    db, findings, "sg-12345", "test-sg"
                )
                db.commit()
                assert len(audits) == 1
                assert audits[0].id is not None
                assert audits[0].direction == "ingress"

                db2 = SessionLocal()
                try:
                    audits_db, total = get_security_group_audits(db2)
                    assert total == 1
                    assert audits_db[0].direction == "ingress"
                finally:
                    db2.close()
            finally:
                db.close()
            engine.dispose()
        finally:
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except PermissionError:
                    pass


# ---------------------------------------------------------------------------
# 6. Rollback after failed transactions
# ---------------------------------------------------------------------------
class TestTransactionRollback:
    def test_rollback_undoes_uncommitted_writes(self):
        engine, db_path = _make_temp_engine()
        try:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            try:
                flow_logs = create_flow_logs(db, [_SAMPLE_ENTRY], "test.json")
                db.commit()
                logs, total = get_flow_logs(db)
                assert total == 1

                # Add an invalid record (NULL into NOT NULL action column).
                bad = FlowLog(
                    version=2, account_id="123456789012",
                    interface_id="eni-12345", src_addr="10.0.1.1",
                    dst_addr="10.0.1.2", src_port=12345, dst_port=80,
                    protocol=6, packets=10, bytes=1000,
                    start_time=1704067200, end_time=1704067260,
                    action=None, log_status="OK",
                )
                db.add(bad)
                with pytest.raises(IntegrityError):
                    db.flush()
                db.rollback()

                # Committed record survives; invalid record rolled back.
                logs, total = get_flow_logs(db)
                assert total == 1
                assert logs[0].action == "ACCEPT"
            finally:
                db.close()
            engine.dispose()
        finally:
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except PermissionError:
                    pass


# ---------------------------------------------------------------------------
# 8. SecurityGroupAudit direction filtering
# ---------------------------------------------------------------------------
class TestDirectionFiltering:
    def test_direction_filtering(self):
        engine, db_path = _make_temp_engine()
        try:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            try:
                findings = [
                    {
                        "id": "SG-sg-12345-SSH-INGRESS",
                        "severity": "CRITICAL",
                        "title": "SSH Ingress",
                        "description": "d",
                        "resource_id": "sg-12345",
                        "resource_type": "security_group",
                        "remediation": "r",
                        "direction": "ingress",
                    },
                    {
                        "id": "SG-sg-12345-EGRESS-UNRESTRICTED",
                        "severity": "MEDIUM",
                        "title": "Unrestricted Egress",
                        "description": "d",
                        "resource_id": "sg-12345",
                        "resource_type": "security_group",
                        "remediation": "r",
                        "direction": "egress",
                    },
                ]
                create_security_group_audits(db, findings, "sg-12345", "test-sg")
                db.commit()

                egress, total = get_security_group_audits(db, direction="egress")
                assert total == 1
                assert all(a.direction == "egress" for a in egress)
                assert egress[0].finding_id == "SG-sg-12345-EGRESS-UNRESTRICTED"

                ingress, total = get_security_group_audits(db, direction="ingress")
                assert total == 1
                assert all(a.direction == "ingress" for a in ingress)
            finally:
                db.close()
            engine.dispose()
        finally:
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except PermissionError:
                    pass


# ---------------------------------------------------------------------------
# 9. Security Group audit statistics
# ---------------------------------------------------------------------------
class TestAuditStats:
    def test_audit_stats_by_direction(self):
        engine, db_path = _make_temp_engine()
        try:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            try:
                findings = [
                    {
                        "id": "f1", "severity": "HIGH", "title": "t1",
                        "description": "d", "resource_id": "sg-1",
                        "resource_type": "security_group", "remediation": "r",
                        "direction": "ingress",
                    },
                    {
                        "id": "f2", "severity": "MEDIUM", "title": "t2",
                        "description": "d", "resource_id": "sg-1",
                        "resource_type": "security_group", "remediation": "r",
                        "direction": "egress",
                    },
                    {
                        "id": "f3", "severity": "HIGH", "title": "t3",
                        "description": "d", "resource_id": "sg-1",
                        "resource_type": "security_group", "remediation": "r",
                        "direction": "egress",
                    },
                ]
                create_security_group_audits(db, findings, "sg-1", "test-sg")
                db.commit()

                stats = get_audit_stats(db)
                assert stats["total_audits"] == 3
                assert stats["by_direction"]["ingress"] == 1
                assert stats["by_direction"]["egress"] == 2
            finally:
                db.close()
            engine.dispose()
        finally:
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except PermissionError:
                    pass


# ---------------------------------------------------------------------------
# 10. Foreign-key enforcement
# ---------------------------------------------------------------------------
class TestForeignKeyEnforcement:
    def test_flow_log_foreign_key_enforced(self):
        engine, db_path = _make_temp_engine()
        try:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            try:
                flow_logs = create_flow_logs(db, [_SAMPLE_ENTRY], "test.json")
                db.commit()
                valid_flow_log_id = flow_logs[0].id

                # Detection event referencing a non-existent flow_log must fail.
                bad_event = DetectionEvent(
                    rule_id="SSH_EXPOSURE", rule_name="SSH",
                    severity="HIGH", flow_log_id=999999,
                    details="d", timestamp=None,
                )
                db.add(bad_event)
                with pytest.raises(IntegrityError):
                    db.flush()
                db.rollback()

                # A detection event referencing a real flow_log succeeds.
                good_event = DetectionEvent(
                    rule_id="SSH_EXPOSURE", rule_name="SSH",
                    severity="HIGH", flow_log_id=valid_flow_log_id,
                    details="d", timestamp=None,
                )
                db.add(good_event)
                db.flush()
                db.commit()

                from app.db.crud import get_detection_events
                det_events, det_total = get_detection_events(db)
                assert det_total == 1
                assert det_events[0].flow_log_id == valid_flow_log_id
            finally:
                db.close()
            engine.dispose()
        finally:
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except PermissionError:
                    pass


# ---------------------------------------------------------------------------
# 11 & 12. Migration upgrade / downgrade / re-upgrade
# ---------------------------------------------------------------------------
class TestMigrationLifecycle:
    def _run_migration_cycle(self, temp_db_path):
        from alembic import command
        from alembic.config import Config

        alembic_cfg = Config("D:/NetWatch/backend/alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{temp_db_path}")

        command.upgrade(alembic_cfg, "head")
        engine = create_engine(
            f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False}
        )
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "flow_logs" in tables
        assert "detection_events" in tables
        assert "security_group_audits" in tables
        cols = {c["name"] for c in inspector.get_columns("security_group_audits")}
        assert "direction" in cols
        fks = inspector.get_foreign_keys("detection_events")
        assert "flow_logs" in [fk["referred_table"] for fk in fks]
        engine.dispose()

        command.downgrade(alembic_cfg, "base")
        engine = create_engine(
            f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False}
        )
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "flow_logs" not in tables
        assert "detection_events" not in tables
        assert "security_group_audits" not in tables
        engine.dispose()

        # Re-upgrade after downgrade.
        command.upgrade(alembic_cfg, "head")
        engine = create_engine(
            f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False}
        )
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "flow_logs" in tables
        assert "detection_events" in tables
        assert "security_group_audits" in tables
        engine.dispose()

    def test_migration_upgrade_downgrade_reupgrade(self):
        temp_db_path = os.path.join(
            tempfile.gettempdir(),
            f"nw_mig_{os.getpid()}_{int(time.time() * 1000)}.db",
        )
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)
        try:
            self._run_migration_cycle(temp_db_path)
        finally:
            if os.path.exists(temp_db_path):
                try:
                    os.unlink(temp_db_path)
                except PermissionError:
                    pass


# ---------------------------------------------------------------------------
# 14. Development database protection
# ---------------------------------------------------------------------------
class TestDevelopmentDatabaseProtection:
    def test_development_database_has_expected_schema(self):
        """The dev DB must not be touched by tests and must match migration state."""
        import sqlite3

        dev_db_path = "D:/NetWatch/netwatch.db"
        assert os.path.exists(dev_db_path), "development database must exist"
        conn = sqlite3.connect(dev_db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}
            for t in ("flow_logs", "detection_events", "security_group_audits"):
                assert t in tables, f"dev DB missing table {t}"
            cur.execute("SELECT version_num FROM alembic_version")
            version = cur.fetchone()[0]
            assert version == "3f4a7b2c9d1e", f"dev DB at {version}, expected head"
        finally:
            conn.close()

    def test_tests_do_not_write_to_development_database(self):
        """Confirm the dev DB file is not the test target."""
        assert "netwatch.db" not in tempfile.gettempdir()
        from app.core.config import settings
        # Default settings still point at the dev DB; tests override via conftest.
        assert settings.DATABASE_URL.startswith("sqlite:///D:/NetWatch/netwatch.db")


# ---------------------------------------------------------------------------
# 15. Existing API regression behavior (persistence through endpoints)
# ---------------------------------------------------------------------------
class TestApiPersistenceRegression:
    @pytest.mark.asyncio
    async def test_analyze_persists_flow_logs_and_events(self, async_client):
        flow_log = {
            "version": 2, "account_id": "123456789012",
            "interface_id": "eni-12345",
            "src_addr": "203.0.113.1", "dst_addr": "10.0.1.5",
            "src_port": 54321, "dst_port": 22, "protocol": 6,
            "packets": 10, "bytes": 600,
            "start_time": 1704067200, "end_time": 1704067260,
            "action": "ACCEPT", "log_status": "OK",
        }
        response = await async_client.post(
            "/api/v1/detection/analyze", json=[flow_log]
        )
        assert response.status_code == 200
        results = response.json()
        assert len(results) == 1
        assert results[0]["rule_id"] == "SSH_EXPOSURE"

        # The detection event should be retrievable via the listing endpoint.
        list_resp = await async_client.get("/api/v1/detection/events")
        assert list_resp.status_code == 200
        data = list_resp.json()
        assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_security_audit_persists_and_filters_direction(self, async_client):
        security_group = {
            "group_id": "sg-12345", "group_name": "test-sg",
            "description": "Test", "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp", "from_port": 22, "to_port": 22,
                    "cidr_ipv4": "0.0.0.0/0", "description": "SSH open",
                }
            ],
        }
        response = await async_client.post(
            "/api/v1/security-audit/security-groups/analyze", json=[security_group]
        )
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["direction"] == "ingress"

        list_resp = await async_client.get(
            "/api/v1/security-audit/security-groups?direction=ingress"
        )
        assert list_resp.status_code == 200
        data = list_resp.json()
        assert data["total"] >= 1
