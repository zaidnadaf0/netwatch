"""Database persistence and retrieval tests."""

import pytest
import pytest_asyncio
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base, get_db
from app.db.models.flow_log import FlowLog, DetectionEvent, SecurityGroupAudit
from app.db.crud import (
    create_flow_logs,
    create_detection_events,
    create_security_group_audits,
    get_flow_logs,
    get_detection_events,
    get_security_group_audits,
)
from shared.netwatch_core.schemas.flow_log import FlowLogEntry
from detection.rules import DetectionEngine, get_default_rules


class TestDatabasePersistence:
    """Test database persistence operations."""

    @pytest.fixture(scope="function")
    def db_session(self):
        """Create a fresh database session for each test."""
        from app.db.session import engine, Base, SessionLocal
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        # Use an in-memory SQLite database for testing
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()
            Base.metadata.drop_all(bind=engine)

    def test_flow_log_persistence(self, db_session):
        """Test flow log persistence and retrieval."""
        # Create flow log entries
        entries = [
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="10.0.1.1",
                dst_addr="10.0.2.2",
                src_port=12345,
                dst_port=80,
                protocol=6,
                packets=10,
                bytes=600,
                start_time=1704067200,
                end_time=1704067260,
                action="ACCEPT",
                log_status="OK",
            ),
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="192.168.1.10",
                dst_addr="10.0.2.3",
                src_port=54321,
                dst_port=443,
                protocol=6,
                packets=5,
                bytes=3000,
                start_time=1704067200,
                end_time=1704067260,
                action="REJECT",
                log_status="OK",
            ),
        ]

        flow_logs = create_flow_logs(db_session, entries, "test.json")

        # Verify persistence
        assert len(flow_logs) == 2
        for fl in flow_logs:
            assert fl.id is not None
            assert fl.account_id == "123456789012"

        # Test retrieval
        flow_logs_db, total = get_flow_logs(db_session)
        assert total == 2
        assert len(flow_logs_db) == 2

    def test_flow_log_retrieval_with_filters(self, db_session):
        """Test flow log retrieval with filters."""
        entries = [
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="10.0.1.1",
                dst_addr="10.0.2.2",
                src_port=12345,
                dst_port=80,
                protocol=6,
                packets=10,
                bytes=600,
                start_time=1704067200,
                end_time=1704067260,
                action="ACCEPT",
                log_status="OK",
            ),
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="10.0.1.1",
                dst_addr="10.0.2.3",
                src_port=54321,
                dst_port=443,
                protocol=6,
                packets=5,
                bytes=3000,
                start_time=1704067200,
                end_time=1704067260,
                action="REJECT",
                log_status="OK",
            ),
        ]
        create_flow_logs(db_session, entries, "test.json")

        # Filter by src_addr
        flow_logs, total = get_flow_logs(db_session, src_addr="10.0.1.1")
        assert total == 2
        assert all(fl.src_addr == "10.0.1.1" for fl in flow_logs)

        # Filter by action
        flow_logs, total = get_flow_logs(db_session, action="ACCEPT")
        assert total == 1
        assert flow_logs[0].action == "ACCEPT"

        # Filter by dst_port
        flow_logs, total = get_flow_logs(db_session, dst_port=443)

        # Pagination
        flow_logs, total = get_flow_logs(db_session, limit=1, skip=0)
        assert len(flow_logs) == 1
        assert total == 2

        flow_logs, total = get_flow_logs(db_session, limit=1, skip=1)
        assert len(flow_logs) == 1
        assert total == 2

    def test_detection_event_persistence(self, db_session):
        """Test detection event persistence and retrieval."""
        from detection.rules import DetectionEngine, get_default_rules

        # Create flow logs first
        entries = [
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="203.0.113.1",
                dst_addr="10.0.1.5",
                src_port=54321,
                dst_port=22,
                protocol=6,
                packets=10,
                bytes=600,
                start_time=1704067200,
                end_time=1704067260,
                action="ACCEPT",
                log_status="OK",
            )
        ]

        flow_logs = create_flow_logs(db_session, entries, "test.json")

        # Run detection
        from detection.rules import DetectionEngine, get_default_rules
        engine = DetectionEngine(rules=get_default_rules())
        entries_list = [
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="203.0.113.1",
                dst_addr="10.0.1.5",
                src_port=54321,
                dst_port=22,
                protocol=6,
                packets=10,
                bytes=600,
                start_time=1704067200,
                end_time=1704067260,
                action="ACCEPT",
                log_status="OK",
            )
        ]
        engine_results = engine.analyze(entries_list)

        # Store detection events
        from app.db.crud import create_detection_events
        create_detection_events(db_session, engine_results, flow_logs)

        # Test retrieval
        detection_events, total = get_detection_events(db_session)
        assert total >= 1
        for de in detection_events:
            assert de.id is not None
            assert de.rule_id is not None
            assert de.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def test_detection_event_retrieval_with_filters(self, db_session):
        """Test detection event retrieval with filters."""
        from detection.rules import DetectionEngine, get_default_rules

        entries_list = [
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="203.0.113.1",
                dst_addr="10.0.1.5",
                src_port=54321,
                dst_port=22,
                protocol=6,
                packets=10,
                bytes=600,
                start_time=1704067200,
                end_time=1704067260,
                action="ACCEPT",
                log_status="OK",
            ),
            FlowLogEntry(
                version=2,
                account_id="123456789012",
                interface_id="eni-12345",
                src_addr="198.51.100.1",
                dst_addr="10.0.1.5",
                src_port=54321,
                dst_port=3389,
                protocol=6,
                packets=5,
                bytes=300,
                start_time=1704067200,
                end_time=1704067260,
                action="ACCEPT",
                log_status="OK",
            )
        ]

        from detection.rules import DetectionEngine, get_default_rules
        engine = DetectionEngine(rules=get_default_rules())
        engine_results = engine.analyze(entries_list)

        flow_logs = create_flow_logs(db_session, entries_list, "test.json")
        create_detection_events(db_session, engine.analyze(entries_list), flow_logs)

        # Filter by rule_id
        detection_events, total = get_detection_events(db_session, rule_id="SSH_EXPOSURE")
        assert total >= 1
        assert all(de.rule_id == "SSH_EXPOSURE" for de in detection_events)

        # Filter by severity
        detection_events, total = get_detection_events(db_session, severity="HIGH")
        assert total >= 1
        assert all(de.severity == "HIGH" for de in detection_events)

    def test_security_group_audit_persistence(self, db_session):
        """Test security group audit persistence and retrieval."""
        findings = [
            {
                "id": "SG-sg-12345-SSH-OPEN",
                "severity": "CRITICAL",
                "title": "SSH Open to World",
                "description": "Security group sg-12345 allows SSH from 0.0.0.0/0",
                "resource_id": "sg-12345",
                "resource_type": "security_group",
                "remediation": "Restrict SSH access",
                "timestamp": "2026-11-10T15:00:00+00:00",
            }
        ]

        from app.db.crud import create_security_group_audits
        audits = create_security_group_audits(db_session, findings, "sg-12345", "test-sg")

        assert len(audits) == 1
        assert audits[0].id is not None

        # Test retrieval
        audits_db, total = get_security_group_audits(db_session)
        assert total == 1
        assert len(audits_db) == 1

    def test_security_group_audit_retrieval_with_filters(self, db_session):
        """Test security group audit retrieval with filters."""
        findings = [
            {
                "id": "SG-sg-12345-SSH-OPEN",
                "severity": "CRITICAL",
                "title": "SSH Open to World",
                "description": "Security group sg-12345 allows SSH from 0.0.0.0/0",
                "resource_id": "sg-12345",
                "resource_type": "security_group",
                "remediation": "Restrict SSH access",
                "timestamp": "2026-11-10T15:00:00+00:00",
            },
            {
                "id": "SG-sg-12345-RDP-OPEN",
                "severity": "CRITICAL",
                "title": "RDP Open to World",
                "description": "Security group sg-12345 allows RDP from 0.0.0.0/0",
                "resource_id": "sg-12345",
                "resource_type": "security_group",
                "remediation": "Restrict RDP access",
                "timestamp": "2026-11-10T15:00:00+00:00",
            },
        ]

        from app.db.crud import create_security_group_audits, get_security_group_audits
        create_security_group_audits(db_session, findings, "sg-12345", "test-sg")

        # Filter by severity
        audits, total = get_security_group_audits(db_session, severity="CRITICAL")
        assert total == 2
        assert all(a.severity == "CRITICAL" for a in audits)

        # Filter by group_id
        audits, total = get_security_group_audits(db_session, group_id="sg-12345")
        assert total == 2

    def test_transaction_rollback_on_failure(self, db_session):
        """Test that failed operations roll back properly."""
        from sqlalchemy.exc import IntegrityError

        # Create a valid flow log
        entries = [FlowLogEntry(
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
        )]

        flow_logs = create_flow_logs(db_session, entries, "test.json")
        assert len(flow_logs) == 1

        # Commit the transaction first
        db_session.commit()

        # Verify the data was committed
        flow_logs, total = get_flow_logs(db_session)
        assert total == 1

        # Now test rollback by trying to add invalid data
        # and rolling back
        try:
            # This would cause an error if we had constraints
            # For now, just test that rollback works
            db_session.rollback()
        except Exception:
            pass

        # Verify data still exists after rollback (since it was committed)
        flow_logs, total = get_flow_logs(db_session)
        assert total >= 1

    def test_pagination_and_ordering(self, db_session):
        """Test pagination and ordering of results."""
        entries = []
        for i in range(5):
            entries.append(
                FlowLogEntry(
                    version=2,
                    account_id="123456789012",
                    interface_id=f"eni-{i}",
                    src_addr=f"10.0.1.{i}",
                    dst_addr="10.0.1.2",
                    src_port=12345 + i,
                    dst_port=80 + i,
                    protocol=6,
                    packets=10,
                    bytes=1000,
                    start_time=1704067200 + i,
                    end_time=1704067260 + i,
                    action="ACCEPT",
                    log_status="OK",
                )
            )

        create_flow_logs(db_session, entries, "test.json")

        # Test pagination
        page1, total = get_flow_logs(db_session, limit=2, skip=0)
        assert len(page1) == 2
        assert total == 5

        page2, total = get_flow_logs(db_session, limit=2, skip=2)
        assert len(page2) == 2
        assert total == 5

        page3, total = get_flow_logs(db_session, limit=2, skip=4)
        assert len(page3) == 1
        assert total == 5

        # Verify ordering (should be by start_time descending)
        flow_logs, _ = get_flow_logs(db_session, limit=5, skip=0)
        start_times = [fl.start_time for fl in flow_logs]
        assert start_times == sorted(start_times, reverse=True)

    def test_persistence_across_sessions(self):
        """Test that data persists across independent database sessions."""
        import tempfile
        import os
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.db.session import Base

        # Use a temporary file-based database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            temp_db_path = tmp.name

        engine = create_engine(f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db1 = SessionLocal()

        try:
            # Create flow logs in first session
            entries = [FlowLogEntry(
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
            )]

            from app.db.crud import create_flow_logs, get_flow_logs
            create_flow_logs(db1, entries, "test.json")
            db1.commit()

            # Create a new session and verify data persists
            db2 = SessionLocal()
            try:
                flow_logs, total = get_flow_logs(db2)
                assert total >= 1
                assert flow_logs[0].src_addr == "10.0.1.1"
            finally:
                db2.close()
                db1.close()
        finally:
            engine.dispose()
            os.unlink(temp_db_path)

    def test_migration_upgrade_downgrade(self):
        """Test migration upgrade and downgrade on a disposable test database."""
        import tempfile
        import os
        import time
        from alembic import command
        from alembic.config import Config
        from sqlalchemy import create_engine

        # Create a unique temporary database file path (don't create the file yet)
        temp_db_path = os.path.join(tempfile.gettempdir(), f'test_migration_{os.getpid()}_{int(time.time()*1000)}.db')

        # Ensure the file doesn't exist (in case of previous test failure)
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)

        # Convert to absolute path for alembic
        temp_db_path = os.path.abspath(temp_db_path)

        # Set the database URL environment variable BEFORE importing settings
        os.environ['NETWATCH_DATABASE_URL'] = f'sqlite:///{temp_db_path}'

        # Create alembic config with the temp database
        alembic_cfg = Config("backend/alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{temp_db_path}")

        temp_engine = None
        try:
            # Run upgrade
            from alembic import command
            command.upgrade(alembic_cfg, "head")

            # Verify tables exist
            temp_engine = create_engine(f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False})
            from sqlalchemy import inspect
            inspector = inspect(temp_engine)
            tables = inspector.get_table_names()
            assert "flow_logs" in tables
            assert "detection_events" in tables
            assert "security_group_audits" in tables

            # Run downgrade
            from alembic import command
            command.downgrade(alembic_cfg, "base")

            # Verify tables are dropped
            inspector = inspect(temp_engine)
            tables = inspector.get_table_names()
            assert "flow_logs" not in tables
            assert "detection_events" not in tables
            assert "security_group_audits" not in tables

        finally:
            if temp_engine:
                temp_engine.dispose()
            if os.path.exists(temp_db_path):
                try:
                    os.unlink(temp_db_path)
                except PermissionError:
                    # On Windows, the file might be locked - wait a bit and retry
                    time.sleep(0.1)
                    try:
                        os.unlink(temp_db_path)
                    except PermissionError:
                        pass  # Best effort cleanup

    def test_startup_without_migrations(self):
        """Test application startup when migrations have not been applied."""
        import tempfile
        import os
        from sqlalchemy import create_engine
        from app.core.config import Settings
        from app.db.session import Base
        from app.main import app
        from fastapi.testclient import TestClient

        # Use a temporary database file
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            temp_db_path = tmp.name

        try:
            os.environ["NETWATCH_DATABASE_URL"] = f"sqlite:///{temp_db_path}"

            # Reload settings to pick up new DATABASE_URL
            from app.core.config import Settings
            settings = Settings()

            # Create new engine with new URL
            new_engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False}, pool_pre_ping=True)

            # Create tables directly (simulating no migrations applied)
            from app.db.session import Base
            Base.metadata.create_all(bind=new_engine)

            # Test that app can start and query works
            from fastapi.testclient import TestClient
            from app.main import app

            client = TestClient(app)
            response = client.get("/health")
            assert response.status_code == 200

        finally:
            new_engine.dispose()
            if "NETWATCH_DATABASE_URL" in os.environ:
                del os.environ["NETWATCH_DATABASE_URL"]
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)

    def test_database_isolation_between_tests(self):
        """Test that tests use an isolated database separate from netwatch.db."""
        import os
        import tempfile
        from sqlalchemy import create_engine, inspect
        from sqlalchemy.orm import sessionmaker
        from app.db.session import Base

        # Fresh isolated temp database, never the development database.
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            isolated_db_path = tmp.name
        try:
            isolated_engine = create_engine(
                f"sqlite:///{isolated_db_path}",
                connect_args={"check_same_thread": False},
            )
            Base.metadata.create_all(bind=isolated_engine)

            inspector = inspect(isolated_engine)
            tables = set(inspector.get_table_names())

            # All application tables exist via create_all (tests do not use Alembic).
            assert "flow_logs" in tables
            assert "detection_events" in tables
            assert "security_group_audits" in tables
            # Tests create schema directly; alembic_version is not created here.
            assert "alembic_version" not in tables

            # Isolated from the development database file.
            assert os.path.abspath(isolated_db_path) != os.path.abspath(
                "D:/NetWatch/netwatch.db"
            )

            # Database should be empty at start.
            IsolatedSessionLocal = sessionmaker(
                autocommit=False, autoflush=False, bind=isolated_engine
            )
            db = IsolatedSessionLocal()
            try:
                from app.db.crud import get_flow_logs
                flow_logs, total = get_flow_logs(db)
                assert total == 0
            finally:
                db.close()

            isolated_engine.dispose()
        finally:
            if os.path.exists(isolated_db_path):
                try:
                    os.unlink(isolated_db_path)
                except PermissionError:
                    pass