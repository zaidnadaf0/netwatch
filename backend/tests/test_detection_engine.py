"""Tests for brute force grouping and timestamp windowing."""

import pytest
from datetime import timezone
from detection.rules import (
    DetectionEngine, BruteForceRule, PortScanRule, 
    FlowLogEntry, DetectionContext
)


class TestBruteForceGrouping:
    """Test brute force detection with proper source-target-service grouping."""

    def test_brute_force_groups_by_src_dst_port(self):
        """Attempts against different target IPs should not combine."""
        base_time = 1704067200
        entries = []
        
        # 5 failed SSH attempts to target A (10.0.1.5)
        for i in range(5):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=22,
                protocol=6, packets=1, bytes=100, start_time=base_time + i*60, 
                end_time=base_time + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        # 5 failed SSH attempts to target B (10.0.1.6) - different target IP
        for i in range(5):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.6', src_port=60000+i, dst_port=22,
                protocol=6, packets=1, bytes=100, start_time=base_time + i*60, 
                end_time=base_time + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        engine = DetectionEngine()
        results = engine.analyze(entries)
        
        # Should NOT trigger because each target only has 5 attempts (< 10 threshold)
        bf_results = [r for r in results if r.rule_id == "BRUTE_FORCE"]
        assert len(bf_results) == 0, f"Expected 0 brute force findings, got {len(bf_results)}"

    def test_brute_force_triggers_per_target(self):
        """10 failed attempts to same target should trigger."""
        base_time = 1704067200
        entries = []
        
        # 10 failed SSH attempts to same target
        for i in range(10):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=22,
                protocol=6, packets=1, bytes=100, start_time=1704067200 + i*60, 
                end_time=1704067200 + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        engine = DetectionEngine()
        results = engine.analyze(entries)
        
        bf_results = [r for r in results if r.rule_id == "BRUTE_FORCE"]
        assert len(bf_results) == 1, f"Expected 1 brute force finding, got {len(bf_results)}"
        assert bf_results[0].details == "Brute force detected on port 22 from 203.0.113.50 to 10.0.1.5: 10 failed attempts within time window"

    def test_brute_force_different_ports_separate(self):
        """Failed attempts to different ports on same target should be separate."""
        base_time = 1704067200
        entries = []
        
        # 5 failed SSH attempts (port 22)
        for i in range(5):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=22,
                protocol=6, packets=1, bytes=100, start_time=1704067200 + i*60, 
                end_time=1704067200 + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        # 5 failed RDP attempts (port 3389) - different port
        for i in range(5):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=60000+i, dst_port=3389,
                protocol=6, packets=1, bytes=100, start_time=1704067200 + i*60, 
                end_time=1704067200 + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        engine = DetectionEngine()
        results = engine.analyze(entries)
        
        # Should NOT trigger because each port only has 5 attempts
        bf_results = [r for r in results if r.rule_id == "BRUTE_FORCE"]
        assert len(bf_results) == 0, f"Expected 0 brute force findings, got {len(bf_results)}"


class TestPortScanGrouping:
    """Test port scan detection with distinct destination port counting."""

    def test_port_scan_counts_distinct_ports(self):
        """Should count distinct destination ports from same source."""
        base_time = 1704067200
        entries = []
        
        # 20 unique ports from same source
        for i, port in enumerate(range(1000, 1020)):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=port,
                protocol=6, packets=1, bytes=100, start_time=1704067200 + i*60, 
                end_time=1704067200 + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        engine = DetectionEngine()
        results = engine.analyze(entries)
        
        ps_results = [r for r in results if r.rule_id == "PORT_SCAN"]
        assert len(ps_results) == 1
        assert "20 unique ports targeted" in ps_results[0].details

    def test_port_scan_duplicate_ports_not_counted(self):
        """Duplicate ports should not increase unique port count."""
        base_time = 1704067200
        entries = []
        
        # 20 REJECTs but only 10 unique ports (each port hit twice)
        for i in range(10):
            for _ in range(2):
                entries.append(FlowLogEntry(
                    version=2, account_id='123456789012', interface_id='eni-test',
                    src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=1000+i,
                    protocol=6, packets=1, bytes=100, start_time=1704067200 + i*60, 
                    end_time=1704067200 + i*60 + 60, action='REJECT', log_status='OK'
                ))
        
        engine = DetectionEngine()
        results = engine.analyze(entries)
        
        ps_results = [r for r in results if r.rule_id == "PORT_SCAN"]
        assert len(ps_results) == 0, "Should not trigger with only 10 unique ports"


class TestTimestampWindowing:
    """Test timestamp-based windowing behavior."""

    def test_window_boundary_port_scan(self):
        """Events outside the time window should not contribute."""
        base_time = 1704067200
        window = 3600  # 1 hour
        entries = []
        
        # 10 ports in first window
        for i, port in enumerate(range(1000, 1010)):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=port,
                protocol=6, packets=1, bytes=100, start_time=base_time + i*60, 
                end_time=base_time + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        # 10 ports in second window (1 hour + 1 minute later)
        for i, port in enumerate(range(2000, 2010)):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=port,
                protocol=6, packets=1, bytes=100, start_time=base_time + 3660 + i*60, 
                end_time=base_time + 3660 + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        engine = DetectionEngine(time_window_seconds=3600)
        results = engine.analyze(entries)
        
        ps_results = [r for r in results if r.rule_id == "PORT_SCAN"]
        assert len(ps_results) == 0, f"Expected 0 findings (split across windows), got {len(ps_results)}"

    def test_window_boundary_brute_force(self):
        """Brute force attempts outside window should not combine."""
        base_time = 1704067200
        entries = []
        
        # 5 attempts in first window
        for i in range(5):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=22,
                protocol=6, packets=1, bytes=100, start_time=base_time + i*60, 
                end_time=base_time + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        # 5 attempts in second window (outside 1-hour window)
        for i in range(5):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=22,
                protocol=6, packets=1, bytes=100, start_time=1704067200 + 3660 + i*60, 
                end_time=1704067200 + 3660 + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        engine = DetectionEngine(time_window_seconds=3600)
        results = engine.analyze(entries)
        
        bf_results = [r for r in results if r.rule_id == "BRUTE_FORCE"]
        assert len(bf_results) == 0, f"Expected 0 findings (split across windows), got {len(bf_results)}"

    def test_order_independence(self):
        """Results should be deterministic regardless of input ordering."""
        base_time = 1704067200
        entries = []
        
        # Create 10 failed SSH attempts
        for i in range(10):
            entries.append(FlowLogEntry(
                version=2, account_id='123456789012', interface_id='eni-test',
                src_addr='203.0.113.50', dst_addr='10.0.1.5', src_port=50000+i, dst_port=22,
                protocol=6, packets=1, bytes=100, start_time=base_time + i*60, 
                end_time=base_time + i*60 + 60, action='REJECT', log_status='OK'
            ))
        
        # Shuffle entries
        import random
        random.seed(42)
        shuffled = entries.copy()
        random.shuffle(shuffled)
        
        engine = DetectionEngine()
        results1 = engine.analyze(entries)
        results2 = engine.analyze(shuffled)
        
        # Both should produce same results
        bf1 = sorted([r.rule_id for r in results1 if r.rule_id == "BRUTE_FORCE"])
        bf2 = sorted([r.rule_id for r in results2 if r.rule_id == "BRUTE_FORCE"])
        assert bf1 == bf2, "Results should be deterministic regardless of input order"


class TestDetectionContext:
    """Test DetectionContext directly."""

    def test_context_prunes_old_entries(self):
        """Context should prune entries outside the time window."""
        context = DetectionContext(time_window_seconds=3600)
        base_time = 1704067200
        
        # Add entry at base time
        context.record_port_scan_attempt('203.0.113.50', 22, base_time)
        context.record_port_scan_attempt('203.0.113.50', 23, base_time)
        
        # Advance time beyond window
        context._port_scan_counters['203.0.113.50']._prune(base_time + 3601)
        
        count = context.get_port_scan_count('203.0.113.50', base_time + 3601)
        assert count == 0, "Old entries should be pruned"

    def test_context_keeps_recent_entries(self):
        """Context should keep entries within the time window."""
        context = DetectionContext(time_window_seconds=3600)
        base_time = 1704067200
        
        context.record_port_scan_attempt('203.0.113.50', 22, base_time)
        context.record_port_scan_attempt('203.0.113.50', 23, base_time)
        
        count = context.get_port_scan_count('203.0.113.50', base_time + 1800)
        assert count == 2, "Recent entries should be kept"