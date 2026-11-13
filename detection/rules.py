"""Detection rules and engine with timestamp-based windowing and IP classification."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from datetime import datetime, timezone
from enum import Enum
from collections import defaultdict
import ipaddress

from shared.netwatch_core.schemas.flow_log import FlowLogEntry


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class DetectionResult:
    """Detection result."""
    rule_id: str
    rule_name: str
    severity: Severity
    timestamp: datetime
    flow_log: FlowLogEntry
    details: str


@dataclass
class DetectionRule:
    """Detection rule definition."""
    id: str
    name: str
    description: str
    severity: Severity
    enabled: bool = True

    def match(self, entry: FlowLogEntry, context: Optional["DetectionContext"] = None) -> Optional[DetectionResult]:
        """Check if rule matches the flow log entry."""
        raise NotImplementedError


class IPClassification:
    """Explicit IP address classification with special-use range handling."""
    
    # Special-use IPv4 ranges that are NOT globally routable
    IPV4_SPECIAL_RANGES = [
        ipaddress.IPv4Network("0.0.0.0/8"),          # "This" network
        ipaddress.IPv4Network("10.0.0.0/8"),         # RFC1918 private
        ipaddress.IPv4Network("100.64.0.0/10"),      # Carrier-grade NAT
        ipaddress.IPv4Network("127.0.0.0/8"),        # Loopback
        ipaddress.IPv4Network("169.254.0.0/16"),     # Link-local
        ipaddress.IPv4Network("172.16.0.0/12"),      # RFC1918 private
        ipaddress.IPv4Network("192.0.0.0/24"),       # IETF protocol assignments
        ipaddress.IPv4Network("192.0.2.0/24"),       # TEST-NET-1 (documentation)
        ipaddress.IPv4Network("192.88.99.0/24"),     # 6to4 relay
        ipaddress.IPv4Network("192.168.0.0/16"),     # RFC1918 private
        ipaddress.IPv4Network("198.18.0.0/15"),      # Benchmark testing
        ipaddress.IPv4Network("198.51.100.0/24"),    # TEST-NET-2 (documentation)
        ipaddress.IPv4Network("203.0.113.0/24"),     # TEST-NET-3 (documentation)
        ipaddress.IPv4Network("224.0.0.0/4"),        # Multicast
        ipaddress.IPv4Network("240.0.0.0/4"),        # Reserved
        ipaddress.IPv4Network("255.255.255.255/32"), # Broadcast
    ]
    
    # Special-use IPv6 ranges that are NOT globally routable
    IPV6_SPECIAL_RANGES = [
        ipaddress.IPv6Network("::1/128"),            # Loopback
        ipaddress.IPv6Network("::/128"),             # Unspecified
        ipaddress.IPv6Network("::ffff:0:0/96"),      # IPv4-mapped
        ipaddress.IPv6Network("64:ff9b::/96"),       # IPv4-IPv6 translation
        ipaddress.IPv6Network("100::/64"),           # Discard
        ipaddress.IPv6Network("2001::/32"),          # Teredo
        ipaddress.IPv6Network("2001:db8::/32"),      # Documentation
        ipaddress.IPv6Network("2001:10::/28"),       # ORCHID
        ipaddress.IPv6Network("2002::/16"),          # 6to4
        ipaddress.IPv6Network("fc00::/7"),           # ULA (Unique Local Address)
        ipaddress.IPv6Network("fe80::/10"),          # Link-local
        ipaddress.IPv6Network("ff00::/8"),           # Multicast
    ]

    @classmethod
    def classify_ipv4(cls, ip_str: str) -> str:
        """Classify IPv4 address. Returns: 'private', 'documentation', 'special', 'loopback', 'link_local', 'carrier_nat', 'multicast', 'reserved', 'global'"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return "invalid"
        
        # Check special ranges FIRST (before is_private)
        if ip.is_loopback:
            return "loopback"
        if ip.is_multicast:
            return "multicast"
        
        # Check link-local (169.254.0.0/16) - must come before is_private
        if ip in ipaddress.IPv4Network("169.254.0.0/16"):
            return "link_local"
        
        # Check carrier-grade NAT (100.64.0.0/10)
        if ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return "carrier_nat"
        
        # Check documentation ranges (TEST-NET)
        if ip in ipaddress.IPv4Network("192.0.2.0/24") or \
           ip in ipaddress.IPv4Network("198.51.100.0/24") or \
           ip in ipaddress.IPv4Network("203.0.113.0/24"):
            return "documentation"
        
        # Check benchmark testing (198.18.0.0/15)
        if ip in ipaddress.IPv4Network("198.18.0.0/15"):
            return "benchmark"
        
        # Check reserved ranges (240.0.0.0/4) and broadcast - before is_private
        if ip in ipaddress.IPv4Network("240.0.0.0/4") or ip == ipaddress.IPv4Address("255.255.255.255"):
            return "reserved"
        
        # Check RFC1918 private
        if ip.is_private:
            return "private"
        
        # If not in any special range, it's globally routable
        return "global"

    @classmethod
    def classify_ipv6(cls, ip_str: str) -> str:
        """Classify IPv6 address. Returns: 'loopback', 'unspecified', 'ipv4_mapped', 'documentation', 'ula', 'link_local', 'multicast', 'teredo', 'orchid', '6to4', 'global'"""
        try:
            ip = ipaddress.IPv6Address(ip_str)
        except ValueError:
            return "invalid"
        
        # Check special ranges FIRST (before is_private which catches ULA)
        if ip.is_loopback:
            return "loopback"
        if ip.is_unspecified:
            return "unspecified"
        if ip.is_multicast:
            return "multicast"
        if ip.is_link_local:
            return "link_local"
        
        # Check documentation range (2001:db8::/32)
        if ip in ipaddress.IPv6Network("2001:db8::/32"):
            return "documentation"
        
        # Check Teredo (2001::/32)
        if ip in ipaddress.IPv6Network("2001::/32"):
            return "teredo"
        
        # Check ORCHID (2001:10::/28)
        if ip in ipaddress.IPv6Network("2001:10::/28"):
            return "orchid"
        
        # Check 6to4 (2002::/16)
        if ip in ipaddress.IPv6Network("2002::/16"):
            return "6to4"
        
        # Check IPv4-mapped
        if ip.ipv4_mapped is not None:
            return "ipv4_mapped"
        
        # Check ULA (Unique Local Address) - fc00::/7
        if ip.is_private:  # This catches ULA (fc00::/7)
            return "ula"
        
        return "global"

    @classmethod
    def is_globally_routable(cls, ip_str: str) -> bool:
        """Check if an IP address is globally routable (not in any special-use range)."""
        try:
            if ':' in ip_str:
                classification = cls.classify_ipv6(ip_str)
                return classification == "global"
            else:
                classification = cls.classify_ipv4(ip_str)
                return classification == "global"
        except ValueError:
            return False


def is_public_ip(ip: str) -> bool:
    """Check if IP should be treated as public for exposure detection.
    
    For security exposure detection, we consider:
    - Globally routable addresses as public (real internet exposure)
    - Documentation ranges (TEST-NET) as public for exposure detection 
      because they should not appear in real traffic and their presence 
      indicates potential misconfiguration or testing exposure.
    - Private, loopback, link-local, carrier NAT, benchmark, multicast, 
      reserved, and other special-use ranges as non-public.
    """
    try:
        if ':' in ip:
            classification = IPClassification.classify_ipv6(ip)
            return classification in ("global", "documentation")
        else:
            classification = IPClassification.classify_ipv4(ip)
            return classification in ("global", "documentation")
    except ValueError:
        return False


@dataclass
class TimeWindowCounter:
    """Counter with timestamp-based windowing for a single source."""
    entries: List[Tuple[int, int]] = field(default_factory=list)  # (timestamp, value)
    window_seconds: int = 3600

    def add(self, timestamp: int, value: int):
        """Add an entry with timestamp."""
        self.entries.append((timestamp, value))
        self._prune(timestamp)

    def _prune(self, current_timestamp: int):
        """Remove entries outside the time window."""
        cutoff = current_timestamp - self.window_seconds
        self.entries = [(ts, val) for ts, val in self.entries if ts >= cutoff]

    def count_unique_values(self) -> int:
        """Count unique values within the time window."""
        return len(set(val for _, val in self.entries))

    def count_total(self) -> int:
        """Count total entries within the time window."""
        return len(self.entries)


class DetectionContext:
    """Context for timestamp-based detection with time windows."""

    def __init__(self, time_window_seconds: int = 3600):
        self.time_window_seconds = time_window_seconds
        # Port scan: src_addr -> TimeWindowCounter of dst_ports
        self._port_scan_counters: Dict[str, TimeWindowCounter] = defaultdict(
            lambda: TimeWindowCounter(window_seconds=self.time_window_seconds)
        )
        # Brute force: (src_addr, dst_addr, dst_port) -> TimeWindowCounter of attempts
        self._brute_force_counters: Dict[Tuple[str, str, int], TimeWindowCounter] = defaultdict(
            lambda: TimeWindowCounter(window_seconds=self.time_window_seconds)
        )

    def record_port_scan_attempt(self, src_addr: str, dst_port: int, timestamp: int) -> int:
        """Record a REJECT for port scan detection. Returns unique port count for src within window."""
        counter = self._port_scan_counters[src_addr]
        counter.window_seconds = self.time_window_seconds
        counter.add(timestamp, dst_port)
        return counter.count_unique_values()

    def record_brute_force_attempt(self, src_addr: str, dst_addr: str, dst_port: int, timestamp: int) -> int:
        """Record a REJECT for brute force detection. Returns attempt count for (src, dst, port) within window."""
        key = (src_addr, dst_addr, dst_port)
        counter = self._brute_force_counters[key]
        counter.window_seconds = self.time_window_seconds
        counter.add(timestamp, 1)
        return counter.count_total()

    def get_port_scan_count(self, src_addr: str, timestamp: int) -> int:
        counter = self._port_scan_counters.get(src_addr)
        if counter:
            counter.window_seconds = self.time_window_seconds
            counter._prune(timestamp)
            return counter.count_unique_values()
        return 0

    def get_brute_force_count(self, src_addr: str, dst_addr: str, dst_port: int, timestamp: int) -> int:
        counter = self._brute_force_counters.get((src_addr, dst_addr, dst_port))
        if counter:
            counter.window_seconds = self.time_window_seconds
            counter._prune(timestamp)
            return counter.count_total()
        return 0

    def reset(self):
        """Reset all counters."""
        self._port_scan_counters.clear()
        self._brute_force_counters.clear()


class SSHEexposureRule(DetectionRule):
    """Detect SSH exposed to internet."""

    def __init__(self):
        super().__init__(
            id="SSH_EXPOSURE",
            name="SSH Exposed to Internet",
            description="SSH port 22 accepting connections from external sources",
            severity=Severity.HIGH
        )

    def match(self, entry: FlowLogEntry, context: Optional[DetectionContext] = None) -> Optional[DetectionResult]:
        if entry.dst_port == 22 and entry.action == "ACCEPT":
            if is_public_ip(entry.src_addr):
                return DetectionResult(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    timestamp=datetime.now(timezone.utc),
                    flow_log=entry,
                    details="SSH port 22 accepting connections from external sources"
                )
        return None


class RDPExposureRule(DetectionRule):
    """Detect RDP exposed to internet."""

    def __init__(self):
        super().__init__(
            id="RDP_EXPOSURE",
            name="RDP Exposed to Internet",
            description="RDP port 3389 accepting connections from external sources",
            severity=Severity.HIGH
        )

    def match(self, entry: FlowLogEntry, context: Optional[DetectionContext] = None) -> Optional[DetectionResult]:
        if entry.dst_port == 3389 and entry.action == "ACCEPT":
            if is_public_ip(entry.src_addr):
                return DetectionResult(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    timestamp=datetime.now(timezone.utc),
                    flow_log=entry,
                    details="RDP port 3389 accepting connections from external sources"
                )
        return None


class DataExfiltrationRule(DetectionRule):
    """Detect potential data exfiltration."""

    def __init__(self, threshold_bytes: int = 10_000_000):
        super().__init__(
            id="DATA_EXFILTRATION",
            name="Potential Data Exfiltration",
            description="Large data transfer detected",
            severity=Severity.MEDIUM
        )
        self.threshold_bytes = threshold_bytes

    def match(self, entry: FlowLogEntry, context: Optional[DetectionContext] = None) -> Optional[DetectionResult]:
        if entry.bytes > self.threshold_bytes and entry.protocol == 17:  # UDP
            return DetectionResult(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                timestamp=datetime.now(timezone.utc),
                flow_log=entry,
                details=f"Large UDP transfer: {entry.bytes} bytes"
            )
        return None


class PortScanRule(DetectionRule):
    """Detect port scanning activity using timestamp-based windowed aggregation."""

    def __init__(self, threshold_ports: int = 20):
        super().__init__(
            id="PORT_SCAN",
            name="Port Scanning Detection",
            description="Multiple connection attempts to different ports from same source within time window",
            severity=Severity.MEDIUM
        )
        self.threshold_ports = threshold_ports

    def match(self, entry: FlowLogEntry, context: Optional[DetectionContext] = None) -> Optional[DetectionResult]:
        if entry.action == "REJECT" and context is not None:
            unique_ports = context.record_port_scan_attempt(entry.src_addr, entry.dst_port, entry.start_time)
            if unique_ports >= self.threshold_ports:
                return DetectionResult(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    timestamp=datetime.fromtimestamp(entry.end_time, tz=timezone.utc),
                    flow_log=entry,
                    details=f"Port scan detected from {entry.src_addr}: {unique_ports} unique ports targeted within time window"
                )
        return None


class BruteForceRule(DetectionRule):
    """Detect brute force attacks using timestamp-based windowed aggregation."""

    def __init__(self, threshold_attempts: int = 10):
        super().__init__(
            id="BRUTE_FORCE",
            name="Brute Force Attack",
            description="Multiple failed login attempts detected within time window",
            severity=Severity.HIGH
        )
        self.threshold_attempts = threshold_attempts
        self.auth_ports = {22, 3389, 21, 23, 5900, 5901}

    def match(self, entry: FlowLogEntry, context: Optional[DetectionContext] = None) -> Optional[DetectionResult]:
        if entry.dst_port in self.auth_ports and entry.action == "REJECT" and context is not None:
            attempts = context.record_brute_force_attempt(entry.src_addr, entry.dst_addr, entry.dst_port, entry.start_time)
            if attempts >= self.threshold_attempts:
                return DetectionResult(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    timestamp=datetime.fromtimestamp(entry.end_time, tz=timezone.utc),
                    flow_log=entry,
                    details=f"Brute force detected on port {entry.dst_port} from {entry.src_addr} to {entry.dst_addr}: {attempts} failed attempts within time window"
                )
        return None


class DetectionEngine:
    """Detection engine that runs all enabled rules against flow logs with timestamp-based windowing."""

    def __init__(
        self,
        rules: Optional[List[DetectionRule]] = None,
        time_window_seconds: int = 3600
    ):
        self.rules = rules or get_default_rules()
        self.time_window_seconds = time_window_seconds

    def analyze(self, entries: List[FlowLogEntry]) -> List[DetectionResult]:
        """Analyze flow log entries against all rules with timestamp-based context."""
        # Sort entries by start_time to ensure proper time windowing
        sorted_entries = sorted(entries, key=lambda e: e.start_time)
        context = DetectionContext(time_window_seconds=self.time_window_seconds)
        results = []
        for entry in sorted_entries:
            for rule in self.rules:
                if rule.enabled:
                    result = rule.match(entry, context)
                    if result:
                        results.append(result)
        return results

    def add_rule(self, rule: DetectionRule):
        """Add a custom rule."""
        self.rules.append(rule)

    def get_rules(self) -> List[DetectionRule]:
        """Get all rules."""
        return self.rules


def get_default_rules(
    ssh_rdp_private_check: bool = True,
    port_scan_threshold: int = 20,
    brute_force_threshold: int = 10,
    data_exfil_threshold: int = 10_000_000,
    time_window_seconds: int = 3600
) -> List[DetectionRule]:
    """Get default detection rules with configurable thresholds."""
    return [
        SSHEexposureRule(),
        RDPExposureRule(),
        DataExfiltrationRule(threshold_bytes=data_exfil_threshold),
        PortScanRule(threshold_ports=port_scan_threshold),
        BruteForceRule(threshold_attempts=brute_force_threshold),
    ]