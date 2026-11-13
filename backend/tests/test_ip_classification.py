"""Tests for IP classification logic."""

import pytest
from detection.rules import IPClassification, is_public_ip


class TestIPClassification:
    """Test IP address classification for IPv4 and IPv6."""

    # IPv4 Private (RFC1918)
    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
    ])
    def test_ipv4_private_rfc1918(self, ip):
        assert IPClassification.classify_ipv4(ip) == "private"
        assert is_public_ip(ip) is False

    # IPv4 Loopback
    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "127.255.255.255",
    ])
    def test_ipv4_loopback(self, ip):
        assert IPClassification.classify_ipv4(ip) == "loopback"
        assert is_public_ip(ip) is False

    # IPv4 Link-local
    @pytest.mark.parametrize("ip", [
        "169.254.0.1",
        "169.254.255.255",
    ])
    def test_ipv4_link_local(self, ip):
        assert IPClassification.classify_ipv4(ip) == "link_local"
        assert is_public_ip(ip) is False

    # IPv4 Carrier-grade NAT
    @pytest.mark.parametrize("ip", [
        "100.64.0.1",
        "100.127.255.255",
    ])
    def test_ipv4_carrier_nat(self, ip):
        assert IPClassification.classify_ipv4(ip) == "carrier_nat"
        assert is_public_ip(ip) is False

    # IPv4 Documentation (TEST-NET)
    @pytest.mark.parametrize("ip", [
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
    ])
    def test_ipv4_documentation(self, ip):
        assert IPClassification.classify_ipv4(ip) == "documentation"
        # For security exposure detection, documentation addresses are treated as public
        assert is_public_ip(ip) is True

    # IPv4 Benchmark
    @pytest.mark.parametrize("ip", [
        "198.18.0.1",
        "198.19.255.255",
    ])
    def test_ipv4_benchmark(self, ip):
        assert IPClassification.classify_ipv4(ip) == "benchmark"
        assert is_public_ip(ip) is False

    # IPv4 Multicast
    @pytest.mark.parametrize("ip", [
        "224.0.0.1",
        "239.255.255.255",
    ])
    def test_ipv4_multicast(self, ip):
        assert IPClassification.classify_ipv4(ip) == "multicast"
        assert is_public_ip(ip) is False

    # IPv4 Reserved
    @pytest.mark.parametrize("ip", [
        "240.0.0.1",
        "255.255.255.255",
    ])
    def test_ipv4_reserved(self, ip):
        assert IPClassification.classify_ipv4(ip) in ("reserved", "multicast", "broadcast")
        assert is_public_ip(ip) is False

# IPv4 Global (publicly routable)
    @pytest.mark.parametrize("ip", [
        "1.1.1.1",
        "8.8.8.8",
        "172.32.0.1",  # Outside RFC1918
        # Note: 203.0.113.50 is TEST-NET-3 (documentation), so is_public_ip returns True
    ])
    def test_ipv4_global(self, ip):
        if ip == "203.0.113.50":
            assert IPClassification.classify_ipv4(ip) == "documentation"
            assert is_public_ip(ip) is True
        else:
            assert IPClassification.classify_ipv4(ip) == "global"
            assert is_public_ip(ip) is True

    # IPv6 Loopback
    def test_ipv6_loopback(self):
        assert IPClassification.classify_ipv6("::1") == "loopback"
        assert is_public_ip("::1") is False

    # IPv6 Unspecified
    def test_ipv6_unspecified(self):
        assert IPClassification.classify_ipv6("::") == "unspecified"
        assert is_public_ip("::") is False

    # IPv6 Loopback (link-local)
    @pytest.mark.parametrize("ip", [
        "fe80::1",
        "fe80::abcd:ef12:3456:7890",
    ])
    def test_ipv6_link_local(self, ip):
        assert IPClassification.classify_ipv6(ip) == "link_local"
        assert is_public_ip(ip) is False

    # IPv6 ULA (Unique Local Address)
    @pytest.mark.parametrize("ip", [
        "fc00::1",
        "fd00::1",
        "fd12:3456::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ])
    def test_ipv6_ula(self, ip):
        assert IPClassification.classify_ipv6(ip) == "ula"
        assert is_public_ip(ip) is False

    # IPv6 Documentation
    @pytest.mark.parametrize("ip", [
        "2001:db8::1",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
    ])
    def test_ipv6_documentation(self, ip):
        assert IPClassification.classify_ipv6(ip) == "documentation"
        # For security exposure detection, documentation addresses are treated as public
        assert is_public_ip(ip) is True

    # IPv6 Teredo
    def test_ipv6_teredo(self):
        assert IPClassification.classify_ipv6("2001::1") == "teredo"
        assert is_public_ip("2001::1") is False

    # IPv6 ORCHID
    def test_ipv6_orchid(self):
        assert IPClassification.classify_ipv6("2001:10::1") == "orchid"
        assert is_public_ip("2001:10::1") is False

    # IPv6 6to4
    def test_ipv6_6to4(self):
        assert IPClassification.classify_ipv6("2002::1") == "6to4"
        assert is_public_ip("2002::1") is False

    # IPv6 IPv4-mapped
    def test_ipv6_ipv4_mapped(self):
        assert IPClassification.classify_ipv6("::ffff:192.0.2.1") == "ipv4_mapped"
        assert is_public_ip("::ffff:192.0.2.1") is False

    # IPv6 Global
    @pytest.mark.parametrize("ip", [
        "2001:4860:4860::8888",  # Google DNS
        "2606:4700:4700::1111",  # Cloudflare DNS
    ])
    def test_ipv6_global(self, ip):
        assert IPClassification.classify_ipv6(ip) == "global"
        assert is_public_ip(ip) is True

    # Invalid IPs
    @pytest.mark.parametrize("ip", [
        "not.an.ip",
        "999.999.999.999",
        "::gggg",
        "",
    ])
    def test_invalid_ips(self, ip):
        assert IPClassification.classify_ipv4(ip) == "invalid" or IPClassification.classify_ipv6(ip) == "invalid"
        assert is_public_ip(ip) is False