"""Security audit endpoint tests."""

import pytest


class TestSecurityAuditEndpoints:
    @pytest.mark.asyncio
    async def test_analyze_security_groups_ssh_open(self, async_client):
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_ipv4": "0.0.0.0/0",
                    "description": "SSH from anywhere"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["id"] == "SG-sg-12345-SSH-OPEN-IPv4"
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["direction"] == "ingress"

    @pytest.mark.asyncio
    async def test_analyze_security_groups_all_ports_open(self, async_client):
        """Test that 0-65535 rule triggers all applicable findings (independent evaluation)."""
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 0,
                    "to_port": 65535,
                    "cidr_ipv4": "0.0.0.0/0",
                    "description": "All ports"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        # Should trigger: SSH, RDP, FTP, Telnet, DB, ALL_PORTS = 6 findings (all IPv4)
        assert len(findings) == 6
        finding_ids = {f["id"] for f in findings}
        assert "SG-sg-12345-SSH-OPEN-IPv4" in finding_ids
        assert "SG-sg-12345-RDP-OPEN-IPv4" in finding_ids
        assert "SG-sg-12345-FTP-OPEN-IPv4" in finding_ids
        assert "SG-sg-12345-TELNET-OPEN-IPv4" in finding_ids
        assert "SG-sg-12345-DB-OPEN-IPv4" in finding_ids
        assert "SG-sg-12345-ALL-PORTS-OPEN-IPv4" in finding_ids
        # All should be CRITICAL or HIGH
        for f in findings:
            assert f["severity"] in ("CRITICAL", "HIGH")
            assert f["direction"] == "ingress"

    @pytest.mark.asyncio
    async def test_analyze_security_groups_telnet_open(self, async_client):
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 23,
                    "to_port": 23,
                    "cidr_ipv4": "0.0.0.0/0",
                    "description": "Telnet from anywhere"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["id"] == "SG-sg-12345-TELNET-OPEN-IPv4"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["direction"] == "ingress"

    @pytest.mark.asyncio
    async def test_analyze_security_groups_db_open(self, async_client):
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 3306,
                    "to_port": 3306,
                    "cidr_ipv4": "0.0.0.0/0",
                    "description": "MySQL from anywhere"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["id"] == "SG-sg-12345-DB-OPEN-IPv4"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["direction"] == "ingress"

    @pytest.mark.asyncio
    async def test_analyze_security_groups_ipv6_ssh(self, async_client):
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_ipv6": "::/0",
                    "description": "SSH from anywhere IPv6"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["id"] == "SG-sg-12345-SSH-OPEN-IPv6"
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["direction"] == "ingress"

    @pytest.mark.asyncio
    async def test_analyze_security_groups_protocol_all(self, async_client):
        """Test that protocol -1 (all) matches TCP rules."""
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "-1",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_ipv4": "0.0.0.0/0",
                    "description": "All protocols SSH"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["id"] == "SG-sg-12345-SSH-OPEN-IPv4"
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["direction"] == "ingress"

    @pytest.mark.asyncio
    async def test_analyze_security_groups_egress_unrestricted(self, async_client):
        """Test unrestricted egress detection."""
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 0,
                    "to_port": 65535,
                    "cidr_ipv4": "0.0.0.0/0",
                    "is_egress": True,
                    "description": "All egress"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        # Should have unrestricted egress finding
        egress_findings = [f for f in findings if f["direction"] == "egress"]
        assert len(egress_findings) >= 1
        assert any(f["id"] == "SG-sg-12345-UNRESTRICTED-EGRESS-IPV4" for f in egress_findings)
        assert any(f["severity"] == "MEDIUM" for f in egress_findings)

    @pytest.mark.asyncio
    async def test_analyze_security_groups_egress_sensitive_port(self, async_client):
        """Test egress to sensitive port detection."""
        security_group = {
            "group_id": "sg-12345",
            "group_name": "test-sg",
            "description": "Test security group",
            "vpc_id": "vpc-12345",
            "rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_ipv4": "0.0.0.0/0",
                    "is_egress": True,
                    "description": "SSH egress"
                }
            ]
        }
        response = await async_client.post("/api/v1/security-audit/security-groups/analyze", json=[security_group])
        assert response.status_code == 200
        findings = response.json()
        egress_findings = [f for f in findings if f["direction"] == "egress"]
        assert len(egress_findings) >= 1
        assert any("EGRESS-SENSITIVE-PORT22" in f["id"] for f in egress_findings)

    @pytest.mark.asyncio
    async def test_list_audit_rules(self, async_client):
        response = await async_client.get("/api/v1/security-audit/rules")
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert len(data["rules"]) >= 6