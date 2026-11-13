"""Detection endpoint tests."""

import pytest
from datetime import datetime


class TestDetectionEndpoints:
    @pytest.mark.asyncio
    async def test_analyze_flow_logs_ssh_exposure(self, async_client):
        flow_log = {
            "version": 2,
            "account_id": "123456789012",
            "interface_id": "eni-12345",
            "src_addr": "203.0.113.1",
            "dst_addr": "10.0.1.5",
            "src_port": 54321,
            "dst_port": 22,
            "protocol": 6,
            "packets": 10,
            "bytes": 600,
            "start_time": 1704067200,
            "end_time": 1704067260,
            "action": "ACCEPT",
            "log_status": "OK"
        }
        response = await async_client.post("/api/v1/detection/analyze", json=[flow_log])
        assert response.status_code == 200
        results = response.json()
        assert len(results) == 1
        assert results[0]["rule_id"] == "SSH_EXPOSURE"
        assert results[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_analyze_flow_logs_rdp_exposure(self, async_client):
        flow_log = {
            "version": 2,
            "account_id": "123456789012",
            "interface_id": "eni-12345",
            "src_addr": "203.0.113.1",
            "dst_addr": "10.0.1.5",
            "src_port": 54321,
            "dst_port": 3389,
            "protocol": 6,
            "packets": 10,
            "bytes": 600,
            "start_time": 1704067200,
            "end_time": 1704067260,
            "action": "ACCEPT",
            "log_status": "OK"
        }
        response = await async_client.post("/api/v1/detection/analyze", json=[flow_log])
        assert response.status_code == 200
        results = response.json()
        assert len(results) == 1
        assert results[0]["rule_id"] == "RDP_EXPOSURE"
        assert results[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_analyze_flow_logs_no_threat(self, async_client):
        flow_log = {
            "version": 2,
            "account_id": "123456789012",
            "interface_id": "eni-12345",
            "src_addr": "10.0.1.10",
            "dst_addr": "10.0.1.5",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": 6,
            "packets": 10,
            "bytes": 600,
            "start_time": 1704067200,
            "end_time": 1704067260,
            "action": "ACCEPT",
            "log_status": "OK"
        }
        response = await async_client.post("/api/v1/detection/analyze", json=[flow_log])
        assert response.status_code == 200
        results = response.json()
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_list_detection_rules(self, async_client):
        response = await async_client.get("/api/v1/detection/rules")
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert len(data["rules"]) >= 5