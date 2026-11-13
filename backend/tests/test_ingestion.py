"""Ingestion endpoint tests."""

import pytest
import json


class TestIngestionEndpoints:
    @pytest.mark.asyncio
    async def test_ingest_flow_logs_json(self, async_client):
        flow_logs = [
            {
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
        ]
        files = {"file": ("test.json", json.dumps(flow_logs), "application/json")}
        response = await async_client.post("/api/v1/ingestion/flow-logs", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["job"]["records_processed"] == 1
        assert data["job"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_list_ingestion_jobs(self, async_client):
        response = await async_client.get("/api/v1/ingestion/jobs")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1