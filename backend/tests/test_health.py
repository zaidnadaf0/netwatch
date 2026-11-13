"""Health endpoint tests."""

import pytest


class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_health_check(self, async_client):
        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "netwatch-api"

    @pytest.mark.asyncio
    async def test_readiness_check(self, async_client):
        response = await async_client.get("/api/v1/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "netwatch-api"