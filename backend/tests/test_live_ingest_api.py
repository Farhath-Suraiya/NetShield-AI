import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.auth.handler import create_access_token


def test_live_ingest_unauthorized():
    """Verify that /live-capture/ingest rejects requests without valid API Key or JWT token."""
    with TestClient(app) as client:
        payload = {
            "source_ip": "192.168.1.150",
            "destination_ip": "10.0.0.5",
            "source_port": 50123,
            "Destination Port": 80,
            "protocol": "TCP",
            "Total Length of Fwd Packets": 1024
        }
        res = client.post("/api/v1/network/live-capture/ingest", json=payload)
        assert res.status_code == 401


def test_live_ingest_with_api_key():
    """Verify that /live-capture/ingest accepts requests authenticated with X-API-Key."""
    with TestClient(app) as client:
        payload = {
            "source_ip": "192.168.1.150",
            "destination_ip": "10.0.0.5",
            "source_port": 50123,
            "Destination Port": 80,
            "protocol": "TCP",
            "Total Length of Fwd Packets": 1024
        }
        headers = {"X-API-Key": settings.NETSHIELD_CAPTURE_API_KEY}
        res = client.post("/api/v1/network/live-capture/ingest", json=payload, headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "packet_count" in data


def test_live_ingest_with_jwt_token():
    """Verify that /live-capture/ingest accepts requests authenticated with Bearer JWT."""
    with TestClient(app) as client:
        test_token = create_access_token("507f1f77bcf86cd799439011")
        headers = {"Authorization": f"Bearer {test_token}"}
        payload = {
            "source_ip": "192.168.1.151",
            "destination_ip": "10.0.0.6",
            "source_port": 50124,
            "Destination Port": 443,
            "protocol": "TCP",
            "Total Length of Fwd Packets": 512
        }
        res = client.post("/api/v1/network/live-capture/ingest", json=payload, headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"


def test_live_capture_status_includes_agent_state():
    """Verify that status response includes capture_mode and agent_active tracking."""
    with TestClient(app) as client:
        test_token = create_access_token("507f1f77bcf86cd799439011")
        headers = {"Authorization": f"Bearer {test_token}"}
        res = client.get("/api/v1/network/live-capture/status", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert "agent_active" in data
        assert "capture_mode" in data
        assert "mode" in data
