from fastapi.testclient import TestClient
from src.main import app

def test_health():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

def test_execute():
    with TestClient(app) as client:
        response = client.post("/api/v1/execute", json={"test": "data"})
        assert response.status_code == 200
        assert response.json()["status"] == "success"
