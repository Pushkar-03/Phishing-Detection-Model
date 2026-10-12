import os
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint_shape():
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()

def test_malformed_url_rejected():
    response = client.post("/predict", json={"url": "not a url"})
    assert response.status_code == 422

@pytest.mark.skipif(not os.path.exists("artifacts/phishing_url_v1.joblib"), reason="Train model first")
def test_prediction_endpoint():
    response = client.post("/predict", json={"url": "https://example.com/"})
    assert response.status_code == 200
    assert response.json()["predicted_class"] in {"phishing", "legitimate"}
