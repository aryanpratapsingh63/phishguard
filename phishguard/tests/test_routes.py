"""
Automated integration tests for Flask web routes and JSON API.
"""

import os
import gc
import tempfile
import pytest
from app import create_app
from config import Config


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False


@pytest.fixture
def client():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    class CustomConfig(TestConfig):
        DATABASE_PATH = db_path

    app = create_app(CustomConfig)
    with app.test_client() as client:
        yield client

    gc.collect()
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
    except OSError:
        pass


def test_index_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PHISHGUARD" in response.data
    assert b"URL Security Inspection Engine" in response.data


def test_analyze_valid_url(client):
    response = client.post("/analyze", data={"url": "https://www.google.com"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Assessment" in response.data
    assert b"Likely Safe" in response.data


def test_analyze_phishing_url(client):
    response = client.post("/analyze", data={"url": "http://192.168.1.100/paypal/login.php"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Potential Phishing" in response.data
    assert b"IP Address" in response.data


def test_analyze_empty_url(client):
    response = client.post("/analyze", data={"url": ""}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Please enter a valid URL" in response.data or b"empty" in response.data


def test_api_analyze_valid(client):
    response = client.get("/api/analyze?url=https://en.wikipedia.org/wiki/Phishing")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["is_valid"] is True
    assert data["classification"] == "Likely Safe"
    assert "risk_score" in data
    assert "indicators" in data


def test_api_analyze_invalid(client):
    response = client.get("/api/analyze?url=")
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "error"
    assert data["is_valid"] is False


def test_history_and_clear_routes(client):
    # Scan a URL first
    client.post("/analyze", data={"url": "https://example.com"})

    # Check history page
    res_hist = client.get("/history")
    assert res_hist.status_code == 200
    assert b"example.com" in res_hist.data

    # Export history
    res_exp = client.get("/history/export")
    assert res_exp.status_code == 200
    assert res_exp.mimetype == "application/json"

    # Clear history
    res_clear = client.post("/history/clear", follow_redirects=True)
    assert res_clear.status_code == 200
    assert b"Scan history successfully cleared" in res_clear.data


def test_ml_dashboard_and_train_route(client):
    res_ml = client.get("/ml")
    assert res_ml.status_code == 200
    assert b"Machine Learning Model Evaluation" in res_ml.data
    assert b"Confusion Matrix" in res_ml.data

    # Re-train trigger
    res_train = client.post("/ml/train", follow_redirects=True)
    assert res_train.status_code == 200
    assert b"re-trained and re-evaluated" in res_train.data


def test_404_error_page(client):
    response = client.get("/non-existent-security-page-1234")
    assert response.status_code == 404
    assert b"Resource Not Found" in response.data
    assert b"HTTP 404" in response.data
