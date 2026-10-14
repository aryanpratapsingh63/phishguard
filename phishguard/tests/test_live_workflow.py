"""
End-to-end integration and workflow verification script.
Simulates real user browsing, scanning, history management, and API calls.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from database import get_recent_scans, get_scan_stats

def test_full_user_workflow():
    with app.test_client() as client:
        # 1. Access Index
        res = client.get("/")
        assert res.status_code == 200
        assert b"PHISHGUARD" in res.data

        # 2. Submit Safe URL
        res_safe = client.post("/analyze", data={"url": "https://www.google.com"}, follow_redirects=True)
        assert res_safe.status_code == 200
        assert b"Likely Safe" in res_safe.data

        # 3. Submit Phishing URL
        res_phish = client.post("/analyze", data={"url": "http://192.168.1.105/paypal/login.php"}, follow_redirects=True)
        assert res_phish.status_code == 200
        assert b"Potential Phishing" in res_phish.data

        # 4. Query JSON API
        res_api = client.get("/api/analyze?url=http://tinyurl.com/update-password")
        assert res_api.status_code == 200
        data = res_api.get_json()
        assert data["status"] == "success"
        assert "risk_score" in data

        # 5. Check History
        res_hist = client.get("/history")
        assert res_hist.status_code == 200
        assert b"192.168.1.105" in res_hist.data

        # 6. Check ML Dashboard
        res_ml = client.get("/ml")
        assert res_ml.status_code == 200
        assert b"Confusion Matrix" in res_ml.data

        # 7. Check Database Statistics
        stats = get_scan_stats()
        assert stats["total_scans"] >= 3
        print(f"\n[+] Full Workflow Verified! Total Scans Logged: {stats['total_scans']}")

if __name__ == "__main__":
    test_full_user_workflow()
