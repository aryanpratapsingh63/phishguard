"""
Automated unit tests for SQLite Database operations.
"""

import os
import gc
import tempfile
import pytest
from database.db import (
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    delete_scan,
    clear_history,
    get_scan_stats,
)


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    gc.collect()
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def test_save_and_retrieve_scan(temp_db):
    scan_id = save_scan(
        url="https://example.com",
        normalized_url="https://example.com",
        hostname="example.com",
        risk_score=15,
        classification="Likely Safe",
        indicators_count=1,
        indicators_summary="Standard web conventions",
        db_path=temp_db,
    )
    assert scan_id > 0

    scans = get_recent_scans(limit=10, db_path=temp_db)
    assert len(scans) == 1
    assert scans[0]["hostname"] == "example.com"
    assert scans[0]["risk_score"] == 15
    assert scans[0]["classification"] == "Likely Safe"


def test_get_scan_stats_and_aggregation(temp_db):
    save_scan("https://safe.com", "https://safe.com", "safe.com", 10, "Likely Safe", db_path=temp_db)
    save_scan("http://suspicious.com", "http://suspicious.com", "suspicious.com", 45, "Suspicious", db_path=temp_db)
    save_scan("http://192.168.1.1/phish", "http://192.168.1.1/phish", "192.168.1.1", 85, "Potential Phishing", db_path=temp_db)

    stats = get_scan_stats(db_path=temp_db)
    assert stats["total_scans"] == 3
    assert stats["safe_count"] == 1
    assert stats["suspicious_count"] == 1
    assert stats["phishing_count"] == 1
    # Average of 10, 45, 85 is (140 / 3) = 46.7
    assert stats["avg_risk_score"] == pytest.approx(46.7, 0.2)


def test_delete_and_clear_history(temp_db):
    id1 = save_scan("https://a.com", "https://a.com", "a.com", 10, "Likely Safe", db_path=temp_db)
    id2 = save_scan("https://b.com", "https://b.com", "b.com", 20, "Likely Safe", db_path=temp_db)

    assert len(get_recent_scans(db_path=temp_db)) == 2

    # Delete single
    deleted = delete_scan(id1, db_path=temp_db)
    assert deleted is True
    assert len(get_recent_scans(db_path=temp_db)) == 1

    # Clear all
    count = clear_history(db_path=temp_db)
    assert count == 1
    assert len(get_recent_scans(db_path=temp_db)) == 0
