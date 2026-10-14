"""
SQLite database management module for PHISHGUARD.
Stores URL scan history safely without credentials, cookies, or personal data.
Properly closes all SQLite connection handles to prevent Windows file locking.
"""

import os
import sqlite3
from typing import List, Dict, Any, Optional

from config import Config


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a database connection with dict-like row factories."""
    path = db_path or Config.DATABASE_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes SQLite tables and indexes."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                normalized_url TEXT,
                hostname TEXT,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                indicators_count INTEGER DEFAULT 0,
                indicators_summary TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_history(scanned_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_classification ON scan_history(classification)")
        conn.commit()
    finally:
        conn.close()


def save_scan(
    url: str,
    normalized_url: str,
    hostname: str,
    risk_score: int,
    classification: str,
    indicators_count: int = 0,
    indicators_summary: str = "",
    db_path: Optional[str] = None
) -> int:
    """
    Saves a URL scan record into SQLite.
    Returns the newly created scan ID.
    Never stores any credentials, passwords, or personal data.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (
                url, normalized_url, hostname, risk_score, classification,
                indicators_count, indicators_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            url,
            normalized_url,
            hostname,
            risk_score,
            classification,
            indicators_count,
            indicators_summary
        ))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_recent_scans(limit: int = 50, search_query: Optional[str] = None, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves recent scans ordered by timestamp descending.
    Supports optional search filter by URL or hostname.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if search_query:
            wildcard = f"%{search_query.strip()}%"
            cursor.execute("""
                SELECT * FROM scan_history
                WHERE url LIKE ? OR hostname LIKE ? OR classification LIKE ?
                ORDER BY scanned_at DESC, id DESC
                LIMIT ?
            """, (wildcard, wildcard, wildcard, limit))
        else:
            cursor.execute("""
                SELECT * FROM scan_history
                ORDER BY scanned_at DESC, id DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_scan_by_id(scan_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetches a single scan record by ID."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_scan(scan_id: int, db_path: Optional[str] = None) -> bool:
    """Deletes a specific scan record by ID."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def clear_history(db_path: Optional[str] = None) -> int:
    """
    Clears all scan history from the table.
    Returns the number of deleted records.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history")
        deleted = cursor.rowcount
        conn.commit()
        return deleted
    finally:
        conn.close()


def get_scan_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Calculates aggregate statistics for dashboard summaries."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN classification = 'Likely Safe' THEN 1 ELSE 0 END) as safe_count,
                SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_count,
                SUM(CASE WHEN classification = 'Potential Phishing' THEN 1 ELSE 0 END) as phishing_count,
                AVG(risk_score) as avg_risk_score
            FROM scan_history
        """)
        row = cursor.fetchone()
        
        total = row["total_scans"] if row and row["total_scans"] else 0
        safe = row["safe_count"] if row and row["safe_count"] else 0
        suspicious = row["suspicious_count"] if row and row["suspicious_count"] else 0
        phishing = row["phishing_count"] if row and row["phishing_count"] else 0
        avg_score = round(row["avg_risk_score"], 1) if row and row["avg_risk_score"] is not None else 0.0

        return {
            "total_scans": total,
            "safe_count": safe,
            "suspicious_count": suspicious,
            "phishing_count": phishing,
            "avg_risk_score": avg_score
        }
    finally:
        conn.close()
