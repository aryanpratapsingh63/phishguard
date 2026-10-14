"""
Database package for PHISHGUARD scan history.
"""

from .db import (
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    clear_history,
    delete_scan,
    get_scan_stats,
)

__all__ = [
    "init_db",
    "save_scan",
    "get_recent_scans",
    "get_scan_by_id",
    "clear_history",
    "delete_scan",
    "get_scan_stats",
]
