"""SQLite store for Hivewatch.

One file, WAL mode, no ORM. Events are append-only; aggregates are computed on
read because the volume a homelab honeypot sees is tiny by database standards.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

DB_PATH = os.environ.get("HIVEWATCH_DB", "/data/hivewatch.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    source          TEXT    NOT NULL,   -- sentinel | mclog | npm | manual
    kind            TEXT    NOT NULL,   -- probe | login | scan | malformed | error
    severity        INTEGER NOT NULL DEFAULT 1,
    ip              TEXT    NOT NULL,
    port            INTEGER,
    is_private      INTEGER NOT NULL DEFAULT 0,
    country         TEXT,
    country_code    TEXT,
    city            TEXT,
    lat             REAL,
    lon             REAL,
    isp             TEXT,
    username        TEXT,
    proto_version   INTEGER,
    server_address  TEXT,
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip           TEXT PRIMARY KEY,
    country      TEXT,
    country_code TEXT,
    city         TEXT,
    lat          REAL,
    lon          REAL,
    isp          TEXT,
    ts           REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.executescript(_SCHEMA)
        _conn.commit()
    return _conn


def insert_event(ev: Dict[str, Any]) -> int:
    cols = ("ts", "source", "kind", "severity", "ip", "port", "is_private",
            "country", "country_code", "city", "lat", "lon", "isp",
            "username", "proto_version", "server_address", "detail")
    row = [ev.get(c) for c in cols]
    sql = "INSERT INTO events (%s) VALUES (%s)" % (
        ",".join(cols), ",".join("?" * len(cols)))
    with _lock:
        cur = connect().execute(sql, row)
        connect().commit()
        return cur.lastrowid


def recent_events(limit: int = 200, since: Optional[float] = None) -> List[Dict]:
    sql = "SELECT * FROM events"
    params: List[Any] = []
    if since is not None:
        sql += " WHERE ts > ?"
        params.append(since)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(min(max(limit, 1), 2000))
    with _lock:
        return [dict(r) for r in connect().execute(sql, params).fetchall()]


def _rows(sql: str, params: Iterable[Any] = ()) -> List[Dict]:
    with _lock:
        return [dict(r) for r in connect().execute(sql, tuple(params)).fetchall()]


def stats(window_hours: int = 24) -> Dict[str, Any]:
    cutoff = time.time() - window_hours * 3600
    total = _rows("SELECT COUNT(*) c FROM events")[0]["c"]
    windowed = _rows("SELECT COUNT(*) c FROM events WHERE ts > ?", (cutoff,))[0]["c"]
    uniq = _rows("SELECT COUNT(DISTINCT ip) c FROM events WHERE ts > ?", (cutoff,))[0]["c"]
    return {
        "total_events": total,
        "window_hours": window_hours,
        "events_in_window": windowed,
        "unique_ips_in_window": uniq,
        "by_kind": _rows(
            "SELECT kind, COUNT(*) c FROM events WHERE ts > ? "
            "GROUP BY kind ORDER BY c DESC", (cutoff,)),
        "by_source": _rows(
            "SELECT source, COUNT(*) c FROM events WHERE ts > ? "
            "GROUP BY source ORDER BY c DESC", (cutoff,)),
        "top_countries": _rows(
            "SELECT country, country_code, COUNT(*) c FROM events "
            "WHERE ts > ? AND country IS NOT NULL AND is_private = 0 "
            "GROUP BY country_code ORDER BY c DESC LIMIT 12", (cutoff,)),
        "top_ips": _rows(
            "SELECT ip, country_code, isp, COUNT(*) c, MAX(ts) last_seen "
            "FROM events WHERE ts > ? AND is_private = 0 "
            "GROUP BY ip ORDER BY c DESC LIMIT 12", (cutoff,)),
        "top_usernames": _rows(
            "SELECT username, COUNT(*) c FROM events "
            "WHERE ts > ? AND username IS NOT NULL AND username != '' "
            "GROUP BY username ORDER BY c DESC LIMIT 10", (cutoff,)),
        "timeline": _rows(
            "SELECT CAST(ts / 3600 AS INTEGER) * 3600 bucket, COUNT(*) c "
            "FROM events WHERE ts > ? GROUP BY bucket ORDER BY bucket", (cutoff,)),
    }


# -- geo cache ---------------------------------------------------------------

def geo_get(ip: str, max_age_days: int = 30) -> Optional[Dict]:
    rows = _rows("SELECT * FROM geo_cache WHERE ip = ?", (ip,))
    if not rows:
        return None
    row = rows[0]
    if time.time() - row["ts"] > max_age_days * 86400:
        return None
    return row


def geo_put(ip: str, info: Dict) -> None:
    with _lock:
        connect().execute(
            "INSERT OR REPLACE INTO geo_cache "
            "(ip, country, country_code, city, lat, lon, isp, ts) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (ip, info.get("country"), info.get("country_code"), info.get("city"),
             info.get("lat"), info.get("lon"), info.get("isp"), time.time()))
        connect().commit()


# -- tailer offsets ----------------------------------------------------------

def state_get(key: str) -> Optional[str]:
    rows = _rows("SELECT value FROM state WHERE key = ?", (key,))
    return rows[0]["value"] if rows else None


def state_set(key: str, value: str) -> None:
    with _lock:
        connect().execute(
            "INSERT OR REPLACE INTO state (key, value) VALUES (?,?)", (key, str(value)))
        connect().commit()


def clear_events() -> int:
    """Delete every recorded event. Geo cache and tailer offsets are kept."""
    with _lock:
        cur = connect().execute("DELETE FROM events")
        connect().commit()
        connect().execute("VACUUM")
        return cur.rowcount


def prune(keep_days: int) -> int:
    """Drop events older than keep_days. Returns rows removed."""
    if keep_days <= 0:
        return 0
    cutoff = time.time() - keep_days * 86400
    with _lock:
        cur = connect().execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        connect().commit()
        return cur.rowcount
