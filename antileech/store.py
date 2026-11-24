"""SQLite 持久化：Peer 状态、封禁记录、事件日志、peer_id 索引。"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class PeerState:
    ip: str
    infohash: str
    port: int = 0
    client: str = ""
    peer_id: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    downloaded: int = 0
    uploaded: int = 0
    progress: float = 0.0
    score: float = 0.0
    score_ts: float = 0.0
    win_start: float = 0.0
    win_up: int = 0
    win_down: int = 0
    strikes: int = 0
    samples: int = 0


@dataclass
class Ban:
    ip: str
    reason: str
    score: float
    created: float
    expires: float
    active: int = 1
    source: str = ""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS peer_state (
    ip TEXT NOT NULL,
    infohash TEXT NOT NULL,
    port INTEGER DEFAULT 0,
    client TEXT DEFAULT '',
    peer_id TEXT DEFAULT '',
    first_seen REAL DEFAULT 0,
    last_seen REAL DEFAULT 0,
    downloaded INTEGER DEFAULT 0,
    uploaded INTEGER DEFAULT 0,
    progress REAL DEFAULT 0,
    score REAL DEFAULT 0,
    score_ts REAL DEFAULT 0,
    win_start REAL DEFAULT 0,
    win_up INTEGER DEFAULT 0,
    win_down INTEGER DEFAULT 0,
    strikes INTEGER DEFAULT 0,
    samples INTEGER DEFAULT 0,
    PRIMARY KEY (ip, infohash)
);
CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    reason TEXT DEFAULT '',
    score REAL DEFAULT 0,
    created REAL DEFAULT 0,
    expires REAL DEFAULT 0,
    active INTEGER DEFAULT 1,
    source TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    ip TEXT,
    action TEXT,
    reason TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS peer_ids (
    peer_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    last_seen REAL DEFAULT 0,
    PRIMARY KEY (peer_id, ip)
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE INDEX IF NOT EXISTS idx_bans_active ON bans(active, expires);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # -------- Peer 状态 --------
    def get_peer(self, ip: str, infohash: str) -> Optional[PeerState]:
        row = self.conn.execute(
            "SELECT * FROM peer_state WHERE ip=? AND infohash=?", (ip, infohash)
        ).fetchone()
        if not row:
            return None
        return PeerState(**{k: row[k] for k in row.keys()})

    def save_peer(self, st: PeerState):
        self.conn.execute(
            "INSERT OR REPLACE INTO peer_state (ip, infohash, port, client, peer_id,"
            " first_seen, last_seen, downloaded, uploaded, progress, score, score_ts,"
            " win_start, win_up, win_down, strikes, samples)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (st.ip, st.infohash, st.port, st.client, st.peer_id, st.first_seen,
             st.last_seen, st.downloaded, st.uploaded, st.progress, st.score,
             st.score_ts, st.win_start, st.win_up, st.win_down, st.strikes, st.samples),
        )
        self.conn.commit()

    def prune_peers(self, before_ts: float) -> int:
        cur = self.conn.execute("DELETE FROM peer_state WHERE last_seen < ?", (before_ts,))
        self.conn.commit()
        return cur.rowcount

    # -------- 封禁 --------
    def add_ban(self, ip: str, reason: str, score: float, created: float,
                expires: float, source: str = "auto"):
        self.conn.execute(
            "INSERT OR REPLACE INTO bans (ip, reason, score, created, expires, active, source)"
            " VALUES (?,?,?,?,?,1,?)",
            (ip, reason, score, created, expires, source),
        )
        self.conn.commit()

    def get_ban(self, ip: str) -> Optional[Ban]:
        row = self.conn.execute("SELECT * FROM bans WHERE ip=?", (ip,)).fetchone()
        return Ban(**{k: row[k] for k in row.keys()}) if row else None

    def active_bans(self) -> List[Ban]:
        rows = self.conn.execute(
            "SELECT * FROM bans WHERE active=1 ORDER BY created DESC"
        ).fetchall()
        return [Ban(**{k: r[k] for k in r.keys()}) for r in rows]

    def active_ban_ips(self) -> Set[str]:
        rows = self.conn.execute("SELECT ip FROM bans WHERE active=1").fetchall()
        return {r["ip"] for r in rows}

    def expired_bans(self, now: float) -> List[Ban]:
        rows = self.conn.execute(
            "SELECT * FROM bans WHERE active=1 AND expires>0 AND expires<=?", (now,)
        ).fetchall()
        return [Ban(**{k: r[k] for k in r.keys()}) for r in rows]

    def deactivate_ban(self, ip: str, note: str = ""):
        self.conn.execute("UPDATE bans SET active=0 WHERE ip=?", (ip,))
        self.conn.commit()

    def count_active_bans(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS c FROM bans WHERE active=1").fetchone()
        return int(row["c"] if row else 0)

    # -------- 事件 --------
    def record_event(self, ip: str, action: str, reason: str, detail: str = ""):
        self.conn.execute(
            "INSERT INTO events (ts, ip, action, reason, detail) VALUES (?,?,?,?,?)",
            (time.time(), ip, action, reason, detail),
        )
        self.conn.commit()

    def recent_events(self, limit: int = 50) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def trim_events(self, keep: int = 200000):
        self.conn.execute(
            "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?", (keep,)
        )
        self.conn.commit()

    # -------- peer_id 索引 --------
    def bump_peer_id(self, peer_id: str, ip: str, now: float):
        if not peer_id:
            return
        self.conn.execute(
            "INSERT OR REPLACE INTO peer_ids (peer_id, ip, last_seen) VALUES (?,?,?)",
            (peer_id, ip, now),
        )
        self.conn.commit()

    def peer_id_ip_count(self, peer_id: str, since: float) -> int:
        row = self.conn.execute(
            "SELECT COUNT(DISTINCT ip) AS c FROM peer_ids WHERE peer_id=? AND last_seen>=?",
            (peer_id, since),
        ).fetchone()
        return int(row["c"] if row else 0)

    def prune_peer_ids(self, before_ts: float):
        self.conn.execute("DELETE FROM peer_ids WHERE last_seen < ?", (before_ts,))
        self.conn.commit()

    # -------- KV --------
    def kv_get(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default

    def kv_set(self, key: str, value: str):
        self.conn.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?,?)", (key, value))
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except sqlite3.Error:
            pass
