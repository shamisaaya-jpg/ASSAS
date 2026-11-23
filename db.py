"""PostgreSQL storage for ASSAS: users, analyses and alerts."""
import os
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://assas:assas_pass@localhost:5432/assas"
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analyses (
    id          SERIAL PRIMARY KEY,
    filename    TEXT,
    analyzed_by INTEGER REFERENCES users(id),
    total       INTEGER DEFAULT 0,
    critical    INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id) ON DELETE CASCADE,
    event_time  TEXT,
    username    TEXT,
    ip          TEXT,
    event       TEXT,
    severity    VARCHAR(10),
    reason      TEXT,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_analysis ON alerts (analysis_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses (created_at DESC);
"""


@contextmanager
def db_cursor():
    """Open a connection, give a cursor, commit on success, always close."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    try:
        with conn:
            with conn.cursor() as cur:
                yield cur
    finally:
        conn.close()


def init_db():
    """Create the tables if they do not exist yet."""
    with db_cursor() as cur:
        cur.execute(SCHEMA)


# ---------- Users ----------

def create_user(username, password_hash):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO users (username, password_hash) VALUES (%s, %s)
               ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
               RETURNING id""",
            (username, password_hash),
        )
        return cur.fetchone()["id"]


def get_user_by_username(username):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cur.fetchone()


def get_user_by_id(user_id):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cur.fetchone()


# ---------- Analyses and alerts ----------

def save_analysis(filename, summary, threats, user_id):
    """Store one analysis and all its alerts. Returns the analysis id."""
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO analyses (filename, analyzed_by, total, critical, high, medium, low)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (filename, user_id, summary["total_threats"], summary["critical"],
             summary["high"], summary["medium"], summary["low"]),
        )
        analysis_id = cur.fetchone()["id"]

        if threats is not None and not threats.empty:
            rows = [
                (analysis_id, str(r["timestamp"]), str(r["user"]), str(r["ip"]),
                 str(r["event"]), str(r["severity"]), str(r["reason"]))
                for r in threats.fillna("").to_dict(orient="records")
            ]
            execute_values(
                cur,
                """INSERT INTO alerts (analysis_id, event_time, username, ip, event, severity, reason)
                   VALUES %s""",
                rows,
            )
        return analysis_id


def list_analyses(limit=20):
    with db_cursor() as cur:
        cur.execute(
            """SELECT a.*, u.username AS analyst
               FROM analyses a LEFT JOIN users u ON u.id = a.analyzed_by
               ORDER BY a.created_at DESC LIMIT %s""",
            (limit,),
        )
        return cur.fetchall()


def list_alerts(limit=100, severity=None):
    query = """SELECT al.*, an.filename
               FROM alerts al JOIN analyses an ON an.id = al.analysis_id"""
    params = []
    if severity:
        query += " WHERE al.severity = %s"
        params.append(severity.upper())
    query += """ ORDER BY al.created_at DESC, al.analysis_id DESC,
                 CASE al.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                  WHEN 'MEDIUM' THEN 2 ELSE 3 END
                 LIMIT %s"""
    params.append(limit)
    with db_cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def get_analysis(analysis_id):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM analyses WHERE id = %s", (analysis_id,))
        return cur.fetchone()


def get_alerts_for_analysis(analysis_id):
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM alerts WHERE analysis_id = %s
               ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                      WHEN 'MEDIUM' THEN 2 ELSE 3 END, id""",
            (analysis_id,),
        )
        return cur.fetchall()
