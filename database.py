"""
CIAlert — database.py
Compatible PostgreSQL (production) et SQLite (développement local).
"""

import json
import os
from datetime import datetime
from typing import Optional
from contextlib import contextmanager

# ─────────────────────────────────────────────
# DÉTECTION DU MODE (PostgreSQL ou SQLite)
# ─────────────────────────────────────────────

DATABASE_URL = os.environ.get("DATABASE_URL", "")

if DATABASE_URL and DATABASE_URL.startswith("postgres"):
    # MODE POSTGRESQL
    import psycopg2
    import psycopg2.extras

    # Railway fournit parfois "postgres://" au lieu de "postgresql://"
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    USE_POSTGRES = True

    @contextmanager
    def get_connection():
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def fetchone(cursor):
        return cursor.fetchone()

    def fetchall(cursor):
        return cursor.fetchall()

    def row_to_dict(row, cursor):
        if row is None:
            return None
        cols = [desc[0] for desc in cursor.description]
        return dict(zip(cols, row))

    def rows_to_dicts(rows, cursor):
        cols = [desc[0] for desc in cursor.description]
        return [dict(zip(cols, r)) for r in rows]

    PLACEHOLDER = "%s"
    AUTOINCREMENT = "SERIAL PRIMARY KEY"
    DATETIME_DEFAULT = "NOW()"
    ON_CONFLICT_SESSION = """
        INSERT INTO user_sessions (session_token, last_seen, source)
        VALUES (%s, NOW(), 'web')
        ON CONFLICT (session_token) DO UPDATE SET last_seen = NOW()
    """

else:
    # MODE SQLITE (développement local)
    import sqlite3

    DB_PATH = "cialert.db"
    USE_POSTGRES = False

    @contextmanager
    def get_connection():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def fetchone(cursor):
        return cursor.fetchone()

    def fetchall(cursor):
        return cursor.fetchall()

    def row_to_dict(row, cursor=None):
        if row is None:
            return None
        return dict(row)

    def rows_to_dicts(rows, cursor=None):
        return [dict(r) for r in rows]

    PLACEHOLDER = "?"
    AUTOINCREMENT = "INTEGER PRIMARY KEY AUTOINCREMENT"
    DATETIME_DEFAULT = "datetime('now')"
    ON_CONFLICT_SESSION = """
        INSERT INTO user_sessions (session_token, last_seen, source)
        VALUES (?, datetime('now'), 'web')
        ON CONFLICT(session_token) DO UPDATE SET last_seen = datetime('now')
    """


# ─────────────────────────────────────────────
# INITIALISATION DES TABLES
# ─────────────────────────────────────────────

def init_db():
    """Crée toutes les tables si elles n'existent pas."""
    with get_connection() as conn:
        cur = conn.cursor()

        # Table principale des analyses
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS analyses (
                id              {AUTOINCREMENT},
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                input_text      TEXT        NOT NULL,
                input_type      TEXT        NOT NULL DEFAULT 'text',
                is_scam         INTEGER     NOT NULL,
                confidence      REAL        NOT NULL,
                risk_level      TEXT        NOT NULL,
                scam_category   TEXT,
                rule_flags      TEXT,
                ai_explanation  TEXT,
                ai_provider     TEXT,
                ai_used         INTEGER     NOT NULL DEFAULT 0,
                processing_ms   INTEGER,
                user_ip         TEXT,
                user_agent      TEXT,
                source          TEXT        DEFAULT 'web'
            )
        """)

        # Table des signalements manuels
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS reports (
                id              {AUTOINCREMENT},
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                analysis_id     INTEGER,
                reported_text   TEXT        NOT NULL,
                report_type     TEXT        NOT NULL,
                victim_amount   REAL,
                victim_platform TEXT,
                description     TEXT,
                confirmed_count INTEGER     DEFAULT 0,
                status          TEXT        DEFAULT 'pending'
            )
        """)

        # Table des sessions utilisateur
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id              {AUTOINCREMENT},
                session_token   TEXT        NOT NULL UNIQUE,
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                last_seen       TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                source          TEXT        DEFAULT 'web',
                total_analyses  INTEGER     DEFAULT 0,
                scams_detected  INTEGER     DEFAULT 0
            )
        """)

        # Table des stats journalières
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS daily_stats (
                date            TEXT        PRIMARY KEY,
                total_analyses  INTEGER     DEFAULT 0,
                total_scams     INTEGER     DEFAULT 0,
                total_reports   INTEGER     DEFAULT 0,
                categories_json TEXT        DEFAULT '{{}}'
            )
        """)

        # Table feedback (boucle d'amélioration IA)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS feedback (
                id              {AUTOINCREMENT},
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                analysis_id     INTEGER     NOT NULL,
                correct         INTEGER     NOT NULL,
                real_category   TEXT
            )
        """)

        # Index
        cur.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_analyses_scam ON analyses(is_scam)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_analyses_category ON analyses(scam_category)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")

    print(f"✅ Base de données initialisée ({'PostgreSQL' if USE_POSTGRES else 'SQLite'}).")


# ─────────────────────────────────────────────
# CRUD — ANALYSES
# ─────────────────────────────────────────────

def save_analysis(
    input_text: str,
    is_scam: bool,
    confidence: float,
    risk_level: str,
    scam_category: Optional[str] = None,
    rule_flags: Optional[list] = None,
    ai_explanation: Optional[str] = None,
    ai_provider: Optional[str] = None,
    ai_used: bool = False,
    processing_ms: Optional[int] = None,
    input_type: str = "text",
    user_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    source: str = "web"
) -> int:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO analyses (
                    input_text, input_type, is_scam, confidence, risk_level,
                    scam_category, rule_flags, ai_explanation, ai_provider,
                    ai_used, processing_ms, user_ip, user_agent, source
                ) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})
                RETURNING id
            """, (
                input_text, input_type, int(is_scam), confidence, risk_level,
                scam_category, json.dumps(rule_flags or []), ai_explanation,
                ai_provider, int(ai_used), processing_ms, user_ip, user_agent, source
            ))
            analysis_id = cur.fetchone()[0]
        else:
            cur.execute(f"""
                INSERT INTO analyses (
                    input_text, input_type, is_scam, confidence, risk_level,
                    scam_category, rule_flags, ai_explanation, ai_provider,
                    ai_used, processing_ms, user_ip, user_agent, source
                ) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})
            """, (
                input_text, input_type, int(is_scam), confidence, risk_level,
                scam_category, json.dumps(rule_flags or []), ai_explanation,
                ai_provider, int(ai_used), processing_ms, user_ip, user_agent, source
            ))
            analysis_id = cur.lastrowid

    _update_daily_stats(is_scam=is_scam, category=scam_category)
    return analysis_id


def get_analysis(analysis_id: int) -> Optional[dict]:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM analyses WHERE id = {p}", (analysis_id,))
        row = cur.fetchone()
        d = row_to_dict(row, cur)
        if d and "rule_flags" in d and d["rule_flags"]:
            try:
                d["rule_flags"] = json.loads(d["rule_flags"])
            except Exception:
                pass
        return d


def get_recent_analyses(limit: int = 20, scam_only: bool = False) -> list:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if scam_only:
            cur.execute(f"SELECT * FROM analyses WHERE is_scam = 1 ORDER BY created_at DESC LIMIT {p}", (limit,))
        else:
            cur.execute(f"SELECT * FROM analyses ORDER BY created_at DESC LIMIT {p}", (limit,))
        rows = cur.fetchall()
        result = rows_to_dicts(rows, cur)
        for d in result:
            if "rule_flags" in d and d["rule_flags"]:
                try:
                    d["rule_flags"] = json.loads(d["rule_flags"])
                except Exception:
                    pass
        return result


# ─────────────────────────────────────────────
# CRUD — SIGNALEMENTS
# ─────────────────────────────────────────────

def save_report(
    reported_text: str,
    report_type: str,
    analysis_id: Optional[int] = None,
    victim_amount: Optional[float] = None,
    victim_platform: Optional[str] = None,
    description: Optional[str] = None
) -> int:
    p = PLACEHOLDER
    today = datetime.now().strftime("%Y-%m-%d")
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO reports (
                    reported_text, report_type, analysis_id,
                    victim_amount, victim_platform, description
                ) VALUES ({p},{p},{p},{p},{p},{p})
                RETURNING id
            """, (reported_text, report_type, analysis_id, victim_amount, victim_platform, description))
            report_id = cur.fetchone()[0]
        else:
            cur.execute(f"""
                INSERT INTO reports (
                    reported_text, report_type, analysis_id,
                    victim_amount, victim_platform, description
                ) VALUES ({p},{p},{p},{p},{p},{p})
            """, (reported_text, report_type, analysis_id, victim_amount, victim_platform, description))
            report_id = cur.lastrowid

        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO daily_stats (date, total_reports)
                VALUES ({p}, 1)
                ON CONFLICT (date) DO UPDATE SET total_reports = daily_stats.total_reports + 1
            """, (today,))
        else:
            cur.execute(f"""
                INSERT INTO daily_stats (date, total_reports)
                VALUES ({p}, 1)
                ON CONFLICT(date) DO UPDATE SET total_reports = total_reports + 1
            """, (today,))

        return report_id


def get_reports(status: str = "pending", limit: int = 50) -> list:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"SELECT * FROM reports WHERE status = {p} ORDER BY created_at DESC LIMIT {p}",
            (status, limit)
        )
        return rows_to_dicts(cur.fetchall(), cur)


# ─────────────────────────────────────────────
# FEEDBACK (boucle d'amélioration IA)
# ─────────────────────────────────────────────

def save_feedback(analysis_id: int, correct: bool, real_category: Optional[str] = None) -> int:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO feedback (analysis_id, correct, real_category)
                VALUES ({p}, {p}, {p})
                RETURNING id
            """, (analysis_id, int(correct), real_category))
            return cur.fetchone()[0]
        else:
            cur.execute(f"""
                INSERT INTO feedback (analysis_id, correct, real_category)
                VALUES ({p}, {p}, {p})
            """, (analysis_id, int(correct), real_category))
            return cur.lastrowid


def get_feedback_stats() -> dict:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM feedback")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM feedback WHERE correct = 1")
        correct = cur.fetchone()[0]
        return {
            "total_feedback": total,
            "correct": correct,
            "incorrect": total - correct,
            "accuracy_rate": round(correct / total * 100, 1) if total > 0 else 0
        }


# ─────────────────────────────────────────────
# STATS GLOBALES
# ─────────────────────────────────────────────

def get_global_stats() -> dict:
    with get_connection() as conn:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM analyses")
        total = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM analyses WHERE is_scam = 1")
        total_scams = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM reports")
        total_reports = cur.fetchone()[0]

        cur.execute("""
            SELECT scam_category, COUNT(*) as cnt
            FROM analyses
            WHERE is_scam = 1 AND scam_category IS NOT NULL
            GROUP BY scam_category
            ORDER BY cnt DESC
        """)
        cats = cur.fetchall()
        cats_dicts = rows_to_dicts(cats, cur)

        cur.execute("""
            SELECT risk_level, COUNT(*) as cnt
            FROM analyses
            GROUP BY risk_level
        """)
        risks = cur.fetchall()
        risks_dicts = rows_to_dicts(risks, cur)

        cur.execute("""
            SELECT date, total_analyses, total_scams
            FROM daily_stats
            ORDER BY date DESC
            LIMIT 7
        """)
        last_7 = cur.fetchall()
        last_7_dicts = rows_to_dicts(last_7, cur)

        cur.execute("""
            SELECT ai_provider, COUNT(*) as cnt
            FROM analyses
            WHERE ai_used = 1
            GROUP BY ai_provider
            ORDER BY cnt DESC
            LIMIT 1
        """)
        provider_row = cur.fetchone()
        provider_dict = row_to_dict(provider_row, cur) if provider_row else None

    return {
        "total_analyses": total,
        "total_scams": total_scams,
        "total_reports": total_reports,
        "scam_rate": round(total_scams / total * 100, 1) if total > 0 else 0,
        "categories": {r["scam_category"]: r["cnt"] for r in cats_dicts},
        "risk_levels": {r["risk_level"]: r["cnt"] for r in risks_dicts},
        "last_7_days": last_7_dicts,
        "top_ai_provider": provider_dict["ai_provider"] if provider_dict else None,
    }


def get_user_history(session_token: str, limit: int = 10) -> list:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(ON_CONFLICT_SESSION, (session_token,))
        cur.execute(f"""
            SELECT id, created_at, input_text, is_scam, confidence,
                   risk_level, scam_category, ai_explanation
            FROM analyses
            ORDER BY created_at DESC
            LIMIT {p}
        """, (limit,))
        return rows_to_dicts(cur.fetchall(), cur)


# ─────────────────────────────────────────────
# UTILITAIRES INTERNES
# ─────────────────────────────────────────────

def _update_daily_stats(is_scam: bool, category: Optional[str]):
    today = datetime.now().strftime("%Y-%m-%d")
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO daily_stats (date, total_analyses, total_scams)
                VALUES ({p}, 1, {p})
                ON CONFLICT (date) DO UPDATE SET
                    total_analyses = daily_stats.total_analyses + 1,
                    total_scams    = daily_stats.total_scams + {p}
            """, (today, int(is_scam), int(is_scam)))
        else:
            cur.execute(f"""
                INSERT INTO daily_stats (date, total_analyses, total_scams)
                VALUES ({p}, 1, {p})
                ON CONFLICT(date) DO UPDATE SET
                    total_analyses = total_analyses + 1,
                    total_scams    = total_scams + {p}
            """, (today, int(is_scam), int(is_scam)))

        if is_scam and category:
            cur.execute(f"SELECT categories_json FROM daily_stats WHERE date = {p}", (today,))
            row = cur.fetchone()
            cats = json.loads(row[0]) if row and row[0] else {}
            cats[category] = cats.get(category, 0) + 1
            cur.execute(
                f"UPDATE daily_stats SET categories_json = {p} WHERE date = {p}",
                (json.dumps(cats), today)
            )
