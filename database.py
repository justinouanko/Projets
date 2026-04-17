"""
CIAlert — database.py
Couche données compatible PostgreSQL (production) et SQLite (développement local).
"""

import json
import os
from datetime import datetime
from typing import Optional
from contextlib import contextmanager

# ─────────────────────────────────────────────
# DÉTECTION DU MODE : PostgreSQL ou SQLite
# ─────────────────────────────────────────────

DATABASE_URL = os.environ.get("DATABASE_URL", "")

if DATABASE_URL and DATABASE_URL.startswith("postgres"):
    import psycopg2
    import psycopg2.extras

    # Railway utilise parfois "postgres://" — on normalise
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

    def row_to_dict(row, cursor):
        if row is None:
            return None
        cols = [desc[0] for desc in cursor.description]
        return dict(zip(cols, row))

    def rows_to_dicts(rows, cursor):
        cols = [desc[0] for desc in cursor.description]
        return [dict(zip(cols, row)) for row in rows]

    PLACEHOLDER = "%s"
    AUTOINCREMENT = "SERIAL PRIMARY KEY"
    DATETIME_DEFAULT = "NOW()"

    ON_CONFLICT_SESSION = """
        INSERT INTO user_sessions (session_token, last_seen, source)
        VALUES (%s, NOW(), 'web')
        ON CONFLICT (session_token) DO UPDATE SET last_seen = NOW()
    """

else:
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

    def row_to_dict(row, cursor=None):
        if row is None:
            return None
        return dict(row)

    def rows_to_dicts(rows, cursor=None):
        return [dict(row) for row in rows]

    PLACEHOLDER = "?"
    AUTOINCREMENT = "INTEGER PRIMARY KEY AUTOINCREMENT"
    DATETIME_DEFAULT = "(datetime('now'))"

    ON_CONFLICT_SESSION = """
        INSERT INTO user_sessions (session_token, last_seen, source)
        VALUES (?, datetime('now'), 'web')
        ON CONFLICT(session_token) DO UPDATE SET last_seen = datetime('now')
    """


# ─────────────────────────────────────────────
# INITIALISATION DES TABLES
# ─────────────────────────────────────────────

def init_db():
    """Crée toutes les tables si elles n'existent pas encore."""
    with get_connection() as conn:
        cur = conn.cursor()

        # Analyses individuelles (V1 — conservée pour compatibilité)
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

        # Table unifiée V2.0 — remplace analyses + fake_news_analyses + file_analyses
        # Chaque ligne correspond à un appel POST /scan
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS scans (
                id                  {AUTOINCREMENT},
                created_at          TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                raw_input           TEXT        NOT NULL,
                input_type          TEXT        NOT NULL DEFAULT 'auto',
                has_file            INTEGER     NOT NULL DEFAULT 0,
                filename            TEXT,
                is_scam             INTEGER,
                confidence          REAL,
                risk_level          TEXT,
                scam_category       TEXT,
                rule_flags          TEXT,
                has_fake_news       INTEGER     DEFAULT 0,
                fake_news_verdict   TEXT,
                fake_news_score     INTEGER     DEFAULT 0,
                phone_flagged       INTEGER     DEFAULT 0,
                ai_explanation      TEXT,
                ai_provider         TEXT,
                processing_ms       INTEGER,
                source              TEXT        DEFAULT 'web'
            )
        """)

        # Signalements manuels
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS reports (
                id              {AUTOINCREMENT},
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                scan_id         INTEGER,
                reported_text   TEXT        NOT NULL,
                report_type     TEXT        NOT NULL,
                victim_amount   REAL,
                victim_platform TEXT,
                description     TEXT,
                status          TEXT        DEFAULT 'pending'
            )
        """)

        # Répertoire des numéros signalés — usage interne uniquement
        # Jamais exposé sur le frontend
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS phone_reports (
                id              {AUTOINCREMENT},
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                phone_number    TEXT        NOT NULL,
                scam_category   TEXT,
                source          TEXT        DEFAULT 'report',
                scan_id         INTEGER,
                report_id       INTEGER
            )
        """)

        # Index pour accélérer les lookups sur les numéros
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_phone_reports_number
            ON phone_reports(phone_number)
        """)

        # Feedback utilisateur sur les résultats d'analyse
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS feedback (
                id              {AUTOINCREMENT},
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                scan_id         INTEGER,
                analysis_id     INTEGER,
                correct         INTEGER     NOT NULL,
                real_category   TEXT
            )
        """)

        # Sessions anonymes pour le suivi d'usage
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

        # Statistiques agrégées par jour
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS daily_stats (
                date            TEXT        PRIMARY KEY,
                total_analyses  INTEGER     DEFAULT 0,
                total_scams     INTEGER     DEFAULT 0,
                total_reports   INTEGER     DEFAULT 0,
                categories_json TEXT        DEFAULT '{{}}'
            )
        """)

        # Tables V1 conservées pour ne pas perdre les données existantes
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS fake_news_analyses (
                id                  {AUTOINCREMENT},
                created_at          TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                contenu             TEXT        NOT NULL,
                type_contenu        TEXT        DEFAULT 'texte',
                verdict             TEXT        NOT NULL,
                score_manipulation  INTEGER     DEFAULT 0,
                resultat_json       TEXT
            )
        """)

        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS file_analyses (
                id              {AUTOINCREMENT},
                created_at      TIMESTAMP   NOT NULL DEFAULT {DATETIME_DEFAULT},
                filename        TEXT,
                content         TEXT,
                verdict         TEXT,
                score           REAL,
                category        TEXT,
                explanation     TEXT,
                method          TEXT,
                source          TEXT        DEFAULT 'file_upload'
            )
        """)

        # Index principaux
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_level)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_analyses_scam ON analyses(is_scam)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")

    print(f"✅ Base de données initialisée ({'PostgreSQL' if USE_POSTGRES else 'SQLite'}).")


# ─────────────────────────────────────────────
# CRUD — SCANS (V2.0)
# ─────────────────────────────────────────────

def save_scan(
    raw_input: str,
    input_type: str,
    is_scam: Optional[bool] = None,
    confidence: Optional[float] = None,
    risk_level: Optional[str] = None,
    scam_category: Optional[str] = None,
    rule_flags: Optional[list] = None,
    has_fake_news: bool = False,
    fake_news_verdict: Optional[str] = None,
    fake_news_score: int = 0,
    phone_flagged: bool = False,
    ai_explanation: Optional[str] = None,
    ai_provider: Optional[str] = None,
    processing_ms: Optional[int] = None,
    has_file: bool = False,
    filename: Optional[str] = None,
    source: str = "web"
) -> int:
    """Sauvegarde un scan V2.0 et met à jour les stats du jour."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO scans (
                    raw_input, input_type, has_file, filename,
                    is_scam, confidence, risk_level, scam_category, rule_flags,
                    has_fake_news, fake_news_verdict, fake_news_score,
                    phone_flagged, ai_explanation, ai_provider,
                    processing_ms, source
                ) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})
                RETURNING id
            """, (
                raw_input, input_type, int(has_file), filename,
                int(is_scam) if is_scam is not None else None,
                confidence, risk_level, scam_category,
                json.dumps(rule_flags or []),
                int(has_fake_news), fake_news_verdict, fake_news_score,
                int(phone_flagged), ai_explanation, ai_provider,
                processing_ms, source
            ))
            scan_id = cur.fetchone()[0]
        else:
            cur.execute(f"""
                INSERT INTO scans (
                    raw_input, input_type, has_file, filename,
                    is_scam, confidence, risk_level, scam_category, rule_flags,
                    has_fake_news, fake_news_verdict, fake_news_score,
                    phone_flagged, ai_explanation, ai_provider,
                    processing_ms, source
                ) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})
            """, (
                raw_input, input_type, int(has_file), filename,
                int(is_scam) if is_scam is not None else None,
                confidence, risk_level, scam_category,
                json.dumps(rule_flags or []),
                int(has_fake_news), fake_news_verdict, fake_news_score,
                int(phone_flagged), ai_explanation, ai_provider,
                processing_ms, source
            ))
            scan_id = cur.lastrowid

    _update_daily_stats(is_scam=is_scam or False, category=scam_category)
    return scan_id


def get_recent_scans(limit: int = 20) -> list:
    """Retourne les derniers scans — usage interne uniquement."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"SELECT * FROM scans ORDER BY created_at DESC LIMIT {p}",
            (limit,)
        )
        rows = rows_to_dicts(cur.fetchall(), cur)
        for row in rows:
            if row.get("rule_flags"):
                try:
                    row["rule_flags"] = json.loads(row["rule_flags"])
                except Exception:
                    pass
        return rows


# ─────────────────────────────────────────────
# CRUD — RÉPERTOIRE DE NUMÉROS (interne)
# ─────────────────────────────────────────────

def add_phone_report(
    phone_number: str,
    scam_category: Optional[str] = None,
    source: str = "report",
    scan_id: Optional[int] = None,
    report_id: Optional[int] = None
) -> int:
    """Ajoute un numéro au répertoire. Ne jamais exposer sur le frontend."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO phone_reports (phone_number, scam_category, source, scan_id, report_id)
                VALUES ({p},{p},{p},{p},{p})
                RETURNING id
            """, (phone_number, scam_category, source, scan_id, report_id))
            return cur.fetchone()[0]
        else:
            cur.execute(f"""
                INSERT INTO phone_reports (phone_number, scam_category, source, scan_id, report_id)
                VALUES ({p},{p},{p},{p},{p})
            """, (phone_number, scam_category, source, scan_id, report_id))
            return cur.lastrowid


def get_phone_report_count(phone_number: str) -> int:
    """Retourne le nombre de signalements pour un numéro donné."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"SELECT COUNT(*) FROM phone_reports WHERE phone_number = {p}",
            (phone_number,)
        )
        return cur.fetchone()[0]


def is_phone_flagged(phone_number: str) -> bool:
    """Retourne True si le numéro a été signalé au moins une fois."""
    return get_phone_report_count(phone_number) > 0


def get_phone_categories(phone_number: str) -> list:
    """Retourne les catégories d'arnaque associées à un numéro — usage interne."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT DISTINCT scam_category
            FROM phone_reports
            WHERE phone_number = {p} AND scam_category IS NOT NULL
        """, (phone_number,))
        return [row[0] for row in cur.fetchall()]


# ─────────────────────────────────────────────
# CRUD — SIGNALEMENTS
# ─────────────────────────────────────────────

def save_report(
    reported_text: str,
    report_type: str,
    scan_id: Optional[int] = None,
    analysis_id: Optional[int] = None,
    victim_amount: Optional[float] = None,
    victim_platform: Optional[str] = None,
    description: Optional[str] = None
) -> int:
    """Sauvegarde un signalement manuel."""
    p = PLACEHOLDER
    today = datetime.now().strftime("%Y-%m-%d")
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO reports (
                    reported_text, report_type, scan_id,
                    victim_amount, victim_platform, description
                ) VALUES ({p},{p},{p},{p},{p},{p})
                RETURNING id
            """, (reported_text, report_type, scan_id or analysis_id,
                  victim_amount, victim_platform, description))
            report_id = cur.fetchone()[0]

            cur.execute(f"""
                INSERT INTO daily_stats (date, total_reports)
                VALUES ({p}, 1)
                ON CONFLICT (date) DO UPDATE SET
                    total_reports = daily_stats.total_reports + 1
            """, (today,))
        else:
            cur.execute(f"""
                INSERT INTO reports (
                    reported_text, report_type, scan_id,
                    victim_amount, victim_platform, description
                ) VALUES ({p},{p},{p},{p},{p},{p})
            """, (reported_text, report_type, scan_id or analysis_id,
                  victim_amount, victim_platform, description))
            report_id = cur.lastrowid

            cur.execute(f"""
                INSERT INTO daily_stats (date, total_reports)
                VALUES ({p}, 1)
                ON CONFLICT(date) DO UPDATE SET
                    total_reports = total_reports + 1
            """, (today,))

        return report_id


def get_reports(status: str = "pending", limit: int = 50) -> list:
    """Retourne les signalements par statut — usage interne."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"SELECT * FROM reports WHERE status = {p} ORDER BY created_at DESC LIMIT {p}",
            (status, limit)
        )
        return rows_to_dicts(cur.fetchall(), cur)


# ─────────────────────────────────────────────
# CRUD — FEEDBACK
# ─────────────────────────────────────────────

def save_feedback(
    correct: bool,
    scan_id: Optional[int] = None,
    analysis_id: Optional[int] = None,
    real_category: Optional[str] = None
) -> int:
    """Sauvegarde le retour utilisateur sur un résultat d'analyse."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO feedback (scan_id, analysis_id, correct, real_category)
                VALUES ({p},{p},{p},{p})
                RETURNING id
            """, (scan_id, analysis_id, int(correct), real_category))
            return cur.fetchone()[0]
        else:
            cur.execute(f"""
                INSERT INTO feedback (scan_id, analysis_id, correct, real_category)
                VALUES ({p},{p},{p},{p})
            """, (scan_id, analysis_id, int(correct), real_category))
            return cur.lastrowid


def get_feedback_stats() -> dict:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM feedback")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM feedback WHERE correct = 1")
        correct = cur.fetchone()[0]
        return {
            "total": total,
            "correct": correct,
            "incorrect": total - correct,
            "accuracy_rate": round(correct / total * 100, 1) if total > 0 else 0
        }


# ─────────────────────────────────────────────
# CRUD — TABLES V1 (compatibilité)
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
    """Conservée pour compatibilité avec le bot Telegram et les anciens endpoints."""
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
        row = row_to_dict(cur.fetchone(), cur)
        if row and row.get("rule_flags"):
            try:
                row["rule_flags"] = json.loads(row["rule_flags"])
            except Exception:
                pass
        return row


def get_recent_analyses(limit: int = 20, scam_only: bool = False) -> list:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if scam_only:
            cur.execute(
                f"SELECT * FROM analyses WHERE is_scam = 1 ORDER BY created_at DESC LIMIT {p}",
                (limit,)
            )
        else:
            cur.execute(
                f"SELECT * FROM analyses ORDER BY created_at DESC LIMIT {p}",
                (limit,)
            )
        rows = rows_to_dicts(cur.fetchall(), cur)
        for row in rows:
            if row.get("rule_flags"):
                try:
                    row["rule_flags"] = json.loads(row["rule_flags"])
                except Exception:
                    pass
        return rows


def save_fake_news_to_db(contenu: str, type_contenu: str, resultat: dict) -> int:
    """Conservée pour compatibilité avec l'ancien endpoint /fake-news."""
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO fake_news_analyses
                    (contenu, type_contenu, verdict, score_manipulation, resultat_json)
                VALUES ({p},{p},{p},{p},{p})
                RETURNING id
            """, (
                contenu[:500], type_contenu,
                resultat.get("verdict", "ERREUR"),
                resultat.get("score_manipulation", 0),
                json.dumps(resultat, ensure_ascii=False)
            ))
            return cur.fetchone()[0]
        else:
            cur.execute(f"""
                INSERT INTO fake_news_analyses
                    (contenu, type_contenu, verdict, score_manipulation, resultat_json)
                VALUES ({p},{p},{p},{p},{p})
            """, (
                contenu[:500], type_contenu,
                resultat.get("verdict", "ERREUR"),
                resultat.get("score_manipulation", 0),
                json.dumps(resultat, ensure_ascii=False)
            ))
            return cur.lastrowid


# ─────────────────────────────────────────────
# STATS GLOBALES
# ─────────────────────────────────────────────

def get_global_stats() -> dict:
    """Stats agrégées pour le dashboard interne."""
    with get_connection() as conn:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM scans")
        total = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM scans WHERE is_scam = 1")
        total_scams = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM reports")
        total_reports = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM phone_reports")
        total_phone_reports = cur.fetchone()[0]

        cur.execute("""
            SELECT scam_category, COUNT(*) as cnt
            FROM scans
            WHERE is_scam = 1 AND scam_category IS NOT NULL
            GROUP BY scam_category
            ORDER BY cnt DESC
        """)
        categories = rows_to_dicts(cur.fetchall(), cur)

        cur.execute("""
            SELECT risk_level, COUNT(*) as cnt
            FROM scans
            WHERE risk_level IS NOT NULL
            GROUP BY risk_level
        """)
        risk_levels = rows_to_dicts(cur.fetchall(), cur)

        cur.execute("""
            SELECT date, total_analyses, total_scams
            FROM daily_stats
            ORDER BY date DESC
            LIMIT 7
        """)
        last_7_days = rows_to_dicts(cur.fetchall(), cur)

    return {
        "total_analyses": total,
        "total_scams": total_scams,
        "total_reports": total_reports,
        "total_phone_reports": total_phone_reports,
        "scam_rate": round(total_scams / total * 100, 1) if total > 0 else 0,
        "categories": {r["scam_category"]: r["cnt"] for r in categories},
        "risk_levels": {r["risk_level"]: r["cnt"] for r in risk_levels},
        "last_7_days": last_7_days,
    }


def get_user_history(session_token: str, limit: int = 10) -> list:
    p = PLACEHOLDER
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(ON_CONFLICT_SESSION, (session_token,))
        cur.execute(f"""
            SELECT id, created_at, input_type, is_scam, confidence,
                   risk_level, scam_category, ai_explanation
            FROM scans
            ORDER BY created_at DESC
            LIMIT {p}
        """, (limit,))
        return rows_to_dicts(cur.fetchall(), cur)


# ─────────────────────────────────────────────
# UTILITAIRES INTERNES
# ─────────────────────────────────────────────

def _update_daily_stats(is_scam: bool, category: Optional[str]):
    """Met à jour les compteurs du jour — appelée après chaque scan ou analyse."""
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
            cur.execute(
                f"SELECT categories_json FROM daily_stats WHERE date = {p}",
                (today,)
            )
            row = cur.fetchone()
            cats = json.loads(row[0]) if row and row[0] else {}
            cats[category] = cats.get(category, 0) + 1
            cur.execute(
                f"UPDATE daily_stats SET categories_json = {p} WHERE date = {p}",
                (json.dumps(cats), today)
            )