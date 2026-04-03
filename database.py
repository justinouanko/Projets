"""
CIAlert — database.py
Gestion SQLite ultra-complète : signalements, stats, historique utilisateur.
"""

import sqlite3
import json
from datetime import datetime
from typing import Optional
from contextlib import contextmanager

DB_PATH = "cialert.db"

# ─────────────────────────────────────────────
# CONNEXION
# ─────────────────────────────────────────────

@contextmanager
def get_connection():
    """Gestionnaire de contexte pour la connexion SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Accès par nom de colonne
    conn.execute("PRAGMA journal_mode=WAL")  # Meilleures performances
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────
# INITIALISATION DES TABLES
# ─────────────────────────────────────────────

def init_db():
    """Crée toutes les tables si elles n'existent pas."""
    with get_connection() as conn:

        # Table principale des analyses
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                
                -- Contenu analysé
                input_text      TEXT    NOT NULL,
                input_type      TEXT    NOT NULL DEFAULT 'text',  -- text | url | phone | sms
                
                -- Résultat de détection
                is_scam         INTEGER NOT NULL,                  -- 0 ou 1
                confidence      REAL    NOT NULL,                  -- 0.0 → 1.0
                risk_level      TEXT    NOT NULL,                  -- FAIBLE | MOYEN | ÉLEVÉ | CRITIQUE
                scam_category   TEXT,                              -- broutage | mobile_money | phishing | autre
                
                -- Détails techniques
                rule_flags      TEXT,                              -- JSON : liste des règles déclenchées
                ai_explanation  TEXT,                              -- Explication IA en français
                ai_provider     TEXT,                              -- groq | gemini | claude
                ai_used         INTEGER NOT NULL DEFAULT 0,        -- IA appelée ?
                processing_ms   INTEGER,                           -- Temps de traitement
                
                -- Contexte réseau
                user_ip         TEXT,
                user_agent      TEXT,
                source          TEXT DEFAULT 'web'                 -- web | telegram | api
            )
        """)

        # Table des signalements manuels
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                
                -- Lien avec une analyse existante (optionnel)
                analysis_id     INTEGER REFERENCES analyses(id),
                
                -- Contenu signalé
                reported_text   TEXT    NOT NULL,
                report_type     TEXT    NOT NULL,  -- arnaque | faux_site | sms_frauduleux | autre
                
                -- Informations optionnelles du signaleur
                victim_amount   REAL,              -- Montant escroqué en FCFA
                victim_platform TEXT,              -- MTN | Orange | Wave | autre
                description     TEXT,              -- Description libre
                
                -- Validation communautaire
                confirmed_count INTEGER DEFAULT 0,
                status          TEXT DEFAULT 'pending'  -- pending | confirmed | rejected
            )
        """)

        # Table des sessions utilisateur (anonymes)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token   TEXT    NOT NULL UNIQUE,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
                source          TEXT    DEFAULT 'web',
                
                -- Stats agrégées par session
                total_analyses  INTEGER DEFAULT 0,
                scams_detected  INTEGER DEFAULT 0
            )
        """)

        # Table des stats journalières (cache agrégé)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS daily_stats (
                date            TEXT    PRIMARY KEY,  -- YYYY-MM-DD
                total_analyses  INTEGER DEFAULT 0,
                total_scams     INTEGER DEFAULT 0,
                total_reports   INTEGER DEFAULT 0,
                
                -- Répartition par catégorie (JSON)
                categories_json TEXT    DEFAULT '{}'
            )
        """)

        # Index pour les requêtes fréquentes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_scam ON analyses(is_scam)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_category ON analyses(scam_category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")

    print("✅ Base de données initialisée.")


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
    """Enregistre une analyse et met à jour les stats du jour. Retourne l'ID."""
    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO analyses (
                input_text, input_type, is_scam, confidence, risk_level,
                scam_category, rule_flags, ai_explanation, ai_provider,
                ai_used, processing_ms, user_ip, user_agent, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            input_text, input_type, int(is_scam), confidence, risk_level,
            scam_category, json.dumps(rule_flags or []), ai_explanation,
            ai_provider, int(ai_used), processing_ms, user_ip, user_agent, source
        ))
        analysis_id = cursor.lastrowid

    # Mise à jour des stats journalières
    _update_daily_stats(is_scam=is_scam, category=scam_category)
    return analysis_id


def get_analysis(analysis_id: int) -> Optional[dict]:
    """Récupère une analyse par ID."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def get_recent_analyses(limit: int = 20, scam_only: bool = False) -> list[dict]:
    """Retourne les dernières analyses."""
    query = "SELECT * FROM analyses"
    params = []
    if scam_only:
        query += " WHERE is_scam = 1"
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [_row_to_dict(r) for r in rows]


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
    """Enregistre un signalement manuel. Retourne l'ID."""
    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO reports (
                reported_text, report_type, analysis_id,
                victim_amount, victim_platform, description
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            reported_text, report_type, analysis_id,
            victim_amount, victim_platform, description
        ))

        # Mise à jour des stats
        today = datetime.now().strftime("%Y-%m-%d")
        conn.execute("""
            INSERT INTO daily_stats (date, total_reports)
            VALUES (?, 1)
            ON CONFLICT(date) DO UPDATE SET
                total_reports = total_reports + 1
        """, (today,))

        return cursor.lastrowid


def get_reports(status: str = "pending", limit: int = 50) -> list[dict]:
    """Retourne les signalements filtrés par statut."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (status, limit)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


# ─────────────────────────────────────────────
# STATS GLOBALES
# ─────────────────────────────────────────────

def get_global_stats() -> dict:
    """Retourne les statistiques globales de la plateforme."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        total_scams = conn.execute(
            "SELECT COUNT(*) FROM analyses WHERE is_scam = 1"
        ).fetchone()[0]
        total_reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

        # Répartition par catégorie
        cats = conn.execute("""
            SELECT scam_category, COUNT(*) as cnt
            FROM analyses
            WHERE is_scam = 1 AND scam_category IS NOT NULL
            GROUP BY scam_category
            ORDER BY cnt DESC
        """).fetchall()

        # Répartition par niveau de risque
        risks = conn.execute("""
            SELECT risk_level, COUNT(*) as cnt
            FROM analyses
            GROUP BY risk_level
        """).fetchall()

        # Stats des 7 derniers jours
        last_7_days = conn.execute("""
            SELECT date, total_analyses, total_scams
            FROM daily_stats
            ORDER BY date DESC
            LIMIT 7
        """).fetchall()

        # Provider IA le plus utilisé
        providers = conn.execute("""
            SELECT ai_provider, COUNT(*) as cnt
            FROM analyses
            WHERE ai_used = 1
            GROUP BY ai_provider
            ORDER BY cnt DESC
            LIMIT 1
        """).fetchone()

    return {
        "total_analyses": total,
        "total_scams": total_scams,
        "total_reports": total_reports,
        "scam_rate": round(total_scams / total * 100, 1) if total > 0 else 0,
        "categories": {row["scam_category"]: row["cnt"] for row in cats},
        "risk_levels": {row["risk_level"]: row["cnt"] for row in risks},
        "last_7_days": [dict(r) for r in last_7_days],
        "top_ai_provider": providers["ai_provider"] if providers else None,
    }


def get_user_history(session_token: str, limit: int = 10) -> list[dict]:
    """Retourne l'historique d'analyses d'une session utilisateur."""
    with get_connection() as conn:
        # Mise à jour last_seen
        conn.execute("""
            INSERT INTO user_sessions (session_token, last_seen, source)
            VALUES (?, datetime('now'), 'web')
            ON CONFLICT(session_token) DO UPDATE SET
                last_seen = datetime('now')
        """, (session_token,))

        rows = conn.execute("""
            SELECT id, created_at, input_text, is_scam, confidence,
                   risk_level, scam_category, ai_explanation
            FROM analyses
            WHERE user_ip = (
                SELECT user_ip FROM analyses
                WHERE user_ip IS NOT NULL
                LIMIT 1
            )
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [_row_to_dict(r) for r in rows]


# ─────────────────────────────────────────────
# UTILITAIRES INTERNES
# ─────────────────────────────────────────────

def _update_daily_stats(is_scam: bool, category: Optional[str]):
    """Met à jour la table des stats journalières."""
    today = datetime.now().strftime("%Y-%m-%d")
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO daily_stats (date, total_analyses, total_scams)
            VALUES (?, 1, ?)
            ON CONFLICT(date) DO UPDATE SET
                total_analyses = total_analyses + 1,
                total_scams    = total_scams + ?
        """, (today, int(is_scam), int(is_scam)))

        if is_scam and category:
            row = conn.execute(
                "SELECT categories_json FROM daily_stats WHERE date = ?", (today,)
            ).fetchone()
            cats = json.loads(row["categories_json"]) if row else {}
            cats[category] = cats.get(category, 0) + 1
            conn.execute(
                "UPDATE daily_stats SET categories_json = ? WHERE date = ?",
                (json.dumps(cats), today)
            )


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convertit une Row SQLite en dict, désérialise le JSON imbriqué."""
    d = dict(row)
    if "rule_flags" in d and d["rule_flags"]:
        try:
            d["rule_flags"] = json.loads(d["rule_flags"])
        except (json.JSONDecodeError, TypeError):
            pass
    return d
