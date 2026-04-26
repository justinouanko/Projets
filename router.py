"""
CIAlert — router.py
Détecte automatiquement le type de contenu soumis par l'utilisateur
et orchestre les analyses en parallèle (arnaques, fake news, numéros).

C'est le cerveau du endpoint POST /scan.
"""

import asyncio
import re
import time
from typing import Optional

from agent import CIAlertAgent
from fake_news_agent import analyser_fake_news
from phone_registry import check_phones_in_text, register_phone_from_text
from file_extractor import extract_text
from receipt_agent import analyser_recu
import logging
logger = logging.getLogger(__name__)
# Instance partagée de l'agent — initialisée une seule fois au démarrage
_agent = CIAlertAgent()


# ─────────────────────────────────────────────
# DÉTECTION DU TYPE D'INPUT
# ─────────────────────────────────────────────

URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)

# Formats ivoiriens : +225, 00225, 07/05/01 XXXXXXXX, numéro à 9 chiffres
PHONE_PATTERN = re.compile(
    r"(\+225|00225)[\s\-]?\d[\d\s\-]{7,12}|(?<!\d)0[157]\d{8}(?!\d)"
)

# Un texte est "long" au-delà de cette limite — on y ajoute l'analyse fake news
LONG_TEXT_THRESHOLD = 300


# ─────────────────────────────────────────────
# DÉTECTION DE CONTENU TECHNIQUE
# ─────────────────────────────────────────────

LOG_SIGNALS = [
    "HTTP/1.1", "INFO:", "ERROR:", "WARNING:", "DEBUG:",
    "railway.app", "100.64.", "uvicorn", "fastapi",
    "CREATE TABLE", "SELECT ", "INSERT INTO", "ALTER TABLE",
    "TIMESTAMP", "psycopg2", "PostgreSQL", "SQLite",
    "Starting Container", "Application startup",
    "200 OK", "404 Not Found", "500 Internal",
]

def _is_technical_log(text: str) -> bool:
    """Retourne True si le texte ressemble à un log ou du code technique."""
    matches = sum(1 for s in LOG_SIGNALS if s in text)
    return matches >= 3


def detect_input_type(text: str) -> str:
    """
    Retourne le type détecté parmi :
    - "url"   si le texte est uniquement une URL
    - "phone" si le texte est uniquement un numéro de téléphone
    - "sms"   si le texte est court (< 300 caractères)
    - "text"  si le texte est long (>= 300 caractères)
    """
    stripped = text.strip()

    if URL_PATTERN.fullmatch(stripped):
        return "url"

    if PHONE_PATTERN.fullmatch(stripped):
        return "phone"

    if len(stripped) < LONG_TEXT_THRESHOLD:
        return "sms"

    return "text"


def should_check_fake_news(input_type: str) -> bool:
    """
    L'analyse fake news est pertinente pour les URLs et les textes longs.
    Inutile sur un SMS court ou un numéro de téléphone seul.
    """
    return input_type in ("url", "text")


# ─────────────────────────────────────────────
# ORCHESTRATION PRINCIPALE
# ─────────────────────────────────────────────

async def run_scan(
    text: Optional[str] = None,
    file_data: Optional[bytes] = None,
    file_content_type: Optional[str] = None,
    filename: Optional[str] = None,
    source: str = "web"
) -> dict:
    """
    Point d'entrée principal du router.

    Accepte du texte libre et/ou un fichier.
    Détecte automatiquement le type de contenu.
    Lance les analyses nécessaires en parallèle.
    Retourne un résultat unifié prêt à être sauvegardé et retourné au client.

    Ne lève jamais d'exception vers l'extérieur — les erreurs sont incluses
    dans le résultat pour que le endpoint puisse toujours répondre.
    """
    start = time.time()

    has_file = file_data is not None
    extracted_file_info = None

    # ── Étape 1 : extraction du texte si fichier joint ────────────────────
    if has_file:
        try:
            extracted = extract_text(file_data, file_content_type or "", filename or "")
            file_text = extracted["text"]
            extracted_file_info = {
                "filename": filename,
                "size_kb": round(len(file_data) / 1024, 1),
                "extraction_method": extracted["method"],
                "char_count": extracted["char_count"],
                "truncated": extracted["truncated"],
            }
            # Fusion texte libre + texte extrait si les deux sont présents
            if text:
                text = text.strip() + "\n\n" + file_text
            else:
                text = file_text
        except ValueError as error:
            return {
                "success": False,
                "error": str(error),
                "processing_ms": int((time.time() - start) * 1000),
            }

    # ── Étape 2 : analyse faux reçu si fichier image/PDF ──────────────────
    receipt_result = None
    if has_file and file_content_type and file_content_type.startswith(("image/", "application/pdf")):
        try:
            receipt_result = await asyncio.to_thread(analyser_recu, text)
        except Exception as e:
            logger.error(f"receipt_agent erreur : {e}")
            receipt_result = None

    # ── Étape 2b : vérification minimale ───────────────────────────────────
    if not text or not text.strip():
        return {
            "success": False,
            "error": "Aucun contenu à analyser. Collez un texte ou joignez un fichier.",
            "processing_ms": int((time.time() - start) * 1000),
        }

    text = text.strip()

    # ── Étape 2c : contenu technique → pas d'arnaque ──────────────────────
    if _is_technical_log(text):
        return {
            "success": True,
            "raw_input": text,
            "input_type": "text",
            "has_file": has_file,
            "filename": filename,
            "source": source,
            "is_scam": False,
            "confidence": 0.02,
            "confidence_label": "Probabilité d'arnaque",
            "risk_level": "FAIBLE",
            "scam_category": None,
            "rule_flags": [],
            "ai_explanation": "Contenu technique identifié (logs, code, traces système). Aucune arnaque détectée.",
            "ai_provider": None,
            "ai_used": False,
            "has_fake_news": False,
            "fake_news_verdict": None,
            "fake_news_score": 0,
            "fake_news_detail": None,
            "phone_flagged": False,
            "numbers_found": [],
            "file_info": extracted_file_info,
            "receipt_result": None,
            "is_fake_receipt": False,
            "processing_ms": int((time.time() - start) * 1000),
        }

    # ── Étape 3 : détection du type ───────────────────────────────────────
    input_type = detect_input_type(text)

    # ── Étape 4 : vérification des numéros (synchrone, rapide) ───────────
    phone_check   = check_phones_in_text(text)
    phone_flagged = phone_check["any_flagged"]
    numbers_found = phone_check["numbers_found"]

    # ── Étape 5 : analyses en parallèle ──────────────────────────────────
    run_fake_news = should_check_fake_news(input_type)

    if run_fake_news:
        scam_result, fake_news_result = await asyncio.gather(
            _agent.analyze(text=text, use_ai=True),
            asyncio.to_thread(
                analyser_fake_news,
                text,
                "url" if input_type == "url" else "texte"
            )
        )
    else:
        scam_result      = await _agent.analyze(text=text, use_ai=True)
        fake_news_result = None

    # ── Étape 6 : extraction des champs fake news ─────────────────────────
    has_fake_news     = False
    fake_news_verdict = None
    fake_news_score   = 0

    if fake_news_result and fake_news_result.get("verdict") not in ("ERREUR", "INDÉTERMINÉ", None):
        fake_news_verdict = fake_news_result.get("verdict")
        fake_news_score   = fake_news_result.get("score_manipulation", 0)
        has_fake_news     = fake_news_verdict in ("SUSPECT", "MANIPULATOIRE")

    processing_ms = int((time.time() - start) * 1000)

    # ── Étape 7 : résultat unifié ─────────────────────────────────────────
    return {
        "success": True,

        # Données pour la sauvegarde en base
        "raw_input":  text,
        "input_type": input_type,
        "has_file":   has_file,
        "filename":   filename,
        "source":     source,

        # Résultat arnaque
        "is_scam":          scam_result["is_scam"],
        "confidence":       scam_result["confidence"],
        "confidence_label": scam_result.get("confidence_label"),
        "risk_level":       scam_result["risk_level"],
        "scam_category":    scam_result.get("scam_category"),
        "rule_flags":       scam_result.get("rule_flags", []),
        "ai_explanation":   scam_result.get("explanation"),
        "ai_provider":      scam_result.get("ai_provider"),
        "ai_used":          scam_result.get("ai_used", False),

        # Résultat fake news
        "has_fake_news":    has_fake_news,
        "fake_news_verdict": fake_news_verdict,
        "fake_news_score":  fake_news_score,
        "fake_news_detail": fake_news_result,  # usage interne uniquement

        # Résultat numéros — seul le booléen va vers le frontend
        "phone_flagged": phone_flagged,
        "numbers_found": numbers_found,        # usage interne uniquement

        # Infos fichier
        "file_info": extracted_file_info,
        # Résultat faux reçu
        "receipt_result":   receipt_result,
        "is_fake_receipt":  bool(
            receipt_result
            and receipt_result.get("est_recu")
            and receipt_result.get("est_faux_recu")
        ),

        "processing_ms": processing_ms,
    }


# ─────────────────────────────────────────────
# ENREGISTREMENT POST-SCAN
# ─────────────────────────────────────────────

def register_scan_phones(scan_result: dict, scan_id: int) -> None:
    """
    Enregistre les numéros trouvés dans le répertoire.
    Appelée après la sauvegarde en base, uniquement si c'est une arnaque.
    """
    if not scan_result.get("is_scam"):
        return

    numbers  = scan_result.get("numbers_found", [])
    category = scan_result.get("scam_category")

    for number in numbers:
        from phone_registry import register_phone
        register_phone(
            phone_number=number,
            scam_category=category,
            source="scan",
            scan_id=scan_id,
        )
