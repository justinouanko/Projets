"""
CIAlert — main.py
API FastAPI V2.0 — endpoint unifié /scan.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from database import (
    init_db,
    save_scan,
    save_report,
    save_feedback,
    get_global_stats,
    get_recent_analyses,
    save_analysis,
)
from router import run_scan, register_scan_phones
from response_builder import build_response, build_error_response

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


# ─────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("🚀 CIAlert V2.0 démarrée.")
    yield


app = FastAPI(
    title="CIAlert API",
    description="Plateforme ivoirienne de détection d'arnaques digitales 🇨🇮",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# SCHÉMAS PYDANTIC
# ─────────────────────────────────────────────

class ReportRequest(BaseModel):
    content: str = Field(..., min_length=3, max_length=5000)
    scan_id: Optional[int] = Field(None)
    victim_amount: Optional[float] = Field(None)
    victim_platform: Optional[str] = Field(None)
    description: Optional[str] = Field(None, max_length=1000)


class FeedbackRequest(BaseModel):
    scan_id: int
    correct: bool
    real_category: Optional[str] = None


# ─────────────────────────────────────────────
# ENDPOINT PRINCIPAL : POST /scan
# ─────────────────────────────────────────────

@app.post("/scan", tags=["Détection"])
async def scan(
    request: Request,
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """
    Analyse universelle — texte libre, lien, numéro, fichier ou combinaison.
    Le type de contenu est détecté automatiquement.
    """
    # Lecture du fichier si présent
    file_data = None
    file_content_type = None
    filename = None

    if file and file.filename:
        file_data = await file.read()
        file_content_type = file.content_type or ""
        filename = file.filename

    # Vérification : au moins un des deux champs est rempli
    if not content and not file_data:
        raise HTTPException(
            status_code=400,
            detail="Collez un texte ou joignez un fichier."
        )

    source = _detect_source(request)

    # Analyse
    scan_result = await run_scan(
        text=content,
        file_data=file_data,
        file_content_type=file_content_type,
        filename=filename,
        source=source,
    )

    if not scan_result.get("success"):
        raise HTTPException(
            status_code=422,
            detail=scan_result.get("error", "Analyse impossible.")
        )

    # Sauvegarde en base
    scan_id = save_scan(
        raw_input=scan_result["raw_input"],
        input_type=scan_result["input_type"],
        is_scam=scan_result["is_scam"],
        confidence=scan_result["confidence"],
        risk_level=scan_result["risk_level"],
        scam_category=scan_result.get("scam_category"),
        rule_flags=scan_result.get("rule_flags", []),
        has_fake_news=scan_result.get("has_fake_news", False),
        fake_news_verdict=scan_result.get("fake_news_verdict"),
        fake_news_score=scan_result.get("fake_news_score", 0),
        phone_flagged=scan_result.get("phone_flagged", False),
        ai_explanation=scan_result.get("ai_explanation"),
        ai_provider=scan_result.get("ai_provider"),
        processing_ms=scan_result.get("processing_ms"),
        has_file=scan_result.get("has_file", False),
        filename=filename,
        source=source,
    )

    # Enregistrement des numéros suspects dans le répertoire
    register_scan_phones(scan_result, scan_id)

    # Réponse simplifiée pour le frontend
    return build_response(scan_result, scan_id=scan_id)


# ─────────────────────────────────────────────
# ENDPOINT : POST /report
# ─────────────────────────────────────────────

@app.post("/report", tags=["Signalements"])
async def report(payload: ReportRequest):
    """
    Signalement manuel. Le type d'arnaque est détecté automatiquement
    depuis le contenu — l'utilisateur n'a pas à le préciser.
    """
    # Détection automatique du type depuis le contenu
    report_type = _detect_report_type(payload.content)

    report_id = save_report(
        reported_text=payload.content,
        report_type=report_type,
        scan_id=payload.scan_id,
        victim_amount=payload.victim_amount,
        victim_platform=payload.victim_platform,
        description=payload.description,
    )

    # Alimentation du répertoire de numéros depuis le signalement
    from phone_registry import register_phone_from_text
    register_phone_from_text(
        text=payload.content,
        scam_category=report_type,
        source="report",
        report_id=report_id,
    )

    return {
        "report_id": report_id,
        "message": "Signalement reçu. Merci de contribuer à la sécurité de la communauté.",
        "status": "pending",
    }


# ─────────────────────────────────────────────
# ENDPOINT : POST /feedback
# ─────────────────────────────────────────────

@app.post("/feedback", tags=["Feedback"])
async def feedback(payload: FeedbackRequest):
    """Retour utilisateur sur un résultat d'analyse (correct / incorrect)."""
    feedback_id = save_feedback(
        correct=payload.correct,
        scan_id=payload.scan_id,
        real_category=payload.real_category,
    )
    return {"feedback_id": feedback_id, "message": "Retour enregistré. Merci."}


# ─────────────────────────────────────────────
# ENDPOINTS INTERNES : stats, historique, santé
# ─────────────────────────────────────────────

@app.get("/stats", tags=["Interne"])
async def stats():
    """Statistiques globales — usage interne."""
    return get_global_stats()


@app.get("/history", tags=["Interne"])
async def history(limit: int = 20):
    """Historique des analyses — usage interne."""
    return get_recent_analyses(limit=limit)


@app.get("/health", tags=["Système"])
async def health():
    return {"status": "ok", "service": "CIAlert API", "version": "2.0.0"}


# ─────────────────────────────────────────────
# ENDPOINTS V1 — compatibilité bot Telegram
# Ces endpoints restent actifs pendant la migration du bot.
# Ils seront supprimés en V2.1 une fois le bot migré vers /scan.
# ─────────────────────────────────────────────

@app.post("/analyze", tags=["Compatibilité V1"], include_in_schema=False)
async def analyze_v1(request: Request):
    """Redirige vers /scan pour compatibilité avec le bot Telegram."""
    body = await request.json()
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Champ 'text' requis.")

    scan_result = await run_scan(text=text, source="bot_v1")

    if not scan_result.get("success"):
        raise HTTPException(status_code=422, detail=scan_result.get("error"))

    # On sauvegarde aussi dans l'ancienne table pour ne pas casser
    # les requêtes existantes du bot sur /history
    analysis_id = save_analysis(
        input_text=text,
        is_scam=scan_result["is_scam"],
        confidence=scan_result["confidence"],
        risk_level=scan_result["risk_level"],
        scam_category=scan_result.get("scam_category"),
        rule_flags=scan_result.get("rule_flags", []),
        ai_explanation=scan_result.get("ai_explanation"),
        ai_provider=scan_result.get("ai_provider"),
        ai_used=scan_result.get("ai_used", False),
        processing_ms=scan_result.get("processing_ms"),
        input_type=body.get("input_type", "text"),
        source="bot_v1",
    )

    return {
        "analysis_id": analysis_id,
        "is_scam": scan_result["is_scam"],
        "confidence": scan_result["confidence"],
        "risk_level": scan_result["risk_level"],
        "scam_category": scan_result.get("scam_category"),
        "rule_flags": scan_result.get("rule_flags", []),
        "explanation": scan_result.get("ai_explanation", ""),
        "ai_used": scan_result.get("ai_used", False),
        "processing_ms": scan_result.get("processing_ms", 0),
    }


@app.post("/fake-news", tags=["Compatibilité V1"], include_in_schema=False)
async def fake_news_v1(request: Request):
    """Redirige vers /scan pour compatibilité."""
    body = await request.json()
    contenu = body.get("contenu", "")
    if not contenu:
        raise HTTPException(status_code=400, detail="Champ 'contenu' requis.")

    scan_result = await run_scan(text=contenu, source="bot_v1_fakenews")
    return {
        "success": True,
        "analyse": scan_result.get("fake_news_detail", {}),
    }


# ─────────────────────────────────────────────
# UTILITAIRES INTERNES
# ─────────────────────────────────────────────

def _detect_source(request: Request) -> str:
    """Identifie la source de la requête depuis le user-agent."""
    user_agent = request.headers.get("user-agent", "").lower()
    if "telegram" in user_agent:
        return "bot"
    if "python" in user_agent:
        return "api"
    return "web"


def _detect_report_type(content: str) -> str:
    """
    Détecte automatiquement le type de signalement depuis le contenu.
    Retourne une catégorie parmi les valeurs valides.
    """
    content_lower = content.lower()

    if any(kw in content_lower for kw in ["mtn", "orange money", "wave", "moov", "mobile money", "momo"]):
        return "mobile_money"
    if any(kw in content_lower for kw in ["http://", "https://", "www.", "site", "lien", "cliquer"]):
        return "faux_site"
    if any(kw in content_lower for kw in ["sms", "message", "numéro", "appel", "whatsapp"]):
        return "sms_frauduleux"
    if any(kw in content_lower for kw in ["emploi", "travail", "recrutement", "salaire", "poste"]):
        return "faux_emploi"
    if any(kw in content_lower for kw in ["héritage", "veuve", "général", "colonel", "amour", "rencontré"]):
        return "broutage"

    return "autre"


# ─────────────────────────────────────────────
# FAVICON ET FICHIERS STATIQUES
# ─────────────────────────────────────────────

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = _STATIC_DIR / "favicon.ico"
    return FileResponse(favicon_path) if favicon_path.exists() else Response(status_code=204)


if _STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="static")
else:
    @app.get("/")
    async def root():
        return {"message": "CIAlert API V2.0", "docs": "/docs"}


# ─────────────────────────────────────────────
# LANCEMENT LOCAL
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)