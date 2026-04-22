"""
CIAlert — main.py
API FastAPI V2.0 — endpoint unifié /scan.
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
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
from whatsapp_bot import send_whatsapp_message

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "cialert_whatsapp_2026")


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
# WEBHOOK WHATSAPP — DOIT ÊTRE AVANT StaticFiles
# ─────────────────────────────────────────────

@app.get("/webhook/whatsapp", tags=["WhatsApp"])
async def whatsapp_verify(
    hub_mode: str = Query(None, alias="hub.mode"),
    hub_challenge: str = Query(None, alias="hub.challenge"),
    hub_verify_token: str = Query(None, alias="hub.verify_token"),
):
    if hub_mode == "subscribe" and hub_verify_token == WHATSAPP_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge)
    return PlainTextResponse("Forbidden", status_code=403)


@app.post("/webhook/whatsapp", tags=["WhatsApp"])
async def whatsapp_webhook(request: Request):
    data = await request.json()
    try:
        entry = data["entry"][0]["changes"][0]["value"]
        message = entry["messages"][0]
        sender = message["from"]
        text = message.get("text", {}).get("body", "")

        if not text:
            return {"status": "ignored"}

        scan_result = await run_scan(text=text, source="whatsapp")
        response_text = _format_whatsapp_response(build_response(scan_result))
        await send_whatsapp_message(sender, response_text)
    except (KeyError, IndexError):
        pass

    return {"status": "ok"}


def _format_whatsapp_response(result: dict) -> str:
    emoji = "🚨" if result.get("is_scam") else "✅"
    label = result.get("confidence_label", "Confiance")
    confidence = int(result.get("confidence", 0) * 100)
    category = result.get("scam_category", "")
    explanation = result.get("explanation", "")
    advice = result.get("advice", "")

    lines = [
        f"{emoji} *{'ARNAQUE DÉTECTÉE' if result.get('is_scam') else 'Message sain'}*",
        f"📊 {label} : {confidence}%",
    ]
    if category:
        lines.append(f"🏷️ Catégorie : {category}")
    if explanation:
        lines.append(f"\n💬 {explanation}")
    if advice:
        lines.append(f"\n💡 {advice}")

    return "\n".join(lines)


# ─────────────────────────────────────────────
# ENDPOINT PRINCIPAL : POST /scan
# ─────────────────────────────────────────────

@app.post("/scan", tags=["Détection"])
async def scan(
    request: Request,
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    file_data = None
    file_content_type = None
    filename = None

    if file and file.filename:
        file_data = await file.read()
        file_content_type = file.content_type or ""
        filename = file.filename

    if not content and not file_data:
        raise HTTPException(
            status_code=400,
            detail="Collez un texte ou joignez un fichier."
        )

    source = _detect_source(request)

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

    register_scan_phones(scan_result, scan_id)

    return build_response(scan_result, scan_id=scan_id)


# ─────────────────────────────────────────────
# ENDPOINT : POST /report
# ─────────────────────────────────────────────

@app.post("/report", tags=["Signalements"])
async def report(payload: ReportRequest):
    report_type = _detect_report_type(payload.content)

    report_id = save_report(
        reported_text=payload.content,
        report_type=report_type,
        scan_id=payload.scan_id,
        victim_amount=payload.victim_amount,
        victim_platform=payload.victim_platform,
        description=payload.description,
    )

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
    return get_global_stats()


@app.get("/history", tags=["Interne"])
async def history(limit: int = 20):
    return get_recent_analyses(limit=limit)


@app.get("/health", tags=["Système"])
async def health():
    return {"status": "ok", "service": "CIAlert API", "version": "2.0.0"}


# ─────────────────────────────────────────────
# ENDPOINTS V1 — compatibilité bot Telegram
# ─────────────────────────────────────────────

@app.post("/analyze", tags=["Compatibilité V1"], include_in_schema=False)
async def analyze_v1(request: Request):
    body = await request.json()
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Champ 'text' requis.")

    scan_result = await run_scan(text=text, source="bot_v1")

    if not scan_result.get("success"):
        raise HTTPException(status_code=422, detail=scan_result.get("error"))

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
    user_agent = request.headers.get("user-agent", "").lower()
    if "telegram" in user_agent:
        return "bot"
    if "python" in user_agent:
        return "api"
    return "web"


def _detect_report_type(content: str) -> str:
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

@app.get("/privacy", include_in_schema=False)
async def privacy():
    html = """
    <!DOCTYPE html>
    <html lang="fr">
    <head><meta charset="UTF-8"><title>Politique de confidentialité — CIAlert</title>
    <style>body{font-family:sans-serif;max-width:800px;margin:40px auto;padding:0 20px;line-height:1.6}</style>
    </head>
    <body>
    <h1>Politique de confidentialité — CIAlert</h1>
    <p><strong>Dernière mise à jour :</strong> Avril 2026</p>
    <h2>Données collectées</h2>
    <p>CIAlert analyse les textes, liens et fichiers soumis par les utilisateurs dans le but de détecter des arnaques digitales. Ces données sont conservées de manière anonyme pour améliorer la détection.</p>
    <h2>Utilisation des données</h2>
    <p>Les données ne sont jamais vendues ni partagées avec des tiers. Elles servent uniquement à améliorer la plateforme CIAlert.</p>
    <h2>Contact</h2>
    <p>Pour toute question : <a href="https://github.com/justinouanko/cialert">github.com/justinouanko/cialert</a></p>
    </body></html>
    """
    from fastapi.responses import HTMLResponse
    return HTMLResponse(html)

# ─────────────────────────────────────────────
# FAVICON ET FICHIERS STATIQUES — EN DERNIER
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