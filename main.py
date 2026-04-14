"""
CIAlert — main.py
Backend FastAPI : endpoints /analyze et /report.
"""

import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from agent import CIAlertAgent
from database import init_db, save_analysis, save_report, get_global_stats, get_recent_analyses

from fastapi import File, UploadFile
from file_extractor import extract_text
# ─────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("🚀 CIAlert API démarrée.")
    yield

app = FastAPI(
    title="CIAlert API",
    description="Plateforme ivoirienne de détection d'arnaques digitales 🇨🇮",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

agent = CIAlertAgent()


# ─────────────────────────────────────────────
# SCHÉMAS PYDANTIC
# ─────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=3, max_length=5000, description="Texte à analyser")
    input_type: str = Field("text", description="Type : text | url | phone | sms")
    use_ai: bool = Field(True, description="Activer l'analyse IA (en plus des règles)")

class AnalyzeResponse(BaseModel):
    analysis_id: int
    is_scam: bool
    confidence: float
    risk_level: str
    scam_category: Optional[str]
    rule_flags: list[str]
    explanation: str
    ai_used: bool
    processing_ms: int

class ReportRequest(BaseModel):
    text: str = Field(..., min_length=3, max_length=5000, description="Contenu signalé")
    report_type: str = Field(..., description="arnaque | faux_site | sms_frauduleux | autre")
    analysis_id: Optional[int] = Field(None, description="ID d'une analyse liée (optionnel)")
    victim_amount: Optional[float] = Field(None, description="Montant escroqué en FCFA")
    victim_platform: Optional[str] = Field(None, description="MTN | Orange | Wave | autre")
    description: Optional[str] = Field(None, max_length=1000, description="Description libre")

class ReportResponse(BaseModel):
    report_id: int
    message: str
    status: str


# ─────────────────────────────────────────────
# ENDPOINT : POST /analyze
# ─────────────────────────────────────────────

@app.post("/analyze", response_model=AnalyzeResponse, tags=["Détection"])
async def analyze(payload: AnalyzeRequest, request: Request):
    """
    Analyse un texte pour détecter une arnaque.
    
    - **Niveau 1** : Règles locales (mots-clés, patterns)  
    - **Niveau 2** : IA (Groq / Gemini / Claude) si activée
    """
    start = time.time()
    user_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Validation du type
    valid_types = {"text", "url", "phone", "sms"}
    if payload.input_type not in valid_types:
        raise HTTPException(400, f"input_type invalide. Valeurs : {valid_types}")

    # Analyse par l'agent
    try:
        result = await agent.analyze(
            text=payload.text,
            use_ai=payload.use_ai
        )
    except Exception as e:
        raise HTTPException(500, f"Erreur d'analyse : {str(e)}")

    processing_ms = int((time.time() - start) * 1000)

    # Sauvegarde en base
    analysis_id = save_analysis(
        input_text=payload.text,
        is_scam=result["is_scam"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        scam_category=result.get("scam_category"),
        rule_flags=result.get("rule_flags", []),
        ai_explanation=result.get("explanation"),
        ai_provider=result.get("ai_provider"),
        ai_used=result.get("ai_used", False),
        processing_ms=processing_ms,
        input_type=payload.input_type,
        user_ip=user_ip,
        user_agent=user_agent,
        source="web"
    )

    return AnalyzeResponse(
        analysis_id=analysis_id,
        is_scam=result["is_scam"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        scam_category=result.get("scam_category"),
        rule_flags=result.get("rule_flags", []),
        explanation=result.get("explanation", "Aucune explication disponible."),
        ai_used=result.get("ai_used", False),
        processing_ms=processing_ms,
    )


# ─────────────────────────────────────────────
# ENDPOINT : POST /report
# ─────────────────────────────────────────────

@app.post("/report", response_model=ReportResponse, tags=["Signalements"])
async def report(payload: ReportRequest):
    """
    Signale manuellement une arnaque.
    
    Peut être lié à une analyse existante via `analysis_id`.
    """
    valid_types = {
    "arnaque", "faux_site", "sms_frauduleux",
    "mobile_money", "faux_emploi", "broutage", "autre"
}
    if payload.report_type not in valid_types:
        raise HTTPException(400, f"report_type invalide. Valeurs : {valid_types}")

    report_id = save_report(
        reported_text=payload.text,
        report_type=payload.report_type,
        analysis_id=payload.analysis_id,
        victim_amount=payload.victim_amount,
        victim_platform=payload.victim_platform,
        description=payload.description,
    )

    return ReportResponse(
        report_id=report_id,
        message="Signalement reçu. Merci de contribuer à la sécurité de la communauté 🙏",
        status="pending"
    )
# ─────────────────────────────────────────────────────────────────────────────
#  POST /analyze-file  — Analyse d'une pièce jointe
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    """
    Reçoit un fichier (PDF, image, texte), en extrait le contenu,
    puis le soumet à l'agent IA exactement comme /analyze.

    Retourne :
      - verdict, score, category, explanation  (même format que /analyze)
      - file_info : nom, taille, méthode d'extraction, troncature
    """
    try:
        # ── Lecture du fichier ────────────────────────────────────────────────
        data = await file.read()
        content_type = file.content_type or ""
        filename = file.filename or "fichier_inconnu"

        # ── Extraction du texte ───────────────────────────────────────────────
        try:
            extracted = extract_text(data, content_type, filename)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        text = extracted["text"]

        # ── Analyse IA (même agent que /analyze) ─────────────────────────────
        analysis = await analyze_content(text)

        # ── Sauvegarde en base (table analyses, comme les textes normaux) ─────
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO analyses
                   (content, verdict, score, category, explanation, source)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    f"[FICHIER: {filename}]\n\n{text[:500]}",  # extrait pour la DB
                    analysis["verdict"],
                    analysis["score"],
                    analysis["category"],
                    analysis["explanation"],
                    "file_upload",
                ),
            )
            conn.commit()
        except Exception as db_err:
            logger.warning(f"Sauvegarde DB échouée : {db_err}")
        finally:
            conn.close()

        # ── Réponse ───────────────────────────────────────────────────────────
        return {
            **analysis,
            "file_info": {
                "filename": filename,
                "size_kb": round(len(data) / 1024, 1),
                "extraction_method": extracted["method"],
                "char_count": extracted["char_count"],
                "truncated": extracted["truncated"],
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur /analyze-file : {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'analyse du fichier.")

# ─────────────────────────────────────────────
# ENDPOINT : GET /stats  (bonus utile)
# ─────────────────────────────────────────────

@app.get("/history", tags=["Statistiques"])
async def history(limit: int = 20):
    """Dernières analyses (pour le dashboard)."""
    return get_recent_analyses(limit=limit)


@app.get("/stats", tags=["Statistiques"])
async def stats():
    """Statistiques globales de la plateforme."""
    return get_global_stats()


# ─────────────────────────────────────────────
# ENDPOINT : GET /health
# ─────────────────────────────────────────────

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(_STATIC_DIR / "favicon.ico") if (_STATIC_DIR / "favicon.ico").exists() else Response(status_code=204)


@app.get("/health", tags=["Système"])
async def health():
    """Vérification que l'API est opérationnelle."""
    return {
        "status": "ok",
        "service": "CIAlert API",
        "version": "1.0.0"
    }


# ─────────────────────────────────────────────
# FICHIERS STATIQUES — dashboard web
# ─────────────────────────────────────────────

# Cherche ./static/ à côté de main.py, quel que soit le répertoire de lancement
_STATIC_DIR = Path(__file__).parent / "static"

if _STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="static")
else:
    @app.get("/")
    async def root():
        return {"message": "CIAlert API opérationnelle 🇨🇮", "docs": "/docs"}


# ─────────────────────────────────────────────
# LANCEMENT LOCAL
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
