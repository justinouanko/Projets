"""
CIAlert — response_builder.py
Traduit les résultats techniques des analyses en messages clairs
pour un utilisateur non expert.

Règle principale : l'utilisateur voit uniquement ce dont il a besoin
pour comprendre le risque et décider quoi faire.
"""

from typing import Optional


# ─────────────────────────────────────────────
# MESSAGES PAR CATÉGORIE D'ARNAQUE
# ─────────────────────────────────────────────

CATEGORY_MESSAGES = {
    "gain_improbable": (
        "Ce message promet un gain trop beau pour être vrai. "
        "Les vraies loteries ne contactent pas les gagnants par SMS ou WhatsApp."
    ),
    "demande_paiement": (
        "Ce message vous demande d'envoyer de l'argent. "
        "Aucun service légitime ne demande un paiement à l'avance pour débloquer un gain ou un dossier."
    ),
    "urgence": (
        "Ce message crée une fausse urgence pour vous pousser à agir vite sans réfléchir. "
        "Prenez le temps de vérifier avant d'agir."
    ),
    "mobile_money": (
        "Ce message implique un transfert Mobile Money suspect. "
        "Ne partagez jamais votre code secret et n'envoyez pas d'argent à un inconnu."
    ),
    "broutage": (
        "Ce message ressemble à une arnaque de type broutage. "
        "Des personnes mal intentionnées utilisent de fausses identités pour gagner votre confiance."
    ),
    "phishing": (
        "Ce lien ou message tente de vous rediriger vers un faux site "
        "pour voler vos informations personnelles ou bancaires."
    ),
    "faux_emploi": (
        "Cette offre d'emploi présente des signaux d'arnaque. "
        "Les vrais employeurs ne demandent pas d'argent pour recruter."
    ),
    "crypto_invest": (
        "Cette proposition d'investissement est très probablement frauduleuse. "
        "Aucun investissement ne garantit des profits certains."
    ),
    "arnaque_admin": (
        "Cette démarche administrative semble frauduleuse. "
        "Les services officiels ne demandent pas de paiement par Mobile Money."
    ),
}

GENERIC_SCAM_MESSAGE = (
    "Ce contenu présente plusieurs signaux caractéristiques d'une arnaque."
)

SAFE_MESSAGE = "Ce contenu ne présente pas de signal d'arnaque évident."


# ─────────────────────────────────────────────
# CONSEILS PAR NIVEAU DE RISQUE
# ─────────────────────────────────────────────

RISK_ADVICE = {
    "CRITIQUE": "Ne répondez pas, ne cliquez sur aucun lien et ne transférez aucun argent. Signalez ce contenu.",
    "ÉLEVÉ":    "Soyez très prudent. Vérifiez l'information auprès d'une source officielle avant d'agir.",
    "MOYEN":    "Restez vigilant. En cas de doute, ne donnez pas suite.",
    "FAIBLE":   "Aucune action particulière requise.",
}


# ─────────────────────────────────────────────
# MESSAGES FAKE NEWS
# ─────────────────────────────────────────────

FAKE_NEWS_MESSAGES = {
    "MANIPULATOIRE": "Ce contenu contient des signaux forts de manipulation ou de désinformation.",
    "SUSPECT":       "Ce contenu présente certains signaux de manipulation. Vérifiez la source.",
    "FIABLE":        "Aucun signal de manipulation détecté dans ce contenu.",
}


# ─────────────────────────────────────────────
# CONSTRUCTION DE LA RÉPONSE
# ─────────────────────────────────────────────

def build_response(scan_result: dict, scan_id: Optional[int] = None) -> dict:
    """
    Construit la réponse finale envoyée au frontend.

    Ce que le frontend reçoit :
    - Le verdict et le niveau de risque
    - Un label de confiance conditionnel (Probabilité d'arnaque / Fiabilité)
    - Un message clair en français simple
    - Un conseil d'action adapté au risque
    - Les signaux fake news si pertinents
    - Un flag si un numéro signalé a été détecté
    - L'identifiant du scan pour le feedback

    Ce que le frontend ne reçoit jamais :
    - Les numéros de téléphone extraits
    - Le détail interne des résultats fake news
    - Les flags techniques de l'agent
    - Les données brutes de l'IA
    """
    is_scam           = scan_result.get("is_scam", False)
    risk_level        = scan_result.get("risk_level", "FAIBLE")
    scam_category     = scan_result.get("scam_category")
    fake_news_verdict = scan_result.get("fake_news_verdict")
    phone_flagged     = scan_result.get("phone_flagged", False)
    ai_explanation    = scan_result.get("ai_explanation", "")
    file_info         = scan_result.get("file_info")
    processing_ms     = scan_result.get("processing_ms", 0)

    # Label conditionnel — Option A
    # is_scam=True  → "Probabilité d'arnaque" (on indique la probabilité que ce soit une arnaque)
    # is_scam=False → "Fiabilité"             (on indique à quel point le contenu semble fiable)
    confidence_label = scan_result.get(
        "confidence_label",
        "Probabilité d\u2019arnaque" if is_scam else "Fiabilité"
    )

    # ── Message principal ─────────────────────────────────────────────────
    if is_scam:
        main_message = CATEGORY_MESSAGES.get(scam_category, GENERIC_SCAM_MESSAGE)
    else:
        main_message = SAFE_MESSAGE

    # ── Explication IA nettoyée ───────────────────────────────────────────
    explanation = _clean_explanation(ai_explanation) if ai_explanation else None

    # ── Conseil d'action ──────────────────────────────────────────────────
    advice = RISK_ADVICE.get(risk_level, RISK_ADVICE["FAIBLE"])

    # ── Bloc fake news simplifié ──────────────────────────────────────────
    fake_news_block = None
    if fake_news_verdict and fake_news_verdict not in ("ERREUR", "INDÉTERMINÉ"):
        fake_news_block = {
            "verdict": fake_news_verdict,
            "message": FAKE_NEWS_MESSAGES.get(fake_news_verdict, ""),
        }

    # ── Avertissement numéro signalé ──────────────────────────────────────
    phone_warning = None
    if phone_flagged:
        phone_warning = "Un numéro présent dans ce message a déjà été signalé par la communauté."

    # ── Résultat final ────────────────────────────────────────────────────
    response = {
    "scan_id":          scan_id,
    "is_scam":          is_scam,
    "confidence":       scan_result.get("confidence", 0),      # ← AJOUT
    "risk_level":       risk_level,
    "scam_category":    scam_category,                          # ← AJOUT
    "confidence_label": confidence_label,
    "message":          main_message,
    "explanation":      explanation,
    "advice":           advice,
    "fake_news":        fake_news_block,
    "phone_warning":    phone_warning,
    "file_info":        file_info,
    "processing_ms":    processing_ms,
}
    return {k: v for k, v in response.items() if v is not None}


# ─────────────────────────────────────────────
# UTILITAIRES INTERNES
# ─────────────────────────────────────────────

def _clean_explanation(text: str) -> Optional[str]:
    """Nettoie l'explication brute de l'IA avant affichage."""
    if not text or len(text.strip()) < 20:
        return None

    if "[IA indisponible" in text:
        text = text[:text.index("[IA indisponible")].strip()

    technical_phrases = [
        "Analyse par règles locales",
        "Niveau de confiance",
        "Score de",
        "Pattern détecté",
    ]
    for phrase in technical_phrases:
        if phrase.lower() in text.lower():
            return None

    cleaned = text.strip()
    return cleaned if len(cleaned) > 20 else None


def build_error_response(error_message: str, processing_ms: int = 0) -> dict:
    """Réponse d'erreur uniforme pour le frontend."""
    return {
        "success":       False,
        "error":         error_message,
        "processing_ms": processing_ms,
    }
