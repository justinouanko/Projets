"""
CIAlert — agent.py
Détection en 2 niveaux : règles locales + IA.
"""

import re
import os
from typing import Optional
from ai_provider import get_ai_provider

# ─────────────────────────────────────────────
# RÈGLES LOCALES (Niveau 1)
# ─────────────────────────────────────────────

SCAM_PATTERNS = {
    "gain_improbable": [
        r"gagn[ée]\w*\s+\d[\d\s]*fcfa",
        r"lot\s+de\s+\d",
        r"félicitation",
        r"vous\s+avez\s+été\s+sélectionné",
        r"tirage\s+au\s+sort",
        r"gagnant",
        r"prize\s+winner",
    ],
    "demande_paiement": [
        r"envoy[ez]+\s+\d[\d\s]*\s*(f|fcfa|fr)",
        r"frais\s+de\s+dossier",
        r"frais\s+de\s+traitement",
        r"avance\s+de\s+\d",
        r"recharge\s+\d",
        r"transfert\s+de\s+\d",
        r"payer\s+\d",
    ],
    "urgence": [
        r"urgent",
        r"immédiatement",
        r"dans\s+les\s+\d+\s+heure",
        r"expire\s+aujourd",
        r"derni[eè]re\s+chance",
        r"maintenant\s+sinon",
        r"dernier\s+délai",
    ],
    "mobile_money": [
        r"mtn\s*momo",
        r"orange\s*money",
        r"wave\s*ci",
        r"moov\s*money",
        r"mobile\s*money",
        r"numero\s*momo",
        r"\+225\s*0[57]\d{8}",
    ],
    "broutage": [
        r"je\s+suis\s+(veuve|veuf|général|colonel|directeur)",
        r"heritage\s+de",
        r"héritage\s+de",
        r"millions?\s+de\s+dollars",
        r"compte\s+bloqué.{0,30}besoin",
        r"love\s+you",
        r"rencontr[ée]\s+sur\s+(facebook|instagram|tinder)",
    ],
    "phishing": [
        r"cliqu[ez]+\s+(ici|sur\s+le\s+lien)",
        r"http[s]?://\S+\.(tk|ml|ga|cf|gq)",
        r"vérifie[rz]?\s+votre\s+compte",
        r"mot\s+de\s+passe\s+expiré",
        r"compte\s+suspendu",
        r"connexion\s+suspecte",
    ],
}

RISK_THRESHOLDS = {
    "CRITIQUE": 0.85,
    "ÉLEVÉ":    0.65,
    "MOYEN":    0.40,
    "FAIBLE":   0.0,
}

CATEGORY_WEIGHTS = {
    "broutage":     1.0,
    "mobile_money": 0.9,
    "phishing":     0.85,
    "gain_improbable": 0.8,
    "demande_paiement": 0.75,
    "urgence":      0.5,
}


def _apply_rules(text: str) -> dict:
    """Applique les règles locales et retourne flags + score brut."""
    text_lower = text.lower()
    flags = []
    category_hits = {}

    for category, patterns in SCAM_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                if category not in category_hits:
                    category_hits[category] = 0
                    flags.append(category)
                category_hits[category] += 1

    if not flags:
        return {"flags": [], "raw_score": 0.0, "top_category": None}

    # Score = moyenne pondérée des catégories touchées
    total_weight = sum(CATEGORY_WEIGHTS.get(c, 0.5) * hits for c, hits in category_hits.items())
    normalizer = max(len(category_hits), 1)
    raw_score = min(total_weight / normalizer, 1.0)

    # Catégorie principale = celle avec le plus de hits et le plus grand poids
    top_category = max(
        category_hits,
        key=lambda c: category_hits[c] * CATEGORY_WEIGHTS.get(c, 0.5)
    )

    return {"flags": flags, "raw_score": raw_score, "top_category": top_category}


def _score_to_risk(score: float) -> str:
    for level, threshold in RISK_THRESHOLDS.items():
        if score >= threshold:
            return level
    return "FAIBLE"


# ─────────────────────────────────────────────
# AGENT PRINCIPAL
# ─────────────────────────────────────────────

class CIAlertAgent:
    def __init__(self):
        self.ai = get_ai_provider()

    async def analyze(self, text: str, use_ai: bool = True) -> dict:
        """
        Analyse un texte en 2 niveaux.
        Retourne un dict avec is_scam, confidence, risk_level, etc.
        """
        # ── Niveau 1 : règles locales ──
        rule_result = _apply_rules(text)
        raw_score   = rule_result["raw_score"]
        flags       = rule_result["flags"]
        category    = rule_result["top_category"]

        ai_used       = False
        ai_provider   = None
        explanation   = self._rule_explanation(flags, category)

        # ── Niveau 2 : IA (si activée et score ambigu) ──
        if use_ai and self.ai:
            try:
                ai_result = await self.ai.analyze(text, flags, raw_score)
                # Fusion : moyenne pondérée règles (40%) + IA (60%)
                raw_score   = raw_score * 0.4 + ai_result["confidence"] * 0.6
                explanation = ai_result.get("explanation", explanation)
                category    = ai_result.get("category") or category
                ai_used     = True
                ai_provider = self.ai.provider_name
            except Exception as e:
                # L'IA a échoué → on garde le résultat des règles
                explanation += f" (IA indisponible : {e})"

        confidence = round(min(max(raw_score, 0.0), 1.0), 3)
        is_scam    = confidence >= 0.40
        risk_level = _score_to_risk(confidence) if is_scam else "FAIBLE"

        return {
            "is_scam":      is_scam,
            "confidence":   confidence,
            "risk_level":   risk_level,
            "scam_category": category,
            "rule_flags":   flags,
            "explanation":  explanation,
            "ai_used":      ai_used,
            "ai_provider":  ai_provider,
        }

    def _rule_explanation(self, flags: list, category: Optional[str]) -> str:
        if not flags:
            return "Aucun signal d'arnaque détecté par les règles locales."
        labels = {
            "gain_improbable":  "promesse de gain improbable",
            "demande_paiement": "demande de paiement suspect",
            "urgence":          "mise en situation d'urgence",
            "mobile_money":     "référence à un service Mobile Money",
            "broutage":         "schéma de broutage / romance scam",
            "phishing":         "tentative de phishing",
        }
        flag_labels = [labels.get(f, f) for f in flags]
        return (
            f"Ce contenu présente {len(flags)} signal(s) suspect(s) : "
            + ", ".join(flag_labels) + "."
        )
