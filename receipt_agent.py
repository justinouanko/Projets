"""
CIAlert — receipt_agent.py
Détection de faux reçus Mobile Money (Wave, MTN, Orange, Moov).
Analyse le texte OCR extrait d'une capture d'écran ou d'un PDF de reçu.

Ne remplace pas l'analyse arnaque principale — s'y ajoute en couche spécialisée.
"""

import re
import os
import json
import logging

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# MOTS-CLÉS DE DÉTECTION REÇU
# ─────────────────────────────────────────────

# Termes présents dans les vrais reçus Mobile Money ivoiriens
RECEIPT_KEYWORDS = [
    # Wave
    "wave", "transaction réussie", "transfert effectué",
    # MTN MoMo
    "mtn mobile money", "momo", "votre transaction", "a été effectuée",
    "transaction id", "transid",
    # Orange Money
    "orange money", "om", "votre paiement", "a bien été effectué",
    # Moov
    "moov money", "flooz",
    # Génériques
    "reçu", "recu", "confirmé", "montant", "bénéficiaire", "beneficiaire",
    "référence", "reference", "solde", "fcfa", "xof",
    "envoyé", "envoye", "reçu de", "paiement de",
]

# Patterns de montants (ex: 5 000 FCFA, 5000 XOF, 5,000 F)
AMOUNT_PATTERN = re.compile(
    r"(\d[\d\s,\.]{1,10})\s*(fcfa|xof|f\b|cfa)",
    re.IGNORECASE
)

# Patterns de numéros ivoiriens
PHONE_PATTERN = re.compile(
    r"(\+225|00225)?\s*0?[157]\d{8}"
)

# Patterns d'ID de transaction (alphanumériques, souvent 8-20 caractères)
TRANSACTION_ID_PATTERN = re.compile(
    r"(id|ref|transaction|trans)[:\s#]*([A-Z0-9\-]{6,20})",
    re.IGNORECASE
)

# Patterns de date/heure
DATETIME_PATTERN = re.compile(
    r"\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}"
    r"|\d{1,2}:\d{2}"
)

# Signaux de falsification courants
FALSIFICATION_SIGNALS = [
    # Fautes dans les noms de services officiels
    (r"w[a4]ve\b", "Orthographe suspecte du nom Wave"),
    (r"0range", "Orthographe suspecte du nom Orange"),
    (r"m[t7]n", "Orthographe suspecte du nom MTN"),
    # Montants ronds suspects (très souvent falsifiés)
    (r"\b(100000|200000|500000|1000000)\s*(fcfa|xof|f\b)", "Montant rond suspect"),
    # Mots indiquant une fabrication
    (r"(test|demo|exemple|sample|fake)", "Mot indicateur de reçu de test"),
    # Incohérences de format
    (r"\d{5,}", "Numéro de transaction trop long ou inhabituel"),
]


# ─────────────────────────────────────────────
# PRÉ-ANALYSE STATIQUE
# ─────────────────────────────────────────────

def _is_likely_receipt(text: str) -> bool:
    """Détermine si le texte ressemble à un reçu Mobile Money."""
    text_lower = text.lower()
    matches = sum(1 for kw in RECEIPT_KEYWORDS if kw in text_lower)
    return matches >= 2


def _extract_receipt_fields(text: str) -> dict:
    """Extrait les champs clés d'un reçu pour les soumettre à l'IA."""
    amounts = AMOUNT_PATTERN.findall(text)
    phones  = PHONE_PATTERN.findall(text)
    tx_ids  = TRANSACTION_ID_PATTERN.findall(text)
    dates   = DATETIME_PATTERN.findall(text)

    signals = []
    text_lower = text.lower()
    for pattern, description in FALSIFICATION_SIGNALS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            signals.append(description)

    return {
        "montants_detectes":      [f"{a[0].strip()} {a[1]}" for a in amounts],
        "numeros_detectes":       phones,
        "ids_transaction":        [t[1] for t in tx_ids],
        "dates_detectees":        dates,
        "signaux_falsification":  signals,
    }


# ─────────────────────────────────────────────
# APPEL IA
# ─────────────────────────────────────────────

def _get_client():
    provider = os.getenv("AI_PROVIDER", "groq").lower()
    if provider == "gemini":
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GEMINI_API_KEY", ""))
        return "gemini", None
    if provider == "claude":
        import anthropic
        return "claude", anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))
    from groq import Groq
    return "groq", Groq(api_key=os.getenv("GROQ_API_KEY", ""))


RECEIPT_SYSTEM_PROMPT = """Tu es un expert en fraude aux reçus Mobile Money en Côte d'Ivoire.
Tu analyses le texte OCR extrait d'une capture d'écran de reçu (Wave, MTN MoMo, Orange Money, Moov Money).

Ton rôle : détecter si ce reçu est authentique ou falsifié.

## Signaux de faux reçu que tu recherches

### Format et structure
- Absence d'éléments obligatoires (ID transaction, date, heure, numéros expéditeur/destinataire)
- Mise en page atypique par rapport aux vrais reçus de l'opérateur
- Fautes dans le nom de l'opérateur ou les formulations officielles

### Montants
- Montant incohérent avec le format de l'opérateur
- Montant modifié après coup (pixels différents, police différente)
- Absence de solde restant (présent sur les vrais reçus Wave/MTN)

### Identifiants
- ID de transaction absent, trop court, trop long, ou avec un format inhabituel
- Référence qui ne correspond pas au format réel de l'opérateur
  - Wave : 10 chiffres
  - MTN MoMo : commence par TXN ou MP suivi de chiffres
  - Orange Money : format alphanumérique court

### Numéros de téléphone
- Numéro bénéficiaire suspect (déjà signalé ou format invalide)
- Numéro masqué partiellement de façon inhabituelle

## Format de réponse OBLIGATOIRE (JSON strict, rien avant ni après)

{
  "est_faux_recu": true | false,
  "confiance": 0.0 à 1.0,
  "operateur_detecte": "Wave" | "MTN MoMo" | "Orange Money" | "Moov Money" | "Inconnu",
  "signaux_falsification": [
    {
      "type": "format" | "montant" | "identifiant" | "numero" | "autre",
      "description": "Description courte du problème détecté"
    }
  ],
  "elements_manquants": ["liste des champs obligatoires absents"],
  "resume": "Explication en 2-3 phrases pour un utilisateur non expert",
  "recommandation": "Action concrète conseillée"
}

## Règles
- Si le texte OCR est trop dégradé pour analyser, indique est_faux_recu: false avec confiance: 0.0
- Ne jamais inventer des signaux absents du texte
- Réponds UNIQUEMENT en JSON valide, sans markdown ni texte avant/après
"""


def _call_ai(fields: dict, raw_text: str) -> dict:
    provider, client = _get_client()

    user_prompt = (
        f"Analyse ce reçu Mobile Money :\n\n"
        f"--- TEXTE OCR BRUT ---\n{raw_text[:3000]}\n\n"
        f"--- CHAMPS EXTRAITS ---\n{json.dumps(fields, ensure_ascii=False, indent=2)}\n\n"
        f"Détermine si ce reçu est authentique ou falsifié."
    )

    messages = [
        {"role": "system", "content": RECEIPT_SYSTEM_PROMPT},
        {"role": "user",   "content": user_prompt},
    ]

    if provider == "groq":
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            temperature=0.1,
            max_tokens=800,
        )
        raw = resp.choices[0].message.content.strip()

    elif provider == "gemini":
        import google.generativeai as genai
        model = genai.GenerativeModel("gemini-1.5-flash")
        resp  = model.generate_content(f"{RECEIPT_SYSTEM_PROMPT}\n\n{user_prompt}")
        raw   = resp.text.strip()

    elif provider == "claude":
        resp = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=800,
            system=RECEIPT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw = resp.content[0].text.strip()

    else:
        raise ValueError(f"Provider IA non reconnu : {provider}")

    # Extraction robuste du JSON
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        raise ValueError("Réponse IA non parseable")
    return json.loads(match.group(0))


# ─────────────────────────────────────────────
# FONCTION PRINCIPALE
# ─────────────────────────────────────────────

def analyser_recu(text: str) -> dict:
    """
    Analyse un texte OCR pour détecter un faux reçu Mobile Money.

    Args:
        text: Texte extrait par OCR d'une image ou PDF

    Returns:
        dict avec est_faux_recu, confiance, signaux, résumé
        ou {"est_recu": False} si le texte n'est pas un reçu
    """
    if not text or len(text.strip()) < 30:
        return {"est_recu": False}

    # Vérification rapide : est-ce que ça ressemble à un reçu ?
    if not _is_likely_receipt(text):
        return {"est_recu": False}

    fields = _extract_receipt_fields(text)

    try:
        result = _call_ai(fields, text)
        result["est_recu"] = True
        result["champs_extraits"] = fields
        return result

    except Exception as e:
        logger.error(f"receipt_agent : erreur — {e}")
        # Fallback sur l'analyse statique uniquement
        has_signals = len(fields["signaux_falsification"]) > 0
        return {
            "est_recu":            True,
            "est_faux_recu":       has_signals,
            "confiance":           0.5 if has_signals else 0.2,
            "operateur_detecte":   "Inconnu",
            "signaux_falsification": [
                {"type": "autre", "description": s}
                for s in fields["signaux_falsification"]
            ],
            "elements_manquants":  [],
            "resume":              "Analyse partielle — vérification IA indisponible.",
            "recommandation":      "Vérifiez ce reçu directement auprès de l'opérateur.",
            "champs_extraits":     fields,
        }