"""
CIAlert — fake_news_agent.py
Détection de signaux de manipulation et de désinformation.
Analyse rhétorique et contextuelle — ne fait pas de fact-checking absolu.

Utilise le même provider IA que le reste de la plateforme (Groq par défaut,
swappable via la variable d'environnement AI_PROVIDER).
"""

import re
import json
import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CLIENT IA — même provider que agent.py
# ─────────────────────────────────────────────

def _get_client():
    """
    Retourne un client IA selon AI_PROVIDER.
    Groq par défaut, Gemini ou Claude si configuré.
    Isolé dans une fonction pour éviter les imports au niveau module.
    """
    provider = os.getenv("AI_PROVIDER", "groq").lower()

    if provider == "gemini":
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GEMINI_API_KEY", ""))
        return "gemini", None

    if provider == "claude":
        import anthropic
        return "claude", anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

    # Groq par défaut
    from groq import Groq
    return "groq", Groq(api_key=os.getenv("GROQ_API_KEY", ""))


def _call_ai(prompt_system: str, prompt_user: str) -> str:
    """Appelle le provider IA configuré et retourne le texte brut de la réponse."""
    provider, client = _get_client()

    if provider == "groq":
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": prompt_system},
                {"role": "user",   "content": prompt_user},
            ],
            temperature=0.1,
            max_tokens=1000,
        )
        return response.choices[0].message.content.strip()

    if provider == "gemini":
        import google.generativeai as genai
        model    = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(f"{prompt_system}\n\n{prompt_user}")
        return response.text.strip()

    if provider == "claude":
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=1000,
            system=prompt_system,
            messages=[{"role": "user", "content": prompt_user}],
        )
        return response.content[0].text.strip()

    raise ValueError(f"Provider IA non reconnu : {provider}")


# ─────────────────────────────────────────────
# PROMPT SYSTÈME
# ─────────────────────────────────────────────

FAKE_NEWS_SYSTEM_PROMPT = """Tu es un expert en détection de désinformation et manipulation de l'information,
spécialisé dans le contexte ivoirien et ouest-africain.

Ton rôle est d'analyser un texte ou une URL pour détecter des SIGNAUX DE MANIPULATION,
sans prétendre vérifier les faits absolus. Tu es honnête sur les limites de ton analyse.

## Signaux que tu recherches

### Signaux rhétoriques
- Langage alarmiste ou émotionnel excessif (URGENT, CHOC, INCROYABLE, PARTAGEZ AVANT SUPPRESSION)
- Appel explicite à partager massivement ou rapidement
- Affirmations absolues sans nuance ("100% prouvé", "officiellement confirmé" sans source)
- Absence totale de source citée pour des affirmations graves
- Contradiction interne dans le texte

### Signaux de manipulation contextuelle
- Usurpation de personnalités ou institutions (Président, ministre, OMS, ARTCI, BCEAO, MTN, Orange)
- Référence à des tensions ethniques ou religieuses pour amplifier l'émotion
- Fausses alertes bancaires ou MoMo déguisées en information générale
- Rumeurs sur des événements non vérifiables (catastrophe, arrestation, décès de personnalité)
- Contenu politique visant à créer la panique ou la division

### Signaux de source
- URL imitant un média connu (bbc-afrique-info.com, rtinews24.com, etc.)
- Absence de date de publication
- Auteur inexistant ou générique ("La Rédaction", "Source fiable")

## Format de réponse OBLIGATOIRE (JSON strict)

{
  "verdict": "FIABLE" | "SUSPECT" | "MANIPULATOIRE",
  "score_manipulation": 0-100,
  "signaux_detectes": [
    {
      "type": "rhétorique" | "contextuel" | "source",
      "description": "Description courte du signal détecté",
      "extrait": "Fragment du texte concerné (si applicable)"
    }
  ],
  "resume": "Explication claire en 2-3 phrases pour un utilisateur non-expert",
  "recommandation": "Action concrète conseillée à l'utilisateur",
  "limite_analyse": "Ce que cette analyse ne peut PAS confirmer"
}

## Règles importantes
- VERDICT "FIABLE" si score < 30 et aucun signal fort détecté
- VERDICT "SUSPECT" si score 30-65 ou signaux modérés
- VERDICT "MANIPULATOIRE" si score > 65 ou signaux forts présents
- Sois honnête : si le texte est trop court ou ambigu, dis-le dans "limite_analyse"
- N'invente jamais de signaux qui ne sont pas dans le texte
- Réponds UNIQUEMENT en JSON valide, sans markdown ni texte avant/après
"""


# ─────────────────────────────────────────────
# PRÉ-ANALYSE STATIQUE
# ─────────────────────────────────────────────

ALARMISTE_KEYWORDS = [
    "urgent", "choc", "incroyable", "exclusif", "breaking", "alerte",
    "partagez avant", "avant suppression", "censuré", "ils cachent",
    "100% prouvé", "officiellement confirmé", "source sûre",
    "le gouvernement ne veut pas", "les médias taisent",
]

INSTITUTIONS_USURPEES = [
    "oms", "who", "artci", "bceao", "fmi", "banque mondiale",
    "ministre", "président", "premier ministre", "mtn", "orange money",
    "wave", "moov", "côte d'ivoire officiel",
]

TENSIONS_KEYWORDS = [
    "dioula", "bété", "baoulé", "guéré", "nordiste", "sudiste",
    "chrétien", "musulman", "étranger", "ivoirien de souche",
]


def _pre_analyse_statique(texte: str) -> dict:
    """Détecte des signaux évidents avant l'appel IA pour enrichir le contexte."""
    texte_lower = texte.lower()
    signaux     = []

    found_alarm = [kw for kw in ALARMISTE_KEYWORDS if kw in texte_lower]
    if found_alarm:
        signaux.append({"type": "rhétorique", "mots": found_alarm, "poids": len(found_alarm) * 10})

    found_instit = [kw for kw in INSTITUTIONS_USURPEES if kw in texte_lower]
    if found_instit:
        signaux.append({"type": "usurpation", "mots": found_instit, "poids": len(found_instit) * 15})

    found_tensions = [kw for kw in TENSIONS_KEYWORDS if kw in texte_lower]
    if found_tensions:
        signaux.append({"type": "tension", "mots": found_tensions, "poids": len(found_tensions) * 20})

    mots_majuscules = [m for m in texte.split() if m.isupper() and len(m) > 3]
    if len(mots_majuscules) > 3:
        signaux.append({"type": "rhétorique", "mots": mots_majuscules[:5], "poids": 15})

    score_statique = min(sum(s["poids"] for s in signaux), 60)

    return {"signaux_statiques": signaux, "score_statique": score_statique}


# ─────────────────────────────────────────────
# FONCTION PRINCIPALE
# ─────────────────────────────────────────────

def analyser_fake_news(contenu: str, type_contenu: str = "texte") -> dict:
    """
    Analyse un texte ou une URL pour détecter des signaux de manipulation.

    Args:
        contenu: Le texte ou l'URL à analyser
        type_contenu: "texte" ou "url"

    Returns:
        dict avec verdict, score, signaux, résumé, recommandation
    """
    if not contenu or len(contenu.strip()) < 20:
        return {
            "verdict":           "INDÉTERMINÉ",
            "score_manipulation": 0,
            "signaux_detectes":  [],
            "resume":            "Le contenu fourni est trop court pour être analysé.",
            "recommandation":    "Fournissez un texte plus complet ou une URL valide.",
            "limite_analyse":    "Analyse impossible sur un contenu aussi court.",
            "erreur":            "contenu_trop_court",
        }

    pre_analyse = _pre_analyse_statique(contenu)

    if type_contenu == "url":
        user_prompt = (
            f"Analyse cette URL pour détecter des signaux de manipulation :\n\n"
            f"URL : {contenu}\n\n"
            f"Note : Je ne peux pas accéder au contenu de l'URL directement. "
            f"Analyse l'URL elle-même (structure du domaine, mots-clés suspects, imitation de médias connus).\n\n"
            f"Signaux pré-détectés dans l'URL : {json.dumps(pre_analyse, ensure_ascii=False)}"
        )
    else:
        user_prompt = (
            f"Analyse ce texte pour détecter des signaux de manipulation :\n\n"
            f"---\n{contenu}\n---\n\n"
            f"Signaux pré-détectés automatiquement : {json.dumps(pre_analyse, ensure_ascii=False)}\n\n"
            f"Tiens compte de ces signaux dans ton analyse mais reste critique et indépendant."
        )

    try:
        raw = _call_ai(FAKE_NEWS_SYSTEM_PROMPT, user_prompt)

        # Nettoyage JSON si le modèle ajoute des balises markdown
        raw = re.sub(r'^```json\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)

        resultat = json.loads(raw)
        resultat["score_statique"] = pre_analyse["score_statique"]
        resultat["type_contenu"]   = type_contenu

        return resultat

    except json.JSONDecodeError:
        logger.error("fake_news_agent : réponse IA non parseable")
        return {
            "verdict":           "ERREUR",
            "score_manipulation": 0,
            "signaux_detectes":  [],
            "resume":            "Erreur lors de l'analyse. Réessayez.",
            "recommandation":    "Vérifiez que le contenu est bien du texte lisible.",
            "limite_analyse":    "Réponse IA non parseable.",
            "erreur":            "json_parse_error",
        }

    except Exception as error:
        logger.error(f"fake_news_agent : erreur inattendue — {error}")
        return {
            "verdict":           "ERREUR",
            "score_manipulation": 0,
            "signaux_detectes":  [],
            "resume":            "Une erreur technique s'est produite.",
            "recommandation":    "Réessayez dans quelques instants.",
            "limite_analyse":    str(error),
            "erreur":            "api_error",
        }


# ─────────────────────────────────────────────
# TEST LOCAL
# ─────────────────────────────────────────────

if __name__ == "__main__":
    texte_test = """
    URGENT !!! LE GOUVERNEMENT CACHE LA VÉRITÉ !
    Selon une source sûre au sein de la BCEAO, Orange Money va bloquer tous les comptes
    des Ivoiriens la semaine prochaine. PARTAGEZ AVANT SUPPRESSION !
    Le FMI a officiellement confirmé que la Côte d'Ivoire est en faillite.
    Ne laissez pas les médias vous mentir. 100% PROUVÉ.
    """
    resultat = analyser_fake_news(texte_test, "texte")
    print(json.dumps(resultat, ensure_ascii=False, indent=2))
