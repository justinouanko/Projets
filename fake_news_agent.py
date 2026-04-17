"""
CIAlert - Module de détection de fausses informations
Analyse les signaux de manipulation sans prétendre faire du fact-checking absolu.
"""

import os
import re
import json
from groq import Groq

# --------------------------------------------------------------------------- #
# Client IA (même logique que mon agent principal)
# --------------------------------------------------------------------------- #
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
MODEL = "llama-3.1-8b-instant"

# --------------------------------------------------------------------------- #
# Prompt système spécialisé fake news
# --------------------------------------------------------------------------- #
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

# --------------------------------------------------------------------------- #
# Pré-analyse statique (avant appel IA)
# --------------------------------------------------------------------------- #

ALARMISTE_KEYWORDS = [
    "urgent", "choc", "incroyable", "exclusif", "breaking", "alerte",
    "partagez avant", "avant suppression", "censuré", "ils cachent",
    "100% prouvé", "officiellement confirmé", "source sûre",
    "le gouvernement ne veut pas", "les médias taisent"
]

INSTITUTIONS_USURPEES = [
    "oms", "who", "artci", "bceao", "fmi", "banque mondiale",
    "ministre", "président", "premier ministre", "mtn", "orange money",
    "wave", "moov", "côte d'ivoire officiel"
]

TENSIONS_KEYWORDS = [
    "dioula", "bété", "baoulé", "guéré", "nordiste", "sudiste",
    "chrétien", "musulman", "étranger", "ivoirien de souche"
]


def pre_analyse_statique(texte: str) -> dict:
    """Détecte des signaux évidents avant l'appel IA pour enrichir le contexte."""
    texte_lower = texte.lower()

    signaux = []

    # Mots alarmistes
    found_alarm = [kw for kw in ALARMISTE_KEYWORDS if kw in texte_lower]
    if found_alarm:
        signaux.append({
            "type": "rhétorique",
            "mots": found_alarm,
            "poids": len(found_alarm) * 10
        })

    # Institutions usurpées
    found_instit = [kw for kw in INSTITUTIONS_USURPEES if kw in texte_lower]
    if found_instit:
        signaux.append({
            "type": "usurpation",
            "mots": found_instit,
            "poids": len(found_instit) * 15
        })

    # Tensions ethniques/religieuses
    found_tensions = [kw for kw in TENSIONS_KEYWORDS if kw in texte_lower]
    if found_tensions:
        signaux.append({
            "type": "tension",
            "mots": found_tensions,
            "poids": len(found_tensions) * 20
        })

    # Texte tout en majuscules (signal fort)
    mots = texte.split()
    mots_majuscules = [m for m in mots if m.isupper() and len(m) > 3]
    if len(mots_majuscules) > 3:
        signaux.append({
            "type": "rhétorique",
            "mots": mots_majuscules[:5],
            "poids": 15
        })

    score_statique = min(sum(s["poids"] for s in signaux), 60)

    return {
        "signaux_statiques": signaux,
        "score_statique": score_statique
    }


# --------------------------------------------------------------------------- #
# Fonction principale d'analyse
# --------------------------------------------------------------------------- #

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
            "verdict": "INDÉTERMINÉ",
            "score_manipulation": 0,
            "signaux_detectes": [],
            "resume": "Le contenu fourni est trop court pour être analysé.",
            "recommandation": "Fournissez un texte plus complet ou une URL valide.",
            "limite_analyse": "Analyse impossible sur un contenu aussi court.",
            "erreur": "contenu_trop_court"
        }

    # Pré-analyse statique
    pre_analyse = pre_analyse_statique(contenu)

    # Construction du prompt utilisateur
    if type_contenu == "url":
        user_prompt = f"""Analyse cette URL pour détecter des signaux de manipulation :

URL : {contenu}

Note : Je ne peux pas accéder au contenu de l'URL directement. Analyse l'URL elle-même 
(structure du domaine, mots-clés suspects dans l'URL, imitation de médias connus).

Signaux pré-détectés dans l'URL : {json.dumps(pre_analyse, ensure_ascii=False)}
"""
    else:
        user_prompt = f"""Analyse ce texte pour détecter des signaux de manipulation :

---
{contenu}
---

Signaux pré-détectés automatiquement : {json.dumps(pre_analyse, ensure_ascii=False)}

Tiens compte de ces signaux dans ton analyse mais reste critique et indépendant.
"""

    # Appel IA
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": FAKE_NEWS_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,  # Faible pour des résultats cohérents
            max_tokens=1000
        )

        raw = response.choices[0].message.content.strip()

        # Nettoyage JSON si nécessaire
        raw = re.sub(r'^```json\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)

        resultat = json.loads(raw)

        # Ajout du score statique comme signal de validation
        resultat["score_statique"] = pre_analyse["score_statique"]
        resultat["type_contenu"] = type_contenu

        return resultat

    except json.JSONDecodeError:
        return {
            "verdict": "ERREUR",
            "score_manipulation": 0,
            "signaux_detectes": [],
            "resume": "Erreur lors de l'analyse. Réessayez.",
            "recommandation": "Vérifiez que le contenu est bien du texte lisible.",
            "limite_analyse": "Réponse IA non parseable.",
            "erreur": "json_parse_error"
        }

    except Exception as e:
        return {
            "verdict": "ERREUR",
            "score_manipulation": 0,
            "signaux_detectes": [],
            "resume": "Une erreur technique s'est produite.",
            "recommandation": "Réessayez dans quelques instants.",
            "limite_analyse": str(e),
            "erreur": "api_error"
        }


# --------------------------------------------------------------------------- #
# Test rapide
# --------------------------------------------------------------------------- #
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
