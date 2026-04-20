"""
CIAlert — agent.py V2.0
Détection en 3 niveaux :
  1. Règles locales étendues (patterns CI 2024-2025)
  2. Threat intelligence (VirusTotal + Google Safe Browsing)
  3. IA avec prompt enrichi contexte arnaque CI

Nouveautés V2.0 :
  - Broutage enrichi avec techniques 2024-2025 (sextorsion, deepfake,
    usurpation célébrité, jeux en ligne, messageries fréquentes)
  - Mobile Money : nouveaux patterns faux agents, faux bonus, syntaxes USSD
  - Crypto/investissement : deepfakes TikTok/Instagram, fausses applis
  - Colis bloqué en douane (variante fréquente 2025-2026)
  - Label de confiance conditionnel (Option A) :
      is_scam=True  → "Probabilité d'arnaque"
      is_scam=False → "Fiabilité"
"""

import re
import os
import asyncio
import httpx
from typing import Optional
from urllib.parse import urlparse
from dotenv import load_dotenv
from ai_provider import get_ai_provider

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SB_KEY  = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")


# ─────────────────────────────────────────────
# PATTERNS DE DÉTECTION
# ─────────────────────────────────────────────

SCAM_PATTERNS = {

    # ── Gain improbable ──────────────────────────────────────────────
    "gain_improbable": [
        r"gagn[ée]\w*\s+\d[\d\s]*\s*(f|fcfa|fr|xof)",
        r"lot\s+de\s+\d",
        r"f[eé]licitation",
        r"vous\s+avez\s+[eé]t[eé]\s+s[eé]lectionn[eé]",
        r"tirage\s+au\s+sort",
        r"gagnant\s+(du\s+jour|officiel|confirm[eé])",
        r"prize\s+winner",
        r"vous\s+[eê]tes\s+l[ea]\s+gagnant",
        r"cadeau\s+(offert|gratuit|confirm[eé])",
        r"reward\s+claim",
        r"bon\s+cadeau\s+de\s+\d",
        r"jackpot",
        r"vous\s+avez\s+remport[eé]",
        r"prime\s+de\s+fid[eé]lit[eé]",
        r"remboursement\s+(mtn|orange|wave|moov)",
        r"bonus\s+(mensuel|gratuit|confirm[eé]).{0,30}(mtn|orange|wave|moov|mobile\s*money)",
        r"300\s*%|400\s*%\s*(bonus|data|appel)",
    ],

    # ── Demande de paiement ──────────────────────────────────────────
    "demande_paiement": [
        r"envoy[ez]+\s+\d[\d\s]*\s*(f|fcfa|fr|xof)",
        r"frais\s+de\s+(dossier|traitement|livraison|d[eé]blocage|transfert|douane|port)",
        r"avance\s+de\s+\d",
        r"recharge\s+(de\s+)?\d",
        r"transfert\s+(de\s+)?\d",
        r"payer\s+\d",
        r"virement\s+de\s+\d",
        r"d[eé]p[oô]t\s+de\s+\d",
        r"envoie\s+moi\s+\d",
        r"send\s+money",
        r"pay\s+now",
        r"paiement\s+requis",
        r"r[eè]glement\s+imm[eé]diat",
        r"frais\s+(de\s+)?(d[eé]douanement|livraison|r[eé]cup[eé]ration)",
        r"d[eé]bloquer\s+(votre|le)\s+(colis|paquet|envoi)",
        r"5\s*000\s*(fcfa|f|fr).{0,30}(colis|paquet|douane)",
        r"20\s*000\s*(fcfa|f|fr).{0,30}(colis|paquet|douane)",
    ],

    # ── Urgence ──────────────────────────────────────────────────────
    "urgence": [
        r"urgent[e]?",
        r"imm[eé]diatement",
        r"dans\s+les\s+\d+\s+(heure|minute|jour)",
        r"expire\s+(aujourd|ce\s+soir|demain|bient[oô]t)",
        r"derni[eè]re\s+chance",
        r"maintenant\s+sinon",
        r"dernier\s+d[eé]lai",
        r"offre\s+limit[eé]e",
        r"act\s+now",
        r"ne\s+ratez\s+pas",
        r"plus\s+que\s+\d+\s+(place|heure)",
        r"d[eé]p[eê]chez.vous",
        r"avant\s+(ce\s+soir|minuit|demain\s+matin)",
        r"compte\s+\u00e0\s+vue",
    ],

    # ── Mobile Money (enrichi 2024-2025) ────────────────────────────
    "mobile_money": [
        r"mtn\s*(momo|mobile\s*money)",
        r"orange\s*money",
        r"wave\s*(ci|c[oô]te|money)?",
        r"moov\s*money",
        r"mobile\s*money",
        r"momo\s*(ci|pay|numero)",
        r"\+?225\s*0[57]\d{8}",
        r"\+?225\s*01\d{8}",
        r"numero\s*(momo|wave|orange)",
        r"envoie\s*(sur|via)\s*(mtn|orange|wave|moov)",
        r"recharg(e|er)\s*(mon\s*)?(compte|num[eé]ro)",
        r"code\s+(ussd|de\s+retrait|secret|otp|pin)",
        r"\*133\*|\*144\*|\*555\*|\*126\*|\*170\*",
        # Nouveaux : faux agents, faux syntaxes, social engineering
        r"agent\s+(mtn|orange|wave|moov).{0,30}(appel|contacte|envoy)",
        r"syntaxe.{0,20}(mtn|orange|wave|moov)",
        r"manipulation.{0,20}(compte|mobile\s*money)",
        r"ne\s+(communiquez|donnez|partagez)\s+pas\s+(votre\s+)?(code|pin|otp|secret)",
        r"compositez?\s+le\s+(code|\*\d)",
        r"validation\s+mobile\s*money",
        r"r[eé]initialisation\s+(de\s+votre\s+)?(compte|pin|code)",
        r"votre\s+compte\s+(mtn|orange|wave|moov).{0,30}(bloqu[eé]|suspendu|limit[eé])",
    ],

    # ── Broutage (fortement enrichi 2024-2025) ──────────────────────
    "broutage": [
        # Identités fictives classiques
        r"je\s+suis\s+(veuve?|g[eé]n[eé]ral|colonel|directeur|ing[eé]nieur|docteur|m[eé]decin|ambassadeur|diplomate|infirmier)",
        r"h[eé]ritage\s+de",
        r"millions?\s+de\s+(dollars|euros|fcfa|livres)",
        r"compte\s+bloqu[eé].{0,40}besoin",
        r"fonds\s+(bloqu[eé]s|disponibles).{0,30}transf[eé]rer",

        # Approche sentimentale — premiers contacts
        r"i\s+love\s+you",
        r"je\s+t.aime\s+d[eé]j[aà]",
        r"coup\s+de\s+foudre",
        r"tu\s+es\s+(la\s+femme|l.homme)\s+de\s+ma\s+vie",
        r"j.ai\s+besoin\s+de\s+toi",
        r"tu\s+me\s+manques\s+d[eé]j[aà]",
        r"(belle|beau|magnifique).{0,20}profil",

        # Plateformes de rencontre et réseaux sociaux
        r"rencontr[eé][e]?\s+sur\s+(facebook|instagram|tinder|badoo|telegram|whatsapp|snapchat|meetic|adopteunmec|bumble|linkedin|jeux\s+en\s+ligne)",
        r"jeu\s+(en\s+ligne|mobile).{0,30}(rencontr[eé]|ami|contact)",
        r"(facebook|instagram|tinder|snapchat).{0,20}(profil|message|contact)",

        # Identités militaires et humanitaires (très fréquent)
        r"soldat\s+(am[eé]ricain|fran[cç]ais|onusien|canadien|britannique|belge)",
        r"militaire\s+(en\s+mission|d[eé]ploy[eé]|en\s+afghanistan|en\s+irak|en\s+syrie|en\s+afrique)",
        r"op[eé]ration\s+de\s+(maintien\s+de\s+la\s+paix|l.onu|l.otan)",
        r"casque\s+bleu",
        r"m[eé]decin\s+sans\s+fronti[eè]res",
        r"ong.{0,20}(mission|humanitaire|afrique)",
        r"ing[eé]nieur\s+(p[eé]trolier|offshore|sur\s+un\s+chantier)",

        # Scénarios de colis et arnaques douanières
        r"colis\s+bloqu[eé]\s+(en\s+douane|[aà]\s+l.a[eé]roport|[aà]\s+roissy|[aà]\s+orly)",
        r"paquet.{0,30}(bloqu[eé]|retenu|douane|livraison)",
        r"(dhl|fedex|chronopost|colissimo).{0,30}(bloqu[eé]|colis|suivi)",
        r"num[eé]ro\s+de\s+suivi.{0,30}(colis|paquet)",

        # Sextorsion (technique en forte hausse 2024-2025)
        r"photo(s)?\s+(intimes?|nues?|priv[eé]es?)",
        r"vid[eé]o(s)?\s+(intimes?|priv[eé]es?|compromettantes?)",
        r"webcam.{0,30}(vid[eé]o|enregistr|film)",
        r"je\s+vais\s+(publier|diffuser|envoyer).{0,30}(photo|vid[eé]o)",
        r"chantage.{0,20}(photo|vid[eé]o|intime)",
        r"sextorsion",
        r"rancon.{0,20}(photo|vid[eé]o|image)",

        # Usurpation de célébrité (deepfake, faux comptes)
        r"je\s+suis\s+(c[eé]l[eé]brit[eé]|vedette|acteur|actrice|chanteur|chanteuse|footballeur|joueur)",
        r"(cristiano|messi|ronaldo|zidane|drogba|didier).{0,30}(message|contact|profil)",
        r"compte\s+(v[eé]rifi[eé]|certifi[eé]|officiel).{0,30}(facebook|instagram|telegram)",
        r"deepfake|faux\s+profil|usurpation\s+d.identit[eé]",
        r"c[eé]l[eé]brit[eé].{0,30}(cadeau|don|loterie|s[eé]lectionn[eé])",

        # Investissement crypto romantique (pig butchering)
        r"cryptocurrency\s+investment",
        r"bitcoin.{0,20}profit",
        r"forex.{0,20}(gagner|profit|invest)",
        r"pig\s+butchering|abattage\s+de\s+cochon",
        r"plateforme\s+(crypto|trading|invest).{0,30}(ensemble|toi\s+et\s+moi|je\s+t.apprends)",
        r"je\s+(vais\s+)?(t.apprendre|te\s+montrer).{0,30}(crypto|trading|investir)",

        # Argot nouchi / expressions ivoiriennes
        r"\bbara\b.{0,30}(argent|gagner|envoyer)",
        r"\bbroutage\b|\bbrouteur\b|\bbarasseur\b",
    ],

    # ── Phishing ─────────────────────────────────────────────────────
    "phishing": [
        r"cliqu[ez]+\s+(ici|sur\s+le\s+lien|pour\s+r[eé]cup[eé]rer)",
        r"http[s]?://\S+\.(tk|ml|ga|cf|gq|xyz|top|click|buzz|link|shop)",
        r"v[eé]rifi[ez]+\s+votre\s+compte",
        r"mot\s+de\s+passe\s+expir[eé]",
        r"compte\s+suspendu",
        r"connexion\s+suspecte",
        r"confirm[ez]+\s+votre\s+(identit[eé]|compte|num[eé]ro)",
        r"acc[eè]s\s+limit[eé]\s+[aà]\s+votre\s+compte",
        r"your\s+account\s+(has\s+been|is)\s+(suspended|blocked|limited)",
        r"unusual\s+(activity|login|sign.in)",
        r"verify\s+your\s+(account|identity|payment)",
        # Nouveaux : faux sites opérateurs CI
        r"(mtn|orange|wave|moov).{0,15}(\.tk|\.ml|\.ga|\.cf|\.xyz|\.top|\.click|\.link|\.shop)",
        r"fournissez\s+(vos|votre)\s+(informations?|identifiant|mot\s+de\s+passe|num[eé]ro)",
        r"formulaire.{0,20}(mobile\s*money|compte|identit[eé])",
    ],

    # ── Faux emploi ──────────────────────────────────────────────────
    "faux_emploi": [
        r"offre\s+d.emploi.{0,30}(fcfa|salaire|urgent)",
        r"travaill[ez]+\s+(depuis\s+chez\s+vous|[aà]\s+domicile).{0,30}\d",
        r"recrutement\s+(urgent|imm[eé]diat)",
        r"sans\s+exp[eé]rience.{0,30}(fcfa|\d+\s*f\b)",
        r"gagner\s+\d.{0,10}(par\s+jour|par\s+semaine|par\s+heure)",
        r"agent\s+commercial.{0,20}commission",
        r"travail\s+en\s+ligne.{0,20}(fcfa|\d)",
        r"t[eé]l[eé]travail.{0,20}(fcfa|\d+\s*000)",
        r"recrutement.{0,20}(whatsapp|telegram|facebook)",
    ],

    # ── Crypto / Investissement frauduleux (enrichi 2024-2025) ──────
    "crypto_invest": [
        r"investiss[ez]+\s+\d.{0,20}(crypto|bitcoin|btc|eth|usdt|bnb|usdc)",
        r"doubl[ez]+\s+(votre|ton)\s+(mise|argent|investissement)",
        r"rendement\s+garanti",
        r"profit\s+(assur[eé]|garanti|journalier)",
        r"plateforme\s+d.investissement.{0,30}(fcfa|\d)",
        r"100\s*%\s*(garanti|s[uû]r|profit)",
        # Nouveaux 2024-2025
        r"30\s*%\s*(par\s+mois|mensuel|de\s+rendement)",
        r"50\s*%\s*(par\s+mois|mensuel|de\s+rendement)",
        r"application\s+(d.investissement|crypto|trading).{0,30}(t[eé]l[eé]charger|installer|rejoindre)",
        r"(tiktok|instagram|youtube).{0,30}(investissement|crypto|bitcoin|trading)",
        r"c[eé]l[eé]brit[eé].{0,20}(investissement|crypto|bitcoin|recommande)",
        r"millions?\s+(en\s+)?\d+\s+(jours?|semaines?|mois)",
        r"plateforme\s+(agr[eé][eé]e?|officielle|s[eé]curis[eé]e?).{0,30}(crypto|invest|trading)",
        r"retrait\s+(garanti|imm[eé]diat|en\s+\d+\s+h)",
    ],

    # ── Arnaque administrative ───────────────────────────────────────
    "arnaque_admin": [
        r"visa.{0,20}(garanti|express|urgent).{0,30}fcfa",
        r"passeport.{0,20}(rapide|urgent).{0,20}\d",
        r"bourse\s+(d.[eé]tude|universitaire).{0,30}(envoyer|payer|virement)",
        r"ambassade.{0,30}frais",
        r"titre\s+de\s+s[eé]jour.{0,30}(urgent|rapide)",
        r"carte\s+de\s+r[eé]sidence.{0,30}(payer|frais|urgent)",
        r"permis\s+de\s+travail.{0,30}(payer|frais|\d)",
    ],
}


# ─────────────────────────────────────────────
# POIDS ET SEUILS
# ─────────────────────────────────────────────

CATEGORY_WEIGHTS = {
    "gain_improbable":  0.80,
    "demande_paiement": 0.85,
    "urgence":          0.45,
    "mobile_money":     0.72,
    "broutage":         0.95,
    "phishing":         0.90,
    "faux_emploi":      0.80,
    "crypto_invest":    0.85,
    "arnaque_admin":    0.80,
}

RISK_THRESHOLDS = {
    "CRITIQUE": 0.80,
    "ÉLEVÉ":    0.60,
    "MOYEN":    0.35,
    "FAIBLE":   0.0,
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".buzz", ".link", ".shop", ".win", ".loan",
    ".download", ".racing", ".review", ".stream", ".info",
    ".biz", ".online", ".site", ".website", ".space",
}

WHITELIST_DOMAINS = {
    "mtn.ci", "orange.ci", "wave.com", "moov.ci",
    "gouv.ci", "bceao.int", "artci.ci", "plcc.ci",
    "google.com", "facebook.com", "instagram.com",
    "youtube.com", "whatsapp.com", "twitter.com", "x.com",
    "dhl.com", "fedex.com", "colissimo.fr",
}

# Label de confiance conditionnel (Option A)
CONFIDENCE_LABEL = {
    True:  "Probabilité d'arnaque",
    False: "Fiabilité",
}


# ─────────────────────────────────────────────
# ANALYSE DES URLs
# ─────────────────────────────────────────────

def extract_urls(text: str) -> list:
    return re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text)


def is_suspicious_url(url: str) -> tuple:
    flags = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append(f"tld_suspect:{tld}")

        parts = domain.split(".")
        main  = parts[0] if parts else ""
        if len(main) > 25:
            flags.append("domaine_trop_long")
        if main.count("-") >= 3:
            flags.append("domaine_trait_union_suspect")

        for brand in ["orange", "mtn", "wave", "moov", "gouv", "bceao",
                      "paypal", "amazon", "apple", "microsoft", "google",
                      "dhl", "fedex", "colissimo", "artci"]:
            if brand in domain and domain not in WHITELIST_DOMAINS:
                flags.append(f"imitation_marque:{brand}")

        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            flags.append("ip_directe")

        for kw in ["login", "verify", "secure", "account", "confirm",
                   "update", "momo", "prize", "winner", "claim", "reward",
                   "bonus", "validation", "reinitialisation", "douane"]:
            if kw in path:
                flags.append(f"path_suspect:{kw}")

        for shortener in ["bit.ly", "tinyurl", "t.co", "ow.ly", "goo.gl",
                          "rb.gy", "cutt.ly", "short.io", "is.gd", "buff.ly"]:
            if shortener in domain:
                flags.append("url_raccourcie")
                break

    except Exception:
        flags.append("url_malformee")

    return len(flags) > 0, flags


# ─────────────────────────────────────────────
# THREAT INTELLIGENCE
# ─────────────────────────────────────────────

async def check_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"available": False}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
            )
            if resp.status_code == 404:
                await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": VIRUSTOTAL_KEY},
                    data={"url": url},
                )
                return {"available": True, "status": "submitted", "malicious": 0, "total": 0}
            if resp.status_code != 200:
                return {"available": False}
            data  = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "available":  True,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total":      sum(stats.values()),
                "reputation": data["data"]["attributes"].get("reputation", 0),
            }
    except Exception as error:
        return {"available": False, "error": str(error)}


async def check_google_safe_browsing(urls: list) -> dict:
    if not GOOGLE_SB_KEY or not urls:
        return {"available": False}
    try:
        payload = {
            "client": {"clientId": "cialert", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": u} for u in urls],
            },
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}",
                json=payload,
            )
            if resp.status_code != 200:
                return {"available": False}
            data    = resp.json()
            matches = data.get("matches", [])
            return {
                "available": True,
                "threats": [{"url": m["threat"]["url"], "type": m["threatType"]} for m in matches],
            }
    except Exception as error:
        return {"available": False, "error": str(error)}


# ─────────────────────────────────────────────
# MOTEUR DE RÈGLES
# ─────────────────────────────────────────────

def _apply_rules(text: str) -> dict:
    text_lower = text.lower()
    flags      = []
    cat_hits   = {}

    for category, patterns in SCAM_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                if category not in cat_hits:
                    cat_hits[category] = 0
                    flags.append(category)
                cat_hits[category] += 1

    if not flags:
        return {"flags": [], "raw_score": 0.0, "top_category": None}

    total = sum(CATEGORY_WEIGHTS.get(c, 0.5) * min(h, 3) for c, h in cat_hits.items())
    denom = sum(min(h, 3) for h in cat_hits.values())
    raw   = min(total / max(denom, 1), 1.0)

    # Bonus multi-catégories — signal fort de broutage combiné
    if len(cat_hits) >= 3:
        raw = min(raw + 0.15, 1.0)
    elif len(cat_hits) >= 2:
        raw = min(raw + 0.08, 1.0)

    # Bonus spécifique : broutage + demande paiement = combo classique
    if "broutage" in cat_hits and "demande_paiement" in cat_hits:
        raw = min(raw + 0.10, 1.0)

    # Bonus spécifique : broutage + urgence = pression sentimentale
    if "broutage" in cat_hits and "urgence" in cat_hits:
        raw = min(raw + 0.05, 1.0)

    top = max(cat_hits, key=lambda c: cat_hits[c] * CATEGORY_WEIGHTS.get(c, 0.5))
    return {"flags": flags, "raw_score": raw, "top_category": top}


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

        # Niveau 1 — règles locales
        rule_result = _apply_rules(text)
        raw_score   = rule_result["raw_score"]
        flags       = list(rule_result["flags"])
        category    = rule_result["top_category"]
        explanation = self._rule_explanation(flags, category)

        # Niveau 2 — URLs + threat intelligence
        urls      = extract_urls(text)
        ti_result = {}

        if urls:
            for url in urls:
                suspicious, url_flags = is_suspicious_url(url)
                if suspicious:
                    flags.extend(url_flags)
                    raw_score = min(raw_score + 0.20, 1.0)
                    if "phishing" not in flags:
                        flags.append("phishing")
                    category = category or "phishing"

            if VIRUSTOTAL_KEY or GOOGLE_SB_KEY:
                vt_coro  = check_virustotal(urls[0]) if VIRUSTOTAL_KEY else asyncio.coroutine(lambda: {"available": False})()
                gsb_coro = check_google_safe_browsing(urls) if GOOGLE_SB_KEY else asyncio.coroutine(lambda: {"available": False})()
                vt_res, gsb_res = await asyncio.gather(vt_coro, gsb_coro)

                if vt_res.get("available") and vt_res.get("malicious", 0) > 0:
                    mal   = vt_res["malicious"]
                    total = vt_res["total"] or 1
                    raw_score = min(raw_score + min(mal / total * 1.5, 0.40), 1.0)
                    flags.append(f"virustotal:{mal}_moteurs_positifs")
                    ti_result["virustotal"] = vt_res

                if gsb_res.get("available") and gsb_res.get("threats"):
                    raw_score = min(raw_score + 0.35, 1.0)
                    flags.append("google_safe_browsing:DANGEREUX")
                    ti_result["google_safe_browsing"] = gsb_res

        # Niveau 3 — IA
        ai_used     = False
        ai_provider = None

        if use_ai and self.ai:
            try:
                ai_result = await self.ai.analyze(text, flags, raw_score)
                ai_confidence = ai_result.get("confidence", 0)

                if raw_score > 0:
                    # Fusion pondérée règles + IA
                    raw_score = raw_score * 0.35 + ai_confidence * 0.65
                else:
                    # Pas de signal règles — on fait davantage confiance à l'IA
                    raw_score = ai_confidence * 0.90

                explanation = ai_result.get("explanation", explanation)
                category    = ai_result.get("category") or category
                ai_used     = True
                ai_provider = self.ai.provider_name
            except Exception as error:
                explanation += f" [IA indisponible : {error}]"

        confidence = round(min(max(raw_score, 0.0), 1.0), 3)
        is_scam    = confidence >= 0.35

        # Cohérence : si des flags critiques existent (threat intel, URL malveillante),
        # forcer is_scam=True et un confidence minimum représentatif
        critical_flags = [f for f in flags if any(
            kw in f for kw in ["virustotal", "google_safe_browsing", "tld_suspect", "imitation_marque", "ip_directe"]
        )]
        if critical_flags and not is_scam:
            is_scam    = True
            confidence = max(confidence, 0.55)

        risk_level = _score_to_risk(confidence) if is_scam else "FAIBLE"

        return {
            "is_scam":          is_scam,
            "confidence":       confidence,
            "confidence_label": CONFIDENCE_LABEL[is_scam],
            "risk_level":       risk_level,
            "scam_category":    category,
            "rule_flags":       flags,
            "explanation":      explanation,
            "ai_used":          ai_used,
            "ai_provider":      ai_provider,
            "threat_intel":     ti_result,
            "urls_found":       urls,
        }

    def _rule_explanation(self, flags: list, category: Optional[str]) -> str:
        if not flags:
            return "Aucun signal d'arnaque détecté."

        labels = {
            "gain_improbable":  "promesse de gain improbable",
            "demande_paiement": "demande de paiement suspect",
            "urgence":          "mise en situation d'urgence",
            "mobile_money":     "référence Mobile Money CI",
            "broutage":         "broutage / arnaque sentimentale",
            "phishing":         "phishing / faux site",
            "faux_emploi":      "offre d'emploi frauduleuse",
            "crypto_invest":    "arnaque crypto / investissement",
            "arnaque_admin":    "arnaque visa / démarche administrative",
        }

        readable = [labels.get(f, f) for f in flags if f in labels]
        if not readable:
            return f"Signaux techniques : {', '.join(flags[:5])}."

        return (
            f"Ce contenu présente {len(readable)} signal(s) : "
            + ", ".join(readable) + "."
        )
