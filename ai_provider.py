"""
CIAlert — ai_provider.py
Couche IA interchangeable : Groq | Gemini | Claude.
Change AI_PROVIDER dans .env pour switcher.
"""

import os
import json
import httpx
from abc import ABC, abstractmethod
from dotenv import load_dotenv

load_dotenv()

AI_PROVIDER = os.getenv("AI_PROVIDER", "groq").lower()

SYSTEM_PROMPT = (
    "Tu es CIAlert, expert en cybersécurité spécialisé dans les arnaques digitales en Côte d'Ivoire et en Afrique de l'Ouest.\n\n"
    "## CONTEXTE ARNAQUES CI 2024-2025\n"
    "Les techniques actuelles incluent :\n"
    "- Broutage évolué : faux soldats ONU, faux médecins étrangers sur WhatsApp/Telegram, faux héritages, arnaques sentimentales\n"
    "- Mobile Money : faux agents MTN/Orange/Wave, codes USSD piégés (*133*,*144*,*555*), demande de code secret\n"
    "- Phishing CI : faux sites orange-money-ci.com, mtn-momo-bonus.tk, SMS avec liens courts\n"
    "- Faux emplois : recrutement urgent sans expérience, travail depuis domicile\n"
    "- Arnaques crypto : plateformes d'investissement garanties 100%, doublement de mise en 24h\n"
    "- Arnaques admin : faux visas express, faux agents consulaires\n"
    "- Arnaque colis douane : colis bloqué nécessitant frais de dédouanement\n\n"
    "## SIGNAUX D'ALARME CLÉS\n"
    "- Demande de paiement préalable pour recevoir un gain\n"
    "- Urgence artificielle + pression temporelle\n"
    "- URLs avec TLDs gratuits (.tk .ml .ga .cf .gq .xyz .buzz) -> TOUJOURS suspect, confidence >= 0.70\n"
    "- Numéros +225 07xx ou 05xx dans contexte suspect\n\n"
    "## RÈGLES CRITIQUES POUR LE SCORE confidence\n"
    "- Si les flags contiennent tld_suspect, imitation_marque, google_safe_browsing ou virustotal -> confidence MINIMUM 0.65, is_scam = true\n"
    "- Si le score règles fourni est > 0.30 -> ton confidence ne peut PAS être inférieur à 0.40\n"
    "- Un message anodin sans flag et score règles = 0.0 -> confidence < 0.20\n"
    "- Ne retourne JAMAIS confidence = 0 si des flags suspects sont présents\n\n"
    "## INSTRUCTION\n"
    "Analyse le texte ET les flags déjà détectés, puis réponds UNIQUEMENT en JSON valide, sans backticks, sans commentaires :\n"
    '{"is_scam": true ou false, "confidence": 0.0 à 1.0, '
    '"category": "broutage"|"mobile_money"|"phishing"|"faux_emploi"|"crypto_invest"|"arnaque_admin"|"autre"|null, '
    '"explanation": "Explication claire en français pour un citoyen ivoirien (2-3 phrases max)"}'
)


def _build_user_prompt(text: str, flags: list, rule_score: float) -> str:
    return (
        f"Texte à analyser :\n\"\"\"\n{text}\n\"\"\"\n\n"
        f"Règles locales déclenchées : {flags}\n"
        f"Score règles : {rule_score:.2f}\n\n"
        "Donne ton analyse JSON."
    )


def _parse_ai_json(raw: str) -> dict:
    """Parse la réponse JSON de l'IA, robuste aux backticks."""
    clean = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(clean)


def _clamp_confidence(confidence: float, flags: list, rule_score: float) -> float:
    """
    Garantit la coherence entre confidence, flags detectes et score de regles.
    Evite le cas ou confidence=0 alors que des signaux critiques existent.
    """
    critical_flag_keywords = [
        "tld_suspect", "imitation_marque", "google_safe_browsing",
        "virustotal", "ip_directe", "url_raccourcie", "path_suspect",
    ]
    has_critical = any(
        any(kw in f for kw in critical_flag_keywords)
        for f in flags
    )

    if has_critical:
        confidence = max(confidence, 0.65)
    elif rule_score > 0.30:
        confidence = max(confidence, 0.40)
    elif rule_score > 0.10:
        confidence = max(confidence, 0.25)

    return round(min(max(confidence, 0.0), 1.0), 3)


# ─────────────────────────────────────────────
# INTERFACE ABSTRAITE
# ─────────────────────────────────────────────

class AIProvider(ABC):
    provider_name: str = "unknown"

    @abstractmethod
    async def analyze(self, text: str, flags: list, rule_score: float) -> dict:
        """Retourne dict avec confidence, category, explanation."""
        ...


# ─────────────────────────────────────────────
# GROQ (gratuit — défaut)
# ─────────────────────────────────────────────

class GroqProvider(AIProvider):
    provider_name = "groq"

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.model   = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        self.url     = "https://api.groq.com/openai/v1/chat/completions"

    async def analyze(self, text: str, flags: list, rule_score: float) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                self.url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": _build_user_prompt(text, flags, rule_score)},
                    ],
                    "temperature": 0.1,
                    "max_tokens":  300,
                },
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"]
            data = _parse_ai_json(raw)
            return {
                "confidence":  _clamp_confidence(float(data.get("confidence", rule_score)), flags, rule_score),
                "category":    data.get("category"),
                "explanation": data.get("explanation", ""),
            }


# ─────────────────────────────────────────────
# GEMINI (gratuit — alternative)
# ─────────────────────────────────────────────

class GeminiProvider(AIProvider):
    provider_name = "gemini"

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model   = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self.url     = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

    async def analyze(self, text: str, flags: list, rule_score: float) -> dict:
        prompt = SYSTEM_PROMPT + "\n\n" + _build_user_prompt(text, flags, rule_score)
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                self.url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
            )
            resp.raise_for_status()
            raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            data = _parse_ai_json(raw)
            return {
                "confidence":  _clamp_confidence(float(data.get("confidence", rule_score)), flags, rule_score),
                "category":    data.get("category"),
                "explanation": data.get("explanation", ""),
            }


# ─────────────────────────────────────────────
# CLAUDE (payant — meilleur)
# ─────────────────────────────────────────────

class ClaudeProvider(AIProvider):
    provider_name = "claude"

    def __init__(self):
        self.api_key = os.getenv("CLAUDE_API_KEY", "")
        self.model   = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
        self.url     = "https://api.anthropic.com/v1/messages"

    async def analyze(self, text: str, flags: list, rule_score: float) -> dict:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                self.url,
                headers={
                    "x-api-key":         self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                },
                json={
                    "model":      self.model,
                    "max_tokens": 300,
                    "system":     SYSTEM_PROMPT,
                    "messages":   [
                        {"role": "user", "content": _build_user_prompt(text, flags, rule_score)}
                    ],
                },
            )
            resp.raise_for_status()
            raw = resp.json()["content"][0]["text"]
            data = _parse_ai_json(raw)
            return {
                "confidence":  _clamp_confidence(float(data.get("confidence", rule_score)), flags, rule_score),
                "category":    data.get("category"),
                "explanation": data.get("explanation", ""),
            }


# ─────────────────────────────────────────────
# FACTORY
# ─────────────────────────────────────────────

def get_ai_provider() -> AIProvider | None:
    """Retourne le provider IA selon AI_PROVIDER dans .env."""
    providers = {
        "groq":   GroqProvider,
        "gemini": GeminiProvider,
        "claude": ClaudeProvider,
    }
    cls = providers.get(AI_PROVIDER)
    if cls is None:
        print(f"⚠️  Provider IA inconnu : '{AI_PROVIDER}'. Détection par règles uniquement.")
        return None
    instance = cls()
    print(f"✅ Provider IA chargé : {instance.provider_name}")
    return instance
