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
import google.generativeai as genai
from PIL import Image
import io
import os
load_dotenv()

AI_PROVIDER = os.getenv("AI_PROVIDER", "groq").lower()

SYSTEM_PROMPT = """Tu es CIAlert, expert en cybersécurité spécialisé dans les arnaques digitales en Côte d'Ivoire et en Afrique de l'Ouest.

## CONTEXTE ARNAQUES CI 2024-2025
Les techniques actuelles incluent :
- **Broutage évolué** : faux soldats ONU, faux médecins étrangers sur WhatsApp/Telegram, faux héritages, arnaques sentimentales longue durée
- **Mobile Money** : faux agents MTN/Orange/Wave, faux remboursements, codes USSD piégés (*133*,*144*,*555*), demande de code secret sous prétexte de "déblocage"
- **Phishing CI** : faux sites orange-money-ci.com, mtn-momo-bonus.tk, pages de connexion clonées, SMS avec liens courts
- **Faux emplois** : recrutement urgent sans expérience, agent commercial avec "avance sur commission", travail depuis domicile
- **Arnaques crypto** : plateformes d'investissement garanties 100%, doublement de mise en 24h, faux bots de trading forex
- **Arnaques admin** : faux visas express, faux agents consulaires, bourses d'études frauduleuses
- **Arnaque colis douane** : colis bloqué nécessitant frais de dédouanement
- **SIM swap** : demande d'informations pour "mettre à jour" la carte SIM

## SIGNAUX D'ALARME CLÉS
- Demande de paiement préalable pour recevoir un gain
- Urgence artificielle + pression temporelle
- Demande de secret / discrétion
- Numéros +225 07xx ou 05xx dans contexte suspect
- URLs avec TLDs gratuits (.tk .ml .ga .cf .gq .xyz .buzz)
- Gains disproportionnés (500 000+ FCFA sans raison)
- Fautes d'orthographe dans communications "officielles"

## INSTRUCTION
Analyse le texte et réponds UNIQUEMENT en JSON valide, sans backticks, sans commentaires :
{
  "is_scam": true ou false,
  "confidence": 0.0 à 1.0,
  "category": "broutage" | "mobile_money" | "phishing" | "faux_emploi" | "crypto_invest" | "arnaque_admin" | "autre" | null,
  "explanation": "Explication claire en français pour un citoyen ivoirien (2-3 phrases max)"
}

Sois précis et contextualise pour la Côte d'Ivoire. Un message anodin doit avoir confidence < 0.2."""


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
                "confidence":  float(data.get("confidence", rule_score)),
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
                "confidence":  float(data.get("confidence", rule_score)),
                "category":    data.get("category"),
                "explanation": data.get("explanation", ""),
            }


def analyser_image_visuellement(image_data: bytes) -> str:
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        return "Erreur : Clé API Vision non configurée."

    try:
        import google.generativeai as genai
        genai.configure(api_key=gemini_key)
        
        # On utilise le modèle sans le préfixe 'models/' si on passe par la lib
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        img = Image.open(io.BytesIO(image_data))
        
        # Prompt optimisé pour ne pas renvoyer de vide
        prompt = "Extrais tout le texte de cette image et analyse s'il y a une arnaque."
        
        response = model.generate_content([prompt, img])
        
        if response and response.text:
            return response.text
        return "L'IA n'a pu lire aucun texte sur cette image."

    except Exception as e:
        logger.error(f"❌ Erreur Gemini Vision : {e}")
        # Si même Flash échoue, on peut tenter 'gemini-1.5-pro' en dernier recours
        return ""
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
                "confidence":  float(data.get("confidence", rule_score)),
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
