"""
CIAlert — whatsapp_bot.py
Gestion complète du bot WhatsApp :
- Envoi de messages
- Téléchargement de médias
- Sessions conversationnelles (PostgreSQL)
- Flux signalement guidé
- Menu / aide / stats
- Onboarding nouveaux utilisateurs
"""

import httpx
import os
import logging
from database import get_connection

logger = logging.getLogger(__name__)

WHATSAPP_TOKEN    = os.getenv("WHATSAPP_TOKEN")
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID")

SUPPORTED_MEDIA_TYPES = {"image", "document", "audio"}

ACCEPTED_MIME = {
    "image/jpeg", "image/png", "image/webp", "image/gif",
    "application/pdf",
    "text/plain",
}

# ─────────────────────────────────────────────
# MOTS DÉCLENCHEURS
# ─────────────────────────────────────────────

TRIGGER_SIGNALEMENT = {
    "signaler", "signalement", "arnaque", "arnaquer", "arnaqué",
    "j'ai été arnaqué", "je veux signaler", "reporter", "report",
}

TRIGGER_MENU = {"menu", "aide", "help", "bonjour", "salut", "hello", "start", "démarrer"}
TRIGGER_STATS = {"stats", "statistiques", "chiffres"}
TRIGGER_ANNULER = {"annuler", "cancel", "stop", "quitter", "fin"}

# ─────────────────────────────────────────────
# MESSAGES
# ─────────────────────────────────────────────

MSG_BIENVENUE = """👋 Bienvenue sur *CIAlert* 🇨🇮

Je suis ton assistant de détection d'arnaques digitales.

Envoie-moi directement :
📝 Un *texte* ou *SMS* suspect
🔗 Un *lien* ou *URL*
📞 Un *numéro de téléphone*
🖼️ Une *image* ou *capture d'écran*
📄 Un *document PDF*

Et je l'analyse immédiatement.

Tape *menu* pour voir toutes les options."""

MSG_MENU = """📋 *Menu CIAlert*

*Analyser* — Envoie directement le contenu suspect
*signaler* — Signaler une arnaque dont tu as été victime
*stats* — Statistiques de la plateforme
*annuler* — Annuler une action en cours

🌐 cialert.up.railway.app"""

MSG_ANNULATION = "✅ Action annulée. Envoie-moi un contenu à analyser ou tape *menu*."

# Étapes du flux signalement
ETAPES = {
    1: "📌 *Étape 1/4* — Envoie le texte, numéro ou lien que tu veux signaler.",
    2: "📱 *Étape 2/4* — Sur quelle plateforme as-tu été contacté ?\n\nRéponds : MTN / Orange / Wave / WhatsApp / Facebook / Autre",
    3: "💸 *Étape 3/4* — Quel montant as-tu perdu ? (en FCFA)\nRéponds *0* si aucune perte.",
    4: "📝 *Étape 4/4* — Décris brièvement ce qui s'est passé.",
}

# ─────────────────────────────────────────────
# ENVOI DE MESSAGE
# ─────────────────────────────────────────────

async def send_whatsapp_message(to: str, text: str):
    url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text},
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json=payload, headers=headers)
        if resp.status_code != 200:
            logger.error(f"Erreur envoi WhatsApp {resp.status_code}: {resp.text}")

# ─────────────────────────────────────────────
# TÉLÉCHARGEMENT MÉDIA
# ─────────────────────────────────────────────

async def download_whatsapp_media(media_id: str) -> tuple[bytes, str, str]:
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}"}
    async with httpx.AsyncClient() as client:
        meta_resp = await client.get(
            f"https://graph.facebook.com/v19.0/{media_id}",
            headers=headers,
        )
        meta_resp.raise_for_status()
        meta = meta_resp.json()

        download_url = meta.get("url")
        mime_type    = meta.get("mime_type", "application/octet-stream")
        file_size    = meta.get("file_size", 0)

        if file_size > 10 * 1024 * 1024:
            raise ValueError("Fichier trop volumineux (max 10 Mo).")

        media_resp = await client.get(download_url, headers=headers)
        media_resp.raise_for_status()

    ext_map = {
        "image/jpeg": "image.jpg",
        "image/png":  "image.png",
        "image/webp": "image.webp",
        "image/gif":  "image.gif",
        "application/pdf": "document.pdf",
        "text/plain": "document.txt",
    }
    filename = ext_map.get(mime_type, "fichier.bin")
    return media_resp.content, mime_type, filename

# ─────────────────────────────────────────────
# EXTRACTION CONTENU MESSAGE
# ─────────────────────────────────────────────

def extract_message_content(message: dict) -> tuple[str | None, str | None]:
    msg_type = message.get("type", "")
    if msg_type == "text":
        return message.get("text", {}).get("body", ""), None
    if msg_type in SUPPORTED_MEDIA_TYPES:
        media_block = message.get(msg_type, {})
        media_id    = media_block.get("id")
        caption     = media_block.get("caption", "")
        return caption or None, media_id
    return None, None

# ─────────────────────────────────────────────
# GESTION DES SESSIONS (PostgreSQL)
# ─────────────────────────────────────────────

def _init_sessions_table():
    """Crée la table sessions WhatsApp si elle n'existe pas."""
    is_pg = "postgresql" in os.getenv("DATABASE_URL", "")
    if is_pg:
        sql = """
            CREATE TABLE IF NOT EXISTS whatsapp_sessions (
                sender      TEXT PRIMARY KEY,
                etape       INTEGER NOT NULL DEFAULT 0,
                content     TEXT,
                platform    TEXT,
                amount      REAL DEFAULT 0,
                description TEXT,
                is_new_user INTEGER DEFAULT 1,
                updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
    else:
        sql = """
            CREATE TABLE IF NOT EXISTS whatsapp_sessions (
                sender      TEXT PRIMARY KEY,
                etape       INTEGER NOT NULL DEFAULT 0,
                content     TEXT,
                platform    TEXT,
                amount      REAL DEFAULT 0,
                description TEXT,
                is_new_user INTEGER DEFAULT 1,
                updated_at  DATETIME DEFAULT (datetime('now'))
            )
        """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(sql)


def get_session(sender: str) -> dict | None:
    """Retourne la session active d'un sender, ou None."""
    is_pg = "postgresql" in os.getenv("DATABASE_URL", "")
    ph = "%s" if is_pg else "?"
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM whatsapp_sessions WHERE sender = {ph}", (sender,))
        row = cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))


def set_session(sender: str, etape: int, data: dict = {}):
    """Crée ou met à jour une session."""
    is_pg = "postgresql" in os.getenv("DATABASE_URL", "")
    with get_connection() as conn:
        cur = conn.cursor()
        if is_pg:
            cur.execute("""
                INSERT INTO whatsapp_sessions (sender, etape, content, platform, amount, description, is_new_user)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (sender) DO UPDATE SET
                    etape = EXCLUDED.etape,
                    content = EXCLUDED.content,
                    platform = EXCLUDED.platform,
                    amount = EXCLUDED.amount,
                    description = EXCLUDED.description,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                sender, etape,
                data.get("content"), data.get("platform"),
                data.get("amount", 0), data.get("description"),
                data.get("is_new_user", 0),
            ))
        else:
            cur.execute("""
                INSERT OR REPLACE INTO whatsapp_sessions
                    (sender, etape, content, platform, amount, description, is_new_user)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                sender, etape,
                data.get("content"), data.get("platform"),
                data.get("amount", 0), data.get("description"),
                data.get("is_new_user", 0),
            ))


def delete_session(sender: str):
    """Supprime la session d'un sender."""
    is_pg = "postgresql" in os.getenv("DATABASE_URL", "")
    ph = "%s" if is_pg else "?"
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM whatsapp_sessions WHERE sender = {ph}", (sender,))


def is_new_user(sender: str) -> bool:
    """Retourne True si c'est la première fois que ce sender écrit."""
    is_pg = "postgresql" in os.getenv("DATABASE_URL", "")
    ph = "%s" if is_pg else "?"
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT is_new_user FROM whatsapp_sessions WHERE sender = {ph}", (sender,))
        row = cur.fetchone()
        return row is None  # jamais vu = nouvel utilisateur


def mark_user_known(sender: str):
    """Marque un sender comme utilisateur connu."""
    is_pg = "postgresql" in os.getenv("DATABASE_URL", "")
    with get_connection() as conn:
        cur = conn.cursor()
        if is_pg:
            cur.execute("""
                INSERT INTO whatsapp_sessions (sender, etape, is_new_user)
                VALUES (%s, 0, 0)
                ON CONFLICT (sender) DO UPDATE SET is_new_user = 0
            """, (sender,))
        else:
            cur.execute("""
                INSERT OR REPLACE INTO whatsapp_sessions (sender, etape, is_new_user)
                VALUES (?, 0, 0)
            """, (sender,))

# ─────────────────────────────────────────────
# LOGIQUE FLUX SIGNALEMENT
# ─────────────────────────────────────────────

async def handle_signalement_flow(sender: str, text: str, session: dict | None) -> bool:
    """
    Gère le flux signalement étape par étape.
    Retourne True si le message a été traité par le flux, False sinon.
    """
    text_lower = text.strip().lower() if text else ""

    # Annulation en cours de flux
    if text_lower in TRIGGER_ANNULER and session and session.get("etape", 0) > 0:
        delete_session(sender)
        await send_whatsapp_message(sender, MSG_ANNULATION)
        return True

    # Déclenchement du flux
    if text_lower in TRIGGER_SIGNALEMENT and (not session or session.get("etape", 0) == 0):
        set_session(sender, 1, {})
        await send_whatsapp_message(sender, ETAPES[1])
        return True

    # Flux en cours
    if session and session.get("etape", 0) > 0:
        etape = session["etape"]
        data  = dict(session)

        if etape == 1:
            data["content"] = text
            set_session(sender, 2, data)
            await send_whatsapp_message(sender, ETAPES[2])
            return True

        if etape == 2:
            data["platform"] = text.strip()
            set_session(sender, 3, data)
            await send_whatsapp_message(sender, ETAPES[3])
            return True

        if etape == 3:
            try:
                data["amount"] = float(text.strip().replace(" ", "").replace("fcfa", "").replace("f", ""))
            except ValueError:
                data["amount"] = 0
            set_session(sender, 4, data)
            await send_whatsapp_message(sender, ETAPES[4])
            return True

        if etape == 4:
            data["description"] = text.strip()

            # Confirmation avant envoi
            resume = (
                f"📋 *Récapitulatif du signalement*\n\n"
                f"📌 Contenu : {data.get('content', '')[:100]}\n"
                f"📱 Plateforme : {data.get('platform', 'Non précisé')}\n"
                f"💸 Montant : {int(data.get('amount', 0))} FCFA\n"
                f"📝 Description : {data.get('description', '')[:150]}\n\n"
                f"Tape *confirmer* pour envoyer ou *annuler* pour abandonner."
            )
            set_session(sender, 5, data)
            await send_whatsapp_message(sender, resume)
            return True

        if etape == 5:
            if text_lower == "confirmer":
                # Import ici pour éviter circular import
                from database import save_report
                from phone_registry import register_phone_from_text

                report_id = save_report(
                    reported_text=session.get("content", ""),
                    report_type="whatsapp_signalement",
                    victim_amount=session.get("amount", 0),
                    victim_platform=session.get("platform"),
                    description=session.get("description"),
                )
                register_phone_from_text(
                    text=session.get("content", ""),
                    scam_category="whatsapp_signalement",
                    source="whatsapp",
                    report_id=report_id,
                )
                delete_session(sender)
                await send_whatsapp_message(
                    sender,
                    "✅ *Signalement enregistré !*\n\nMerci de contribuer à la sécurité numérique en Côte d'Ivoire 🇨🇮\n\nEnvoie-moi un autre contenu à analyser ou tape *menu*."
                )
            elif text_lower in TRIGGER_ANNULER:
                delete_session(sender)
                await send_whatsapp_message(sender, MSG_ANNULATION)
            else:
                await send_whatsapp_message(sender, "Tape *confirmer* pour envoyer ou *annuler* pour abandonner.")
            return True

    return False

# ─────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────

def init_whatsapp_sessions():
    """À appeler au démarrage de l'application."""
    try:
        _init_sessions_table()
        logger.info("✅ Table sessions WhatsApp initialisée.")
    except Exception as e:
        logger.error(f"Erreur init sessions WhatsApp : {e}")