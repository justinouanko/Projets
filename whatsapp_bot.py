import httpx
import os
import logging

logger = logging.getLogger(__name__)

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID")

SUPPORTED_MEDIA_TYPES = {"image", "document", "audio"}

# Extensions/MIME acceptés par file_extractor
ACCEPTED_MIME = {
    "image/jpeg", "image/png", "image/webp", "image/gif",
    "application/pdf",
    "text/plain",
}


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
        await client.post(url, json=payload, headers=headers)


async def download_whatsapp_media(media_id: str) -> tuple[bytes, str, str]:
    """
    Télécharge un média WhatsApp depuis son media_id.
    Retourne (bytes, mime_type, filename).
    """
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}"}

    async with httpx.AsyncClient() as client:
        # Étape 1 : récupérer l'URL de téléchargement
        meta_resp = await client.get(
            f"https://graph.facebook.com/v19.0/{media_id}",
            headers=headers,
        )
        meta_resp.raise_for_status()
        meta = meta_resp.json()

        download_url = meta.get("url")
        mime_type = meta.get("mime_type", "application/octet-stream")
        file_size = meta.get("file_size", 0)

        if file_size > 10 * 1024 * 1024:  # 10 Mo limite CIAlert
            raise ValueError("Fichier trop volumineux (max 10 Mo).")

        # Étape 2 : télécharger le contenu binaire
        media_resp = await client.get(download_url, headers=headers)
        media_resp.raise_for_status()

    # Déduire un nom de fichier depuis le MIME
    ext_map = {
        "image/jpeg": "image.jpg",
        "image/png": "image.png",
        "image/webp": "image.webp",
        "image/gif": "image.gif",
        "application/pdf": "document.pdf",
        "text/plain": "document.txt",
    }
    filename = ext_map.get(mime_type, "fichier.bin")

    return media_resp.content, mime_type, filename


def extract_message_content(message: dict) -> tuple[str | None, str | None]:
    """
    Extrait depuis un message WhatsApp :
    - le texte (si type text)
    - le media_id (si type image/document/audio)

    Retourne (text, media_id).
    """
    msg_type = message.get("type", "")

    if msg_type == "text":
        return message.get("text", {}).get("body", ""), None

    if msg_type in SUPPORTED_MEDIA_TYPES:
        media_block = message.get(msg_type, {})
        media_id = media_block.get("id")
        # Certains documents ont un caption (texte accompagnant)
        caption = media_block.get("caption", "")
        return caption or None, media_id

    return None, None