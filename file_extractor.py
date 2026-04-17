"""
file_extractor.py
Extraction de texte depuis PDF, images et fichiers texte.
Utilis\u00e9 par le endpoint POST /analyze-file de CIAlert.
"""

import io
import logging
import shutil
import os
from typing import Tuple

logger = logging.getLogger(__name__)

# --- CONFIGURATION TESSERACT POUR RAILWAY ---
try:
    import pytesseract
    # On cherche où Nixpacks a installé tesseract
    tesseract_path = shutil.which("tesseract")
    if tesseract_path:
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
        logger.info(f"✅ Tesseract configuré sur : {tesseract_path}")
    else:
        logger.warning("⚠️ Tesseract binaire non trouvé dans le PATH.")
except ImportError:
    logger.error("❌ Librairie pytesseract manquante.")
# --------------------------------------------
def extract_from_image(data: bytes) -> Tuple[str, str]:
    try:
        from PIL import Image
        import pytesseract

        img = Image.open(io.BytesIO(data))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # Tentative OCR locale
        text = pytesseract.image_to_string(img, lang="fra+eng")
        
        if text.strip():
            return text.strip(), "tesseract_ocr"
        
        # --- STRATÉGIE DE SECOURS : IA VISION ---
        logger.info("OCR local vide, tentative via IA Vision...")
        from ai_provider import analyser_image_visuellement # Importation locale pour éviter les cycles
        text_ai = analyser_image_visuellement(data) 
        
        if text_ai:
            return text_ai, "ia_vision_fallback"
            
        raise ValueError("Aucun texte détecté, même par l'IA.")

    except Exception as e:
        logger.error(f"Erreur OCR image : {e}")
        # Si Tesseract n'est pas là, on tente QUAND MÊME l'IA avant de crash
        try:
            from ai_provider import analyser_image_visuellement
            return analyser_image_visuellement(data), "ia_vision_emergency"
        except:
            raise ValueError(f"Échec total de l'extraction image : {e}")
# ── PDF ──────────────────────────────────────────────────────────────────────

def extract_from_pdf(data: bytes) -> Tuple[str, str]:
    """
    Retourne (texte_extrait, methode_utilisee).
    Essaie pdfplumber en premier. Bascule sur OCR si le PDF est scann\u00e9 (sans couche texte).
    """
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            pages_text = []
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    pages_text.append(t.strip())
            text = "\n\n".join(pages_text)

        if len(text.strip()) > 50:
            return text, "pdfplumber"

        # PDF scann\u00e9 : pas de couche texte, on tente l'OCR page par page
        logger.info("PDF sans couche texte, tentative OCR...")
        return _ocr_pdf_pages(data), "ocr_pdf"

    except Exception as e:
        logger.error(f"Erreur extraction PDF : {e}")
        raise ValueError(f"Impossible de lire ce PDF : {e}")


def _ocr_pdf_pages(data: bytes) -> str:
    """OCR sur chaque page d'un PDF scann\u00e9 via pdf2image + Tesseract."""
    try:
        from pdf2image import convert_from_bytes
        import pytesseract

        images = convert_from_bytes(data, dpi=200)
        results = []
        for img in images:
            t = pytesseract.image_to_string(img, lang="fra+eng")
            if t.strip():
                results.append(t.strip())
        return "\n\n".join(results)
    except ImportError:
        raise ValueError(
            "pdf2image n\u2019est pas install\u00e9. Pour les PDF scann\u00e9s, "
            "installez : pip install pdf2image"
        )


# ── IMAGE ────────────────────────────────────────────────────────────────────

def extract_from_image(data: bytes) -> Tuple[str, str]:
    """
    OCR sur une image (PNG, JPG, WEBP...).
    Tente fran\u00e7ais + anglais pour couvrir les SMS ivoiriens.
    """
    try:
        import pytesseract
        from PIL import Image

        img = Image.open(io.BytesIO(data))

        # Conversion en RGB si n\u00e9cessaire (RGBA, palette...)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        text = pytesseract.image_to_string(img, lang="fra+eng")
        if not text.strip():
            raise ValueError("Aucun texte d\u00e9tect\u00e9 dans l\u2019image.")

        return text.strip(), "tesseract_ocr"

    except ImportError:
        raise ValueError("pytesseract ou Pillow n\u2019est pas install\u00e9.")
    except Exception as e:
        logger.error(f"Erreur OCR image : {e}")
        raise ValueError(f"Impossible d\u2019extraire le texte de cette image : {e}")


# ── TEXTE BRUT ───────────────────────────────────────────────────────────────

def extract_from_text(data: bytes) -> Tuple[str, str]:
    """D\u00e9code un fichier texte brut (.txt, .eml, .csv...)."""
    for encoding in ("utf-8", "latin-1", "cp1252"):
        try:
            return data.decode(encoding).strip(), f"text_{encoding}"
        except UnicodeDecodeError:
            continue
    raise ValueError("Encodage du fichier non support\u00e9.")


# ── DISPATCHER ───────────────────────────────────────────────────────────────

SUPPORTED_TYPES = {
    "application/pdf": extract_from_pdf,
    "image/png": extract_from_image,
    "image/jpeg": extract_from_image,
    "image/webp": extract_from_image,
    "image/gif": extract_from_image,
    "text/plain": extract_from_text,
    "message/rfc822": extract_from_text,   # .eml
    "text/csv": extract_from_text,
}

# Extensions de secours si le content-type est g\u00e9n\u00e9rique
EXTENSION_FALLBACK = {
    ".pdf":  extract_from_pdf,
    ".png":  extract_from_image,
    ".jpg":  extract_from_image,
    ".jpeg": extract_from_image,
    ".webp": extract_from_image,
    ".txt":  extract_from_text,
    ".eml":  extract_from_text,
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 Mo
MAX_TEXT_LENGTH = 8000             # caract\u00e8res envoy\u00e9s \u00e0 l'IA


def extract_text(data: bytes, content_type: str, filename: str) -> dict:
    """
    Point d'entr\u00e9e principal.
    Retourne un dict :
      {
        "text": str,          # texte extrait (tronqu\u00e9 si trop long)
        "method": str,        # m\u00e9thode utilis\u00e9e
        "truncated": bool,    # vrai si le texte a \u00e9t\u00e9 tronqu\u00e9
        "char_count": int,    # longueur avant troncature
      }
    L\u00e8ve ValueError si le fichier est illisible ou non support\u00e9.
    """
    if len(data) > MAX_FILE_SIZE:
        raise ValueError(
            f"Fichier trop volumineux ({len(data) // 1024 // 1024} Mo). "
            f"Limite : {MAX_FILE_SIZE // 1024 // 1024} Mo."
        )

    extractor = SUPPORTED_TYPES.get(content_type)

    if extractor is None:
        # Tentative par extension
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        extractor = EXTENSION_FALLBACK.get(ext)

    if extractor is None:
        raise ValueError(
            f"Type de fichier non support\u00e9 : {content_type} ({filename}). "
            f"Types accept\u00e9s : PDF, PNG, JPG, WEBP, TXT, EML."
        )

    text, method = extractor(data)

    if not text.strip():
        raise ValueError("Aucun texte n\u2019a pu \u00eatre extrait de ce fichier.")

    char_count = len(text)
    truncated = char_count > MAX_TEXT_LENGTH
    if truncated:
        text = text[:MAX_TEXT_LENGTH] + "\n\n[... texte tronqu\u00e9 \u2014 limite atteinte]"

    return {
        "text": text,
        "method": method,
        "truncated": truncated,
        "char_count": char_count,
    }
