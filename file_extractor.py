import io
import logging
import shutil
import os
import logging
import json
from typing import Tuple

# Initialisation du logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO) # Assure que les logs s'affichent

# --- CONFIGURATION TESSERACT POUR RAILWAY ---
try:
    import pytesseract
    # Liste des chemins probables sur Railway/Nix
    possible_paths = [
        shutil.which("tesseract"),
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/nix/var/nix/profiles/default/bin/tesseract"
    ]
    # On prend le premier qui existe réellement
    tesseract_bin = next((p for p in possible_paths if p and os.path.exists(p)), None)

    if tesseract_bin:
        pytesseract.pytesseract.tesseract_cmd = tesseract_bin
        logger.info(f"✅ Tesseract forcé sur : {tesseract_bin}")
    else:
        logger.warning("⚠️ Tesseract introuvable. On bascule sur l'IA de Vision pour les images.")
except ImportError:
    logger.error("❌ Librairie pytesseract manquante.")

# ── IMAGE ────────────────────────────────────────────────────────────────────

def extract_from_image(data: bytes) -> Tuple[str, str]:
    """
    OCR sur une image avec Fallback IA Vision si Tesseract échoue.
    """
    try:
        from PIL import Image
        import pytesseract

        img = Image.open(io.BytesIO(data))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # 1. Tentative OCR locale (Rapide & Gratuit)
        text = ""
        try:
            text = pytesseract.image_to_string(img, lang="fra+eng")
        except Exception as e:
            logger.error(f"Erreur Tesseract local : {e}")

        if text.strip():
            return text.strip(), "tesseract_ocr"
        
        # 2. STRATÉGIE DE SECOURS : IA VISION (Si Tesseract est absent ou ne voit rien)
        logger.info("Extraction locale impossible ou vide, passage à l'IA Vision...")
        from ai_provider import analyser_image_visuellement 
        text_ai = analyser_image_visuellement(data) 
        
        if text_ai and text_ai.strip():
            return text_ai.strip(), "ia_vision_fallback"
            
        raise ValueError("Aucun texte détecté, même par l'IA Vision.")

    except Exception as e:
        logger.error(f"Erreur globale extraction image : {e}")
        raise ValueError(f"Impossible d'extraire le texte : {e}")

# ── PDF ──────────────────────────────────────────────────────────────────────

def extract_from_pdf(data: bytes) -> Tuple[str, str]:
    try:
        import pdfplumber
        text = ""
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            pages_text = [p.extract_text() for p in pdf.pages if p.extract_text()]
            text = "\n\n".join(pages_text)

        if len(text.strip()) > 50:
            return text, "pdfplumber"

        logger.info("PDF scanné, tentative OCR...")
        return _ocr_pdf_pages(data), "ocr_pdf"
    except Exception as e:
        logger.error(f"Erreur PDF : {e}")
        raise ValueError(f"Erreur PDF : {e}")

def _ocr_pdf_pages(data: bytes) -> str:
    try:
        from pdf2image import convert_from_bytes
        import pytesseract
        images = convert_from_bytes(data, dpi=200)
        results = [pytesseract.image_to_string(img, lang="fra+eng").strip() for img in images]
        return "\n\n".join([r for r in results if r])
    except Exception as e:
        logger.error(f"Erreur OCR PDF : {e}")
        return ""

# ── TEXTE BRUT & DISPATCHER ──────────────────────────────────────────────────

def extract_from_text(data: bytes) -> Tuple[str, str]:
    for enc in ("utf-8", "latin-1", "cp1252"):
        try: return data.decode(enc).strip(), f"text_{enc}"
        except: continue
    raise ValueError("Encodage non supporté.")

SUPPORTED_TYPES = {
    "application/pdf": extract_from_pdf,
    "image/png": extract_from_image,
    "image/jpeg": extract_from_image,
    "image/webp": extract_from_image,
    "image/gif": extract_from_image,
    "text/plain": extract_from_text,
    "text/csv": extract_from_text,
}

EXTENSION_FALLBACK = {
    ".pdf": extract_from_pdf, ".png": extract_from_image,
    ".jpg": extract_from_image, ".jpeg": extract_from_image,
    ".webp": extract_from_image, ".txt": extract_from_text,
}

MAX_FILE_SIZE = 10 * 1024 * 1024 
MAX_TEXT_LENGTH = 8000

def extract_text(data: bytes, content_type: str, filename: str) -> dict:
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Fichier trop lourd (max 10 Mo).")

    extractor = SUPPORTED_TYPES.get(content_type)
    if not extractor:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        extractor = EXTENSION_FALLBACK.get(ext)

    if not extractor:
        raise ValueError(f"Format non supporté : {content_type}")

    text, method = extractor(data)
    char_count = len(text)
    truncated = char_count > MAX_TEXT_LENGTH
    
    return {
        "text": text[:MAX_TEXT_LENGTH] + ("\n\n[Tronqué]" if truncated else ""),
        "method": method,
        "truncated": truncated,
        "char_count": char_count,
    }
