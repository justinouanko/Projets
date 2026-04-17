"""
CIAlert — phone_registry.py
Extraction de numéros de téléphone depuis un texte libre
et consultation du répertoire interne des numéros signalés.

Usage interne uniquement — aucune donnée de ce module
ne doit être exposée directement sur le frontend.
"""

import re
from typing import Optional

from database import (
    add_phone_report,
    is_phone_flagged,
    get_phone_categories,
    get_phone_report_count,
)


# ─────────────────────────────────────────────
# NORMALISATION
# ─────────────────────────────────────────────

def normalize_phone(raw: str) -> str:
    """
    Normalise un numéro de téléphone au format international +225XXXXXXXXXX.
    Supprime espaces, tirets, points. Ajoute +225 si absent.
    """
    digits = re.sub(r"[\s\-\.\(\)]", "", raw)

    # Déjà au format international
    if digits.startswith("+225"):
        return digits

    # Format 00225XXXXXXXXXX
    if digits.startswith("00225"):
        return "+" + digits[2:]

    # Format local ivoirien : 10 chiffres commençant par 0
    if digits.startswith("0") and len(digits) == 10:
        return "+225" + digits[1:]

    # Format local sans zéro : 9 chiffres (ex: 758341122)
    if len(digits) == 9:
        return "+225" + digits

    # Autres cas : on retourne tel quel pour ne pas perdre le numéro
    return digits


# ─────────────────────────────────────────────
# EXTRACTION
# ─────────────────────────────────────────────

# Formats ivoiriens couverts :
# +225 07 58 34 11 22
# +225 0758341122
# 00225 07 58 34 11 22
# 07 58 34 11 22
# 0758341122
# 758341122

PHONE_PATTERN = re.compile(
    r"""
    (?:
        \+225[\s\-]?         |   # +225 avec espace ou tiret optionnel
        00225[\s\-]?         |   # 00225
        (?<!\d)0             |   # 0 en début de numéro local (pas précédé d'un chiffre)
        (?<!\d)(?=[5-9])         # chiffre 5-9 en début (numéro sans zéro)
    )
    (?:\d[\s\-]?){8,10}         # 8 à 10 chiffres avec séparateurs optionnels
    (?!\d)                       # pas suivi d'un chiffre
    """,
    re.VERBOSE
)


def extract_phone_numbers(text: str) -> list[str]:
    """
    Extrait et normalise tous les numéros de téléphone trouvés dans un texte.
    Retourne une liste sans doublons.
    """
    matches = PHONE_PATTERN.findall(text)
    seen = set()
    result = []
    for match in matches:
        normalized = normalize_phone(match.strip())
        # On garde seulement les numéros qui ressemblent à un vrai numéro
        if len(re.sub(r"\D", "", normalized)) >= 9 and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


# ─────────────────────────────────────────────
# CONSULTATION DU RÉPERTOIRE
# ─────────────────────────────────────────────

def check_phone(phone_number: str) -> dict:
    """
    Vérifie si un numéro est dans le répertoire.

    Retourne un dict à usage interne :
    {
        "flagged": bool,
        "report_count": int,
        "categories": list[str]
    }

    Le frontend ne reçoit que "flagged" (booléen).
    """
    flagged = is_phone_flagged(phone_number)
    if not flagged:
        return {"flagged": False, "report_count": 0, "categories": []}

    return {
        "flagged": True,
        "report_count": get_phone_report_count(phone_number),
        "categories": get_phone_categories(phone_number),
    }


def check_phones_in_text(text: str) -> dict:
    """
    Extrait tous les numéros d'un texte et vérifie chacun dans le répertoire.

    Retourne :
    {
        "numbers_found": list[str],   # numéros extraits (usage interne)
        "any_flagged": bool,          # seul ce champ va vers le frontend
        "details": dict               # numéro → résultat check (usage interne)
    }
    """
    numbers = extract_phone_numbers(text)

    if not numbers:
        return {"numbers_found": [], "any_flagged": False, "details": {}}

    details = {}
    any_flagged = False

    for number in numbers:
        result = check_phone(number)
        details[number] = result
        if result["flagged"]:
            any_flagged = True

    return {
        "numbers_found": numbers,
        "any_flagged": any_flagged,
        "details": details,
    }


# ─────────────────────────────────────────────
# ALIMENTATION DU RÉPERTOIRE
# ─────────────────────────────────────────────

def register_phone_from_text(
    text: str,
    scam_category: Optional[str] = None,
    source: str = "report",
    scan_id: Optional[int] = None,
    report_id: Optional[int] = None
) -> int:
    """
    Extrait les numéros d'un texte signalé et les ajoute au répertoire.
    Retourne le nombre de numéros enregistrés.
    """
    numbers = extract_phone_numbers(text)
    count = 0
    for number in numbers:
        add_phone_report(
            phone_number=number,
            scam_category=scam_category,
            source=source,
            scan_id=scan_id,
            report_id=report_id,
        )
        count += 1
    return count


def register_phone(
    phone_number: str,
    scam_category: Optional[str] = None,
    source: str = "report",
    scan_id: Optional[int] = None,
    report_id: Optional[int] = None
) -> None:
    """Ajoute un numéro unique au répertoire (déjà normalisé ou extrait)."""
    normalized = normalize_phone(phone_number)
    add_phone_report(
        phone_number=normalized,
        scam_category=scam_category,
        source=source,
        scan_id=scan_id,
        report_id=report_id,
    )