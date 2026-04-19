"""
CIAlert — bot.py
Bot Telegram de détection d'arnaques — V2.0.
Toutes les analyses passent par POST /scan.
Supporte : texte, liens, numéros, photos, documents.
"""

import logging
import os

import httpx
from dotenv import load_dotenv
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    KeyboardButton,
)
from telegram.constants import ParseMode, ChatAction
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

from database import init_db, get_global_stats, save_report

load_dotenv()

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s · %(name)s · %(levelname)s · %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CIAlert·Bot")

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
API_URL        = os.getenv("API_URL", "http://localhost:8000")

# États du flux de signalement
AWAIT_REPORT_PLATFORM, AWAIT_REPORT_AMOUNT, AWAIT_REPORT_DESC = range(3)

RISK_EMOJI = {
    "FAIBLE":   "🟢",
    "MOYEN":    "🟡",
    "ÉLEVÉ":    "🟠",
    "CRITIQUE": "🔴",
}


# ─────────────────────────────────────────────
# APPELS API
# ─────────────────────────────────────────────

async def call_scan_text(text: str) -> dict:
    """Envoie du texte à POST /scan."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{API_URL}/scan",
            data={"content": text},
        )
        response.raise_for_status()
        return response.json()


async def call_scan_file(file_bytes: bytes, filename: str, content_type: str) -> dict:
    """Envoie un fichier à POST /scan."""
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            f"{API_URL}/scan",
            files={"file": (filename, file_bytes, content_type)},
        )
        response.raise_for_status()
        return response.json()


async def call_scan_text_and_file(
    text: str,
    file_bytes: bytes,
    filename: str,
    content_type: str,
) -> dict:
    """Envoie texte + fichier ensemble à POST /scan."""
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            f"{API_URL}/scan",
            data={"content": text},
            files={"file": (filename, file_bytes, content_type)},
        )
        response.raise_for_status()
        return response.json()


# ─────────────────────────────────────────────
# KEYBOARDS
# ─────────────────────────────────────────────

def main_keyboard():
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton("🔍 Analyser"),  KeyboardButton("📊 Statistiques")],
            [KeyboardButton("⚠️ Signaler"), KeyboardButton("❓ Aide")],
        ],
        resize_keyboard=True,
    )


def report_platform_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("MTN MoMo",    callback_data="rplat:MTN"),
            InlineKeyboardButton("Orange Money", callback_data="rplat:Orange"),
        ],
        [
            InlineKeyboardButton("Wave",         callback_data="rplat:Wave"),
            InlineKeyboardButton("WhatsApp",     callback_data="rplat:WhatsApp"),
        ],
        [InlineKeyboardButton("Passer",          callback_data="rplat:skip")],
    ])


def result_keyboard(scan_id: int):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⚠️ Signaler cette arnaque", callback_data=f"report_from:{scan_id}")],
        [InlineKeyboardButton("🔍 Analyser autre chose",   callback_data="new_analysis")],
    ])


# ─────────────────────────────────────────────
# FORMATAGE DU RÉSULTAT
# ─────────────────────────────────────────────

def format_result(data: dict) -> str:
    """Formate le résultat de /scan en message Telegram."""
    is_scam    = data.get("is_scam", False)
    risk_level = data.get("risk_level", "FAIBLE")
    emoji      = RISK_EMOJI.get(risk_level, "⚪")

    if is_scam:
        header = f"🚨 *Arnaque probable*\n{emoji} Niveau de risque : *{risk_level}*"
    else:
        header = "✅ *Contenu sain*\nAucun signal d'arnaque détecté."

    confidence = round((data.get("confidence") or 0) * 100)
    conf_bar   = "█" * (confidence // 10) + "░" * (10 - confidence // 10)

    message     = data.get("message", "")
    explanation = data.get("explanation", "")
    advice      = data.get("advice", "")

    # Infos fichier si présent
    file_info = data.get("file_info")
    file_line = ""
    if file_info:
        file_line = f"📎 _{file_info.get('filename', '')}_ · {file_info.get('size_kb', '')} Ko\n\n"

    # Avertissements supplémentaires
    extras = []
    if data.get("phone_warning"):
        extras.append(f"📵 _{data['phone_warning']}_")
    if data.get("fake_news") and data["fake_news"].get("verdict") != "FIABLE":
        extras.append(f"🔍 _{data['fake_news'].get('message', '')}_")

    scan_id = data.get("scan_id", "—")

    lines = [header, "", f"📊 *Confiance :* {confidence}%", f"`{conf_bar}`", ""]

    if file_line:
        lines.append(file_line)

    if message:
        lines += [f"💬 {message}", ""]

    if explanation:
        lines += [f"📝 _{explanation}_", ""]

    if advice:
        lines += [f"💡 *Que faire ?* {advice}", ""]

    for extra in extras:
        lines += [extra, ""]

    lines.append("┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄")
    lines.append(f"🆔 Analyse #{scan_id}")

    return "\n".join(lines)


def format_error(context: str) -> str:
    return f"L'analyse a échoué ({context}). Réessaye dans quelques instants."


# ─────────────────────────────────────────────
# COMMANDES
# ─────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "ami"
    await update.message.reply_text(
        f"🇨🇮 *Bienvenue sur CIAlert, {name} !*\n\n"
        "Je suis ton assistant anti-arnaques pour la Côte d'Ivoire.\n\n"
        "Envoie-moi un SMS suspect, un lien, un numéro "
        "ou une capture d'écran — j'analyse tout automatiquement.\n\n"
        "Utilise le menu ci-dessous 👇",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )


async def cmd_aide(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "❓ *Comment utiliser CIAlert ?*\n\n"
        "Envoie n'importe quel contenu suspect :\n"
        "• Un SMS ou message WhatsApp\n"
        "• Un lien : `http://orange-money-bonus.tk`\n"
        "• Un numéro : `+225 07 00 00 00`\n"
        "• Une capture d'écran (photo)\n"
        "• Un fichier PDF ou texte\n\n"
        "CIAlert détecte le type automatiquement et analyse.\n\n"
        "🔒 Analyse anonyme.",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )


async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        s    = get_global_stats()
        cats = s.get("categories", {})
        cats_txt = "\n".join(
            f"  • {k} : {v}"
            for k, v in sorted(cats.items(), key=lambda x: -x[1])
        ) or "  Aucune donnée"

        await update.message.reply_text(
            f"📊 *Statistiques CIAlert*\n\n"
            f"🔍 Analyses : {s['total_analyses']}\n"
            f"🚨 Arnaques : {s['total_scams']}\n"
            f"📈 Taux : {s['scam_rate']}%\n"
            f"📝 Signalements : {s['total_reports']}\n\n"
            f"🏷 Par catégorie :\n{cats_txt}",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard(),
        )
    except Exception as error:
        logger.error(f"Erreur stats : {error}")
        await update.message.reply_text("Impossible de charger les statistiques.")


# ─────────────────────────────────────────────
# ANALYSE — TEXTE
# ─────────────────────────────────────────────

async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Reçoit tout message texte et le soumet à /scan."""
    text = update.message.text.strip()

    # Boutons du clavier principal
    if text == "🔍 Analyser":
        await update.message.reply_text(
            "Envoie le texte, lien ou numéro à vérifier :",
            reply_markup=main_keyboard(),
        )
        return
    if text == "📊 Statistiques":
        return await cmd_stats(update, ctx)
    if text == "⚠️ Signaler":
        return await start_report(update, ctx)
    if text == "❓ Aide":
        return await cmd_aide(update, ctx)

    await update.message.chat.send_action(ChatAction.TYPING)

    try:
        result = await call_scan_text(text)
    except httpx.HTTPStatusError as error:
        logger.error(f"Erreur API /scan texte : {error}")
        await update.message.reply_text(format_error("API"))
        return
    except Exception as error:
        logger.error(f"Erreur inattendue /scan texte : {error}")
        await update.message.reply_text(format_error("inattendue"))
        return

    ctx.user_data["last_scan_id"] = result.get("scan_id")
    ctx.user_data["last_text"]    = text

    await update.message.reply_text(
        format_result(result),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=result_keyboard(result.get("scan_id") or 0),
    )


# ─────────────────────────────────────────────
# ANALYSE — FICHIERS ET PHOTOS
# ─────────────────────────────────────────────

async def handle_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    Reçoit une photo ou un document Telegram,
    télécharge le fichier en mémoire et l'envoie à /scan.
    La légende du fichier est envoyée avec si présente.
    """
    msg = update.message

    # Détermination du type
    if msg.photo:
        tg_file      = await msg.photo[-1].get_file()  # meilleure résolution
        filename     = "capture.jpg"
        content_type = "image/jpeg"
    elif msg.document:
        tg_file      = await msg.document.get_file()
        filename     = msg.document.file_name or "fichier"
        content_type = msg.document.mime_type or "application/octet-stream"
    else:
        return

    await msg.chat.send_action(ChatAction.UPLOAD_DOCUMENT)

    # Téléchargement en mémoire
    try:
        file_bytes = bytes(await tg_file.download_as_bytearray())
    except Exception as error:
        logger.error(f"Erreur téléchargement fichier Telegram : {error}")
        await msg.reply_text("Impossible de récupérer le fichier. Réessaye.")
        return

    await msg.chat.send_action(ChatAction.TYPING)

    # Légende éventuelle accompagnant le fichier
    caption = (msg.caption or "").strip()

    try:
        if caption:
            result = await call_scan_text_and_file(caption, file_bytes, filename, content_type)
        else:
            result = await call_scan_file(file_bytes, filename, content_type)

    except httpx.HTTPStatusError as error:
        logger.error(f"Erreur API /scan fichier ({error.response.status_code})")
        if error.response.status_code == 422:
            detail = error.response.json().get("detail", "Format non supporté.")
            await msg.reply_text(f"Ce fichier ne peut pas être analysé : {detail}")
        else:
            await msg.reply_text(format_error("API"))
        return
    except Exception as error:
        logger.error(f"Erreur inattendue /scan fichier : {error}")
        await msg.reply_text(format_error("inattendue"))
        return

    ctx.user_data["last_scan_id"] = result.get("scan_id")
    ctx.user_data["last_text"]    = caption or filename

    await msg.reply_text(
        format_result(result),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=result_keyboard(result.get("scan_id") or 0),
    )


# ─────────────────────────────────────────────
# FLUX DE SIGNALEMENT
# ─────────────────────────────────────────────

async def start_report(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.setdefault("report_data", {})
    ctx.user_data["report_data"]["content"] = ctx.user_data.get("last_text", "Signalement Telegram")
    ctx.user_data["report_data"]["scan_id"] = ctx.user_data.get("last_scan_id")

    msg = update.message or update.callback_query.message
    await msg.reply_text(
        "⚠️ *Signaler une arnaque*\n\nQuelle plateforme est concernée ?",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=report_platform_keyboard(),
    )
    return AWAIT_REPORT_PLATFORM


async def report_platform_chosen(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query    = update.callback_query
    await query.answer()
    platform = query.data.split(":")[1]
    ctx.user_data["report_data"]["platform"] = None if platform == "skip" else platform

    await query.edit_message_text(
        "💰 Montant escroqué en FCFA (tape `0` pour passer) :",
        parse_mode=ParseMode.MARKDOWN,
    )
    return AWAIT_REPORT_AMOUNT


async def report_amount_received(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        amount = float(update.message.text.replace(" ", "").replace(",", "."))
        ctx.user_data["report_data"]["amount"] = amount if amount > 0 else None
    except ValueError:
        ctx.user_data["report_data"]["amount"] = None

    await update.message.reply_text(
        "📝 Décris brièvement ce qui s'est passé (ou envoie `/passer`) :",
        parse_mode=ParseMode.MARKDOWN,
    )
    return AWAIT_REPORT_DESC


async def report_desc_received(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    ctx.user_data["report_data"]["description"] = (
        None if text.startswith("/passer") else text
    )

    d = ctx.user_data["report_data"]

    try:
        report_id = save_report(
            reported_text=d.get("content", "—"),
            report_type="autre",
            scan_id=d.get("scan_id"),
            victim_amount=d.get("amount"),
            victim_platform=d.get("platform"),
            description=d.get("description"),
        )

        from phone_registry import register_phone_from_text
        register_phone_from_text(
            text=d.get("content", ""),
            source="bot_report",
            report_id=report_id,
        )

        await update.message.reply_text(
            f"🙏 *Merci pour ton signalement !*\n\n"
            f"Référence : `#{report_id}`\n"
            "Ton signalement protège toute la communauté ivoirienne. 🇨🇮",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard(),
        )
    except Exception as error:
        logger.error(f"Erreur sauvegarde signalement : {error}")
        await update.message.reply_text(
            "Signalement non enregistré. Réessaye plus tard.",
            reply_markup=main_keyboard(),
        )

    ctx.user_data["report_data"] = {}
    return ConversationHandler.END


async def report_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Signalement annulé.", reply_markup=main_keyboard())
    return ConversationHandler.END


# ─────────────────────────────────────────────
# CALLBACKS BOUTONS INLINE
# ─────────────────────────────────────────────

async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data  = query.data

    if data == "new_analysis":
        await query.message.reply_text(
            "Envoie le texte, la photo ou le fichier à analyser :",
            reply_markup=main_keyboard(),
        )
    elif data.startswith("report_from:"):
        scan_id = int(data.split(":")[1])
        ctx.user_data.setdefault("report_data", {})
        ctx.user_data["report_data"]["scan_id"] = scan_id
        ctx.user_data["report_data"]["content"] = ctx.user_data.get("last_text", "—")
        await query.message.reply_text(
            "⚠️ *Signaler une arnaque*\n\nQuelle plateforme est concernée ?",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=report_platform_keyboard(),
        )


# ─────────────────────────────────────────────
# LANCEMENT
# ─────────────────────────────────────────────

def main():
    if not TELEGRAM_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN manquant dans .env")

    init_db()

    app = Application.builder().token(TELEGRAM_TOKEN).build()

    report_conv = ConversationHandler(
        entry_points=[CommandHandler("signaler", start_report)],
        states={
            AWAIT_REPORT_PLATFORM: [CallbackQueryHandler(report_platform_chosen, pattern="^rplat:")],
            AWAIT_REPORT_AMOUNT:   [MessageHandler(filters.TEXT & ~filters.COMMAND, report_amount_received)],
            AWAIT_REPORT_DESC:     [MessageHandler(filters.TEXT, report_desc_received)],
        },
        fallbacks=[CommandHandler("annuler", report_cancel)],
        allow_reentry=True,
        per_message=False,  # supprime le warning PTBUserWarning
    )

    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("aide",     cmd_aide))
    app.add_handler(CommandHandler("help",     cmd_aide))
    app.add_handler(CommandHandler("stats",    cmd_stats))
    app.add_handler(report_conv)
    app.add_handler(CallbackQueryHandler(handle_callback))

    # Fichiers et photos — avant le handler texte
    app.add_handler(MessageHandler(filters.PHOTO,        handle_file))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    # Texte en dernier
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("CIAlert Bot V2.0 démarré.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()